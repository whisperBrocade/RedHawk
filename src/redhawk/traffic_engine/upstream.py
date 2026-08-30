"""RedHawk v2 — 上游转发会话 + 连接池（W2）。

对应 06 号文档 §四.2。职责：
1. 解析目标 host/port/tls/url（代理请求 / CONNECT-MITM 两种来源）
2. 连接池按 (tls, host, port, 上游代理) 键控复用上游连接
3. 用 h11 CLIENT 角色转发请求（过滤 hop-by-hop 头，h11 自动补 CL/chunked）
4. 读取上游响应事件，回传给客户端（h11 SERVER 的 conn/writer 由调用方传入）
5. 组装请求/响应对入库（recorder.save_traffic）
"""

from __future__ import annotations

import asyncio
import json
import ssl
import time
from collections import deque
from urllib.parse import urlparse

import h11

from redhawk.traffic_engine import config as engine_config
from redhawk.traffic_engine.recorder import MAX_BODY, collect_body, save_traffic
from redhawk.traffic_engine.stream_store import BlobWriter

log = __import__("logging").getLogger("redhawk.traffic_engine.upstream")

# 逐跳头：转发上游/回传客户端时剔除（h11 自行处理 framing）
HOP_BY_HOP = {
    "connection", "proxy-connection", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "keep-alive", "upgrade",
}


def _get_header(headers, name: str) -> str:
    """从 h11 头列表（bytes 对）取首个指定头的值。"""
    for k, v in headers:
        if k.lower() == name.encode("latin-1"):
            return v.decode("latin-1")
    return ""


def _headers_to_dict(headers) -> dict:
    return {k.decode("latin-1"): v.decode("latin-1") for k, v in headers}


async def open_upstream(host: str, port: int, tls: bool) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, bool]:
    """建立上游连接。返回 (reader, writer, via_proxy)。

    优先走显式上游代理（REDHAWK_UPSTREAM_PROXY）：
      - 明文 HTTP：连接代理，请求行用绝对 URL（调用方处理）
      - HTTPS：连接代理 → CONNECT 隧道 → TLS 升级
    无代理时直连（tls=True 做客户端 TLS，默认校验证书）。
    """
    proxy = engine_config.upstream_proxy().strip()
    if proxy:
        u = urlparse(proxy if "://" in proxy else "http://" + proxy)
        p_host = u.hostname or "127.0.0.1"
        p_port = u.port or 8080
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(p_host, p_port), timeout=engine_config.CONN_TIMEOUT
        )
        if tls:
            # CONNECT 隧道
            writer.write(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
            await writer.drain()
            head = await asyncio.wait_for(_read_head(reader), timeout=engine_config.CONN_TIMEOUT)
            status_line = head.split(b"\r\n", 1)[0]
            if not status_line.startswith(b"HTTP/1.1 200") and not status_line.startswith(b"HTTP/1.0 200"):
                raise ConnectionError(f"upstream proxy CONNECT failed: {status_line.decode('latin-1', 'replace')}")
            # TLS over tunnel（客户端侧升级）
            if engine_config.upstream_verify():
                ctx = ssl.create_default_context()
            else:
                ctx = ssl._create_unverified_context()
            await writer.start_tls(ctx, server_hostname=host)
        return reader, writer, True

    # 直连
    if tls:
        if engine_config.upstream_verify():
            ctx = ssl.create_default_context()
        else:
            ctx = ssl._create_unverified_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
            timeout=engine_config.CONN_TIMEOUT,
        )
    else:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=engine_config.CONN_TIMEOUT
        )
    return reader, writer, False


async def _read_head(reader: asyncio.StreamReader) -> bytes:
    """读取 HTTP 响应头直到空行（CONNECT 响应用）。"""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = await reader.read(4096)
        if not chunk:
            break
        buf += chunk
    return buf


# ================= 上游连接池（W2） =================
class PooledConn:
    """池中的一条上游连接（reader/writer + h11 CLIENT 状态机）。"""

    __slots__ = ("key", "reader", "writer", "h11", "via_proxy", "last_used")

    def __init__(self, key, reader, writer, h11_conn, via_proxy, last_used):
        self.key = key
        self.reader = reader
        self.writer = writer
        self.h11 = h11_conn
        self.via_proxy = via_proxy
        self.last_used = last_used

    async def close(self) -> None:
        try:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except Exception:
                pass
        except Exception:
            pass


class UpstreamPool:
    """HTTP/1.1 上游连接池：按 (tls, host, port, proxy) 键控复用。

    同一时刻一个 h1 连接只服务一个请求（acquire 独占，release 归还）。
    惰性清理：acquire 时剔除 stale（空闲超时/对端已关）连接。
    单事件循环内使用（asyncio 单线程），无需加锁。
    """

    def __init__(self, max_idle: int = 16, idle_timeout: float | None = None):
        self._idle: dict[tuple, deque[PooledConn]] = {}
        self._max_idle = max_idle
        self._idle_timeout = idle_timeout if idle_timeout is not None else engine_config.IDLE_TIMEOUT
        self.created = 0   # 新建连接计数（测试/观测用）

    # ---------- 获取 / 归还 ----------
    async def acquire(self, host: str, port: int, tls: bool) -> PooledConn:
        """取一条可用连接：优先复用空闲，否则新建。"""
        key = self._key(host, port, tls)
        q = self._idle.get(key)
        if q:
            while q:
                c = q.popleft()
                if self._stale(c):
                    await c.close()
                    continue
                try:
                    c.h11.start_next_cycle()
                except h11.LocalProtocolError:
                    await c.close()
                    continue
                c.last_used = time.monotonic()
                return c
        reader, writer, via_proxy = await open_upstream(host, port, tls)
        h = h11.Connection(h11.CLIENT)
        self.created += 1
        return PooledConn(key, reader, writer, h, via_proxy, time.monotonic())

    def try_release(self, c: PooledConn) -> bool:
        """尝试归还连接。返回 True=已归还（可继续复用），False=调用方应关闭。"""
        h = c.h11
        reusable = (
            h.our_state is h11.DONE
            and h.their_state is h11.DONE
            and h.our_state is not h11.MUST_CLOSE
            and h.their_state is not h11.MUST_CLOSE
            and not c.writer.is_closing()
        )
        q = self._idle.setdefault(c.key, deque())
        if reusable and len(q) < self._max_idle:
            c.last_used = time.monotonic()
            q.append(c)
            return True
        return False

    # ---------- 清理 ----------
    def _stale(self, c: PooledConn) -> bool:
        if c.writer.is_closing():
            return True
        if self._idle_timeout and time.monotonic() - c.last_used > self._idle_timeout:
            return True
        return False

    def _key(self, host: str, port: int, tls: bool) -> tuple:
        return (tls, host, port, engine_config.upstream_proxy().strip())

    async def close_all(self) -> None:
        for q in self._idle.values():
            while q:
                c = q.popleft()
                await c.close()
        self._idle.clear()


class UpstreamSession:
    """单次请求的上游会话：请求转发 + 响应回传 + 入库。连接来自池，用后归还。"""

    def __init__(self, db, pool: UpstreamPool, source: str = "proxy",
                 https_host: str | None = None, https_port: int | None = None):
        self.db = db
        self.pool = pool
        self.source = source
        self.https_host = https_host      # MITM 场景：上游目标 host
        self.https_port = https_port or 443
        self._conn: PooledConn | None = None
        self._req_blob: BlobWriter | None = None   # W3：大请求体流式落盘
        self.meta: dict = {}

    # ---------- 请求侧 ----------
    async def start(self, request: h11.Request) -> dict | None:
        """解析目标并从池取连接，发送请求头。返回请求元信息；失败返回 None。"""
        host, port, tls, target_path, url = self._resolve_target(request)
        if host is None:
            return None
        try:
            self._conn = await self.pool.acquire(host, port, tls)
        except Exception as e:
            log.debug("upstream connect failed %s:%s: %s", host, port, e)
            return None

        conn = self._conn.h11
        headers = [(k, v) for k, v in request.headers if k.lower() not in HOP_BY_HOP]
        # 明文 HTTP 走上游代理时，请求行必须用绝对 URL（RFC 7230 absolute-form）
        target_for_send = target_path
        if self._conn.via_proxy and not tls:
            target_for_send = f"http://{host}:{port}{target_path}"
            headers.append((b"proxy-connection", b"keep-alive"))
        try:
            out = conn.send(h11.Request(
                method=request.method, target=target_for_send, headers=headers))
            if out:
                self._conn.writer.write(out)
            await self._conn.writer.drain()
        except Exception:
            await self._discard()
            return None

        self.meta = {
            "method": request.method.decode("latin-1"),
            "url": url,
            "req_headers": _headers_to_dict(request.headers),
            "req_body": "",
        }
        return self.meta

    def _resolve_target(self, request: h11.Request):
        """解析目标。MITM 场景（https_host 已定）直接用；否则按代理请求解析。"""
        if self.https_host:
            target = request.target.decode("latin-1")
            url = f"https://{self.https_host}:{self.https_port}{target}"
            return self.https_host, self.https_port, True, target, url

        target = request.target.decode("latin-1")
        if target.startswith("http://"):
            u = urlparse(target)
            path = u.path or "/"
            if u.query:
                path += "?" + u.query
            return u.hostname or "127.0.0.1", u.port or 80, False, path, target

        host_hdr = _get_header(request.headers, "host") or "127.0.0.1"
        if ":" in host_hdr and host_hdr.count(":") == 1:
            h, p = host_hdr.rsplit(":", 1)
            try:
                port = int(p)
            except ValueError:
                port = 80
        else:
            h, port = host_hdr, 80
        return h, port, False, target, f"http://{host_hdr}{target}"

    async def send_data(self, data: bytes) -> None:
        # 请求体：前 MAX_BODY 作摘要，超限后全文进 blob（上传大 body 不丢）
        self.meta["req_body"], self._req_blob = collect_body(
            self.meta["req_body"], self._req_blob, data)
        if self._conn:
            out = self._conn.h11.send(h11.Data(data=data))
            if out:
                self._conn.writer.write(out)
            await self._conn.writer.drain()

    async def end_request(self) -> None:
        if self._req_blob is not None:
            self.meta["req_blob_sha"] = self._req_blob.finalize()
            self.meta["req_blob_size"] = self._req_blob.size
            self._req_blob = None
        if self._conn:
            out = self._conn.h11.send(h11.EndOfMessage())
            if out:
                self._conn.writer.write(out)
            await self._conn.writer.drain()

    # ---------- 响应侧 ----------
    async def relay_response(self, client_conn: h11.Connection, client_writer: asyncio.StreamWriter) -> None:
        """读取上游响应，转发回客户端（h11 SERVER），完成后入库并归还连接。

        body 记录策略：前 MAX_BODY 进 traffic 表（快查摘要），
        超限部分全文进 content-addressed blob（边收边写，不截断）。
        """
        status = 0
        resp_headers: dict = {}
        resp_body = ""
        resp_blob: BlobWriter | None = None
        try:
            while True:
                data = await asyncio.wait_for(
                    self._conn.reader.read(65536), timeout=engine_config.RESP_TIMEOUT)
                if not data:
                    break
                self._conn.h11.receive_data(data)
                while True:
                    try:
                        event = self._conn.h11.next_event()
                    except h11.RemoteProtocolError:
                        await self._send_502(client_conn, client_writer)
                        return
                    if event is h11.NEED_DATA or event is h11.PAUSED:
                        break
                    if isinstance(event, h11.InformationalResponse):
                        # 100-continue 等中间响应透传
                        out = client_conn.send(h11.InformationalResponse(
                            status_code=event.status_code, headers=event.headers))
                        if out:
                            client_writer.write(out)
                    elif isinstance(event, h11.Response):
                        status = event.status_code
                        resp_headers = _headers_to_dict(event.headers)
                        hdrs = [(k, v) for k, v in event.headers if k.lower() not in HOP_BY_HOP]
                        out = client_conn.send(h11.Response(status_code=event.status_code, headers=hdrs))
                        if out:
                            client_writer.write(out)
                    elif isinstance(event, h11.Data):
                        out = client_conn.send(h11.Data(data=event.data))
                        if out:
                            client_writer.write(out)
                        resp_body, resp_blob = collect_body(resp_body, resp_blob, event.data)
                    elif isinstance(event, h11.EndOfMessage):
                        out = client_conn.send(h11.EndOfMessage())
                        if out:
                            client_writer.write(out)
                        await client_writer.drain()
                        resp_sha = resp_size = None
                        if resp_blob is not None:
                            resp_sha = resp_blob.finalize()
                            resp_size = resp_blob.size
                            resp_blob = None
                        self._record(status, resp_headers, resp_body,
                                     resp_blob_sha=resp_sha, resp_blob_size=resp_size)
                        return
        except (asyncio.TimeoutError, ConnectionError, OSError):
            if resp_blob is not None:
                resp_blob.abort()
                resp_blob = None
            await self._send_502(client_conn, client_writer)
        finally:
            # 响应结束（或异常）：归还连接复用，无法复用则关闭
            c = self._conn
            self._conn = None
            if c is not None and not self.pool.try_release(c):
                await c.close()

    async def _discard(self) -> None:
        """请求侧失败：关闭连接，不归还池。"""
        c = self._conn
        self._conn = None
        if c is not None:
            await c.close()

    async def _send_502(self, client_conn: h11.Connection, client_writer: asyncio.StreamWriter) -> None:
        try:
            out = client_conn.send(h11.Response(status_code=502, headers=[(b"content-type", b"text/plain")]))
            if out:
                client_writer.write(out)
            out = client_conn.send(h11.Data(data=b"redhawk upstream error".encode()))
            if out:
                client_writer.write(out)
            out = client_conn.send(h11.EndOfMessage())
            if out:
                client_writer.write(out)
            await client_writer.drain()
        except Exception:
            pass

    def _record(self, status: int, resp_headers: dict, resp_body: str,
                resp_blob_sha: str | None = None, resp_blob_size: int = 0) -> None:
        try:
            save_traffic(
                self.db, self.meta["method"], self.meta["url"],
                self.meta["req_headers"], self.meta["req_body"],
                status, resp_headers, resp_body, self.source,
                req_blob_sha=self.meta.get("req_blob_sha"),
                resp_blob_sha=resp_blob_sha,
                req_blob_size=self.meta.get("req_blob_size", 0),
                resp_blob_size=resp_blob_size,
                proto=self.meta.get("proto", "http1"),
                http_version=self.meta.get("http_version"),
            )
        except Exception:
            pass  # 记录失败不阻断转发（v1 同策略）
