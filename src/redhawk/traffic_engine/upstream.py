"""RedHawk v2 — 上游转发会话（W1：每请求新建连接；W2 起加连接池）。

对应 06 号文档 §四.2。职责：
1. 解析目标 host/port/tls/url（代理请求 / CONNECT-MITM 两种来源）
2. 建立上游连接（明文或 TLS）
3. 用 h11 CLIENT 角色转发请求（过滤 hop-by-hop 头，h11 自动补 CL/chunked）
4. 读取上游响应事件，回传给客户端（h11 SERVER 的 conn/writer 由调用方传入）
5. 组装请求/响应对入库（recorder.save_traffic）
"""

from __future__ import annotations

import asyncio
import json
import ssl
from urllib.parse import urlparse

import h11

from redhawk.traffic_engine import config as engine_config
from redhawk.traffic_engine.recorder import MAX_BODY, save_traffic

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


class UpstreamSession:
    """单次请求的上游会话：请求转发 + 响应回传 + 入库。"""

    def __init__(self, db, source: str = "proxy", https_host: str | None = None,
                 https_port: int | None = None):
        self.db = db
        self.source = source
        self.https_host = https_host      # MITM 场景：上游目标 host
        self.https_port = https_port or 443
        self.conn: h11.Connection | None = None
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.via_proxy: bool = False
        self.meta: dict = {}

    # ---------- 请求侧 ----------
    async def start(self, request: h11.Request) -> dict | None:
        """解析目标并建立上游连接，发送请求头。返回请求元信息；失败返回 None。"""
        host, port, tls, target_path, url = self._resolve_target(request)
        if host is None:
            return None
        try:
            self.reader, self.writer, self.via_proxy = await open_upstream(host, port, tls)
        except Exception as e:
            log.debug("upstream connect failed %s:%s: %s", host, port, e)
            return None

        self.conn = h11.Connection(h11.CLIENT)
        headers = [(k, v) for k, v in request.headers if k.lower() not in HOP_BY_HOP]
        # 明文 HTTP 走上游代理时，请求行必须用绝对 URL（RFC 7230 absolute-form）
        target_for_send = target_path
        if self.via_proxy and not tls:
            target_for_send = f"http://{host}:{port}{target_path}"
            headers.append((b"proxy-connection", b"keep-alive"))
        try:
            out = self.conn.send(h11.Request(
                method=request.method, target=target_for_send, headers=headers))
            if out:
                self.writer.write(out)
            await self.writer.drain()
        except Exception:
            await self.close()
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
        self.meta["req_body"] = (
            self.meta["req_body"] + data.decode("utf-8", errors="replace")
        )[:MAX_BODY]
        if self.conn and self.writer:
            out = self.conn.send(h11.Data(data=data))
            if out:
                self.writer.write(out)
            await self.writer.drain()

    async def end_request(self) -> None:
        if self.conn and self.writer:
            out = self.conn.send(h11.EndOfMessage())
            if out:
                self.writer.write(out)
            await self.writer.drain()

    # ---------- 响应侧 ----------
    async def relay_response(self, client_conn: h11.Connection, client_writer: asyncio.StreamWriter) -> None:
        """读取上游响应，转发回客户端（h11 SERVER），完成后入库。"""
        status = 0
        resp_headers: dict = {}
        resp_body = ""
        try:
            while True:
                data = await asyncio.wait_for(self.reader.read(65536), timeout=engine_config.RESP_TIMEOUT)
                if not data:
                    break
                self.conn.receive_data(data)
                while True:
                    try:
                        event = self.conn.next_event()
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
                        if len(resp_body) < MAX_BODY:
                            resp_body += event.data.decode("utf-8", errors="replace")
                    elif isinstance(event, h11.EndOfMessage):
                        out = client_conn.send(h11.EndOfMessage())
                        if out:
                            client_writer.write(out)
                        await client_writer.drain()
                        self._record(status, resp_headers, resp_body)
                        return
        except (asyncio.TimeoutError, ConnectionError, OSError):
            await self._send_502(client_conn, client_writer)

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

    def _record(self, status: int, resp_headers: dict, resp_body: str) -> None:
        try:
            save_traffic(
                self.db, self.meta["method"], self.meta["url"],
                self.meta["req_headers"], self.meta["req_body"],
                status, resp_headers, resp_body, self.source,
            )
        except Exception:
            pass  # 记录失败不阻断转发（v1 同策略）

    async def close(self) -> None:
        try:
            if self.writer:
                self.writer.close()
                try:
                    await self.writer.wait_closed()
                except Exception:
                    pass
        except Exception:
            pass
