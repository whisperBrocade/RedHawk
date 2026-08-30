"""RedHawk v2 — HTTP/2 客户端连接处理器（W3）。

对应 06 号文档 §五。客户端侧 h2 服务端 + 上游侧 h2 客户端，
按流 ID 映射表桥接：
- 客户端请求流 → 上游新流（伪头原样转发，h2→h2 无需转换）
- 上游响应流 → 客户端对应流（多路复用，每流独立组装记录）
- 流量控制：收到 Data 即 acknowledge_received_data 补窗口
- GOAWAY/StreamReset 及时清理流映射

单客户端连接对应一个上游 h2 连接（按首个请求目标建立）。
"""

from __future__ import annotations

import asyncio
import logging
import ssl

import h2.config
import h2.connection
import h2.events
import h2.settings
from h2.settings import SettingCodes

from redhawk.traffic_engine import config as engine_config
from redhawk.traffic_engine.recorder import MAX_BODY, collect_body, save_traffic
from redhawk.traffic_engine.stream_store import BlobWriter
from redhawk.traffic_engine.upstream import _headers_to_dict

log = logging.getLogger("redhawk.traffic_engine.h2")

# 客户端流/连接窗口（8MB：大响应一次发完，避免频繁 WINDOW_UPDATE 循环）
MAX_FLOW_WINDOW = 8 * 1024 * 1024


class _StreamMeta:
    __slots__ = ("client_sid", "up_sid", "method", "url", "req_headers",
                 "req_body", "req_blob", "status", "resp_headers",
                 "resp_body", "resp_blob", "req_ended", "resp_ended")

    def __init__(self, client_sid: int):
        self.client_sid = client_sid
        self.up_sid: int | None = None
        self.method = ""
        self.url = ""
        self.req_headers: dict = {}
        self.req_body = ""
        self.req_blob: BlobWriter | None = None
        self.status = 0
        self.resp_headers: dict = {}
        self.resp_body = ""
        self.resp_blob: BlobWriter | None = None
        self.req_ended = False
        self.resp_ended = False


def _pseudo_value(headers, name: str) -> str:
    for k, v in headers:
        if k.lower() == name.encode("latin-1"):
            return v.decode("latin-1")
    return ""


def _normal_headers(headers) -> list[tuple[bytes, bytes]]:
    """过滤伪头，仅保留普通头（转发用）。"""
    return [(k, v) for k, v in headers if not k.startswith(b":")]


class H2ClientConnection:
    def __init__(self, db, source: str = "proxy_https", port: int = 8888,
                 https_host: str | None = None, https_port: int | None = None):
        self.db = db
        self.source = source
        self.port = port
        self.https_host = https_host
        self.https_port = https_port or 443
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.client: h2.connection.H2Connection | None = None
        self.upstream: h2.connection.H2Connection | None = None
        self.up_reader: asyncio.StreamReader | None = None
        self.up_writer: asyncio.StreamWriter | None = None
        self.streams: dict[int, _StreamMeta] = {}
        self._up_host = https_host
        self._up_port = https_port or 443
        self._client_closed = False
        self._up_closed = False

    # ---------- 主循环 ----------
    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader, self.writer = reader, writer
        log.debug("h2 handle start, upstream=%s:%s", self._up_host, self._up_port)
        cfg = h2.config.H2Configuration(client_side=False, header_encoding=None)
        self.client = h2.connection.H2Connection(config=cfg)
        _s = h2.settings.Settings(client=False)
        _s[SettingCodes.INITIAL_WINDOW_SIZE] = MAX_FLOW_WINDOW
        self.client.local_settings = _s
        # 连接窗口初始仅 64KB（规范固定），立即扩容避免大响应触发窗口更新循环
        self.client.increment_flow_control_window(MAX_FLOW_WINDOW)
        try:
            # 客户端侧读取循环
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                events = self.client.receive_data(data)
                log.debug("h2 recv %d bytes -> %d events", len(data), len(events))
                for ev in events:
                    await self._on_client_event(ev)
                # 事件处理后再 flush（acknowledge 产生的 WINDOW_UPDATE 需发出）
                out = self.client.data_to_send()
                if out:
                    writer.write(out)
                    await writer.drain()
                if self._client_closed:
                    break
        except Exception:
            log.debug("h2 client handler error", exc_info=True)
        finally:
            await self._close_all()

    # ---------- 客户端侧事件 ----------
    async def _on_client_event(self, ev) -> None:
        log.debug("h2 client event: %s", type(ev).__name__)
        if isinstance(ev, h2.events.RequestReceived):
            await self._on_request(ev)
        elif isinstance(ev, h2.events.DataReceived):
            await self._on_client_data(ev)
        elif isinstance(ev, h2.events.StreamEnded):
            self._on_client_stream_ended(ev.stream_id)
        elif isinstance(ev, h2.events.StreamReset):
            self._cleanup(ev.stream_id)
        elif isinstance(ev, h2.events.ConnectionTerminated):
            self._client_closed = True

    async def _on_request(self, ev: h2.events.RequestReceived) -> None:
        sid = ev.stream_id
        meta = _StreamMeta(sid)
        meta.method = _pseudo_value(ev.headers, ":method") or "GET"
        scheme = _pseudo_value(ev.headers, ":scheme") or "https"
        authority = _pseudo_value(ev.headers, ":authority")
        path = _pseudo_value(ev.headers, ":path") or "/"
        meta.url = f"{scheme}://{authority}{path}"
        meta.req_headers = _headers_to_dict(ev.headers)
        self.streams[sid] = meta

        # 确保上游 h2 连接
        if self.upstream is None:
            if not await self._connect_upstream():
                await self._send_502(sid)
                return
        # 打开上游流并转发请求头（伪头原样）
        up_sid = self.upstream.get_next_available_stream_id()
        meta.up_sid = up_sid
        end_stream = ev.stream_ended  # 请求无 body 时直接结束
        self.upstream.send_headers(up_sid, ev.headers, end_stream=end_stream)
        # 流窗口扩容：必须先发 HEADERS 打开流（对未打开流 increment 会抛错被吞）；
        # SETTINGS 若未被对端应用则逐流兜底，保证大响应一次发完
        try:
            self.upstream.increment_flow_control_window(MAX_FLOW_WINDOW, stream_id=up_sid)
        except Exception:
            pass
        await self._flush_upstream()
        if end_stream:
            meta.req_ended = True

    async def _on_client_data(self, ev: h2.events.DataReceived) -> None:
        # 补窗口（h2 API: acknowledge_received_data(size, stream_id)）
        self.client.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
        meta = self.streams.get(ev.stream_id)
        if meta is None or self.upstream is None:
            return
        if meta.up_sid is None:
            return
        # 请求体记录（摘要 + blob）
        self._append_body(meta, ev.data, req=True)
        # 转发上游
        self.upstream.send_data(meta.up_sid, ev.data)
        await self._flush_upstream()

    def _on_client_stream_ended(self, sid: int) -> None:
        meta = self.streams.get(sid)
        if meta is None or self.upstream is None:
            return
        if meta.req_ended:   # 无 body 请求在转发头时已 end_stream
            return
        meta.req_ended = True
        if meta.up_sid is not None and not meta.resp_ended:
            self.upstream.end_stream(meta.up_sid)
            asyncio.ensure_future(self._flush_upstream())

    # ---------- 上游侧 ----------
    async def _connect_upstream(self) -> bool:
        try:
            ctx = ssl.create_default_context() if engine_config.upstream_verify() \
                else ssl._create_unverified_context()
            ctx.set_alpn_protocols(["h2"])
            self.up_reader, self.up_writer = await asyncio.wait_for(
                asyncio.open_connection(self._up_host, self._up_port,
                                        ssl=ctx, server_hostname=self._up_host),
                timeout=engine_config.CONN_TIMEOUT)
        except Exception as e:
            log.debug("h2 upstream connect failed: %s", e)
            return False
        if self.up_writer.get_extra_info("ssl_object").selected_alpn_protocol() != "h2":
            log.debug("upstream %s:%s does not support h2", self._up_host, self._up_port)
            return False
        cfg = h2.config.H2Configuration(client_side=True, header_encoding=None)
        self.upstream = h2.connection.H2Connection(config=cfg)
        _s = h2.settings.Settings(client=True)
        _s[SettingCodes.INITIAL_WINDOW_SIZE] = MAX_FLOW_WINDOW
        self.upstream.local_settings = _s
        out = self.upstream.initiate_connection() or b""
        # 连接窗口扩容：大响应一次发完（真实场景同样提升吞吐）
        self.upstream.increment_flow_control_window(MAX_FLOW_WINDOW)
        out += self.upstream.data_to_send() or b""
        if out:
            self.up_writer.write(out)
            await self.up_writer.drain()
        # 上游读取循环
        asyncio.ensure_future(self._upstream_loop())
        return True

    async def _upstream_loop(self) -> None:
        try:
            while self.upstream is not None and not self._up_closed:
                data = await self.up_reader.read(65536)
                if not data:
                    break
                events = self.upstream.receive_data(data)
                for ev in events:
                    await self._on_upstream_event(ev)
                # 事件处理后再 flush（acknowledge 产生的 WINDOW_UPDATE 需发出）
                out = self.upstream.data_to_send()
                log.debug("h2 upstream flush %d bytes after %d events",
                          len(out or b""), len(events))
                if out:
                    self.up_writer.write(out)
                    await self.up_writer.drain()
        except Exception:
            log.debug("h2 upstream loop error", exc_info=True)
        finally:
            pass

    async def _on_upstream_event(self, ev) -> None:
        if isinstance(ev, h2.events.ResponseReceived):
            # 上游流 → 客户端流
            meta = self._meta_by_up_sid(ev.stream_id)
            if meta is None:
                return
            meta.status = int(_pseudo_value(ev.headers, ":status") or "0")
            meta.resp_headers = _headers_to_dict(ev.headers)
            self.client.send_headers(meta.client_sid, ev.headers)
            await self._flush_client()
        elif isinstance(ev, h2.events.DataReceived):
            meta = self._meta_by_up_sid(ev.stream_id)
            log.debug("upstream DataReceived sid=%s meta=%s", ev.stream_id,
                      meta.up_sid if meta else None)
            if meta is None:
                return
            self.upstream.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
            self.client.send_data(meta.client_sid, ev.data)
            await self._flush_client()
            self._append_body(meta, ev.data, req=False)
        elif isinstance(ev, h2.events.StreamEnded):
            meta = self._meta_by_up_sid(ev.stream_id)
            if meta is None:
                return
            meta.resp_ended = True
            self.client.end_stream(meta.client_sid)
            await self._flush_client()
            self._record(meta)
            self.streams.pop(meta.client_sid, None)
        elif isinstance(ev, h2.events.StreamReset):
            meta = self._meta_by_up_sid(ev.stream_id)
            if meta is not None:
                self._cleanup(meta.client_sid)
        elif isinstance(ev, h2.events.ConnectionTerminated):
            self._up_closed = True

    def _meta_by_up_sid(self, up_sid: int) -> _StreamMeta | None:
        for m in self.streams.values():
            if m.up_sid == up_sid:
                return m
        return None

    # ---------- 记录 ----------
    def _append_body(self, meta: _StreamMeta, data: bytes, req: bool) -> None:
        if req:
            meta.req_body, meta.req_blob = collect_body(meta.req_body, meta.req_blob, data)
        else:
            meta.resp_body, meta.resp_blob = collect_body(meta.resp_body, meta.resp_blob, data)

    def _record(self, meta: _StreamMeta) -> None:
        try:
            req_sha = req_size = None
            if meta.req_blob is not None:
                req_sha = meta.req_blob.finalize()
                req_size = meta.req_blob.size
            resp_sha = resp_size = None
            if meta.resp_blob is not None:
                resp_sha = meta.resp_blob.finalize()
                resp_size = meta.resp_blob.size
            save_traffic(
                self.db, meta.method, meta.url, meta.req_headers, meta.req_body,
                meta.status, meta.resp_headers, meta.resp_body, self.source,
                req_blob_sha=req_sha, resp_blob_sha=resp_sha,
                req_blob_size=req_size or 0, resp_blob_size=resp_size or 0,
                proto="http2", http_version="HTTP/2",
            )
        except Exception:
            log.debug("h2 record error", exc_info=True)

    # ---------- 工具 ----------
    async def _flush_upstream(self) -> None:
        if self.upstream is not None and self.up_writer is not None:
            out = self.upstream.data_to_send()
            if out:
                self.up_writer.write(out)
                await self.up_writer.drain()

    async def _flush_client(self) -> None:
        if self.client is not None and self.writer is not None:
            out = self.client.data_to_send()
            if out:
                self.writer.write(out)
                await self.writer.drain()

    async def _send_502(self, sid: int) -> None:
        try:
            self.client.send_headers(sid, [(b":status", b"502")], end_stream=False)
            self.client.send_data(sid, b"redhawk upstream error", end_stream=True)
            await self._flush_client()
        except Exception:
            pass

    def _cleanup(self, sid: int) -> None:
        meta = self.streams.pop(sid, None)
        if meta is None:
            return
        for b in (meta.req_blob, meta.resp_blob):
            if b is not None:
                b.abort()

    async def _close_all(self) -> None:
        for m in self.streams.values():
            for b in (m.req_blob, m.resp_blob):
                if b is not None:
                    try:
                        b.abort()
                    except Exception:
                        pass
        self.streams.clear()
        try:
            if self.up_writer:
                self.up_writer.close()
        except Exception:
            pass
