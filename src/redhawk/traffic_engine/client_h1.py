"""RedHawk v2 — HTTP/1.1 客户端连接处理器（h11 SERVER 角色）。

对应 06 号文档 §四。处理一条客户端连接上的 HTTP/1.1 流量：
- h11 状态机接管解析（keep-alive / chunked / 异常关闭由库兜底）
- 事件 → UpstreamSession 转发（请求事件流式转发，响应流式回传）
- 支持 keep-alive 多请求循环
- 代理自环检测（Host=127.0.0.1:port → 200 空）

W2 范围：上游连接池（键控复用/空闲超时/失效重建）；明文 HTTP +
CONNECT-MITM（h1 over TLS）均可处理；HTTP/2 为 W3。
"""

from __future__ import annotations

import asyncio
import logging

import h11

from redhawk.traffic_engine.upstream import UpstreamPool, UpstreamSession

log = logging.getLogger("redhawk.traffic_engine.h1")


class H1ClientConnection:
    def __init__(self, db, source: str = "proxy", port: int = 8888,
                 https_host: str | None = None, https_port: int | None = None,
                 pool: UpstreamPool | None = None):
        self.db = db
        self.source = source
        self.port = port                      # 本机代理端口（自环检测用）
        self.https_host = https_host          # MITM 场景：上游目标 host
        self.https_port = https_port or 443
        self.pool = pool or UpstreamPool()

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                     first_data: bytes = b"") -> None:
        """处理一条客户端连接。first_data 为 listener 已预读的首包。

        h11 0.14+ API：receive_data 只缓冲（返回 None），事件用
        next_event() 逐个拉取，直到 NEED_DATA（等更多数据）或 PAUSED
        （服务器等待请求体完成）。
        """
        conn = h11.Connection(h11.SERVER)
        up: UpstreamSession | None = None
        pending = first_data
        try:
            while True:
                if pending:
                    data, pending = pending, b""
                else:
                    data = await reader.read(65536)
                    if not data:
                        break
                try:
                    conn.receive_data(data)
                except h11.RemoteProtocolError:
                    break

                while True:
                    try:
                        event = conn.next_event()
                    except h11.RemoteProtocolError:
                        return
                    if event is h11.NEED_DATA or event is h11.PAUSED:
                        break
                    log.debug("h1 event: %s", type(event).__name__)
                    if isinstance(event, h11.Request):
                        if self._self_loop(event, conn, writer):
                            return
                        up = UpstreamSession(self.db, self.pool, self.source,
                                             self.https_host, self.https_port)
                        meta = await up.start(event)
                        if meta is None:
                            await self._send_502(conn, writer)
                            return
                    elif isinstance(event, h11.Data):
                        if up is not None:
                            await up.send_data(event.data)
                    elif isinstance(event, h11.EndOfMessage):
                        if up is not None:
                            await up.end_request()
                            ws = await up.relay_response(conn, writer)
                            if ws:
                                # WebSocket：握手透传完成，接管双向帧中继
                                # 之后整个连接结束（WS 不走 HTTP keep-alive）
                                try:
                                    trailing, _ = conn.trailing_data
                                except Exception:
                                    trailing = b""
                                await up.relay_ws(reader, writer, client_trailing=trailing)
                                return
                            # relay_response 内部已归还/关闭上游连接
                            up = None
                            # 一个请求-响应循环完成：准备下一个（keep-alive）
                            if conn.our_state is h11.DONE:
                                try:
                                    conn.start_next_cycle()
                                except h11.LocalProtocolError:
                                    return
                            if conn.our_state is h11.MUST_CLOSE or conn.their_state is h11.MUST_CLOSE:
                                return
                    elif isinstance(event, h11.ConnectionClosed):
                        return
        except Exception:
            log.debug("h1 handler error", exc_info=True)
        finally:
            try:
                writer.close()
            except Exception:
                pass

    # ---------- 代理自环（健康检查） ----------
    def _self_loop(self, request: h11.Request, conn: h11.Connection,
                   writer: asyncio.StreamWriter) -> bool:
        """Windows 接管系统代理后周期性探测代理自身端口 → 直接 200 空，不记录。"""
        host = ""
        for k, v in request.headers:
            if k.lower() == b"host":
                host = v.decode("latin-1")
                break
        if host in (f"127.0.0.1:{self.port}", f"localhost:{self.port}"):
            try:
                out = conn.send(h11.Response(status_code=200, headers=[(b"content-length", b"0")]))
                if out:
                    writer.write(out)
                out = conn.send(h11.EndOfMessage())
                if out:
                    writer.write(out)
                asyncio.create_task(writer.drain())
            except Exception:
                pass
            return True
        return False

    async def _send_502(self, conn: h11.Connection, writer: asyncio.StreamWriter) -> None:
        try:
            out = conn.send(h11.Response(status_code=502, headers=[(b"content-type", b"text/plain")]))
            if out:
                writer.write(out)
            out = conn.send(h11.Data(data=b"redhawk cannot connect upstream".encode()))
            if out:
                writer.write(out)
            out = conn.send(h11.EndOfMessage())
            if out:
                writer.write(out)
            await writer.drain()
        except Exception:
            pass
