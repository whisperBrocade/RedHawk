"""RedHawk v2 — 流量引擎监听入口（asyncio + TLS/ALPN 分发）。

对应 06 号文档 §二/§三。职责：
1. asyncio.start_server 监听代理端口，每连接一个 task
2. 首包判定：CONNECT（HTTPS MITM）或普通 HTTP → 分发给 H1ClientConnection
3. CONNECT：动态签发域名证书 → writer.start_tls 服务端升级
   （ALPN 当前只声明 http/1.1；h2 为 W3）→ 上游由 UpstreamSession 走 TLS
4. 健康检查过滤：探测关键词首包 → 204（不记录）

W11 起系统代理接管收进 platform/ 抽象；W1 复用 intercept.set_system_proxy。
"""

from __future__ import annotations

import asyncio
import logging
import ssl

from redhawk.traffic_engine.client_h1 import H1ClientConnection
from redhawk.traffic_engine.config import PROBE_KEYWORDS

log = logging.getLogger("redhawk.traffic_engine.listener")


class ProxyListener:
    def __init__(self, db, host: str = "127.0.0.1", port: int = 8888,
                 source: str = "proxy", take_system_proxy: bool = True):
        self.db = db
        self.host = host
        self.port = port
        self.source = source
        self.take_system_proxy = take_system_proxy
        self._server: asyncio.AbstractServer | None = None
        self._sys_proxy_taken = False
        self._sys_proxy_prev: dict | None = None   # 接管前的系统代理原设置

    async def serve(self) -> None:
        self._server = await asyncio.start_server(
            self._on_client, self.host, self.port,
        )
        if self.take_system_proxy:
            try:
                # W11 起迁移 platform/；W1 复用 v1 实现
                from redhawk.intercept import set_system_proxy
                r = set_system_proxy(self.port)
                self._sys_proxy_taken = bool(r.get("ok", False))
                if self._sys_proxy_taken:
                    self._sys_proxy_prev = r.get("previous")
            except Exception:
                self._sys_proxy_taken = False
                self._sys_proxy_prev = None

    async def close(self) -> None:
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
            self._server = None
        if self._sys_proxy_taken:
            try:
                from redhawk.intercept import restore_system_proxy
                # 恢复接管前的原设置（原为启用则还原原 server，避免误关用户自己的代理）
                restore_system_proxy(self._sys_proxy_prev)
            except Exception:
                pass
            self._sys_proxy_taken = False
            self._sys_proxy_prev = None

    # ---------- 客户端连接 ----------
    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            data = await reader.read(65536)
            if not data:
                return
            # 健康检查过滤（首包关键词，v1 逻辑迁移）
            if any(k.encode("ascii") in data.lower() for k in PROBE_KEYWORDS):
                writer.write(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return
            if data.startswith(b"CONNECT "):
                await self._handle_connect(reader, writer, data)
            else:
                h = H1ClientConnection(self.db, self.source, port=self.port)
                await h.handle(reader, writer, first_data=data)
        except Exception:
            log.debug("client handler error", exc_info=True)
        finally:
            try:
                writer.close()
            except Exception:
                pass

    # ---------- HTTPS 中间人（CONNECT） ----------
    async def _handle_connect(self, reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter, data: bytes) -> None:
        # 解析 CONNECT 行：CONNECT host:port HTTP/1.1
        first_line = data.split(b"\r\n", 1)[0]
        parts = first_line.split()
        if len(parts) < 2:
            return
        hostport = parts[1].decode("latin-1")
        if ":" in hostport and hostport.count(":") == 1:
            host, p = hostport.rsplit(":", 1)
            try:
                port = int(p)
            except ValueError:
                port = 443
        else:
            host, port = hostport, 443

        # 丢弃 CONNECT 剩余头（读到空行；首包可能已包含）
        rest = data.split(b"\r\n", 1)[1] if b"\r\n" in data else b""
        while b"\r\n\r\n" not in rest:
            chunk = await reader.read(4096)
            if not chunk:
                break
            rest += chunk

        # 1) 回复 200 Connection Established
        try:
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
        except Exception:
            return

        # 2) 客户端 TLS（动态签发该域名证书，ALPN 仅 http/1.1，h2 为 W3）
        try:
            from redhawk.certgen import get_site_cert
            crt, key = get_site_cert(host)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(crt), str(key))
            ctx.set_alpn_protocols(["http/1.1"])
            await writer.start_tls(ctx, ssl_handshake_timeout=30)
        except Exception:
            log.debug("TLS upgrade failed", exc_info=True)
            return

        # 3) TLS 内的 HTTP/1.1（MITM）：上游由 UpstreamSession 走 TLS
        h = H1ClientConnection(self.db, "proxy_https", port=self.port,
                               https_host=host, https_port=port)
        await h.handle(reader, writer)
