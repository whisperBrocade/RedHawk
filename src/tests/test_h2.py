"""RedHawk v2 — W3 HTTP/2 测试。

覆盖：
- h2 解密端到端（httpx h2 客户端 → 代理 CONNECT → 上游 h2 测试服务器）
- h2 多路复用（同一连接并发多请求，记录无串扰）
- 大 body 流式 blob（>2MB 响应全文落盘，traffic 表存摘要+引用）
- h2 走上游代理（REDHAWK_UPSTREAM_PROXY CONNECT 隧道）
"""

import asyncio
import ipaddress
import os
import select
import socket
import ssl
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import h2.config
import h2.connection
import h2.events
import logging
import pytest

from redhawk.db import DB
from redhawk.traffic_engine import ProxyServer

_srv_log = logging.getLogger("h2testsrv")

BIG_SIZE = 5 * 1024 * 1024
BIG_BODY = b"B" * BIG_SIZE


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _gen_self_signed_cert(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    crt = tmp_path / "srv.crt"
    keyf = tmp_path / "srv.key"
    crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyf.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return crt, keyf


def _pseudo_value(headers, name: str) -> str:
    for k, v in headers:
        if k.lower() == name.encode("latin-1"):
            return v.decode("latin-1")
    return ""


class H2TestServer:
    """基于 h2 库的最小 h2 测试服务器（TLS + ALPN h2）。"""

    def __init__(self, tmp_path):
        self._tmp = tmp_path
        self._loop = asyncio.new_event_loop()
        self._server = None
        self._pending: dict[int, bytes] = {}   # stream_id -> 待发响应体（窗口分批）

    async def _on_conn(self, reader, writer):
        cfg = h2.config.H2Configuration(client_side=False, header_encoding=None)
        conn = h2.connection.H2Connection(config=cfg)
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                events = conn.receive_data(data)
                out = conn.data_to_send()
                if out:
                    writer.write(out)
                    await writer.drain()
                for ev in events:
                    if isinstance(ev, h2.events.RemoteSettingsChanged):
                        _srv_log.debug("RemoteSettings changed: %s",
                                       {k: v for k, v in ev.changed_settings.items()})
                    elif isinstance(ev, h2.events.RequestReceived):
                        self._respond(conn, ev)
                        out = conn.data_to_send()
                        if out:
                            writer.write(out)
                            await writer.drain()
                    elif isinstance(ev, h2.events.DataReceived):
                        conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                    elif isinstance(ev, h2.events.StreamEnded):
                        pass
                    elif isinstance(ev, h2.events.WindowUpdated):
                        _srv_log.debug("WindowUpdated sid=%s delta=%s pending=%s",
                                       ev.stream_id, ev.delta, list(self._pending))
                        # 窗口更新（流级或连接级）：推动所有待发响应继续发送
                        for sid in list(self._pending.keys()):
                            self._flush_pending(conn, sid)
                        out = conn.data_to_send()
                        if out:
                            writer.write(out)
                            await writer.drain()
                # 连接终止（GOAWAY）后关闭；读循环靠 EOF 退出
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    def _respond(self, conn, ev):
        path = _pseudo_value(ev.headers, ":path") or "/"
        if path == "/big":
            body = BIG_BODY
        else:
            body = f"h2-hello {path}".encode()
        conn.send_headers(ev.stream_id, [
            (b":status", b"200"), (b"content-type", b"text/plain"),
            (b"content-length", str(len(body)).encode()),
        ])
        self._pending[ev.stream_id] = body
        self._flush_pending(conn, ev.stream_id)

    def _flush_pending(self, conn, sid):
        """按对端流窗口分批发送（h2 send_data 不自动拆/等窗口）。"""
        body = self._pending.get(sid)
        if not body:
            return
        window = conn.local_flow_control_window(sid)
        sent = 0
        while sent < len(body) and sent < window:
            n = min(16384, window - sent)
            chunk = body[sent:sent + n]
            sent += len(chunk)
            end = sent >= len(body)
            conn.send_data(sid, chunk, end_stream=end)
            if end:
                break
        rest = body[sent:]
        if rest:
            self._pending[sid] = rest
        else:
            self._pending.pop(sid, None)

    def start(self):
        crt, key = _gen_self_signed_cert(self._tmp)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(crt), str(key))
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        port = free_port()

        async def serve():
            self._server = await asyncio.start_server(
                self._on_conn, "127.0.0.1", port, ssl=ctx)

        self._loop.run_until_complete(serve())
        threading.Thread(target=self._loop.run_forever, daemon=True).start()
        return port

    def stop(self):
        if self._server:
            self._loop.call_soon_threadsafe(self._server.close)
        self._loop.call_soon_threadsafe(self._loop.stop)
        time.sleep(0.2)


@pytest.fixture()
def h2_server(tmp_path):
    srv = H2TestServer(tmp_path)
    port = srv.start()
    yield port
    srv.stop()


def _start_proxy_env(tmp_path, monkeypatch):
    db_path = tmp_path / "t.db"
    monkeypatch.setenv("REDHAWK_DB", str(db_path))
    monkeypatch.setenv("REDHAWK_UPSTREAM_VERIFY", "0")   # 上游自签
    monkeypatch.setenv("REDHAWK_CERT_DIR", str(tmp_path / "certs"))
    from redhawk.certgen import cert_dir, get_ca_paths
    get_ca_paths()
    db = DB(str(db_path))
    db.init()
    p = ProxyServer(db, port=free_port(), take_system_proxy=False)
    assert p.start()["status"] == "running"
    return p, db, cert_dir() / "redhawk-ca.crt"


def _h2_client(proxy_port, ca_crt, timeout=10.0):
    import httpx
    return httpx.Client(http2=True, verify=str(ca_crt), timeout=timeout,
                        proxy=f"http://127.0.0.1:{proxy_port}")


# ================= 用例 =================
def test_h2_mitm_recorded(tmp_path, h2_server, monkeypatch):
    """h2 客户端经代理 CONNECT → 上游 h2 解密记录（proto=http2）。"""
    import httpx

    p, db, ca_crt = _start_proxy_env(tmp_path, monkeypatch)
    try:
        with _h2_client(p.port, ca_crt) as c:
            r = c.get(f"https://127.0.0.1:{h2_server}/hello")
            assert r.status_code == 200
            assert "h2-hello" in r.text
    finally:
        p.stop()
    rows = db.query("SELECT * FROM traffic WHERE source='proxy_https'")
    assert len(rows) >= 1, "h2 流量应被记录"
    assert rows[0]["proto"] == "http2", f"proto 应为 http2: {rows[0]['proto']}"
    assert "/hello" in rows[0]["url"]
    assert "h2-hello" in rows[0]["resp_body"]
    db.close()


def test_h2_multiplexing(tmp_path, h2_server, monkeypatch):
    """同一 h2 连接并发 20 请求 → 20 条独立记录，无串扰。"""
    p, db, ca_crt = _start_proxy_env(tmp_path, monkeypatch)
    try:
        import httpx

        async def run():
            async with httpx.AsyncClient(http2=True, verify=str(ca_crt),
                                         proxy=f"http://127.0.0.1:{p.port}") as c:
                async def one(i):
                    r = await c.get(f"https://127.0.0.1:{h2_server}/multi/{i}")
                    return r.status_code, r.text
                return await asyncio.gather(*[one(i) for i in range(20)])
        results = asyncio.run(run())
    finally:
        p.stop()
    assert all(st == 200 for st, _ in results)
    rows = db.query("SELECT url, resp_body FROM traffic WHERE source='proxy_https'")
    assert len(rows) == 20, f"20 个请求应有 20 条记录: {len(rows)}"
    seen = set()
    for r in rows:
        idx = r["url"].rsplit("/", 1)[-1]
        assert idx not in seen, f"记录串扰: {idx}"
        seen.add(idx)
        assert f"h2-hello /multi/{idx}" in r["resp_body"]
    db.close()


def test_h2_large_body_blob(tmp_path, h2_server, monkeypatch):
    """>2MB 响应：全文落 blob，traffic 表存 2MB 摘要 + blob 引用。"""
    import httpx

    p, db, ca_crt = _start_proxy_env(tmp_path, monkeypatch)
    try:
        with _h2_client(p.port, ca_crt, timeout=60) as c:
            r = c.get(f"https://127.0.0.1:{h2_server}/big")
            assert r.status_code == 200
            assert len(r.content) == BIG_SIZE
    finally:
        p.stop()
    row = db.query_one("SELECT * FROM traffic WHERE source='proxy_https' AND url LIKE '%/big'")
    assert row is not None
    assert row["resp_blob_id"] is not None, "大响应应写 blob"
    assert row["resp_blob_size"] == BIG_SIZE
    assert len(row["resp_body"]) < BIG_SIZE, "traffic 表应只存摘要（前 2MB）"
    # blob 文件存在且大小正确
    from redhawk.traffic_engine.stream_store import blob_dir
    blob_row = db.query_one("SELECT * FROM traffic_blobs WHERE id=?", (row["resp_blob_id"],))
    assert blob_row is not None
    assert os.path.exists(blob_row["path"])
    assert os.path.getsize(blob_row["path"]) == BIG_SIZE
    db.close()


# ================= h2 走上游代理（REDHAWK_UPSTREAM_PROXY CONNECT 隧道） =================
class _ConnectProxyHandler(BaseHTTPRequestHandler):
    """简易 CONNECT 隧道代理（h2 流量透传）。"""
    protocol_version = "HTTP/1.1"
    hits = 0

    def log_message(self, *a):
        pass

    def do_CONNECT(self):
        type(self).hits += 1
        host, port = self.path.rsplit(":", 1)
        self.send_response(200, "Connection Established")
        self.end_headers()
        self.wfile.flush()
        up = socket.create_connection((host, int(port)), timeout=10)
        self.connection.settimeout(5)
        up.settimeout(5)
        try:
            while True:
                r, _, _ = select.select([self.connection, up], [], [], 1)
                if not r:
                    continue
                for s in r:
                    try:
                        data = s.recv(65536)
                    except Exception:
                        data = b""
                    if not data:
                        return
                    (up if s is self.connection else self.connection).sendall(data)
        finally:
            up.close()


@pytest.fixture()
def connect_proxy():
    srv = HTTPServer(("127.0.0.1", 0), _ConnectProxyHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    _ConnectProxyHandler.hits = 0
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def test_h2_via_upstream_proxy(tmp_path, h2_server, connect_proxy, monkeypatch):
    """h2 流量经 REDHAWK_UPSTREAM_PROXY（CONNECT 隧道）转发（修复 baidu 502 场景）。"""
    import httpx

    monkeypatch.setenv("REDHAWK_UPSTREAM_PROXY", f"http://127.0.0.1:{connect_proxy}")
    p, db, ca_crt = _start_proxy_env(tmp_path, monkeypatch)
    try:
        with _h2_client(p.port, ca_crt) as c:
            r = c.get(f"https://127.0.0.1:{h2_server}/via-proxy")
            assert r.status_code == 200
            assert "via-proxy" in r.text
    finally:
        p.stop()
    assert _ConnectProxyHandler.hits >= 1, "h2 应经 CONNECT 隧道走上游代理"
    row = db.query_one("SELECT * FROM traffic WHERE source='proxy_https' AND url LIKE '%/via-proxy'")
    assert row is not None and row["proto"] == "http2"
    db.close()
