"""RedHawk v2 — W1 流量引擎测试（traffic_engine 骨架）。

覆盖（对应 12 号清单 W1）：
- HTTP/1.1 代理端到端：GET/POST 通过代理转发并记录
- keep-alive 多请求（同一连接）
- 代理自环过滤（Host=代理端口 → 200 不记录）
- 探测流量过滤（captiveportal → 204 不记录）
- HTTPS MITM（CONNECT → 动态证书 → h1 over TLS → 记录 proxy_https）
"""

import http.client
import os
import select
import socket
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from redhawk.db import DB
from redhawk.traffic_engine import ProxyServer


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _EchoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _reply(self, body: bytes, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._reply(f"hello {self.path}".encode())

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        data = self.rfile.read(n)
        self._reply(b"post:" + data)


@pytest.fixture()
def http_server():
    srv = HTTPServer(("127.0.0.1", 0), _EchoHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


class _ChunkedHandler(BaseHTTPRequestHandler):
    """分块传输响应（Transfer-Encoding: chunked）。"""
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for i in range(5):
            chunk = f"chunk{i}-{'x' * 50}\n".encode()
            self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
            self.wfile.flush()
        self.wfile.write(b"0\r\n\r\n")


@pytest.fixture()
def chunk_server():
    srv = HTTPServer(("127.0.0.1", 0), _ChunkedHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


class _ExpectHandler(BaseHTTPRequestHandler):
    """处理 Expect: 100-continue 的 POST 服务器。"""
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        if (self.headers.get("Expect") or "").lower() == "100-continue":
            self.send_response(100)
            self.end_headers()
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(n)
        resp = b"got:" + body
        self.send_response(200)
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)


@pytest.fixture()
def expect_server():
    srv = HTTPServer(("127.0.0.1", 0), _ExpectHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def _start_proxy(db: DB, port: int | None = None) -> ProxyServer:
    p = ProxyServer(db, port=port or free_port(), take_system_proxy=False)
    assert p.start()["status"] == "running", "代理启动失败"
    return p


def _proxy_request(proxy_port: int, method: str, url: str,
                   body: bytes | None = None, headers: dict | None = None):
    """显式连代理发请求（http.client 无 urllib 的 proxy_bypass 干扰，测试稳定）。"""
    conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=10)
    conn.request(method, url, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data


# ================= HTTP/1.1 端到端 =================
def test_h1_proxy_get_end_to_end(tmp_path, http_server):
    db = DB(tmp_path / "t.db")
    db.init()
    p = _start_proxy(db)
    try:
        status, body = _proxy_request(p.port, "GET", f"http://127.0.0.1:{http_server}/hi")
        assert status == 200
        assert b"hi" in body
    finally:
        p.stop()
    rows = db.query("SELECT * FROM traffic WHERE source='proxy'")
    assert len(rows) == 1
    assert rows[0]["url"] == f"http://127.0.0.1:{http_server}/hi"
    assert rows[0]["status"] == 200
    db.close()


def test_h1_proxy_post_body_recorded(tmp_path, http_server):
    db = DB(tmp_path / "t.db")
    db.init()
    p = _start_proxy(db)
    try:
        status, body = _proxy_request(
            p.port, "POST", f"http://127.0.0.1:{http_server}/login",
            body=b"user=admin&pass=123",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert status == 200
        assert b"post:user=admin" in body
    finally:
        p.stop()
    row = db.query_one("SELECT * FROM traffic WHERE method='POST'")
    assert row is not None
    assert "user=admin" in row["req_body"]
    assert "post:user=admin" in row["resp_body"]
    db.close()


def test_keepalive_multiple_requests(tmp_path, http_server):
    db = DB(tmp_path / "t.db")
    db.init()
    p = _start_proxy(db)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", p.port, timeout=10)
        for i in range(3):
            conn.request("GET", f"http://127.0.0.1:{http_server}/k{i}")
            r = conn.getresponse()
            assert r.status == 200
            r.read()
        conn.close()
    finally:
        p.stop()
    rows = db.query("SELECT * FROM traffic WHERE source='proxy'")
    assert len(rows) == 3
    assert {r["url"].rsplit("/", 1)[-1] for r in rows} == {"k0", "k1", "k2"}
    db.close()


# ================= W2：HTTP/1.1 完整语义 =================
def test_keepalive_100_requests_pool_reuse(tmp_path, http_server):
    """同一客户端连接 100 连发；上游连接应被连接池复用（created 远小于 100）。"""
    db = DB(tmp_path / "t.db")
    db.init()
    p = _start_proxy(db)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", p.port, timeout=10)
        for i in range(100):
            conn.request("GET", f"http://127.0.0.1:{http_server}/k{i}")
            r = conn.getresponse()
            assert r.status == 200
            r.read()
        conn.close()
        created = p._listener.pool.created  # stop 前取（stop 会清 listener）
    finally:
        p.stop()
    rows = db.query("SELECT * FROM traffic WHERE source='proxy'")
    assert len(rows) == 100
    assert created <= 5, f"100 请求应复用上游连接（实际新建 {created}）"
    db.close()


def test_chunked_response_recorded_complete(tmp_path, chunk_server):
    """chunked 响应应完整转发并记录（v1 此场景 body 记录缺失）。"""
    db = DB(tmp_path / "t.db")
    db.init()
    p = _start_proxy(db)
    try:
        status, body = _proxy_request(p.port, "GET", f"http://127.0.0.1:{chunk_server}/chunk")
        assert status == 200
        assert b"chunk4" in body
    finally:
        p.stop()
    row = db.query_one("SELECT * FROM traffic WHERE source='proxy'")
    assert row is not None
    assert "chunk0" in row["resp_body"] and "chunk4" in row["resp_body"], \
        "chunked 响应体应完整记录"
    db.close()


def test_expect_100_continue(tmp_path, expect_server):
    """Expect: 100-continue 应透传，请求体正常转发并记录。"""
    db = DB(tmp_path / "t.db")
    db.init()
    p = _start_proxy(db)
    try:
        status, body = _proxy_request(
            p.port, "POST", f"http://127.0.0.1:{expect_server}/up",
            body=b"hello-continue",
            headers={"Expect": "100-continue", "Content-Type": "text/plain"},
        )
        assert status == 200
        assert b"got:hello-continue" in body
    finally:
        p.stop()
    row = db.query_one("SELECT * FROM traffic WHERE method='POST'")
    assert row is not None
    assert "hello-continue" in row["req_body"]
    db.close()


def test_connection_close_terminates(tmp_path, http_server):
    """请求带 Connection: close → 响应后连接关闭；后续请求 http.client 自动重连。"""
    db = DB(tmp_path / "t.db")
    db.init()
    p = _start_proxy(db)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", p.port, timeout=10)
        conn.request("GET", f"http://127.0.0.1:{http_server}/close1",
                     headers={"Connection": "close"})
        r1 = conn.getresponse()
        assert r1.status == 200
        r1.read()
        # 连接已被代理关闭 → http.client 自动重连
        conn.request("GET", f"http://127.0.0.1:{http_server}/after")
        r2 = conn.getresponse()
        assert r2.status == 200
        r2.read()
        conn.close()
    finally:
        p.stop()
    rows = db.query("SELECT * FROM traffic WHERE source='proxy'")
    assert len(rows) == 2, "两个请求都应有记录"
    db.close()


# ================= 过滤 =================
def test_self_loop_filter_not_recorded(tmp_path):
    db = DB(tmp_path / "t.db")
    db.init()
    p = _start_proxy(db)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", p.port, timeout=10)
        conn.request("GET", "/", headers={"Host": f"127.0.0.1:{p.port}"})
        r = conn.getresponse()
        assert r.status == 200
        r.read()
        conn.close()
    finally:
        p.stop()
    assert db.query_one("SELECT COUNT(*) c FROM traffic")["c"] == 0
    db.close()


def test_probe_filter_204_not_recorded(tmp_path):
    db = DB(tmp_path / "t.db")
    db.init()
    p = _start_proxy(db)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", p.port, timeout=10)
        conn.request(
            "GET", "http://edge-http.microsoft.com/captiveportal/generate_204",
            headers={"Host": "edge-http.microsoft.com"},
        )
        r = conn.getresponse()
        assert r.status == 204
        r.read()
        conn.close()
    finally:
        p.stop()
    assert db.query_one("SELECT COUNT(*) c FROM traffic")["c"] == 0
    db.close()


# ================= HTTPS MITM（h1 over TLS） =================
def _gen_self_signed_cert(tmp_path):
    import ipaddress
    from datetime import datetime, timedelta, timezone

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


@pytest.fixture()
def https_server(tmp_path):
    crt, key = _gen_self_signed_cert(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(crt), str(key))
    srv = HTTPServer(("127.0.0.1", 0), _EchoHandler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def test_https_mitm_recorded(tmp_path, https_server, monkeypatch):
    db_path = tmp_path / "t.db"
    monkeypatch.setenv("REDHAWK_DB", str(db_path))
    # 上游是自签证书：测试用 REDHAWK_UPSTREAM_VERIFY=0（见 config.py）
    monkeypatch.setenv("REDHAWK_UPSTREAM_VERIFY", "0")
    # certgen 的 CA 目录固定（%LOCALAPPDATA%\RedHawk\certs），测试用覆盖
    monkeypatch.setenv("REDHAWK_CERT_DIR", str(tmp_path / "certs"))
    db = DB(str(db_path))
    db.init()
    # 预生成 RedHawk CA（CONNECT 时才懒生成，先触发以便客户端构造信任上下文）
    from redhawk.certgen import cert_dir, get_ca_paths
    get_ca_paths()
    ca_crt = cert_dir() / "redhawk-ca.crt"
    assert ca_crt.exists(), "RedHawk CA 应已生成"
    p = _start_proxy(db)
    try:
        # 客户端信任 RedHawk 动态 CA
        cctx = ssl.create_default_context(cafile=str(ca_crt))
        conn = http.client.HTTPSConnection("127.0.0.1", p.port, context=cctx, timeout=10)
        conn.set_tunnel("127.0.0.1", https_server)
        conn.request("GET", "/secure")
        r = conn.getresponse()
        body = r.read().decode()
        assert r.status == 200
        assert "secure" in body
        conn.close()
    finally:
        p.stop()
    rows = db.query("SELECT * FROM traffic WHERE source='proxy_https'")
    assert len(rows) >= 1, "HTTPS MITM 流量应被记录"
    assert rows[0]["url"].startswith("https://127.0.0.1")
    assert "/secure" in rows[0]["url"]
    db.close()


# ================= 生命周期 =================
def test_proxy_lifecycle(tmp_path):
    db = DB(tmp_path / "t.db")
    db.init()
    p = ProxyServer(db, port=free_port(), take_system_proxy=False)
    assert p.start()["status"] == "running"
    assert p.running is True
    assert p.stop()["status"] == "stopped"
    assert p.running is False
    # 可重复启动
    assert p.start()["status"] == "running"
    p.stop()


# ================= 流量查询（多来源） =================
def test_list_traffic_multi_source(tmp_path):
    """list_traffic 支持逗号分隔多来源（流量劫取用 proxy,proxy_https）。"""
    from redhawk.traffic_engine.recorder import list_traffic, save_traffic

    db = DB(tmp_path / "t.db")
    db.init()
    save_traffic(db, "GET", "http://a/", {}, "", 200, {}, "x", "proxy")
    save_traffic(db, "GET", "http://b/", {}, "", 200, {}, "x", "proxy_https")
    save_traffic(db, "GET", "http://c/", {}, "", 200, {}, "x", "repeater")

    all_rows = list_traffic(db, limit=50)
    assert len(all_rows) == 3
    auto = list_traffic(db, limit=50, source="proxy,proxy_https")
    assert {r["url"] for r in auto} == {"http://a/", "http://b/"}
    single = list_traffic(db, limit=50, source="repeater")
    assert len(single) == 1 and single[0]["url"] == "http://c/"
    db.close()


def test_traffic_categories_multi_source(tmp_path):
    """traffic_categories 支持逗号分隔多来源。"""
    from redhawk.intercept import save_traffic, traffic_categories

    db = DB(tmp_path / "t.db")
    db.init()
    save_traffic(db, "GET", "http://a/x.html", {}, "", 200, {"Content-Type": "text/html"}, "<html>", "proxy")
    save_traffic(db, "GET", "http://b/x.html", {}, "", 200, {"Content-Type": "text/html"}, "<html>", "proxy_https")
    save_traffic(db, "GET", "http://c/x.html", {}, "", 200, {"Content-Type": "text/html"}, "<html>", "repeater")
    cats = traffic_categories(db, limit=50, source="proxy,proxy_https")
    total = sum(c["count"] for c in cats)
    assert total == 2, f"多来源归类应只统计 proxy+proxy_https: {cats}"
    db.close()


def test_list_traffic_search_q(tmp_path):
    """q 关键词搜索：按 URL/方法过滤（流量记录/劫取的搜索功能）。"""
    from redhawk.traffic_engine.recorder import list_traffic, save_traffic

    db = DB(tmp_path / "t.db")
    db.init()
    save_traffic(db, "GET", "http://api.bank.com/v1/login", {}, "", 200, {}, "x", "proxy")
    save_traffic(db, "POST", "http://api.bank.com/v1/pay", {}, "", 200, {}, "x", "proxy")
    save_traffic(db, "GET", "http://cdn.cdn.net/logo.png", {}, "", 200, {}, "x", "proxy_https")

    hit = list_traffic(db, limit=50, source="proxy,proxy_https", q="bank")
    assert {r["url"] for r in hit} == {"http://api.bank.com/v1/login", "http://api.bank.com/v1/pay"}
    hit2 = list_traffic(db, limit=50, source="proxy,proxy_https", q="POST")
    assert [r["url"] for r in hit2] == ["http://api.bank.com/v1/pay"]
    miss = list_traffic(db, limit=50, source="proxy,proxy_https", q="nonexistent")
    assert miss == []
    db.close()


def test_list_traffic_search_q_order_by_position(tmp_path):
    """搜索排序：同秒内关键词在 URL 位置靠前（域名段）优先。"""
    from redhawk.traffic_engine.recorder import list_traffic, save_traffic

    db = DB(tmp_path / "t.db")
    db.init()
    save_traffic(db, "GET", "https://www.baidu.com/s", {}, "", 200, {}, "x", "proxy")       # baidu 在域名
    save_traffic(db, "GET", "https://cn.bing.com/baidu/feed", {}, "", 200, {}, "x", "proxy")  # baidu 在路径
    # 统一为同一秒，验证纯按位置排序
    with db.tx():
        db.conn.execute("UPDATE traffic SET created_at='2026-09-01 10:00:00'")
    rows = list_traffic(db, limit=50, source="proxy,proxy_https", q="baidu")
    assert len(rows) == 2
    assert rows[0]["url"] == "https://www.baidu.com/s", \
        f"域名段匹配应靠前: {[r['url'] for r in rows]}"
    assert rows[1]["url"] == "https://cn.bing.com/baidu/feed"
    db.close()


def test_upstream_proxy_from_settings_file(tmp_path, monkeypatch):
    """上游代理可从 data/settings.json 读取（桌面版双击 exe 无法设环境变量）。"""
    import json
    from redhawk.traffic_engine import config as engine_config

    monkeypatch.setenv("REDHAWK_DB", str(tmp_path / "t.db"))
    monkeypatch.delenv("REDHAWK_UPSTREAM_PROXY", raising=False)
    (tmp_path / "settings.json").write_text(
        json.dumps({"upstream_proxy": "http://127.0.0.1:7897"}), encoding="utf-8")
    assert engine_config.upstream_proxy() == "http://127.0.0.1:7897"
    # 环境变量优先
    monkeypatch.setenv("REDHAWK_UPSTREAM_PROXY", "http://127.0.0.1:9999")
    assert engine_config.upstream_proxy() == "http://127.0.0.1:9999"


def test_list_traffic_client_filter(tmp_path):
    """client=browser/other 按 User-Agent 区分用户浏览与后台自动流量。"""
    from redhawk.traffic_engine.recorder import list_traffic, save_traffic

    db = DB(tmp_path / "t.db")
    db.init()
    # 浏览器 UA（用户主动访问）
    save_traffic(db, "GET", "http://site/", {"User-Agent": "Mozilla/5.0 ... Chrome/126.0"}, "",
                 200, {}, "x", "proxy")
    # 后台程序 UA（自动流量）
    save_traffic(db, "GET", "http://cdn/update", {"User-Agent": "Microsoft BITS/7.8"}, "",
                 200, {}, "x", "proxy")
    # 无 UA（后台）
    save_traffic(db, "GET", "http://pki/crl.crl", {}, "", 200, {}, "x", "proxy_https")

    browser = list_traffic(db, limit=50, source="proxy,proxy_https", client="browser")
    assert [r["url"] for r in browser] == ["http://site/"]
    other = list_traffic(db, limit=50, source="proxy,proxy_https", client="other")
    assert {r["url"] for r in other} == {"http://cdn/update", "http://pki/crl.crl"}
    db.close()


# ================= 系统代理接管/还原 =================
def test_stop_restores_system_proxy(tmp_path, monkeypatch):
    """stop 必须调用 restore_system_proxy（还原接管前的原设置）。"""
    calls = []
    import redhawk.intercept as I

    def fake_set(port):
        calls.append(("set", port))
        return {"ok": True, "previous": {"enabled": False, "server": ""}}

    def fake_restore(prev=None):
        calls.append(("restore", prev))
        return {"ok": True, "was": prev}

    monkeypatch.setattr(I, "set_system_proxy", fake_set)
    monkeypatch.setattr(I, "restore_system_proxy", fake_restore)

    db = DB(tmp_path / "t.db")
    db.init()
    p = ProxyServer(db, port=free_port(), take_system_proxy=True)
    r = p.start()
    assert r["status"] == "running"
    assert ("set", p.port) in calls, f"启动应接管系统代理: {calls}"
    p.stop()
    db.close()
    assert ("restore", {"enabled": False, "server": ""}) in calls, \
        f"stop 应还原系统代理（恢复接管前原设置）: {calls}"


def test_stop_restores_previous_proxy_config(tmp_path, monkeypatch):
    """接管前用户已有代理时，stop 应恢复原代理而非关闭。"""
    calls = []
    import redhawk.intercept as I

    def fake_set(port):
        calls.append(("set", port))
        return {"ok": True, "previous": {"enabled": True, "server": "127.0.0.1:7897"}}

    def fake_restore(prev=None):
        calls.append(("restore", prev))
        return {"ok": True, "was": prev}

    monkeypatch.setattr(I, "set_system_proxy", fake_set)
    monkeypatch.setattr(I, "restore_system_proxy", fake_restore)

    db = DB(tmp_path / "t.db")
    db.init()
    p = ProxyServer(db, port=free_port(), take_system_proxy=True)
    p.start()
    p.stop()
    db.close()
    assert ("restore", {"enabled": True, "server": "127.0.0.1:7897"}) in calls, \
        f"应恢复用户原代理配置: {calls}"


def test_close_cleans_stale_proxy_pointing_to_self(tmp_path, monkeypatch):
    """自动拉起（take_system_proxy=False）+ 系统代理残留指向本代理端口：
    stop 时应清除残留，否则下次启动又自动拉起（永远运行中）。"""
    calls = []
    import redhawk.intercept as I
    port = free_port()

    monkeypatch.setattr(I, "_read_sys_proxy",
                        lambda: {"enabled": True, "server": f"127.0.0.1:{port}"})
    monkeypatch.setattr(I, "_write_sys_proxy",
                        lambda enabled, server: calls.append(("write", enabled, server)) or True)

    db = DB(tmp_path / "t.db")
    db.init()
    p = ProxyServer(db, port=port, take_system_proxy=False)  # 模拟 _auto_restore_proxy 拉起
    assert p.start()["status"] == "running"
    p.stop()
    db.close()
    assert ("write", False, "") in calls, f"应清除指向本代理端口的残留系统代理: {calls}"


def test_close_preserves_unrelated_system_proxy(tmp_path, monkeypatch):
    """未接管且系统代理指向别的地址（用户自己的代理）→ stop 不应误动。"""
    calls = []
    import redhawk.intercept as I

    monkeypatch.setattr(I, "_read_sys_proxy",
                        lambda: {"enabled": True, "server": "127.0.0.1:7897"})
    monkeypatch.setattr(I, "_write_sys_proxy",
                        lambda enabled, server: calls.append(("write", enabled, server)) or True)

    db = DB(tmp_path / "t.db")
    db.init()
    p = ProxyServer(db, port=free_port(), take_system_proxy=False)
    p.start()
    p.stop()
    db.close()
    assert calls == [], f"不应误动用户自己的代理配置: {calls}"


# ================= 上游代理（REDHAWK_UPSTREAM_PROXY） =================
class _UpstreamProxyHandler(BaseHTTPRequestHandler):
    """简易上游代理：绝对 URL 转发（HTTP）+ CONNECT 隧道（HTTPS）。"""
    protocol_version = "HTTP/1.1"
    hits = 0  # 类级计数：验证确实走了上游代理

    def log_message(self, *a):
        pass

    def _forward(self, method):
        type(self).hits += 1
        target = self.path
        if target.startswith("http://"):
            u = urlparse(target)
            host, port = u.hostname, u.port or 80
            path = u.path or "/"
            if u.query:
                path += "?" + u.query
        else:
            hosthdr = self.headers.get("Host", "127.0.0.1")
            host = hosthdr.rsplit(":", 1)[0]
            try:
                port = int(hosthdr.rsplit(":", 1)[1]) if ":" in hosthdr else 80
            except ValueError:
                port = 80
            path = target
        clen = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(clen) if clen else None
        conn = http.client.HTTPConnection(host, port, timeout=10)
        hdrs = {k: v for k, v in self.headers.items()
                if k.lower() not in ("host", "proxy-connection", "connection", "content-length")}
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        rbody = resp.read()
        self.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() not in ("transfer-encoding", "connection"):
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(rbody)))
        self.end_headers()
        self.wfile.write(rbody)
        conn.close()

    def do_GET(self):
        self._forward("GET")

    def do_POST(self):
        self._forward("POST")

    def do_CONNECT(self):
        type(self).hits += 1
        hostport = self.path
        host = hostport.rsplit(":", 1)[0]
        port = int(hostport.rsplit(":", 1)[1])
        self.send_response(200, "Connection Established")
        self.end_headers()
        self.wfile.flush()
        up = socket.create_connection((host, port), timeout=10)
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
def upstream_proxy():
    srv = HTTPServer(("127.0.0.1", 0), _UpstreamProxyHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    _UpstreamProxyHandler.hits = 0
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def test_upstream_proxy_http(tmp_path, http_server, upstream_proxy, monkeypatch):
    monkeypatch.setenv("REDHAWK_UPSTREAM_PROXY", f"http://127.0.0.1:{upstream_proxy}")
    db = DB(tmp_path / "t.db")
    db.init()
    p = _start_proxy(db)
    try:
        status, body = _proxy_request(p.port, "GET", f"http://127.0.0.1:{http_server}/via-proxy")
        assert status == 200
        assert b"via-proxy" in body
    finally:
        p.stop()
    assert _UpstreamProxyHandler.hits >= 1, "请求应经过上游代理"
    rows = db.query("SELECT * FROM traffic WHERE source='proxy'")
    assert len(rows) == 1
    assert rows[0]["url"] == f"http://127.0.0.1:{http_server}/via-proxy"
    db.close()


def test_upstream_proxy_https_mitm(tmp_path, https_server, upstream_proxy, monkeypatch):
    monkeypatch.setenv("REDHAWK_DB", str(tmp_path / "t.db"))
    monkeypatch.setenv("REDHAWK_UPSTREAM_VERIFY", "0")
    monkeypatch.setenv("REDHAWK_CERT_DIR", str(tmp_path / "certs"))
    monkeypatch.setenv("REDHAWK_UPSTREAM_PROXY", f"http://127.0.0.1:{upstream_proxy}")
    db = DB(str(tmp_path / "t.db"))
    db.init()
    from redhawk.certgen import cert_dir, get_ca_paths
    get_ca_paths()
    ca_crt = cert_dir() / "redhawk-ca.crt"
    p = _start_proxy(db)
    try:
        cctx = ssl.create_default_context(cafile=str(ca_crt))
        conn = http.client.HTTPSConnection("127.0.0.1", p.port, context=cctx, timeout=10)
        conn.set_tunnel("127.0.0.1", https_server)
        conn.request("GET", "/secure-via-proxy")
        r = conn.getresponse()
        body = r.read().decode()
        assert r.status == 200
        assert "secure-via-proxy" in body
        conn.close()
    finally:
        p.stop()
    assert _UpstreamProxyHandler.hits >= 1, "CONNECT 应经过上游代理"
    rows = db.query("SELECT * FROM traffic WHERE source='proxy_https'")
    assert len(rows) >= 1
    assert "/secure-via-proxy" in rows[0]["url"]
    db.close()
    db.close()
