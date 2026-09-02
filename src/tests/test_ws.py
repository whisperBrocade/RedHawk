"""RedHawk — WebSocket 帧中继/重放测试。

覆盖：
- 帧编解码往返（make_frame + _try_parse_frame，掩码/长度边界/控制帧/分片帧）
- ws_client_send_and_receive vs 本地同步 echo ws server（握手 + 发收帧）
- recorder WS 函数（规则增删查、消息查询）
- WsRelay 双向中继 + 记录 + 规则篡改/丢弃（asyncio 端到端）
"""

import asyncio
import base64
import hashlib
import os
import socketserver
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from redhawk.db import DB
from redhawk.intercept import ProxyServer
from redhawk.traffic_engine.ws_relay import (
    WsRelay, read_frame, make_frame, ws_client_send_and_receive,
    OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OPCODE_NAME, _try_parse_frame,
)
from redhawk.traffic_engine.recorder import (
    list_ws_messages, list_ws_rules, add_ws_rule, delete_ws_rule, save_traffic,
)

WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


# ================= 帧编解码 =================
class TestFrameCodec:
    def test_text_masked_roundtrip(self):
        f = make_frame(OP_TEXT, b"hello", mask=True)
        buf = bytearray(f)
        fin, op, payload = _try_parse_frame(buf)
        assert fin == 1 and op == OP_TEXT and payload == b"hello"
        assert len(buf) == 0

    def test_binary_unmasked(self):
        data = bytes(range(256))
        f = make_frame(OP_BINARY, data, mask=False)
        fin, op, payload = _try_parse_frame(bytearray(f))
        assert op == OP_BINARY and payload == data

    def test_len_125_short(self):
        p = b"x" * 125
        _, _, pp = _try_parse_frame(bytearray(make_frame(OP_TEXT, p, mask=True)))
        assert pp == p

    def test_len_126_extended16(self):
        p = b"y" * 126
        _, _, pp = _try_parse_frame(bytearray(make_frame(OP_TEXT, p, mask=False)))
        assert pp == p

    def test_len_large_64bit(self):
        p = b"z" * 70000
        _, _, pp = _try_parse_frame(bytearray(make_frame(OP_BINARY, p, mask=True)))
        assert pp == p

    def test_partial_returns_none(self):
        f = make_frame(OP_TEXT, b"hello world", mask=True)
        assert _try_parse_frame(bytearray(f[:3])) is None

    def test_close_control_frame(self):
        f = make_frame(OP_CLOSE, b"\x03\xe8", mask=True)
        fin, op, payload = _try_parse_frame(bytearray(f))
        assert op == OP_CLOSE and payload == b"\x03\xe8"

    def test_multiple_frames_in_one_buffer(self):
        f1 = make_frame(OP_TEXT, b"one", mask=True)
        f2 = make_frame(OP_TEXT, b"two", mask=False)
        buf = bytearray(f1 + f2)
        _, _, p1 = _try_parse_frame(buf)
        _, _, p2 = _try_parse_frame(buf)
        assert p1 == b"one" and p2 == b"two" and len(buf) == 0


# ================= 同步 echo ws server（测 ws_client） =================
class _WsEchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = self.request.recv(4096)
            if not d:
                return
            buf += d
        key = ""
        for line in buf.split(b"\r\n"):
            if line.lower().startswith(b"sec-websocket-key:"):
                key = line.split(b":", 1)[1].strip().decode()
        accept = base64.b64encode(
            hashlib.sha1((key + WS_MAGIC).encode()).digest()).decode()
        self.request.sendall(
            (f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
             f"Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").encode())
        fbuf = bytearray()
        while True:
            f = _try_parse_frame(fbuf)
            while f is None:
                d = self.request.recv(4096)
                if not d:
                    return
                fbuf.extend(d)
                f = _try_parse_frame(fbuf)
            _, op, payload = f
            if op == OP_CLOSE:
                self.request.sendall(make_frame(OP_CLOSE, payload, mask=False))
                return
            self.request.sendall(make_frame(op, payload, mask=False))


class _ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


@pytest.fixture()
def echo_ws_server():
    srv = _ThreadingTCPServer(("127.0.0.1", 0), _WsEchoHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


class TestWsClient:
    def test_send_text_receive_echo(self, echo_ws_server):
        async def _run():
            r = await ws_client_send_and_receive(
                f"ws://127.0.0.1:{echo_ws_server}", OP_TEXT, b"hello")
            assert r["ok"] and r["opcode"] == "text" and r["payload"] == "hello"
        asyncio.run(_run())

    def test_send_binary(self, echo_ws_server):
        data = bytes(range(10))
        async def _run():
            r = await ws_client_send_and_receive(
                f"ws://127.0.0.1:{echo_ws_server}", OP_BINARY, data)
            assert r["ok"] and r["opcode"] == "binary" and r["payload"] == data.hex()
        asyncio.run(_run())

    def test_bad_url_returns_error(self):
        async def _run():
            r = await ws_client_send_and_receive(
                "ws://127.0.0.1:1/nope", OP_TEXT, b"x", timeout=2)
            assert r["ok"] is False
        asyncio.run(_run())


# ================= recorder WS 函数 =================
@pytest.fixture()
def db():
    d = DB(":memory:")
    d.init()
    yield d
    d.close()


class TestRecorderWs:
    def test_rule_add_list_delete(self, db):
        rid = add_ws_rule(db, name="t1", direction="client_to_server",
                          opcode="text", match_contains="secret",
                          action="modify", replace_text="REDACTED")
        assert rid > 0
        rules = list_ws_rules(db)
        assert len(rules) == 1
        assert rules[0]["match_contains"] == "secret"
        assert delete_ws_rule(db, rid) == 1
        assert len(list_ws_rules(db)) == 0

    def test_list_ws_messages(self, db):
        tid = save_traffic(db, "GET", "ws://x/chat", {}, "", 101, {}, "",
                           "proxy", proto="ws_handshake")
        db.insert("ws_messages", {"traffic_id": tid, "direction": "client_to_server",
                                   "opcode": "text", "payload": "hi", "fin": 1})
        msgs = list_ws_messages(db, tid)
        assert len(msgs) == 1 and msgs[0]["payload"] == "hi"


# ================= WsRelay 双向中继（asyncio 端到端） =================
async def _raw_echo(reader, writer):
    """上游 echo：不做 WS 握手，直接帧 echo（模拟握手已完成的 raw 帧流）。"""
    buf = bytearray()
    while True:
        f = await read_frame(buf, reader)
        if f is None:
            break
        _, op, payload = f
        if op == OP_CLOSE:
            writer.write(make_frame(OP_CLOSE, payload, mask=False))
            await writer.drain()
            break
        writer.write(make_frame(op, payload, mask=False))
        await writer.drain()


async def _setup_relay(db, rules=None):
    """起 relay + 客户端接入点 + raw帧echo上游，返回 (cli_r,cli_w,task,tid,servers)。"""
    tid = save_traffic(db, "GET", "ws://t/c", {}, "", 101, {}, "",
                       "proxy", proto="ws_handshake")
    if rules:
        for r in rules:
            add_ws_rule(db, **r)
    echo_srv = await asyncio.start_server(_raw_echo, "127.0.0.1", 0)
    eport = echo_srv.sockets[0].getsockname()[1]
    up_r, up_w = await asyncio.open_connection("127.0.0.1", eport)
    afut = asyncio.get_running_loop().create_future()

    async def _cs(r, w):
        afut.set_result((r, w))
        await asyncio.Event().wait()

    c_srv = await asyncio.start_server(_cs, "127.0.0.1", 0)
    c_port = c_srv.sockets[0].getsockname()[1]
    cli_r, cli_w = await asyncio.open_connection("127.0.0.1", c_port)
    rc_r, rc_w = await asyncio.wait_for(afut, 5)
    relay = WsRelay(db, tid, "ws://t")
    rt = asyncio.create_task(relay.relay(rc_r, rc_w, up_r, up_w))
    await asyncio.sleep(0.15)
    return cli_r, cli_w, rt, tid, [echo_srv, c_srv]


async def _teardown(rt, servers):
    rt.cancel()
    try:
        await rt
    except asyncio.CancelledError:
        pass
    for s in servers:
        s.close()
    for s in servers:
        await s.wait_closed()


class TestWsRelay:
    def test_relay_echo_and_record(self):
        async def _run():
            db = DB(":memory:"); db.init()
            cli_r, cli_w, rt, tid, servers = await _setup_relay(db)
            cli_w.write(make_frame(OP_TEXT, b"hello-relay", mask=True))
            await cli_w.drain()
            buf = bytearray()
            f = await asyncio.wait_for(read_frame(buf, cli_r), timeout=5)
            assert f and f[2] == b"hello-relay"
            cli_w.write(make_frame(OP_CLOSE, b"", mask=True))
            await cli_w.drain()
            await asyncio.sleep(0.3)
            await _teardown(rt, servers)
            msgs = list_ws_messages(db, tid)
            ops = [m["opcode"] for m in msgs]
            assert "text" in ops and "close" in ops
            db.close()
        asyncio.run(_run())

    def test_relay_modify_rule(self):
        async def _run():
            db = DB(":memory:"); db.init()
            rules = [dict(direction="client_to_server", opcode="text",
                          match_contains="secret", action="modify", replace_text="REDACTED")]
            cli_r, cli_w, rt, _, servers = await _setup_relay(db, rules)
            cli_w.write(make_frame(OP_TEXT, b"top secret info", mask=True))
            await cli_w.drain()
            buf = bytearray()
            f = await asyncio.wait_for(read_frame(buf, cli_r), timeout=5)
            assert f and f[2] == b"REDACTED"
            await _teardown(rt, servers)
            db.close()
        asyncio.run(_run())

    def test_relay_drop_rule(self):
        async def _run():
            db = DB(":memory:"); db.init()
            rules = [dict(direction="client_to_server", opcode="text",
                          match_contains="dropme", action="drop")]
            cli_r, cli_w, rt, _, servers = await _setup_relay(db, rules)
            cli_w.write(make_frame(OP_TEXT, b"please dropme now", mask=True))
            await cli_w.drain()
            buf = bytearray()
            try:
                await asyncio.wait_for(read_frame(buf, cli_r), timeout=1.2)
                assert False, "命中 drop 规则，不应有 echo"
            except asyncio.TimeoutError:
                pass
            cli_w.write(make_frame(OP_TEXT, b"keep", mask=True))
            await cli_w.drain()
            buf2 = bytearray()
            f2 = await asyncio.wait_for(read_frame(buf2, cli_r), timeout=5)
            assert f2 and f2[2] == b"keep"
            await _teardown(rt, servers)
            db.close()
        asyncio.run(_run())


# ================= 端到端：真实代理完整路径（101 握手 + 帧中继 + 落库 + 规则） =================
def _free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _ws_upstream_handler(reader, writer):
    """真实 WS 上游：解析握手 → 101 + 同一 write 推送首帧（考验 trailing 处理）→ 帧 echo。"""
    head = await reader.readuntil(b"\r\n\r\n")
    key = ""
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"sec-websocket-key:"):
            key = line.split(b":", 1)[1].strip().decode()
    accept = base64.b64encode(hashlib.sha1((key + WS_MAGIC).encode()).digest()).decode()
    welcome = make_frame(OP_TEXT, b"welcome", mask=False)
    writer.write(
        (f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
         f"Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").encode() + welcome)
    await writer.drain()
    buf = bytearray()
    while True:
        f = await read_frame(buf, reader)
        if f is None:
            break
        _, op, payload = f
        if op == OP_CLOSE:
            writer.write(make_frame(OP_CLOSE, payload, mask=False))
            await writer.drain()
            break
        writer.write(make_frame(op, payload, mask=False))
        await writer.drain()


async def _ws_client_through_proxy(proxy_port, up_port, text="hello"):
    """经代理连 WS：发绝对形式升级请求 → 收 101 → 读服务器推送帧 → 发帧收 echo → close。"""
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (f"GET ws://127.0.0.1:{up_port}/chat HTTP/1.1\r\n"
           f"Host: 127.0.0.1:{up_port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
    writer.write(req.encode())
    await writer.drain()
    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
    got = {"head_ok": b" 101 " in head.split(b"\r\n", 1)[0]}
    frames = []
    buf = bytearray()
    f = await asyncio.wait_for(read_frame(buf, reader), timeout=5)   # 服务器推送 welcome
    frames.append(f[2].decode("utf-8", "replace"))
    writer.write(make_frame(OP_TEXT, text.encode(), mask=True))
    await writer.drain()
    f = await asyncio.wait_for(read_frame(buf, reader), timeout=5)   # echo
    frames.append(f[2].decode("utf-8", "replace"))
    writer.write(make_frame(OP_CLOSE, b"", mask=True))
    await writer.drain()
    try:
        f = await asyncio.wait_for(read_frame(buf, reader), timeout=5)
        got["close_received"] = f[1] == OP_CLOSE
    except asyncio.TimeoutError:
        got["close_received"] = False
    writer.close()
    got["frames"] = frames
    return got


class TestWsEndToEnd:
    def test_handshake_relay_record(self, tmp_path):
        db = DB(tmp_path / "t.db")
        db.init()
        p = ProxyServer(db, port=_free_port(), take_system_proxy=False)
        assert p.start()["status"] == "running"
        try:
            async def _run():
                up_srv = await asyncio.start_server(_ws_upstream_handler, "127.0.0.1", 0)
                up_port = up_srv.sockets[0].getsockname()[1]
                try:
                    got = await _ws_client_through_proxy(p.port, up_port)
                    return got, up_port
                finally:
                    up_srv.close()
                    await up_srv.wait_closed()
            got, up_port = asyncio.run(_run())
            assert got["head_ok"], "客户端应收到 101"
            assert got["frames"] == ["welcome", "hello"], got
            assert got["close_received"]
        finally:
            p.stop()
        row = db.query_one("SELECT * FROM traffic WHERE proto='ws_handshake'")
        assert row is not None and row["status"] == 101
        assert row["url"] == f"ws://127.0.0.1:{up_port}/chat"
        msgs = list_ws_messages(db, row["id"])
        ops = [(m["direction"], m["opcode"]) for m in msgs]
        assert ("server_to_client", "text") in ops, ops   # welcome
        assert ("client_to_server", "text") in ops, ops   # hello
        assert any(m["opcode"] == "close" for m in msgs), ops
        db.close()

    def test_modify_rule_through_proxy(self, tmp_path):
        db = DB(tmp_path / "t.db")
        db.init()
        add_ws_rule(db, name="r", direction="client_to_server", opcode="text",
                    match_contains="secret", action="modify", replace_text="REDACTED")
        p = ProxyServer(db, port=_free_port(), take_system_proxy=False)
        assert p.start()["status"] == "running"
        try:
            async def _run():
                up_srv = await asyncio.start_server(_ws_upstream_handler, "127.0.0.1", 0)
                up_port = up_srv.sockets[0].getsockname()[1]
                try:
                    got = await _ws_client_through_proxy(p.port, up_port, text="top secret info")
                    return got
                finally:
                    up_srv.close()
                    await up_srv.wait_closed()
            got = asyncio.run(_run())
            assert got["head_ok"]
            assert got["frames"] == ["welcome", "REDACTED"], got   # 规则已篡改
        finally:
            p.stop()
        db.close()
