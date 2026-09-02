"""RedHawk — WebSocket 帧中继（101 之后的双向 MITM）。

握手由 h11 透传完成后，UpstreamSession.relay_response 检测到
101 + Upgrade: websocket 即调用本模块接管：两端各一个 asyncio
reader/writer，逐帧解析、记录到 ws_messages、按 ws_intercept_rules
规则篡改/丢弃、转发。另提供 ws_client_send_and_receive 用于
Web 控制台的"重放"端点（连真实 WS 服务器发一帧收响应）。
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import ssl
from urllib.parse import urlparse

log = logging.getLogger("redhawk.traffic_engine.ws_relay")

# RFC 6455 opcode
OP_CONT = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA

OPCODE_NAME = {OP_TEXT: "text", OP_BINARY: "binary", OP_CLOSE: "close",
               OP_PING: "ping", OP_PONG: "pong"}

# 单帧上限：防恶意对端用 2^63 长度声明拖爆内存（超出按协议错误断开）
MAX_WS_FRAME = 64 * 1024 * 1024


def _try_parse_frame(buf: bytearray) -> tuple[int, int, bytes] | None:
    """尝试从 buf 解析一个完整帧。成功返回 (fin, opcode, unmasked_payload) 并消费 buf；不完整返回 None。"""
    if len(buf) < 2:
        return None
    b0, b1 = buf[0], buf[1]
    fin = 1 if (b0 & 0x80) else 0
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    mlen = b1 & 0x7F
    if mlen == 126:
        if len(buf) < 4:
            return None
        payload_len = int.from_bytes(buf[2:4], "big")
        payload_start = 4
    elif mlen == 127:
        if len(buf) < 10:
            return None
        payload_len = int.from_bytes(buf[2:10], "big")
        payload_start = 10
    else:
        payload_len = mlen
        payload_start = 2
    if payload_len > MAX_WS_FRAME:
        raise ValueError(f"ws frame too large: {payload_len}")
    mask_len = 4 if masked else 0
    total = payload_start + mask_len + payload_len
    if len(buf) < total:
        return None
    if masked:
        mk = buf[payload_start:payload_start + 4]
        raw = buf[payload_start + 4:total]
        payload = bytes(b ^ mk[i & 3] for i, b in enumerate(raw))
    else:
        payload = bytes(buf[payload_start:total])
    del buf[:total]
    return fin, opcode, payload


async def read_frame(buf: bytearray, reader: asyncio.StreamReader) -> tuple[int, int, bytes] | None:
    """从 reader 读数据到 buf，解析一个完整帧。返回 (fin,opcode,payload) 或 None（连接关闭）。"""
    while True:
        frame = _try_parse_frame(buf)
        if frame is not None:
            return frame
        data = await reader.read(65536)
        if not data:
            return None
        buf.extend(data)


def make_frame(opcode: int, payload: bytes, mask: bool) -> bytes:
    """组装一个 FIN=1 的帧。mask=True 时加掩码（客户端→服务端方向必须）。"""
    out = bytearray()
    out.append(0x80 | opcode)
    plen = len(payload)
    mask_bit = 0x80 if mask else 0
    if plen < 126:
        out.append(mask_bit | plen)
    elif plen < 65536:
        out.append(mask_bit | 126)
        out += plen.to_bytes(2, "big")
    else:
        out.append(mask_bit | 127)
        out += plen.to_bytes(8, "big")
    if mask:
        mk = os.urandom(4)
        out += mk
        out += bytes(b ^ mk[i & 3] for i, b in enumerate(payload))
    else:
        out += payload
    return bytes(out)


def _payload_to_text(opcode: int, payload: bytes) -> str:
    if opcode == OP_TEXT:
        return payload.decode("utf-8", errors="replace")
    return payload.hex()


def _record_msg(db, traffic_id: int | None, direction: str, opcode: int, payload: bytes) -> None:
    """落库一条 WS 消息。失败不阻断转发。"""
    if traffic_id is None:
        return
    try:
        db.insert("ws_messages", {
            "traffic_id": traffic_id, "direction": direction,
            "opcode": OPCODE_NAME.get(opcode, str(opcode)),
            "payload": _payload_to_text(opcode, payload)[:50000], "fin": 1,
        })
    except Exception:
        log.debug("ws_messages insert failed", exc_info=True)


def _load_rules(db) -> list[dict]:
    """加载所有 enabled 的篡改/丢弃规则。WsRelay 启动时调用一次（对新连接生效）。"""
    try:
        return db.query(
            "SELECT direction, opcode, match_contains, action, replace_text "
            "FROM ws_intercept_rules WHERE enabled=1"
        )
    except Exception:
        return []


def _apply_rules(rules: list[dict], direction: str, opcode: int, payload: bytes) -> tuple[str, bytes | None]:
    """返回 (action, new_payload)。action: pass | drop | modify。"""
    name = OPCODE_NAME.get(opcode, str(opcode))
    for r in rules:
        if r.get("direction") and r["direction"] != direction:
            continue
        if r.get("opcode") and r["opcode"] != name:
            continue
        cont = r.get("match_contains") or ""
        if cont:
            try:
                txt = payload.decode("utf-8", "replace")
            except Exception:
                txt = ""
            if cont not in txt:
                continue
        action = r.get("action")
        if action == "drop":
            return "drop", None
        if action == "modify":
            return "modify", (r.get("replace_text") or "").encode("utf-8")
    return "pass", None


class WsRelay:
    """101 握手后的双向 WS 帧中继：解析、记录、规则篡改/丢弃、转发。"""

    def __init__(self, db, traffic_id: int | None, url: str):
        self.db = db
        self.traffic_id = traffic_id
        self.url = url
        self.rules = _load_rules(db)

    async def relay(self, client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter,
                    up_r: asyncio.StreamReader, up_w: asyncio.StreamWriter,
                    client_trailing: bytes = b"", up_trailing: bytes = b"") -> None:
        """双向帧中继。trailing 为握手阶段 h11 已读入缓冲的帧字节（预置进解析缓冲）。"""
        try:
            await asyncio.gather(
                self._pump(client_r, up_w, "client_to_server", mask_out=True,
                           initial=client_trailing),
                self._pump(up_r, client_w, "server_to_client", mask_out=False,
                           initial=up_trailing),
                return_exceptions=True,
            )
        finally:
            for w in (client_w, up_w):
                try:
                    w.close()
                except Exception:
                    pass

    async def _pump(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                    direction: str, mask_out: bool, initial: bytes = b"") -> None:
        buf = bytearray(initial)
        cur_op: int | None = None
        cur_data = bytearray()
        while True:
            try:
                frame = await read_frame(buf, reader)
            except Exception:
                return
            if frame is None:
                return
            fin, opcode, payload = frame
            if opcode in (OP_CLOSE, OP_PING, OP_PONG):
                _record_msg(self.db, self.traffic_id, direction, opcode, payload)
                try:
                    writer.write(make_frame(opcode, payload, mask_out))
                    await writer.drain()
                except Exception:
                    return
                if opcode == OP_CLOSE:
                    return
                continue
            if opcode == OP_CONT:
                if cur_op is None:
                    continue
                cur_data += payload
            else:
                cur_op = opcode
                cur_data = bytearray(payload)
            if fin:
                full = bytes(cur_data)
                action, newp = _apply_rules(self.rules, direction, cur_op, full)
                if action == "drop":
                    pass
                else:
                    if action == "modify" and newp is not None:
                        full = newp
                    try:
                        writer.write(make_frame(cur_op, full, mask_out))
                        await writer.drain()
                    except Exception:
                        return
                _record_msg(self.db, self.traffic_id, direction, cur_op, full)
                cur_op = None
                cur_data = bytearray()


async def _read_http_head(reader: asyncio.StreamReader) -> bytes:
    """读 HTTP 响应头到 \\r\\n\\r\\n（不含后续帧字节）。"""
    return await reader.readuntil(b"\r\n\r\n")


async def ws_client_send_and_receive(url: str, opcode: int, payload: bytes,
                                    timeout: float = 30.0) -> dict:
    """连真实 WS 服务器（ws/wss），完成握手，发一帧，收一帧响应。用于重放端点。"""
    u = urlparse(url)
    host = u.hostname
    if not host:
        return {"ok": False, "error": "invalid url: no host"}
    port = u.port or (443 if u.scheme == "wss" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    tls = u.scheme == "wss"
    try:
        if tls:
            ctx = ssl.create_default_context()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
                timeout=timeout)
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": f"connect failed: {e}"}
    try:
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n"
               f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
               f"Sec-WebSocket-Version: 13\r\n\r\n")
        writer.write(req.encode())
        await writer.drain()
        head = await asyncio.wait_for(_read_http_head(reader), timeout=timeout)
        first_line = head.split(b"\r\n", 1)[0]
        if b" 101 " not in first_line:
            return {"ok": False, "error": "server did not upgrade: " + first_line.decode("latin-1", "replace")}
        writer.write(make_frame(opcode, payload, mask=True))
        await writer.drain()
        buf = bytearray()
        frame = await asyncio.wait_for(read_frame(buf, reader), timeout=timeout)
        if frame is None:
            return {"ok": False, "error": "no response frame"}
        _, rcv_op, rcv_payload = frame
        return {"ok": True, "opcode": OPCODE_NAME.get(rcv_op, str(rcv_op)),
                "payload": _payload_to_text(rcv_op, rcv_payload)[:50000],
                "size": len(rcv_payload)}
    except asyncio.TimeoutError:
        return {"ok": False, "error": "timeout"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    finally:
        try:
            writer.close()
        except Exception:
            pass
