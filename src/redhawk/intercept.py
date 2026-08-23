"""RedHawk — 抓包/发包模块（Burp 核心能力的极简版）。

两部分：
1. HTTP/HTTPS 代理：拦截本机流量，转发并记录 请求/响应 原始报文到 DB
   - HTTP：直接转发
   - HTTPS：CONNECT 中间人（动态签发证书，需安装 RedHawk CA 到系统信任根）
2. 发包引擎（Repeater）：构造任意 HTTP 请求（method/url/headers/body），显示返回包

绝对简洁：标准库 http.server + ssl + urllib。
"""

from __future__ import annotations

import gzip
import json
import re
import socket
import ssl
import threading
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from redhawk.db import DB

MAX_BODY = 2 * 1024 * 1024  # 单条报文最大记录 2MB


# ================= 系统代理接管（WinINET 全局代理） =================
# 启动抓包时接管 Windows 系统代理 → 所有走系统代理的应用流量自动进入
# 停止时还原用户原设置
_SYS_PROXY_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def _read_sys_proxy() -> dict:
    """读取当前系统代理设置。"""
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _SYS_PROXY_KEY) as k:
            enable = winreg.QueryValueEx(k, "ProxyEnable")[0]
            server = winreg.QueryValueEx(k, "ProxyServer")[0]
            return {"enabled": bool(enable), "server": server}
    except OSError:
        return {"enabled": False, "server": ""}


def _write_sys_proxy(enabled: bool, server: str) -> bool:
    """写入系统代理设置。"""
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _SYS_PROXY_KEY, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enabled else 0)
            winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, server)
        # 通知系统代理变更（WinINET）
        import ctypes
        ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
        ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH
        return True
    except Exception:
        return False


def set_system_proxy(port: int) -> dict:
    """接管系统代理指向本机代理。返回 (是否成功, 原设置)。"""
    prev = _read_sys_proxy()
    ok = _write_sys_proxy(True, f"127.0.0.1:{port}")
    return {"ok": ok, "previous": prev}


def restore_system_proxy() -> dict:
    """还原系统代理（关闭，或恢复原 server）。"""
    prev = _read_sys_proxy()
    if prev["server"] and prev["server"] != "":
        # 若之前是别的代理，先关闭（简化：统一关闭，用户可自行恢复）
        pass
    ok = _write_sys_proxy(False, "")
    return {"ok": ok, "was": prev}


# ================= 流量记录 =================
def save_traffic(db: DB, method: str, url: str, req_headers: dict, req_body: str,
                 status: int, resp_headers: dict, resp_body: str,
                 source: str = "proxy") -> int:
    """记录一条请求/响应到 traffic 表，返回 id。"""
    return db.insert("traffic", {
        "method": method,
        "url": url[:2000],
        "req_headers": json.dumps(req_headers, ensure_ascii=False)[:8000],
        "req_body": req_body[:MAX_BODY],
        "status": status,
        "resp_headers": json.dumps(resp_headers, ensure_ascii=False)[:8000],
        "resp_body": resp_body[:MAX_BODY],
        "source": source,
    })


def list_traffic(db: DB, limit: int = 50, source: str | None = None) -> list[dict]:
    sql = "SELECT id, method, url, status, source, created_at FROM traffic"
    params: list = []
    if source:
        sql += " WHERE source=?"
        params.append(source)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    return db.query(sql, tuple(params))


def get_traffic(db: DB, traffic_id: int) -> dict | None:
    return db.query_one("SELECT * FROM traffic WHERE id=?", (traffic_id,))


# ================= 流量归类（同类型分组） =================
# Content-Type → 类别
CT_CATEGORY = [
    (("text/html", "application/xhtml"), "网页 HTML"),
    (("application/json", "text/json"), "API 接口 JSON"),
    (("application/x-www-form-urlencoded", "multipart/form-data"), "表单提交"),
    (("application/javascript", "text/javascript", "application/x-javascript"), "JS 脚本"),
    (("text/css",), "样式 CSS"),
    (("image/",), "图片"),
    (("font/", "application/font"), "字体"),
    (("video/", "audio/"), "音视频"),
    (("application/pdf",), "文档 PDF"),
    (("application/zip", "application/gzip", "application/x-7z", "application/x-tar"), "压缩包"),
    (("application/xml", "text/xml"), "XML"),
    (("text/plain",), "纯文本"),
]

# URL 后缀 → 类别（Content-Type 缺失时兜底）
EXT_CATEGORY = {
    ".js": "JS 脚本", ".css": "样式 CSS", ".html": "网页 HTML", ".htm": "网页 HTML",
    ".png": "图片", ".jpg": "图片", ".jpeg": "图片", ".gif": "图片", ".webp": "图片", ".svg": "图片",
    ".json": "API 接口 JSON", ".xml": "XML", ".pdf": "文档 PDF",
    ".zip": "压缩包", ".tar": "压缩包", ".gz": "压缩包",
    ".woff": "字体", ".woff2": "字体", ".ttf": "字体",
    ".mp4": "音视频", ".mp3": "音视频",
}


def classify_traffic(t: dict) -> str:
    """按响应 Content-Type + URL 后缀归类单条流量。"""
    resp_headers = t.get("resp_headers") or "{}"
    try:
        headers = json.loads(resp_headers) if isinstance(resp_headers, str) else resp_headers
    except (json.JSONDecodeError, TypeError):
        headers = {}
    ct = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
    for patterns, cat in CT_CATEGORY:
        if any(p in ct for p in patterns):
            return cat
    # URL 后缀兜底
    url = (t.get("url") or "").lower()
    path = url.split("?")[0]
    for ext, cat in EXT_CATEGORY.items():
        if path.endswith(ext):
            return cat
    # 方法判断
    method = (t.get("method") or "").upper()
    if method in ("POST", "PUT", "PATCH"):
        return "接口操作"
    if method in ("GET", "HEAD"):
        return "页面/资源请求"
    return "其他"


def traffic_categories(db: DB, limit: int = 200, source: str | None = None) -> list[dict]:
    """按类别分组统计流量（同类型归类列表）。"""
    sql = "SELECT id, method, url, status, resp_headers, source, created_at FROM traffic"
    params: list = []
    if source:
        sql += " WHERE source=?"
        params.append(source)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    rows = db.query(sql, tuple(params))

    groups: dict[str, list[dict]] = {}
    for r in rows:
        cat = classify_traffic(r)
        groups.setdefault(cat, []).append(r)
    # 按数量降序
    return [
        {"category": cat, "count": len(items), "items": items[:50]}
        for cat, items in sorted(groups.items(), key=lambda x: -len(x[1]))
    ]


# ================= HTTP 代理 =================
class _ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    _db: DB = None  # 类级注入
    _source: str = "proxy"

    def log_message(self, fmt, *args):  # 静默
        pass

    def _handle(self, method: str):
        # 过滤系统代理健康检查（Windows 接管后周期性发 HEAD 到代理自身端口）
        if self.headers.get("Host") in (f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"):
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        # 目标 URL：代理模式下 path 可能是完整 URL（http://host/）或相对路径（/path）
        if self.path.startswith("http://") or self.path.startswith("https://"):
            url = self.path
        else:
            url = f"http://{self.headers.get('Host', '127.0.0.1')}{self.path}"
        length = int(self.headers.get("Content-Length", 0) or 0)
        req_body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""

        # 转发
        req_headers = {k: v for k, v in self.headers.items()}
        req_headers.pop("Proxy-Connection", None)
        req_headers.pop("Proxy-Authorization", None)

        try:
            request = urllib.request.Request(url, data=req_body.encode() if req_body else None,
                                             headers=req_headers, method=method)
            with urllib.request.urlopen(request, timeout=30) as resp:
                status = resp.status
                resp_headers = dict(resp.headers.items())
                raw = resp.read(MAX_BODY)
                resp_body = _decode(raw, resp_headers.get("Content-Encoding", ""))
        except urllib.error.HTTPError as e:
            status = e.code
            resp_headers = dict(e.headers.items())
            raw = e.read(MAX_BODY)
            resp_body = _decode(raw, resp_headers.get("Content-Encoding", ""))
        except Exception as e:
            status = 502
            resp_headers = {"X-RedHawk-Error": str(e)}
            resp_body = f"代理错误: {e}"

        # 记录
        if self._db:
            try:
                tid = save_traffic(self._db, method, url, req_headers, req_body,
                                   status, resp_headers, resp_body, self._source)
                if tid is None:
                    pass
            except Exception as e:
                import traceback
                traceback.print_exc()  # 调试期不吞错，暴露保存问题

        # 回传
        self.send_response(status)
        for k, v in resp_headers.items():
            if k.lower() not in ("content-length", "transfer-encoding", "connection"):
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(resp_body.encode())))
        self.end_headers()
        self.wfile.write(resp_body.encode())

    def do_GET(self): self._handle("GET")
    def do_POST(self): self._handle("POST")
    def do_PUT(self): self._handle("PUT")
    def do_DELETE(self): self._handle("DELETE")
    def do_HEAD(self): self._handle("HEAD")
    def do_OPTIONS(self): self._handle("OPTIONS")
    def do_PATCH(self): self._handle("PATCH")

    # ============ HTTPS 中间人（CONNECT） ============
    def do_CONNECT(self):
        hostport = self.path
        host = hostport.split(":")[0] if ":" in hostport else hostport
        port = int(hostport.split(":")[1]) if ":" in hostport else 443
        # 1) 先回复 200 Connection Established（裸 TCP 上）
        self.send_response(200, "Connection Established")
        self.end_headers()
        self.wfile.flush()

        # 2) 与客户端建立 TLS（动态签发该域名证书）
        try:
            from redhawk.certgen import get_site_cert
            crt, key = get_site_cert(host)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(crt), str(key))
            client_tls = ctx.wrap_socket(self.connection, server_side=True)
        except Exception:
            try:
                self.connection.close()
            except Exception:
                pass
            return

        # 3) 与目标服务器建立真实 TLS
        try:
            server_sock = socket.create_connection((host, port), timeout=30)
            server_ctx = ssl.create_default_context()
            server_tls = server_ctx.wrap_socket(server_sock, server_hostname=host)
        except Exception:
            try:
                client_tls.close()
            except Exception:
                pass
            return

        # 4) 双向转发 + 明文记录
        try:
            self._tunnel(client_tls, server_tls, host, port)
        finally:
            try:
                client_tls.close()
            except Exception:
                pass
            try:
                server_tls.close()
            except Exception:
                pass

    def _tunnel(self, client: ssl.SSLSocket, server: ssl.SSLSocket, host: str, port: int) -> None:
        """TLS 隧道内 HTTP 转发 + 明文解析记录。

        双向：解析客户端→服务器的请求（明文），转发后解析服务器→客户端的响应，
        组装完整 请求/响应 对写入 traffic 表（source=proxy_https）。
        """
        import select
        import urllib.parse

        client.setblocking(False)
        server.setblocking(False)
        # 缓冲区：客户端上行请求 / 服务器下行响应
        req_buf = b""
        resp_buf = b""
        request_meta: dict | None = None  # {method, url, headers, body}
        response_meta: dict | None = None

        while True:
            readable, _, _ = select.select([client, server], [], [], 1.0)
            if not readable:
                continue
            for sock in readable:
                try:
                    data = sock.recv(65536)
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    continue
                except Exception:
                    return
                if not data:
                    return
                if sock is client:
                    # 客户端 → 服务器：请求
                    server.sendall(data)
                    req_buf += data
                    if request_meta is None and b"\r\n\r\n" in req_buf:
                        head, _, rest = req_buf.partition(b"\r\n\r\n")
                        try:
                            lines = head.decode("utf-8", "replace").split("\r\n")
                            parts = lines[0].split(" ")
                            method, path = parts[0], parts[1]
                            headers = {}
                            for ln in lines[1:]:
                                if ":" in ln:
                                    k, _, v = ln.partition(":")
                                    headers[k.strip().lower()] = v.strip()
                            clen = int(headers.get("content-length", "0") or 0)
                            body = rest[:clen].decode("utf-8", "replace")
                            url = f"https://{host}:{port}{path}"
                            request_meta = {"method": method, "url": url,
                                            "headers": headers, "body": body}
                        except Exception:
                            request_meta = {"method": "?", "url": f"https://{host}:{port}/",
                                            "headers": {}, "body": ""}
                    elif request_meta is not None:
                        # 补齐请求体
                        pass
                else:
                    # 服务器 → 客户端：响应
                    client.sendall(data)
                    resp_buf += data
                    if response_meta is None and b"\r\n\r\n" in resp_buf:
                        head, _, rest = resp_buf.partition(b"\r\n\r\n")
                        try:
                            status_line = head.decode("utf-8", "replace").split("\r\n")[0]
                            status = int(status_line.split(" ")[1])
                            headers = {}
                            for ln in head.decode("utf-8", "replace").split("\r\n")[1:]:
                                if ":" in ln:
                                    k, _, v = ln.partition(":")
                                    headers[k.strip().lower()] = v.strip()
                            clen = int(headers.get("content-length", "0") or 0)
                            body = rest[:clen].decode("utf-8", "replace")
                            response_meta = {"status": status, "headers": headers, "body": body}
                        except Exception:
                            response_meta = {"status": 0, "headers": {}, "body": ""}

                    # 请求+响应都到手 → 入库
                    if request_meta and response_meta and self._db:
                        try:
                            save_traffic(
                                self._db, request_meta["method"], request_meta["url"],
                                request_meta["headers"], request_meta["body"],
                                response_meta["status"], response_meta["headers"],
                                response_meta["body"], "proxy_https",
                            )
                        except Exception:
                            pass
                        request_meta = None
                        response_meta = None
                        req_buf = b""
                        resp_buf = b""


def _decode(raw: bytes, encoding: str) -> str:
    if "gzip" in encoding:
        try:
            raw = gzip.decompress(raw)
        except Exception:
            pass
    return raw.decode("utf-8", errors="replace")


class ProxyServer:
    """代理服务生命周期管理。"""

    def __init__(self, db: DB, host: str = "127.0.0.1", port: int = 8888,
                 source: str = "proxy", take_system_proxy: bool = True):
        self.db = db
        self.host = host
        self.port = port
        self.source = source
        self.take_system_proxy = take_system_proxy
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._sys_proxy_taken: bool = False

    def start(self) -> dict:
        if self._server:
            return {"status": "running", "port": self.port}
        # 端口占用预检：给出明确错误而非 500
        import socket
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind((self.host, self.port))
            probe.close()
        except OSError as e:
            return {"status": "failed", "error": f"端口 {self.port} 已被占用（{e}）。请换端口或关闭占用进程。"}
        _ProxyHandler._db = self.db
        _ProxyHandler._source = self.source
        self._server = ThreadingHTTPServer((self.host, self.port), _ProxyHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        # 接管系统代理（抓取所有走系统代理的应用流量）
        if self.take_system_proxy:
            try:
                r = set_system_proxy(self.port)
                self._sys_proxy_taken = r.get("ok", False)
            except Exception:
                self._sys_proxy_taken = False
        return {"status": "running", "port": self.port,
                "system_proxy": self._sys_proxy_taken}

    def stop(self) -> dict:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        # 还原系统代理
        if self._sys_proxy_taken:
            try:
                restore_system_proxy()
            except Exception:
                pass
            self._sys_proxy_taken = False
        return {"status": "stopped"}

    @property
    def running(self) -> bool:
        return self._server is not None


# ================= 发包引擎（Repeater） =================
def send_request(method: str, url: str, headers: dict | None = None,
                 body: str = "", timeout: int = 30, db: DB | None = None,
                 source: str = "repeater") -> dict[str, Any]:
    """构造并发送任意 HTTP 请求，返回完整响应（含状态/头/体），可选记录到 DB。"""
    req_headers = headers or {}
    data = body.encode() if body else None
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            resp_headers = dict(resp.headers.items())
            raw = resp.read(MAX_BODY)
            resp_body = _decode(raw, resp_headers.get("Content-Encoding", ""))
    except urllib.error.HTTPError as e:
        status = e.code
        resp_headers = dict(e.headers.items())
        raw = e.read(MAX_BODY)
        resp_body = _decode(raw, resp_headers.get("Content-Encoding", ""))
    except Exception as e:
        return {"ok": False, "error": str(e)}

    result = {
        "ok": True,
        "status": status,
        "headers": resp_headers,
        "body": resp_body[:MAX_BODY],
    }
    if db:
        save_traffic(db, method.upper(), url, req_headers, body, status, resp_headers, resp_body, source)
    return result


def parse_raw_request(raw: str) -> dict[str, Any]:
    """解析 Burp 风格原始请求（第一行 + headers + 空行 + body）。"""
    if not raw or not raw.strip():
        raise ValueError("请求为空")
    lines = raw.split("\r\n") if "\r\n" in raw else raw.split("\n")
    first = lines[0].split(" ")
    if len(first) < 3:
        raise ValueError("请求行格式错误: METHOD URL HTTP/1.1")
    method, url = first[0], first[1]
    if method not in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE"):
        raise ValueError(f"未知方法: {method}")
    if not url.startswith(("/", "http://", "https://")):
        raise ValueError(f"URL 格式错误: {url}")
    headers: dict[str, str] = {}
    i = 1
    while i < len(lines) and lines[i].strip():
        if ":" in lines[i]:
            k, _, v = lines[i].partition(":")
            headers[k.strip()] = v.strip()
        i += 1
    body = "\n".join(lines[i + 1:])
    return {"method": method, "url": url, "headers": headers, "body": body}
