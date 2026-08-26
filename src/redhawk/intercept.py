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

# ---- v2 迁移：记录与代理实现迁入 traffic_engine（re-export 保持向后兼容） ----
from redhawk.traffic_engine.recorder import (  # noqa: E402
    MAX_BODY,
    get_traffic,
    list_traffic,
    save_traffic,
)
from redhawk.traffic_engine.server import ProxyServer  # noqa: E402


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


def restore_system_proxy(prev: dict | None = None) -> dict:
    """还原系统代理。

    prev：set_system_proxy 返回的 previous（接管前的原设置）。
      - prev 且原为启用 → 恢复原 server（不误伤用户原有代理配置）
      - 否则 → 关闭系统代理（ProxyEnable=0）
    """
    if prev and prev.get("enabled"):
        ok = _write_sys_proxy(True, prev.get("server", ""))
    else:
        ok = _write_sys_proxy(False, "")
    return {"ok": ok, "was": prev}


# ================= 流量记录 =================
# v2：save_traffic / list_traffic / get_traffic 已迁入
# redhawk.traffic_engine.recorder（顶部 re-export），签名与行为不变。


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


def traffic_categories(db: DB, limit: int = 200, source: str | None = None,
                       client: str | None = None) -> list[dict]:
    """按类别分组统计流量（同类型归类列表）。source/client 支持过滤。"""
    from redhawk.traffic_engine.recorder import _client_conditions

    conds: list = []
    params: list = []
    if source:
        srcs = [s.strip() for s in source.split(",") if s.strip()]
        if len(srcs) == 1:
            conds.append("source=?")
            params.append(srcs[0])
        elif srcs:
            conds.append("source IN (" + ",".join("?" * len(srcs)) + ")")
            params.extend(srcs)
    c = _client_conditions(client, params)
    if c:
        conds.append(c)
    sql = "SELECT id, method, url, status, resp_headers, source, created_at FROM traffic"
    if conds:
        sql += " WHERE " + " AND ".join(conds)
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


def _decode(raw: bytes, encoding: str) -> str:
    if "gzip" in encoding:
        try:
            raw = gzip.decompress(raw)
        except Exception:
            pass
    return raw.decode("utf-8", errors="replace")




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
