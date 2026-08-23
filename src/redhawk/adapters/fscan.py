"""RedHawk — fscan 适配器：内网/资产快扫之王。

fscan 输出是文本行，典型格式（v2.2.0 实测）：
  [*] 127.0.0.1:3306                 mysql    [Product:...] Banner:(...)
  [*] 127.0.0.1:445                  microsoft-ds [Product:Microsoft Windows SMB2] ...
  [*] http://127.0.0.1               http     [Product:Open Lighting Architecture daemon] ...
  [*] WebTitle: http://10.0.0.5:8080 code:200 len:1234  title:Nacos
  [+] http://127.0.0.1               code:200 len:2307  title:站点创建成功...
  [!] MySQL 127.0.0.1:3306 root:root
  [+] SMBInfo 127.0.0.1:445 [Windows 11 ...] ...
"""

from __future__ import annotations

import re

from redhawk.adapters.base import BaseAdapter

# [*] IP:port  service  [Product:...] Banner:(...)
_PORT_RE = re.compile(r"^\[\*\]\s*(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\S+)(?:\s+\[Product:([^\]]*)\])?")
# [*] http(s)://host[:port]  http  [Product:...]
_HTTP_RE = re.compile(r"^\[\*\]\s*(https?://\S+)\s+http\b")
# [+] http://host  code:NNN len:NNNN  title:XXX
_TITLE_RE = re.compile(r"WebTitle:\s*(\S+)\s+code:(\d+)\s+len:\d+\s+title:(\S+)")
_TITLE_RE2 = re.compile(r"^\[\+\]\s*(https?://\S+)\s+code:(\d+)\s+len:\d+\s+title:(\S+)")
# [!] MySQL IP:port user:pass（弱口令发现）
_WEAKPWD_RE = re.compile(r"^\[!\]\s*(\w+)\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\S+):(\S+)")
# [+] SMBInfo / 其他信息行
_SMBINFO_RE = re.compile(r"^\[\+\]\s*SMBInfo\s+(\d+\.\d+\.\d+\.\d+):(\d+)")

# 漏洞/未授权启发词
_VULN_KEYWORDS = ("未授权", "unauthorized", "弱口令", "漏洞", "exp", "redis", "nacos", "log4j", "struts", "weblogic", "shiro")


class FscanAdapter(BaseAdapter):
    tool_key = "fscan"
    runtime = "binary"

    def build_cmd(self, target: str, options: dict) -> list[str]:
        cmd = [self.resolve_binary(), "-h", target]
        if options.get("threads"):
            cmd += ["-t", str(options["threads"])]
        if options.get("no_brute"):
            cmd += ["-nobr"]
        if options.get("no_ping"):
            cmd += ["-np"]
        if options.get("ports"):
            cmd += ["-p", str(options["ports"])]
        return cmd

    def parse(self, raw: str) -> list[dict]:
        items: list[dict] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue

            # 1) 端口开放行: [*] IP:port  service  [Product:...]
            m = _PORT_RE.match(line)
            if m:
                items.append({
                    "kind": "port",
                    "value": m.group(1),
                    "detail": {
                        "port": int(m.group(2)),
                        "service": m.group(3),
                        "product": m.group(4) or "",
                    },
                })
                continue

            # 2) HTTP 服务行: [*] http://host  http  [Product:...]
            m = _HTTP_RE.match(line)
            if m:
                items.append({
                    "kind": "http_service",
                    "value": m.group(1),
                    "detail": {"url": m.group(1)},
                })
                continue

            # 3) WebTitle: http://... code:NNN len:NNN title:XXX
            m = _TITLE_RE.search(line)
            if m:
                items.append({
                    "kind": "web_title",
                    "value": m.group(1),
                    "detail": {"code": int(m.group(2)), "title": m.group(3)},
                })
                continue

            # 4) [+] http://... code:NNN len:NNN title:XXX
            m = _TITLE_RE2.match(line)
            if m:
                items.append({
                    "kind": "web_title",
                    "value": m.group(1),
                    "detail": {"code": int(m.group(2)), "title": m.group(3)},
                })
                continue

            # 5) 弱口令: [!] MySQL IP:port user:pass
            m = _WEAKPWD_RE.match(line)
            if m:
                items.append({
                    "kind": "weak_password",
                    "value": f"{m.group(2)}:{m.group(3)}",
                    "detail": {
                        "service": m.group(1),
                        "user": m.group(4),
                        "password": m.group(5),
                    },
                })
                continue

            # 6) SMBInfo
            m = _SMBINFO_RE.match(line)
            if m:
                items.append({
                    "kind": "smb_info",
                    "value": m.group(1),
                    "detail": {"port": int(m.group(2))},
                })
                continue

            # 7) 漏洞/未授权启发（不吞任何行）
            low = line.lower()
            if any(k in low for k in _VULN_KEYWORDS):
                items.append({
                    "kind": "vuln_hint",
                    "value": line[:200],
                    "detail": {"raw": line[:500]},
                })
        return items
