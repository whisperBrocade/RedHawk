"""RedHawk — xray 适配器：被动漏洞扫描。

xray webscan 输出含 "found" 的漏洞行：
  [INFO] found: [poc-yaml-...] (url) ...
"""

from __future__ import annotations

import re

from redhawk.adapters.base import BaseAdapter

_FOUND_RE = re.compile(r"found:\s*\[([^\]]+)\]\s*\(([^)]+)\)")
_SEV_RE = re.compile(r"severity:\s*(\w+)")


class XrayAdapter(BaseAdapter):
    tool_key = "xray"
    runtime = "binary"

    def build_cmd(self, target: str, options: dict) -> list[str]:
        cmd = [self.resolve_binary(), "webscan", "--url", target, "--json-output", "-"]
        if options.get("listen"):
            cmd = [self.resolve_binary(), "webscan", "--listen", str(options["listen"]), "--json-output", "-"]
        return cmd

    def parse(self, raw: str) -> list[dict]:
        items = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            m = _FOUND_RE.search(line)
            if m:
                sev_m = _SEV_RE.search(line)
                items.append({
                    "kind": "finding",
                    "value": m.group(2),
                    "detail": {
                        "poc": m.group(1),
                        "severity": (sev_m.group(1) if sev_m else "medium").lower(),
                        "raw": line[:500],
                    },
                })
        return items
