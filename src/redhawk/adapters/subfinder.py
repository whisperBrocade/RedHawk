"""RedHawk — subfinder 适配器：子域名枚举。

输出：每行一个子域名（-silent 模式）。可选 -json 结构化。
"""

from __future__ import annotations

import json
import re

from redhawk.adapters.base import BaseAdapter

_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$", re.IGNORECASE)


class SubfinderAdapter(BaseAdapter):
    tool_key = "subfinder"
    runtime = "binary"

    def build_cmd(self, target: str, options: dict) -> list[str]:
        cmd = [self.resolve_binary(), "-d", target, "-silent"]
        if options.get("recursive"):
            cmd.append("-recursive")
        if options.get("all"):
            cmd.append("-all")
        return cmd

    def parse(self, raw: str) -> list[dict]:
        items = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or len(line) > 253:
                continue
            # 尝试解析 JSON 行（若 -json 启用）
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    items.append({"kind": "subdomain", "value": obj.get("host", ""),
                                  "detail": {"source": obj.get("source", "")}})
                    continue
                except json.JSONDecodeError:
                    pass
            if _DOMAIN_RE.match(line):
                items.append({"kind": "subdomain", "value": line, "detail": {}})
        return items
