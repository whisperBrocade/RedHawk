"""RedHawk — nuclei 适配器：模板化漏洞验证。

nuclei 支持 -jsonl 原生 JSON 输出，适配器几乎零解析成本。
典型 JSONL 行：
{"template-id":"cve-2021-44228","info":{"name":"...","severity":"critical"},
 "matched-at":"http://10.0.0.5:8080/","type":"http","host":"10.0.0.5"}
"""

from __future__ import annotations

import json
from typing import Any

from redhawk.adapters.base import BaseAdapter


class NucleiAdapter(BaseAdapter):
    tool_key = "nuclei"
    runtime = "binary"

    def build_cmd(self, target: str, options: dict) -> list[str]:
        cmd = [self.resolve_binary(), "-u", target, "-jsonl", "-silent"]
        if options.get("templates"):
            cmd += ["-t", str(options["templates"])]
        if options.get("severity"):
            cmd += ["-severity", str(options["severity"])]
        if options.get("concurrency"):
            cmd += ["-c", str(options["concurrency"])]
        if options.get("rate_limit"):
            cmd += ["-rl", str(options["rate_limit"])]
        return cmd

    def parse(self, raw: str) -> list[dict]:
        items: list[dict] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj: dict[str, Any] = json.loads(line)
            except json.JSONDecodeError:
                continue  # 非 JSONL 行（如 banner），跳过不报错
            info = obj.get("info") or {}
            matched = obj.get("matched-at") or obj.get("host") or ""
            items.append({
                "kind": "finding",
                "value": matched,
                "detail": {
                    "template": obj.get("template-id") or obj.get("template"),
                    "name": info.get("name") or "",
                    "severity": (info.get("severity") or "info").lower(),
                    "tags": info.get("tags") or [],
                    "matched": matched,
                    "type": obj.get("type") or "",
                },
            })
        return items
