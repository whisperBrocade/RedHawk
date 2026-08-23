"""RedHawk — httpx 适配器：存活探测 + 指纹识别。

httpx 输出 JSONL（-json 模式）：
{"url":"http://x.com","status_code":200,"title":"...","webserver":"nginx",...}
"""

from __future__ import annotations

import json

from redhawk.adapters.base import BaseAdapter


class HttpxAdapter(BaseAdapter):
    tool_key = "httpx"
    runtime = "binary"

    def build_cmd(self, target: str, options: dict) -> list[str]:
        cmd = [self.resolve_binary(), "-l", target, "-json", "-silent"]
        # target 可能是文件（子域列表）或单个域名
        if not options.get("list_file"):
            cmd = [self.resolve_binary(), "-u", target, "-json", "-silent"]
        if options.get("status_code"):
            cmd += ["-sc", str(options["status_code"])]
        if options.get("title"):
            cmd += ["-title"]
        if options.get("tech"):
            cmd += ["-tech-detect"]
        if options.get("threads"):
            cmd += ["-t", str(options["threads"])]
        return cmd

    def parse(self, raw: str) -> list[dict]:
        items = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            items.append({
                "kind": "alive_host",
                "value": obj.get("url", ""),
                "detail": {
                    "status": obj.get("status_code"),
                    "title": obj.get("title", ""),
                    "webserver": obj.get("webserver", ""),
                    "tech": obj.get("tech", []),
                    "content_length": obj.get("content_length"),
                },
            })
        return items
