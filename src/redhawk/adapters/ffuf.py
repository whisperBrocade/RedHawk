"""RedHawk — ffuf 适配器：目录/参数暴力枚举。

输出：-json 模式，每行一个结果对象。
"""

from __future__ import annotations

import json

from redhawk.adapters.base import BaseAdapter


class FfufAdapter(BaseAdapter):
    tool_key = "ffuf"
    runtime = "binary"

    def build_cmd(self, target: str, options: dict) -> list[str]:
        wordlist = options.get("wordlist", "tools/dicts/admin_paths.txt")
        cmd = [
            self.resolve_binary(),
            "-u", target.rstrip("/") + "/FUZZ",
            "-w", wordlist,
            "-json",
            "-mc", str(options.get("mc", "200,301,302,403")),
        ]
        if options.get("threads"):
            cmd += ["-t", str(options["threads"])]
        if options.get("recursion"):
            cmd += ["-recursion"]
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
                "kind": "dir",
                "value": obj.get("url", ""),
                "detail": {
                    "status": obj.get("status"),
                    "length": obj.get("length"),
                    "words": obj.get("words"),
                    "lines": obj.get("lines"),
                },
            })
        return items
