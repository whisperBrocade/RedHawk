"""RedHawk — sqlmap 适配器：SQL 注入自动检测与利用。

sqlmap 输出是文本报告，关键信息在末尾汇总：
  Parameter: id (GET)
    Type: boolean-based blind
    Title: ...
    Payload: ...
"""

from __future__ import annotations

import re

from redhawk.adapters.base import BaseAdapter

_PARAM_RE = re.compile(r"Parameter:\s*(\S+)")
_TYPE_RE = re.compile(r"^\s*Type:\s*(.+)$", re.MULTILINE)
_TITLE_RE = re.compile(r"^\s*Title:\s*(.+)$", re.MULTILINE)
_PAYLOAD_RE = re.compile(r"^\s*Payload:\s*(.+)$", re.MULTILINE)
_VULN_RE = re.compile(r"^\s*(?:Parameter|Type|Title|Payload|Vector):", re.MULTILINE)


class SqlmapAdapter(BaseAdapter):
    tool_key = "sqlmap"
    runtime = "python"

    def build_cmd(self, target: str, options: dict) -> list[str]:
        cmd = [self.resolve_binary(), "-u", target, "--batch", "--level", "1", "--risk", "1"]
        if options.get("level"):
            cmd[cmd.index("--level") + 1] = str(options["level"])
        if options.get("risk"):
            cmd[cmd.index("--risk") + 1] = str(options["risk"])
        if options.get("dbs"):
            cmd += ["--dbs"]
        if options.get("tables"):
            cmd += ["-D", str(options.get("db", "")), "--tables"]
        if options.get("dump"):
            cmd += ["--dump"]
        if options.get("no_banner"):
            cmd += ["--batch", "--disable-coloring"]
        return cmd

    def parse(self, raw: str) -> list[dict]:
        items = []
        # 检测是否存在注入（Parameter: 出现即说明发现）
        if _PARAM_RE.search(raw):
            params = [p for p in _PARAM_RE.findall(raw)]
            types = [t.strip() for t in _TYPE_RE.findall(raw)]
            titles = [t.strip() for t in _TITLE_RE.findall(raw)]
            items.append({
                "kind": "finding",
                "value": "sql_injection",
                "detail": {
                    "parameters": params[:5],
                    "types": types[:5],
                    "titles": titles[:5],
                    "raw": raw[:1500],
                },
            })
        return items
