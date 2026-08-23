"""RedHawk — 工具适配器基类。

契约：无论工具输出什么格式，适配器统一吐 JSON list。
规则：
- 解析失败 → ok=False + 保留 raw，永不静默吞错
- 所有执行走 subprocess，支持超时/限速
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ToolResult:
    ok: bool
    items: list[dict[str, Any]] = field(default_factory=list)
    raw: str = ""
    error: str | None = None
    duration_s: float = 0.0

    def to_json(self) -> str:
        return json.dumps(
            {"ok": self.ok, "items": self.items, "raw": self.raw[:2000],
             "error": self.error, "duration_s": round(self.duration_s, 2)},
            ensure_ascii=False,
        )


class BaseAdapter(ABC):
    tool_key: str = ""
    runtime: str = "binary"

    def __init__(self, exec_path: str | None = None, default_opts: dict | None = None):
        self.exec_path = exec_path
        self.default_opts = default_opts or {}

    # ---------- 子类必须实现 ----------
    @abstractmethod
    def build_cmd(self, target: str, options: dict) -> list[str]:
        """构造命令。options 已与 default_opts 合并。"""

    @abstractmethod
    def parse(self, raw: str) -> list[dict]:
        """解析工具输出 → JSON list。"""

    # ---------- 通用执行 ----------
    def resolve_binary(self, hint: str | None = None) -> str:
        path = hint or self.exec_path
        if path and Path(path).exists():
            return path
        found = shutil.which(self.tool_key)
        if found:
            return found
        raise FileNotFoundError(f"工具 {self.tool_key} 未安装（PATH 中找不到，也未指定 exec_path）")

    def run(self, target: str, options: dict | None = None, timeout: int = 300) -> ToolResult:
        opts = {**self.default_opts, **(options or {})}
        cmd = self.build_cmd(target, opts)
        started = time.time()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                errors="replace",
            )
            raw = proc.stdout or proc.stderr
            duration = time.time() - started
            if proc.returncode != 0:
                return ToolResult(ok=False, raw=raw, error=f"exit={proc.returncode}", duration_s=duration)
            try:
                items = self.parse(raw)
            except Exception as e:  # 解析失败不吞错
                return ToolResult(ok=False, raw=raw, error=f"parse failed: {e}", duration_s=duration)
            return ToolResult(ok=True, items=items, raw=raw, duration_s=duration)
        except subprocess.TimeoutExpired:
            return ToolResult(ok=False, error=f"timeout {timeout}s", duration_s=time.time() - started)
        except FileNotFoundError as e:
            return ToolResult(ok=False, error=str(e))
        except Exception as e:
            return ToolResult(ok=False, error=f"exec failed: {e}", duration_s=time.time() - started)
