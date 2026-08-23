"""RedHawk — playbook 引擎：YAML 定义渗透流水线，加流程 = 加文件。

绝对简洁：playbook 是一个 YAML 文件，描述阶段序列与每个阶段的工具调用。
借鉴 VulnClaw 的 skill 参考资料化——知识/流程与代码分离。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

# 内置 playbook 目录（src/redhawk/playbooks/）
DEFAULT_PLAYBOOK_DIR = Path(__file__).parent / "playbooks"


class PlaybookError(Exception):
    pass


def load_playbook(name: str, playbook_dir: str | Path | None = None) -> dict[str, Any]:
    """加载 playbook YAML。name 可以是 'quick_scan' 或 'quick_scan.yaml'。"""
    d = Path(playbook_dir) if playbook_dir else DEFAULT_PLAYBOOK_DIR
    path = d / (name if name.endswith(".yaml") or name.endswith(".yml") else name + ".yaml")
    if not path.exists():
        raise PlaybookError(f"playbook 不存在: {path}（可用: {list_playbooks(playbook_dir)}）")
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    validate(data)
    return data


def list_playbooks(playbook_dir: str | Path | None = None) -> list[str]:
    d = Path(playbook_dir) if playbook_dir else DEFAULT_PLAYBOOK_DIR
    if not d.exists():
        return []
    return sorted(p.stem for p in d.glob("*.yaml"))


def validate(data: dict[str, Any]) -> None:
    if not isinstance(data, dict):
        raise PlaybookError("playbook 必须是 YAML 映射")
    if "name" not in data:
        raise PlaybookError("playbook 缺少 name 字段")
    stages = data.get("stages")
    if not isinstance(stages, list) or not stages:
        raise PlaybookError("playbook 缺少 stages 列表")
    for i, s in enumerate(stages):
        if not isinstance(s, dict) or "tool" not in s:
            raise PlaybookError(f"stage[{i}] 缺少 tool 字段")
        if "phase" not in s:
            raise PlaybookError(f"stage[{i}] 缺少 phase 字段")


def get_stages(data: dict[str, Any]) -> list[dict[str, Any]]:
    """展开 stage：如果某 stage 有 'inputs'，则为每个输入生成一个子步骤。"""
    out = []
    for s in data.get("stages", []):
        inputs = s.get("inputs") or [None]
        for inp in inputs:
            step = dict(s)
            if inp is not None:
                step["input"] = inp
            out.append(step)
    return out
