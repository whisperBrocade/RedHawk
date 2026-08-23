"""RedHawk — playbook 引擎单元测试。

验证：YAML 文件化流程（加流程 = 加文件）、stage 展开、校验失败路径。
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from redhawk.playbook import (
    PlaybookError,
    get_stages,
    list_playbooks,
    load_playbook,
)


def test_quick_scan_exists_and_loads():
    pbs = list_playbooks()
    assert "quick_scan" in pbs
    pb = load_playbook("quick_scan")
    assert pb["name"] == "quick_scan"
    assert len(pb["stages"]) == 2


def test_quick_scan_stages_order():
    pb = load_playbook("quick_scan")
    stages = get_stages(pb)
    assert stages[0]["tool"] == "fscan"
    assert stages[0]["phase"] == "recon"
    assert stages[1]["tool"] == "nuclei"
    assert stages[1]["phase"] == "scan"


def test_stage_options_preserved():
    pb = load_playbook("quick_scan")
    stages = get_stages(pb)
    assert stages[0]["options"]["threads"] == 100
    assert stages[1]["options"]["severity"] == "high,critical"


def test_load_missing_raises():
    with pytest.raises(PlaybookError):
        load_playbook("nonexistent_playbook")


def test_get_stages_expands_inputs():
    pb = {
        "name": "t",
        "stages": [
            {"phase": "recon", "tool": "a", "inputs": ["x", "y", "z"]},
            {"phase": "scan", "tool": "b"},
        ],
    }
    stages = get_stages(pb)
    assert len(stages) == 4
    assert stages[0]["input"] == "x"
    assert stages[2]["input"] == "z"
    # 无 inputs 的 stage 不产生 input 键
    assert "input" not in stages[3]
