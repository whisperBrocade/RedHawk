"""RedHawk 测试 conftest — 沙箱环境适配。

沙箱（DSH workspace-write）下 `tempfile.mkdtemp()` 创建的目录带拒绝访问
ACL（同一进程 listdir 都 PermissionError），导致依赖它的测试
（gatekeeper/kb/csdn/llm_cfg/cert）全部失败。

方案：在测试收集前把 tempfile.mkdtemp 替换为 workspace 内实现
（src/tests/.test_tmp/ 下用 uuid 建目录），测试文件零改动。
"""

import os
import tempfile
import uuid

_SAFE_TMP_BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".test_tmp")


def _safe_mkdtemp(suffix=None, prefix=None, dir=None):
    """与 tempfile.mkdtemp 等价，但目录建在 workspace 内（可写）。"""
    base = dir or _SAFE_TMP_BASE
    os.makedirs(base, exist_ok=True)
    d = os.path.join(base, (prefix or "tmp") + uuid.uuid4().hex[:10] + (suffix or ""))
    os.makedirs(d, exist_ok=True)
    return d


# 在 pytest 收集任何测试模块之前生效（conftest 最先导入）
tempfile.mkdtemp = _safe_mkdtemp


# ---- 覆盖 pytest 内置 tmp_path：沙箱下系统 TEMP 只读，basetemp 无法创建/清理 ----
import pathlib

import pytest


@pytest.fixture
def tmp_path():
    """与 pytest 内置 tmp_path 等价，但目录建在 workspace 内（src/tests/.test_tmp/）。"""
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".test_tmp")
    os.makedirs(base, exist_ok=True)
    d = os.path.join(base, "t" + uuid.uuid4().hex[:10])
    os.makedirs(d, exist_ok=True)
    return pathlib.Path(d)


# ---- 沙箱下 tasklist 查询进程信息被拒（Access denied）→ 跳过依赖它的用例 ----
def _tasklist_available() -> bool:
    try:
        import subprocess

        r = subprocess.run(
            ["tasklist", "/FI", "PID eq 0", "/NH"],
            capture_output=True, timeout=5, errors="replace",
        )
        return r.returncode == 0
    except Exception:
        return False


def pytest_collection_modifyitems(config, items):
    if _tasklist_available():
        return
    for item in items:
        if item.nodeid.endswith("test_process_name_current"):
            item.add_marker(
                pytest.mark.skip(reason="sandbox: tasklist 查询被拒（WinError 5 Access denied）")
            )
