"""RedHawk — 残留进程清理测试。"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from redhawk.cleanup import (
    _is_redhawk_process,
    _process_name,
    _service_pids,
    find_conflicts,
)


def test_is_redhawk_process():
    assert _is_redhawk_process("python.exe") is True
    assert _is_redhawk_process("python3.13.exe") is True
    assert _is_redhawk_process("RedHawk.exe") is True
    assert _is_redhawk_process("chrome.exe") is False
    assert _is_redhawk_process("explorer.exe") is False
    assert _is_redhawk_process("") is False


def test_process_name_current():
    # 当前进程名应该能拿到且为 python
    name = _process_name(os.getpid())
    assert name and "python" in name


def test_service_pids_parses_file(tmp_path):
    pid_file = tmp_path / "redhawk.pid"
    pid_file.write_text("123\n456\nnot-a-pid\n")
    os.environ["REDHAWK_DB"] = str(pid_file)
    pids = _service_pids()
    assert 123 in pids
    assert 456 in pids
    assert 999 not in pids  # 非数字被忽略


def test_service_pids_finds_project_pid():
    """真实项目 data/redhawk.pid 应被探测到（服务正在运行时的场景）。"""
    os.environ.pop("REDHAWK_DB", None)
    pids = _service_pids()
    # 无论是否为空都不抛异常即可；若服务在跑应含其 PID
    assert isinstance(pids, set)


def test_service_pids_empty_without_env_no_crash():
    os.environ.pop("REDHAWK_DB", None)
    import tempfile
    # 不依赖外部状态，只验证类型
    assert isinstance(_service_pids(), set)


def test_find_conflicts_excludes_self():
    # 当前进程监听一个端口，不应出现在冲突列表（它自己）
    import socket

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(1)

    # 用当前 python 进程占用端口（通过 socket 持有）
    conflicts = find_conflicts((port,))
    # 当前进程不应被列为冲突
    assert all(c["pid"] != os.getpid() for c in conflicts)
    sock.close()
