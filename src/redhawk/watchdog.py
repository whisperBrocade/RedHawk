"""RedHawk — 系统代理守护进程（根治"关闭后仍在后台执行代理"）。

原理：代理接管系统代理后，spawn 一个独立小进程（watchdog）监控主进程。
主进程无论以何种方式退出（正常关闭 / 任务管理器强杀 / 崩溃 / 窗口关闭
但进程驻留），watchdog 都能检测到并自动还原系统代理——不依赖主进程的
优雅退出（shutdown 事件 / atexit 在强杀时都不可靠）。

可靠性：同时校验 pid 与进程名，避免"pid 被系统复用"导致误判主进程存活。

用法：
  源码：python -m redhawk.watchdog <主进程PID> <主进程名> <接管前代理设置JSON>
  打包：RedHawk.exe --watchdog <主进程PID> <主进程名> <设置JSON>
"""

from __future__ import annotations

import ctypes
import json
import sys
import time
from ctypes import wintypes

_POLL_SECONDS = 1
TH32CS_SNAPPROCESS = 0x2
MAX_PATH_W = 260


class _PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_char * MAX_PATH_W),
    ]


def _process_name(pid: int) -> str:
    """取指定 pid 的进程名（小写）。pid 不存在返回空串。"""
    try:
        snap = ctypes.windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snap == -1:
            return ""
        e = _PROCESSENTRY32()
        e.dwSize = ctypes.sizeof(_PROCESSENTRY32)
        ok = ctypes.windll.kernel32.Process32First(snap, ctypes.byref(e))
        while ok:
            if e.th32ProcessID == pid:
                ctypes.windll.kernel32.CloseHandle(snap)
                return e.szExeFile.decode("latin-1", "replace").lower()
            ok = ctypes.windll.kernel32.Process32Next(snap, ctypes.byref(e))
        ctypes.windll.kernel32.CloseHandle(snap)
    except Exception:
        pass
    return ""


def _is_alive(pid: int, expected_name: str) -> bool:
    """主进程存活 = pid 存在 且 进程名匹配（防 pid 复用误判）。"""
    return _process_name(pid) == expected_name


def main() -> None:
    if len(sys.argv) < 4:
        sys.exit(2)
    parent_pid = int(sys.argv[1])
    expected_name = sys.argv[2].lower()
    try:
        prev = json.loads(sys.argv[3])
    except (ValueError, KeyError):
        prev = {"enabled": False, "server": ""}

    # 轮询主进程；退出后还原系统代理
    while _is_alive(parent_pid, expected_name):
        time.sleep(_POLL_SECONDS)

    try:
        from redhawk.intercept import restore_system_proxy
        restore_system_proxy(prev)
    except Exception:
        pass
    sys.exit(0)


if __name__ == "__main__":
    main()
