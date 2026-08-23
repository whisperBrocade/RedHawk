"""RedHawk — 残留进程清理。

清理占用 RedHawk 端口（代理 8888 / Web 7788）的残留进程，
避免"端口被占用 → 500"问题。

安全过滤：
- 只处理占用 RedHawk 端口（8888/7788）的进程
- 跳过当前进程（正在运行的 uvicorn/desktop）
- 只杀 python/RedHawk 进程（不误伤其他程序）
- 只杀 LISTENING 状态的（不碰客户端连接）
"""

from __future__ import annotations

import os
import re
import subprocess
from typing import Any

REDHAWK_PORTS = (8888, 7788)


def _service_pids() -> set[int]:
    """读取 redhawk.pid 中的服务 PID（cleanup 不杀自己正在用的服务）。

    优先从环境变量 REDHAWK_DB 同目录读，其次探测常见位置（项目根 data/、exe 同目录 data/）。
    """
    from pathlib import Path
    import os as _os

    candidates: list[Path] = []
    db_path = _os.environ.get("REDHAWK_DB", "")
    if db_path:
        candidates.append(Path(db_path).parent / "redhawk.pid")
    # 探测：从 cleanup.py 向上逐级找 data/redhawk.pid（覆盖源码模式）
    try:
        here = Path(__file__).resolve().parent  # redhawk/
        for _ in range(6):  # 向上最多 6 层
            candidates.append(here / "data" / "redhawk.pid")
            here = here.parent
    except Exception:
        pass
    # exe 模式：探测 exe 同目录 data/
    if getattr(_os, "sys", None) and getattr(_os.sys, "frozen", False):
        try:
            candidates.append(Path(_os.sys.executable).resolve().parent / "data" / "redhawk.pid")
        except Exception:
            pass

    pids: set[int] = set()
    for pid_file in candidates:
        try:
            if pid_file.exists():
                for line in pid_file.read_text().splitlines():
                    line = line.strip()
                    if line.isdigit():
                        pids.add(int(line))
        except Exception:
            continue
    return pids


def _netstat_pids(port: int) -> list[int]:
    """netstat 找出监听指定端口的 PID 列表。"""
    try:
        out = subprocess.run(
            ["netstat", "-ano"], capture_output=True, text=True,
            timeout=10, errors="replace",
        ).stdout
    except Exception:
        return []
    pids: list[int] = []
    for line in out.splitlines():
        if f":{port}" not in line or "LISTENING" not in line.upper():
            continue
        parts = line.split()
        if parts and parts[-1].isdigit():
            pids.append(int(parts[-1]))
    return pids


def _process_name(pid: int) -> str:
    """用 tasklist 获取进程名。"""
    try:
        out = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=10, errors="replace",
        ).stdout
        m = re.search(r'"([^"]+)"', out)
        return m.group(1).lower() if m else ""
    except Exception:
        return ""


def _is_redhawk_process(name: str) -> bool:
    """只认 python / RedHawk 相关进程，避免误杀（大小写不敏感）。"""
    name = (name or "").lower()
    return any(k in name for k in ("python", "redhawk"))


def find_conflicts(ports: tuple[int, ...] = REDHAWK_PORTS) -> list[dict[str, Any]]:
    """列出占用 RedHawk 端口的残留进程（排除当前进程 + 记录在案的服务进程）。"""
    current = os.getpid()
    services = _service_pids()
    results: list[dict[str, Any]] = []
    seen: set[int] = set()
    for port in ports:
        for pid in _netstat_pids(port):
            if pid == current or pid in services or pid in seen:
                continue
            seen.add(pid)
            name = _process_name(pid)
            results.append({
                "pid": pid,
                "port": port,
                "process": name or "unknown",
                "safe_to_kill": _is_redhawk_process(name),
            })
    return results


def cleanup(ports: tuple[int, ...] = REDHAWK_PORTS, force: bool = False) -> dict[str, Any]:
    """清理残留进程。force=True 时连非 redhawk 进程也杀（仅当占用我们的端口）。"""
    conflicts = find_conflicts(ports)
    killed: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for c in conflicts:
        if not (c["safe_to_kill"] or force):
            skipped.append(c)
            continue
        try:
            os.kill(c["pid"], 9)  # 强杀（Windows 下 SIGKILL 等价 TerminateProcess）
            killed.append(c)
        except Exception as e:
            skipped.append({**c, "error": str(e)})
    return {
        "killed": killed,
        "skipped": skipped,
        "killed_count": len(killed),
        "skipped_count": len(skipped),
    }
