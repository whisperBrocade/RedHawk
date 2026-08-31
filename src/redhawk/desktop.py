"""RedHawk — 独立桌面版入口（脱离浏览器）。

用 pywebview 内嵌原生窗口加载本地 FastAPI 服务：
- 启动隐藏的本地 uvicorn（127.0.0.1:7788）
- 弹出独立应用窗口（无浏览器地址栏）
- 支持系统托盘（双击恢复/退出）
- 窗口关闭自动停止服务

运行：python -m redhawk.desktop
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path
from typing import Any

# 确保项目根在 sys.path（PyInstaller 打包时用相对路径）
BASE = Path(__file__).resolve().parent.parent.parent  # src/
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))


def _data_root() -> Path:
    """数据根：打包时用 exe 同目录（可写），源码时用项目根。"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return BASE.parent  # RedHawk/


DATA_ROOT = _data_root()
os.environ.setdefault("REDHAWK_DB", str(DATA_ROOT / "data" / "redhawk.db"))
os.environ.setdefault("REDHAWK_TOOLS", str(DATA_ROOT / "tools"))

PORT = int(os.environ.get("REDHAWK_PORT", "7788"))
HOST = "127.0.0.1"

_server = None
_uvicorn: Any = None


def start_server() -> None:
    """后台启动 uvicorn（守护线程）。"""
    global _uvicorn
    import uvicorn

    config = uvicorn.Config("redhawk.web:app", host=HOST, port=PORT, log_level="warning")
    _uvicorn = uvicorn.Server(config)
    t = threading.Thread(target=_uvicorn.run, daemon=True)
    t.start()
    # 等待端口就绪
    import time
    import urllib.request
    for _ in range(30):
        try:
            urllib.request.urlopen(f"http://{HOST}:{PORT}/api/meta", timeout=1)
            return
        except Exception:
            time.sleep(0.3)


def stop_server() -> None:
    if _uvicorn:
        try:
            _uvicorn.should_exit = True
        except Exception:
            pass


def main() -> None:
    # 打包版守护进程入口：RedHawk.exe --watchdog <pid> <prev_json>
    if len(sys.argv) > 1 and sys.argv[1] == "--watchdog":
        from redhawk.watchdog import main as watchdog_main
        watchdog_main()
        return

    import webview

    # 启动前清理占用 7788/8888 的残留进程（防端口冲突）
    try:
        from redhawk.cleanup import cleanup
        cleanup()
    except Exception:
        pass

    start_server()
    # 注册 API（pywebview 侧可用 window.evaluate_js 访问页面；无需额外桥）
    window = webview.create_window(
        "RedHawk 红隼 // 互联网漏洞挖掘",
        f"http://{HOST}:{PORT}/",
        width=1280,
        height=820,
        min_size=(960, 640),
        confirm_close=True,  # 关闭前确认，防止误关丢服务
    )
    try:
        webview.start()
    finally:
        # 停止 uvicorn（触发 FastAPI shutdown → 代理停止 → 系统代理还原）
        stop_server()
        # 给 shutdown 事件留出执行时间（os._exit 会跳过清理）
        import time
        time.sleep(1.5)
    # 正常退出（不强制 os._exit）：即使这里未走完，watchdog 也会兜底还原系统代理
    sys.exit(0)


if __name__ == "__main__":
    main()
