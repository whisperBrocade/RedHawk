"""RedHawk 调试启动器：把代理 DEBUG 日志写入 proxy-debug.log。

用法：
  1. 关闭正在运行的 RedHawk（桌面版/uvicorn）
  2. 运行：python debug_proxy.py
  3. 打开 http://127.0.0.1:7788 ，点「▶ 启动」抓包，访问目标网站（如 4399）
  4. 停止抓包、关闭程序
  5. 把本目录下的 proxy-debug.log 发回（或查看其中的 h2/upstream 相关行）

注意：本脚本仅供排查问题，正常使用请用 rh web / RedHawk.exe。
"""

import logging
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

LOG_FILE = os.path.join(BASE, "proxy-debug.log")
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    filename=LOG_FILE,
    encoding="utf-8",
)

os.environ.setdefault("REDHAWK_DB", os.path.join(BASE, "..", "data", "redhawk.db"))
os.environ.setdefault("REDHAWK_TOOLS", os.path.join(BASE, "..", "tools"))

print(f"[*] 调试模式启动，日志写入: {LOG_FILE}")
print("[*] 打开 http://127.0.0.1:7788 测试后关闭本窗口")

from redhawk.web import main  # noqa: E402

main()
