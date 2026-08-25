"""RedHawk v2 — 流量引擎配置（环境变量，默认值即最佳实践）。

对应 06 号文档 §九 配置项。W1 阶段先落地代理端口/超时/摘要相关，
blob/WS/SSE 相关配置随对应周次加入。
"""

from __future__ import annotations

import os

PROXY_HOST = os.environ.get("REDHAWK_PROXY_HOST", "127.0.0.1")
PROXY_PORT = int(os.environ.get("REDHAWK_PROXY_PORT", "8888"))

# 单条 body 内存缓冲上限：W1 保持与 v1 一致的截断（2MB）；
# W3 起超出部分转流式 blob 落盘（不再丢数据）。
MAX_MEM_BUF = int(os.environ.get("REDHAWK_MAX_MEM_BUF", str(2 * 1024 * 1024)))
SUMMARY_LEN = int(os.environ.get("REDHAWK_SUMMARY_LEN", str(8192)))

UPSTREAM_PROXY = os.environ.get("REDHAWK_UPSTREAM_PROXY", "")

CONN_TIMEOUT = float(os.environ.get("REDHAWK_CONN_TIMEOUT", "10"))
RESP_TIMEOUT = float(os.environ.get("REDHAWK_RESP_TIMEOUT", "30"))
IDLE_TIMEOUT = float(os.environ.get("REDHAWK_IDLE_TIMEOUT", "60"))


def upstream_proxy() -> str:
    """上游代理地址（如 http://127.0.0.1:7897）。函数式读取，运行时生效。

    代理自身转发时不能走系统代理（系统代理正指向本机 8888，会环回），
    需要出网代理时显式配置此项。
    """
    return os.environ.get("REDHAWK_UPSTREAM_PROXY", "")


def upstream_verify() -> bool:
    """上游 TLS 是否校验证书（默认开启；内网自签场景可置 0）。

    函数式读取：环境变量在每次调用时生效（模块级常量在导入时冻结，
    测试/运行时切换不生效）。
    """
    return os.environ.get("REDHAWK_UPSTREAM_VERIFY", "1") != "0"

# Windows 网络探测流量过滤（迁移自 v1，防止健康检查污染流量日志）
PROBE_KEYWORDS = (
    "captiveportal",
    "msftconnecttest",
    "www.msftncsi.com",
    "connectivity-check",
    "network-test",
    "detectportal",
    "edge-http.microsoft.com",
)
