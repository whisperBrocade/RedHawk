"""RedHawk v2 — 流量引擎包。

W1 骨架：HTTP/1.1（h11）+ CONNECT-MITM（h1 over TLS）+ 摘要入库。
后续周次：h2（W3）· blob 流式存储（W3）· WebSocket/SSE（W4）。

对外导出与 v1 intercept 兼容的 ProxyServer / 记录函数。
"""

from redhawk.traffic_engine.recorder import get_traffic, list_traffic, save_traffic
from redhawk.traffic_engine.server import ProxyServer

__all__ = ["ProxyServer", "save_traffic", "list_traffic", "get_traffic"]
