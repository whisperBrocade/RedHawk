"""RedHawk — 适配器包：注册所有内置工具适配器。

使用：CLI/编排入口调用 register_all() 触发注册（避免循环导入）。
"""

from redhawk.adapters.base import BaseAdapter, ToolResult
from redhawk.adapters.ai_app_scan import AIAppScanAdapter
from redhawk.adapters.fscan import FscanAdapter
from redhawk.adapters.ffuf import FfufAdapter
from redhawk.adapters.httpx import HttpxAdapter
from redhawk.adapters.nuclei import NucleiAdapter
from redhawk.adapters.sqlmap import SqlmapAdapter
from redhawk.adapters.subfinder import SubfinderAdapter
from redhawk.adapters.xray import XrayAdapter

__all__ = [
    "BaseAdapter", "ToolResult",
    "FscanAdapter", "NucleiAdapter", "SubfinderAdapter",
    "FfufAdapter", "SqlmapAdapter", "XrayAdapter", "HttpxAdapter",
    "AIAppScanAdapter", "register_all",
]


def register_all() -> None:
    """注册所有内置适配器到 orchestrator.ADAPTERS。"""
    from redhawk.orchestrator import register_adapter

    for cls in (FscanAdapter, NucleiAdapter, SubfinderAdapter,
                FfufAdapter, SqlmapAdapter, XrayAdapter, HttpxAdapter,
                AIAppScanAdapter):
        register_adapter(cls)
