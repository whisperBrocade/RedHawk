# -*- mode: python ; coding: utf-8 -*-
# RedHawk 独立版打包配置
# 用法: pyinstaller redhawk.spec

import os

ROOT = os.path.dirname(os.path.abspath("redhawk.spec"))

a = Analysis(
    [os.path.join(ROOT, "redhawk", "desktop.py")],
    pathex=[ROOT],
    binaries=[],
    datas=[
        # 静态前端 + playbooks + 插件清单 + labs compose
        (os.path.join(ROOT, "redhawk", "static"), "redhawk/static"),
        (os.path.join(ROOT, "redhawk", "playbooks"), "redhawk/playbooks"),
        (os.path.join(ROOT, "redhawk", "plugins", "manifest.json"), "redhawk/plugins"),
        (os.path.join(ROOT, "redhawk", "labs"), "redhawk/labs"),
    ],
    hiddenimports=[
        "redhawk.web", "redhawk.cli", "redhawk.db", "redhawk.gatekeeper",
        "redhawk.orchestrator", "redhawk.playbook", "redhawk.ai_service",
        "redhawk.ai_guard", "redhawk.report", "redhawk.repro",
        "redhawk.intercept", "redhawk.kb", "redhawk.llm", "redhawk.dicts",
        "redhawk.labs", "redhawk.plugins.registry", "redhawk.desktop",
        "redhawk.traffic_engine", "redhawk.traffic_engine.config",
        "redhawk.traffic_engine.recorder", "redhawk.traffic_engine.upstream",
        "redhawk.traffic_engine.client_h1", "redhawk.traffic_engine.listener",
        "redhawk.traffic_engine.client_h2", "redhawk.traffic_engine.server",
        "redhawk.traffic_engine.stream_store",
        "h11", "h11._connection", "h11._events", "h11._headers",
        "h11._readers", "h11._receivebuffer", "h11._state",
        "h11._util", "h11._writers", "h11._version",
        "h2", "h2.connection", "h2.config", "h2.events", "h2.exceptions",
        "h2.frame_buffer", "h2.settings", "h2.stream", "h2.utilities",
        "h2.windows", "h2.flow_control", "h2.errors", "h2.socks",
        "hpack", "hpack.hpack", "hpack.huffman", "hpack.huffman_constants",
        "hpack.table", "hpack.exceptions", "hpack.struct",
        "hyperframe", "hyperframe.frame", "hyperframe.flags",
        "hyperframe.exceptions", "priority", "priority.priority",
        "redhawk.adapters", "redhawk.adapters.fscan", "redhawk.adapters.nuclei",
        "redhawk.adapters.subfinder", "redhawk.adapters.httpx",
        "redhawk.adapters.ffuf", "redhawk.adapters.sqlmap",
        "redhawk.adapters.xray", "redhawk.adapters.ai_app_scan",
        "uvicorn", "uvicorn.logging", "uvicorn.loops", "uvicorn.loops.auto",
        "uvicorn.protocols", "uvicorn.protocols.http", "uvicorn.protocols.http.auto",
        "uvicorn.protocols.websockets", "uvicorn.protocols.websockets.auto",
        "uvicorn.lifespan", "uvicorn.lifespan.on",
    ],
    excludes=["tkinter", "PyQt5", "PySide2", "matplotlib", "numpy", "pandas"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="RedHawk",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # 无控制台窗口（独立软件）
    icon=os.path.join(ROOT, "..", "redhawk.ico") if os.path.exists(os.path.join(ROOT, "..", "redhawk.ico")) else None,)
