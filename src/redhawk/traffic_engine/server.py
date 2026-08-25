"""RedHawk v2 — ProxyServer（兼容 v1 intercept.ProxyServer 接口）。

asyncio 事件循环跑在后台守护线程（FastAPI 同步端点在线程池中调用 start/stop，
跨线程用 loop.call_soon_threadsafe 提交）。对外接口与 v1 完全一致：
    start() -> dict / stop() -> dict / running -> bool
"""

from __future__ import annotations

import asyncio
import socket
import threading

from redhawk.traffic_engine.listener import ProxyListener


class ProxyServer:
    def __init__(self, db, host: str = "127.0.0.1", port: int = 8888,
                 source: str = "proxy", take_system_proxy: bool = True):
        self.db = db
        self.host = host
        self.port = port
        self.source = source
        self.take_system_proxy = take_system_proxy
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._listener: ProxyListener | None = None
        self._ready = threading.Event()

    # ---------- 生命周期 ----------
    def start(self) -> dict:
        if self._listener is not None:
            return {"status": "running", "port": self.port}
        # 端口占用预检（v1 行为：明确报错而非 500）
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind((self.host, self.port))
            probe.close()
        except OSError as e:
            return {"status": "failed", "error": f"端口 {self.port} 已被占用（{e}）。请换端口或关闭占用进程。"}
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="redhawk-proxy")
        self._thread.start()
        if not self._ready.wait(15):
            return {"status": "failed", "error": "代理启动超时"}
        return {"status": "running", "port": self.port,
                "system_proxy": bool(getattr(self._listener, "_sys_proxy_taken", False))}

    def stop(self) -> dict:
        loop = self._loop
        if loop is not None:
            try:
                loop.call_soon_threadsafe(loop.stop)
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=8)
        self._loop = None
        self._thread = None
        self._listener = None
        return {"status": "stopped"}

    @property
    def running(self) -> bool:
        return self._listener is not None

    # ---------- 内部 ----------
    def _run_loop(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        try:
            loop.run_until_complete(self._start_listener())
            self._ready.set()
            loop.run_forever()
        finally:
            try:
                loop.run_until_complete(self._stop_listener())
            except Exception:
                pass
            # 取消残留的客户端任务，避免 "Task was destroyed but it is pending"
            pending = asyncio.all_tasks(loop)
            for t in pending:
                t.cancel()
            if pending:
                try:
                    loop.run_until_complete(
                        asyncio.gather(*pending, return_exceptions=True)
                    )
                except Exception:
                    pass
            loop.close()
            self._loop = None

    async def _start_listener(self) -> None:
        self._listener = ProxyListener(self.db, self.host, self.port,
                                       self.source, self.take_system_proxy)
        await self._listener.serve()

    async def _stop_listener(self) -> None:
        if self._listener:
            await self._listener.close()
