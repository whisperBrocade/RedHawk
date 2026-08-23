"""RedHawk — Web 控制台后端（FastAPI，绝对简洁：8 个端点）。

端点：
  GET  /                    控制台页面（单 HTML）
  POST /api/targets         登记目标
  GET  /api/targets         目标列表
  POST /api/tasks           创建任务（向导：目标 → 模板 → 开跑）
  GET  /api/tasks/{id}      任务进度
  GET  /api/findings        结果查询（?task_id=&severity=）
  POST /api/tasks/{id}/verdict  触发 AI 研判
  POST /api/tasks/{id}/report   生成报告
  GET  /api/reports/{id}    报告内容
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from redhawk.ai_service import run_ai_analysis
from redhawk.adapters import register_all
from redhawk.db import DB
from redhawk.gatekeeper import Gatekeeper
from redhawk.intercept import get_traffic, list_traffic
from redhawk.orchestrator import Orchestrator
from redhawk.report import generate_report
from redhawk import __version__

register_all()  # 注册内置工具适配器（fscan/nuclei）

app = FastAPI(title="RedHawk 控制台", version=__version__)


# 启动时自动恢复代理：若系统代理指向我们的 8888 且代理未运行 → 自动拉起
# （避免"服务器重启后系统代理残留指向 8888，但代理没监听"→ ERR_PROXY_CONNECTION_FAILED）
@app.on_event("startup")
def _auto_restore_proxy():
    global _proxy  # noqa: F821  实际定义在下方；用模块级兜底
    try:
        from redhawk.intercept import ProxyServer, _read_sys_proxy

        sys_cfg = _read_sys_proxy()
        if not sys_cfg.get("enabled"):
            return
        server = sys_cfg.get("server", "")
        # 提取端口
        port = 8888
        if ":" in server:
            try:
                port = int(server.split(":")[-1])
            except ValueError:
                return
        # 仅当系统代理指向本机代理端口时才恢复
        if not (server.startswith("127.0.0.1:") or server.startswith("localhost:")):
            return
        # 检查 8888 是否已在监听（避免重复启动）
        import socket
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(1)
        try:
            probe.connect(("127.0.0.1", port))
            probe.close()
            return  # 已在监听
        except OSError:
            pass
        # 拉起代理
        db = DB(DB_PATH)
        db.init()
        _proxy = ProxyServer(db, port=port, take_system_proxy=False)
        _proxy.start()
    except Exception:
        pass


# ---------------- 配置 ----------------
DB_PATH = os.environ.get("REDHAWK_DB", "redhawk.db")
TOOLS_DIR = os.environ.get("REDHAWK_TOOLS", "tools")

# 模块加载即记录服务 PID（cleanup 据此排除，防误杀正在运行的服务）
try:
    _pid_file = Path(DB_PATH).parent / "redhawk.pid"
    _pid_file.parent.mkdir(parents=True, exist_ok=True)
    _pid_file.write_text(str(os.getpid()))
except Exception:
    pass


def _app_root() -> Path:
    """PyInstaller 感知的项目根：打包时用 _MEIPASS，源码时用 __file__ 上级。"""
    import sys
    if getattr(sys, "frozen", False):  # PyInstaller 打包环境
        base = Path(sys._MEIPASS)
        return base / "redhawk" if (base / "redhawk").exists() else base
    return Path(__file__).parent


APP_ROOT = _app_root()
STATIC_DIR = APP_ROOT / "static"
PLAYBOOKS_DIR = APP_ROOT / "playbooks"


def _get_services():
    db = DB(DB_PATH)
    db.init()
    gk = Gatekeeper(db)
    orch = Orchestrator(db, gk)
    return db, gk, orch


def _tools_paths() -> dict[str, str]:
    paths: dict[str, str] = {}
    for tk in ("fscan", "nuclei"):
        exe = os.path.join(TOOLS_DIR, tk, f"{tk}.exe")
        if os.path.exists(exe):
            paths[tk] = exe
    return paths


# ---------------- 页面 ----------------
@app.get("/", response_class=HTMLResponse)
def index():
    html = (STATIC_DIR / "index.html")
    if not html.exists():
        return HTMLResponse("<h1>RedHawk 控制台前端缺失: static/index.html</h1>", status_code=500)
    return HTMLResponse(html.read_text(encoding="utf-8"))


# ---------------- 目标 ----------------
class TargetIn(BaseModel):
    name: str
    scope: str
    owner: str = ""


@app.post("/api/targets")
def create_target(t: TargetIn):
    db, gk, _ = _get_services()
    try:
        tid = gk.register_target(t.name, t.scope, t.owner)
        db.close()
        return {"id": tid, "name": t.name, "scope": t.scope}
    except Exception as e:
        db.close()
        raise HTTPException(400, str(e))


@app.get("/api/targets")
def list_targets():
    db, gk, _ = _get_services()
    rows = gk.list_targets()
    db.close()
    return rows


# ---------------- 任务 ----------------
class TaskIn(BaseModel):
    target_id: int
    template: str = "quick_scan"
    options: dict = {}


@app.post("/api/tasks")
def create_task(t: TaskIn):
    db, gk, orch = _get_services()
    try:
        tid = orch.create_task(t.target_id, t.template, t.options)
        db.close()
        return {"task_id": tid, "status": "created"}
    except ValueError as e:
        db.close()
        raise HTTPException(400, str(e))


@app.post("/api/tasks/{task_id}/run")
def run_task(task_id: int, background: bool = Query(False)):
    """同步或后台执行任务。后台用简单线程（绝对简洁，不引 Celery）。"""
    db, gk, orch = _get_services()
    try:
        if background:
            import threading

            def _worker():
                try:
                    orch.run_task(task_id, exec_paths=_tools_paths())
                finally:
                    db.close()

            threading.Thread(target=_worker, daemon=True).start()
            return {"task_id": task_id, "status": "running", "background": True}
        result = orch.run_task(task_id, exec_paths=_tools_paths())
        db.close()
        return result
    except Exception as e:
        db.close()
        raise HTTPException(500, str(e))


@app.get("/api/tasks/{task_id}")
def task_progress(task_id: int):
    db, gk, orch = _get_services()
    p = orch.get_progress(task_id)
    db.close()
    if "error" in p:
        raise HTTPException(404, p["error"])
    return p


# ---------------- 结果 ----------------
@app.get("/api/findings")
def list_findings(task_id: int, severity: Optional[str] = None):
    db, gk, orch = _get_services()
    fs = orch.get_findings(task_id, severity)
    db.close()
    return fs


@app.get("/api/assets")
def list_assets(task_id: int):
    db, _, _ = _get_services()
    rows = db.query(
        "SELECT id, kind, value, detail, source_tool FROM assets WHERE task_id=? ORDER BY id", (task_id,)
    )
    db.close()
    return rows


# ---------------- AI 研判 ----------------
@app.post("/api/tasks/{task_id}/verdict")
def verdict(task_id: int):
    db, _, _ = _get_services()
    try:
        r = run_ai_analysis(db, task_id)
        db.close()
        return r
    except Exception as e:
        db.close()
        raise HTTPException(500, str(e))


# ---------------- 报告 ----------------
@app.post("/api/tasks/{task_id}/report")
def report(task_id: int):
    db, _, _ = _get_services()
    try:
        path = generate_report(db, task_id)
        rows = db.query("SELECT id, title FROM reports WHERE task_id=? ORDER BY id DESC LIMIT 1", (task_id,))
        db.close()
        return {"path": path, "report_id": rows[0]["id"] if rows else None}
    except ValueError as e:
        db.close()
        raise HTTPException(404, str(e))


@app.get("/api/reports/{report_id}")
def get_report(report_id: int):
    db, _, _ = _get_services()
    r = db.query_one("SELECT * FROM reports WHERE id=?", (report_id,))
    db.close()
    if not r:
        raise HTTPException(404, "报告不存在")
    return r


# ---------------- 抓包代理 ----------------
_proxy: Any = None  # 全局代理实例（单实例，绝对简洁）


class ProxyControl(BaseModel):
    action: str  # start / stop
    port: int = 8888


@app.post("/api/proxy")
def proxy_control(ctl: ProxyControl):
    global _proxy
    db, _, _ = _get_services()
    from redhawk.intercept import ProxyServer
    if ctl.action == "start":
        if _proxy is None or not _proxy.running:
            _proxy = ProxyServer(db, port=ctl.port)
            r = _proxy.start()
            if r.get("status") == "failed":
                raise HTTPException(400, r.get("error", "代理启动失败"))
            return {"status": "running", "port": r["port"],
                    "system_proxy": r.get("system_proxy", False),
                    "hint": "已接管系统代理，本机所有 HTTP 流量自动捕获"}
        return {"status": "running", "port": _proxy.port,
                "system_proxy": getattr(_proxy, "_sys_proxy_taken", False)}
    if ctl.action == "stop":
        if _proxy:
            _proxy.stop()
        return {"status": "stopped"}
    raise HTTPException(400, "action 需为 start/stop")


@app.get("/api/proxy/status")
def proxy_status():
    global _proxy
    return {"running": bool(_proxy and _proxy.running), "port": _proxy.port if _proxy else None}


# ---------------- 流量 ----------------
@app.get("/api/traffic")
def traffic_list(limit: int = 50, source: str | None = None):
    db, _, _ = _get_services()
    rows = list_traffic(db, limit, source)
    db.close()
    return rows


@app.get("/api/traffic/{traffic_id}")
def traffic_detail(traffic_id: int):
    db, _, _ = _get_services()
    t = get_traffic(db, traffic_id)
    db.close()
    if not t:
        raise HTTPException(404, "流量记录不存在")
    return t


@app.get("/api/traffic-categories")
def traffic_cats(limit: int = 200, source: str | None = None):
    """流量归类：同类型分组列表。"""
    db, _, _ = _get_services()
    from redhawk.intercept import traffic_categories
    cats = traffic_categories(db, limit=limit, source=source)
    db.close()
    return {"categories": cats, "total_groups": len(cats)}


# ---------------- 发包（Repeater） ----------------
class RepeaterIn(BaseModel):
    method: str = "GET"
    url: str
    headers: dict = {}
    body: str = ""
    record: bool = True


@app.post("/api/repeater")
def repeater(r: RepeaterIn):
    db, _, _ = _get_services()
    from redhawk.intercept import send_request
    result = send_request(r.method, r.url, r.headers, r.body,
                          db=db if r.record else None, source="repeater")
    db.close()
    if not result.get("ok"):
        raise HTTPException(502, result.get("error", "发送失败"))
    return result


class RawIn(BaseModel):
    raw: str


@app.post("/api/repeater/parse")
def repeater_parse(r: RawIn):
    from redhawk.intercept import parse_raw_request
    try:
        return parse_raw_request(r.raw)
    except ValueError as e:
        raise HTTPException(400, str(e))


# ---------------- 漏洞复现报告 ----------------
@app.post("/api/tasks/{task_id}/repro")
def repro_report(task_id: int):
    db, _, _ = _get_services()
    from redhawk.repro import generate_repro_report
    try:
        path = generate_repro_report(db, task_id)
        rows = db.query("SELECT id, title FROM reports WHERE task_id=? ORDER BY id DESC LIMIT 1", (task_id,))
        db.close()
        return {"path": path, "report_id": rows[0]["id"] if rows else None}
    except ValueError as e:
        db.close()
        raise HTTPException(404, str(e))


# ---------------- 知识助手 ----------------
class AskIn(BaseModel):
    question: str
    top_k: int = 5
    csdn: bool = True


@app.post("/api/kb/ask")
def kb_ask(a: AskIn):
    db, _, _ = _get_services()
    from redhawk.kb import ask as kb_ask_fn
    r = kb_ask_fn(db, a.question, a.top_k, csdn_fallback=a.csdn)
    db.close()
    return r


# ---------------- 审计 ----------------
@app.get("/api/audit")
def audit_list(limit: int = 50):
    db, _, _ = _get_services()
    rows = db.query("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
    db.close()
    return {"rows": rows}


# ---------------- 残留进程清理 ----------------
@app.get("/api/cleanup/check")
def cleanup_check():
    from redhawk.cleanup import find_conflicts
    return {"conflicts": find_conflicts()}


class CleanupIn(BaseModel):
    force: bool = False


@app.post("/api/cleanup")
def cleanup_run(ctl: CleanupIn):
    from redhawk.cleanup import cleanup
    return cleanup(force=ctl.force)


# ---------------- AI 模型配置（DeepSeek） ----------------
class LLMConfigIn(BaseModel):
    api_key: str = ""
    model: str = "v4-flash"


@app.get("/api/llm/config")
def llm_get_config():
    from redhawk import llm
    cfg = llm.load_config()
    # 不回传密钥明文
    return {
        "model": cfg["model"],
        "model_name": cfg["model_name"],
        "model_id": cfg["model_id"],
        "base_url": cfg["base_url"],
        "available": cfg["available"],
        "models": {k: {"name": v["name"], "desc": v["desc"]} for k, v in llm.DEEPSEEK_MODELS.items()},
    }


@app.post("/api/llm/config")
def llm_save_config(ctl: LLMConfigIn):
    from redhawk import llm
    try:
        cfg = llm.save_config(api_key=ctl.api_key.strip(), model=ctl.model)
        return {"ok": True, "model": cfg["model"], "available": cfg["available"]}
    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/api/llm/test")
def llm_test():
    from redhawk import llm
    r = llm.test_connection()
    if not r.get("ok"):
        raise HTTPException(400, r.get("error", "连接失败"))
    return r


# ---------------- 一键自动化抓包分析 ----------------
class AutoIn(BaseModel):
    limit: int = 50


@app.post("/api/auto/analyze-traffic")
def auto_analyze(a: AutoIn):
    db, _, _ = _get_services()
    from redhawk.auto_pentest import auto_analyze_traffic
    try:
        r = auto_analyze_traffic(db, limit=a.limit)
        db.close()
        return r
    except Exception as e:
        db.close()
        raise HTTPException(500, str(e))


# ---------------- HTTPS 证书 ----------------
@app.get("/api/cert/ca")
def cert_ca_download():
    """下载 RedHawk CA 证书（安装到系统信任根后可解密 HTTPS）。"""
    from redhawk.certgen import get_ca_pem
    from fastapi.responses import Response
    pem = get_ca_pem()
    return Response(
        content=pem,
        media_type="application/x-x509-ca-cert",
        headers={"Content-Disposition": 'attachment; filename="redhawk-ca.crt"'},
    )


@app.get("/api/cert/status")
def cert_status():
    from redhawk.certgen import get_ca_paths, is_ca_installed
    info = get_ca_paths()
    info["installed"] = is_ca_installed()
    return info


@app.post("/api/cert/install")
def cert_install():
    """一键安装 CA 到系统信任根（弹 UAC 授权）。"""
    from redhawk.certgen import install_ca
    r = install_ca()
    if not r.get("ok"):
        raise HTTPException(400, r.get("error", "安装失败"))
    return r


# ---------------- 数据包分析结果 ----------------
@app.get("/api/analysis/results")
def analysis_results(limit: int = 100):
    """一键 AI 分析的结果列表（关联每个数据包的请求/响应证据）。"""
    db, _, _ = _get_services()
    auto_task = db.query_one("SELECT id FROM tasks WHERE template='__auto_traffic__' LIMIT 1")
    if not auto_task:
        db.close()
        return {"results": [], "total": 0}
    rows = db.query(
        """SELECT f.id, f.asset_ref, f.vuln_type, f.severity, f.title, f.detail,
                  f.ai_status, f.created_at,
                  t.method, t.status AS http_status, t.url AS traffic_url
           FROM findings f
           LEFT JOIN traffic t ON json_extract(f.detail, '$.traffic_id') = t.id
           WHERE f.task_id = ? AND f.tool_key = 'auto_traffic'
           ORDER BY f.id DESC LIMIT ?""",
        (auto_task["id"], limit),
    )
    db.close()
    return {"results": rows, "total": len(rows)}


# ---------------- 赏金平台导航 ----------------
@app.get("/api/src-platforms")
def src_platforms():
    from redhawk.src_platforms import ENTERPRISE_SRC, SRC_PLATFORMS
    return {"groups": SRC_PLATFORMS, "enterprise": ENTERPRISE_SRC}


# ---------------- 元信息 ----------------
@app.get("/api/meta")
def meta():
    return {
        "version": __version__,
        "tools": _tools_paths(),
        "templates": sorted(
            p.stem for p in PLAYBOOKS_DIR.glob("*.yaml")
        ),
        "llm": "ready" if os.environ.get("REDHAWK_LLM_API_KEY") else "offline-rule",
    }


def main():
    import sys
    import uvicorn

    port = 7788
    try:
        if "--port" in sys.argv:
            port = int(sys.argv[sys.argv.index("--port") + 1])
    except (ValueError, IndexError):
        pass
    uvicorn.run("redhawk.web:app", host="127.0.0.1", port=port, reload=False)
