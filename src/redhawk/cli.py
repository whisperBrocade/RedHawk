"""RedHawk — CLI 入口。绝对简洁：8 个子命令，没有第 9 个。

  rh target add <name> --scope "*.example.com, 10.0.0.0/24"
  rh target ls
  rh scan run --target <id> --template quick_scan
  rh scan status <task_id>
  rh findings ls --task <id> [--severity high]
  rh playbooks
  rh audit [--limit N]
  rh init
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer

from redhawk.db import DB
from redhawk.gatekeeper import Gatekeeper

app = typer.Typer(add_completion=False, no_args_is_help=True, rich_markup_mode="rich")

DEFAULT_DB = "redhawk.db"
DEFAULT_TOOLS_DIR = "tools"


def _tools_dir() -> str:
    """工具目录：默认项目内 tools/，可被环境变量 REDHAWK_TOOLS 覆盖。"""
    import os
    return os.environ.get("REDHAWK_TOOLS", DEFAULT_TOOLS_DIR)


def _get_db(path: str) -> DB:
    db = DB(path)
    db.init()
    return db


# =============== init ===============
@app.command()
def init(db_path: str = typer.Option(DEFAULT_DB, "--db", help="数据库文件路径")):
    """初始化数据库（12 张表）"""
    db = _get_db(db_path)
    n = db.query_one("SELECT count(*) AS c FROM sqlite_master WHERE type='table'")
    typer.echo(f"[redhawk] 数据库就绪: {db_path}（{n['c']} 张表）")
    db.close()


# =============== target ===============
@app.command()
def target_add(
    name: str,
    scope: str = typer.Option(..., "--scope", help="授权范围，逗号分隔：*.example.com, 10.0.0.0/24"),
    owner: str = typer.Option("", "--owner"),
    db_path: str = typer.Option(DEFAULT_DB, "--db"),
):
    """登记目标 + 授权范围"""
    db = _get_db(db_path)
    gk = Gatekeeper(db)
    tid = gk.register_target(name, scope, owner)
    typer.echo(f"[+] 目标已登记: #{tid} {name} scope={scope}")
    db.close()


@app.command()
def target_ls(db_path: str = typer.Option(DEFAULT_DB, "--db")):
    """列出目标"""
    db = _get_db(db_path)
    gk = Gatekeeper(db)
    for t in gk.list_targets():
        typer.echo(f"#{t['id']:>3}  {t['name']:<24}  scope={t['scope']}  [{t['status']}]")
    db.close()


# =============== scan ===============
@app.command()
def scan_run(
    target: int = typer.Option(..., "--target", help="目标 ID"),
    template: str = typer.Option("quick_scan", "--template", help="playbook 名称"),
    db_path: str = typer.Option(DEFAULT_DB, "--db"),
):
    """一键运行渗透流程（默认 quick_scan）"""
    db = _get_db(db_path)
    gk = Gatekeeper(db)
    from redhawk.orchestrator import Orchestrator
    from redhawk.adapters import register_all
    import os

    register_all()
    # 自动发现工具路径：<tools_dir>/<tool_key>/<tool_key>.exe
    tools_dir = _tools_dir()
    exec_paths: dict[str, str] = {}
    for tk in ("fscan", "nuclei"):
        exe = os.path.join(tools_dir, tk, f"{tk}.exe")
        if os.path.exists(exe):
            exec_paths[tk] = exe

    orch = Orchestrator(db, gk)
    try:
        tid = orch.create_task(target, template)
    except ValueError as e:
        typer.secho(f"[!] {e}", fg=typer.colors.RED)
        raise typer.Exit(1)
    typer.echo(f"[*] 任务 #{tid} 已创建（template={template}），开始执行...")
    if exec_paths:
        typer.echo(f"[*] 工具路径: {exec_paths}")
    else:
        typer.echo("[!] 警告: 未找到工具二进制（期望 tools/fscan/fscan.exe 等）")
    result = orch.run_task(tid, exec_paths=exec_paths)
    typer.echo(f"[*] 任务状态: {result['status']}")
    if result.get("error"):
        typer.secho(f"[!] {result['error']}", fg=typer.colors.RED)
    if result.get("steps"):
        for s in result["steps"]:
            mark = "OK " if s["status"] == "done" else "FAIL"
            typer.echo(f"    [{mark}] {s['tool']:<10} {s.get('items', '')} {s.get('duration_s', '')}s")
    db.close()


@app.command()
def scan_status(
    task: int = typer.Option(..., "--task", help="任务 ID"),
    db_path: str = typer.Option(DEFAULT_DB, "--db"),
):
    """查看任务进度"""
    db = _get_db(db_path)
    gk = Gatekeeper(db)
    from redhawk.orchestrator import Orchestrator
    orch = Orchestrator(db, gk)
    p = orch.get_progress(task)
    if "error" in p:
        typer.secho(f"[!] {p['error']}", fg=typer.colors.RED)
        raise typer.Exit(1)
    typer.echo(f"任务 #{p['task_id']}  status={p['status']}  phase={p['current_phase']}")
    typer.echo(f"进度: {p['steps_done']}/{p['steps_total']}")
    for s in p["steps"]:
        typer.echo(f"    [{s['status']:<8}] {s['tool_key']:<10} phase={s['phase']}")
    db.close()


# =============== findings ===============
@app.command()
def findings_ls(
    task: int = typer.Option(..., "--task", help="任务 ID"),
    severity: Optional[str] = typer.Option(None, "--severity", help="按严重度过滤: critical/high/medium/low"),
    json_out: bool = typer.Option(False, "--json", help="输出 JSON"),
    db_path: str = typer.Option(DEFAULT_DB, "--db"),
):
    """列出漏洞发现（带证据）"""
    db = _get_db(db_path)
    gk = Gatekeeper(db)
    from redhawk.orchestrator import Orchestrator
    orch = Orchestrator(db, gk)
    fs = orch.get_findings(task, severity)
    if json_out:
        typer.echo(json.dumps(fs, ensure_ascii=False, indent=2))
    else:
        typer.echo(f"共 {len(fs)} 条发现:")
        for f in fs:
            typer.echo(f"    [{f['severity']:<8}] {f['title'][:60]}  @ {f['asset_ref']}")
    db.close()


# =============== verdict（AI 研判） ===============
@app.command()
def verdict_run(
    task: int = typer.Option(..., "--task", help="任务 ID"),
    db_path: str = typer.Option(DEFAULT_DB, "--db"),
):
    """AI 研判：去重 → 精判 → 证据闸门"""
    db = _get_db(db_path)
    from redhawk.ai_service import run_ai_analysis
    import os
    engine_hint = "LLM" if os.environ.get("REDHAWK_LLM_API_KEY") else "规则引擎(离线)"
    typer.echo(f"[*] 研判引擎: {engine_hint}")
    r = run_ai_analysis(db, task)
    typer.echo(f"[*] 完成: 原始 {r['total']} → 去重后 {r['kept']}（丢弃 {r['dropped']}）")
    typer.echo(f"[*] 证据闸门: 通过 {r['verified']} / 拒绝 {r['rejected']}（引擎: {r['engine']}）")
    db.close()


# =============== report ===============
@app.command()
def report_gen(
    task: int = typer.Option(..., "--task", help="任务 ID"),
    output: str = typer.Option("", "--output", help="输出路径（默认 reports/task_<id>.md）"),
    db_path: str = typer.Option(DEFAULT_DB, "--db"),
):
    """生成中文渗透报告（引用证据 ID）"""
    db = _get_db(db_path)
    from redhawk.report import generate_report
    path = generate_report(db, task, output or None)
    typer.echo(f"[+] 报告已生成: {path}")
    db.close()


# =============== playbooks ===============
@app.command()
def playbooks(db_path: str = typer.Option(DEFAULT_DB, "--db")):
    """列出可用 playbook"""
    from redhawk.playbook import list_playbooks
    for name in list_playbooks():
        typer.echo(f"    {name}.yaml")
    typer.echo("[*] 加流程 = 在 playbooks/ 下加一个 YAML 文件，不动代码")


# =============== plugins ===============
@app.command()
def plugins(
    action: str = typer.Argument("list", help="list / install / update"),
    key: str = typer.Option("", "--key", help="工具 key（install 时必填）"),
    tools_dir: str = typer.Option(DEFAULT_TOOLS_DIR, "--tools-dir", help="工具目录"),
    proxy: str = typer.Option("", "--proxy", help="下载代理，如 http://127.0.0.1:7897"),
    db_path: str = typer.Option(DEFAULT_DB, "--db"),
):
    """插件仓库：列出/安装安全工具（sha256 校验）"""
    from redhawk.plugins.registry import install_tool, list_installed, load_manifest

    if action == "list":
        typer.echo(f"{'KEY':<12} {'名称':<14} {'类别':<10} 状态")
        typer.echo("-" * 60)
        for t in list_installed(tools_dir):
            mark = "✅ 已装" if t["installed"] else "⬜ 未装"
            typer.echo(f"{t['key']:<12} {t['name']:<14} {t['category']:<10} {mark}")
    elif action == "install":
        if not key:
            typer.secho("[!] 请指定 --key（可用: " + ", ".join(t["key"] for t in load_manifest()) + "）", fg=typer.colors.RED)
            raise typer.Exit(1)
        typer.echo(f"[*] 安装 {key} ...")
        r = install_tool(key, tools_dir=tools_dir, proxy=proxy or None)
        if r["status"] == "installed":
            typer.secho(f"[+] 安装成功: {r.get('path', r.get('via', ''))}", fg=typer.colors.GREEN)
        elif r["status"] == "manual":
            typer.echo(f"[i] 需手动安装: {r.get('note', '')}")
        else:
            typer.secho(f"[!] 安装失败: {r.get('error', '')}", fg=typer.colors.RED)
    elif action == "update":
        typer.echo("[*] update 暂同 install（重新下载覆盖）")
        if key:
            r = install_tool(key, tools_dir=tools_dir, proxy=proxy or None)
            typer.echo(f"[*] {key}: {r['status']}")
        else:
            for t in load_manifest():
                r = install_tool(t["key"], tools_dir=tools_dir, proxy=proxy or None)
                typer.echo(f"    {t['key']}: {r['status']}")
    else:
        typer.secho(f"[!] 未知动作: {action}（list/install/update）", fg=typer.colors.RED)


# =============== audit ===============
@app.command()
def audit(
    limit: int = typer.Option(20, "--limit"),
    db_path: str = typer.Option(DEFAULT_DB, "--db"),
):
    """查看审计日志（含越权拦截记录）"""
    db = _get_db(db_path)
    rows = db.query("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
    for r in rows:
        typer.echo(f"    [{r['ts']}] {r['actor']:<10} {r['action']:<16} {r['target']}")
    db.close()


# =============== dict（字典管理） ===============
@app.command()
def dict_import(
    name: str = typer.Option(..., "--name", help="字典名"),
    category: str = typer.Option("password", "--category", help="password/username/path/payload"),
    src: str = typer.Option(..., "--src", help="源文件路径"),
    db_path: str = typer.Option(DEFAULT_DB, "--db"),
):
    """导入字典（加密存储）"""
    db = _get_db(db_path)
    from redhawk.dicts import import_dict
    r = import_dict(db, name, category, src)
    if r["status"] == "ok":
        typer.echo(f"[+] 已导入: {r['name']}（{r['lines']} 行 / {r['bytes']} 字节，已加密）")
    else:
        typer.secho(f"[!] {r.get('error')}", fg=typer.colors.RED)
    db.close()


@app.command()
def dict_ls(db_path: str = typer.Option(DEFAULT_DB, "--db")):
    """列出字典"""
    db = _get_db(db_path)
    from redhawk.dicts import list_dicts
    rows = list_dicts(db)
    for r in rows:
        enc = "🔒加密" if r["encrypted"] else "明文"
        typer.echo(f"    #{r['id']:>2} {r['name']:<20} {r['category']:<10} {r['size']:>10}B {enc}")
    db.close()


# =============== lab（靶场模式） ===============
@app.command()
def lab(
    action: str = typer.Argument("list", help="list / up / down"),
    name: str = typer.Option("", "--name", help="靶场名: dvwa/pikachu"),
):
    """靶场模式：一键拉起 DVWA/Pikachu（需 Docker）"""
    from redhawk.labs import LABS, down, list_labs, up
    if action == "list":
        for l in list_labs():
            typer.echo(f"    {l['key']:<10} {l['name']}  → {l['url']}  ({l['default_creds']})")
    elif action == "up":
        if not name:
            typer.secho("[!] 请指定 --name", fg=typer.colors.RED)
            raise typer.Exit(1)
        r = up(name)
        if r["status"] == "up":
            typer.secho(f"[+] 靶场已启动: {r['url']}（默认账号: {r['creds']}）", fg=typer.colors.GREEN)
        else:
            typer.secho(f"[!] 启动失败: {r.get('error')}", fg=typer.colors.RED)
    elif action == "down":
        if not name:
            typer.secho("[!] 请指定 --name", fg=typer.colors.RED)
            raise typer.Exit(1)
        r = down(name)
        typer.echo(f"[*] {name}: {r['status']}")
    else:
        typer.secho(f"[!] 未知动作: {action}", fg=typer.colors.RED)


# =============== cleanup（残留进程清理） ===============
@app.command()
def cleanup(
    force: bool = typer.Option(False, "--force", help="强制清理（含非 RedHawk 进程，仅限占用本工具端口的）"),
):
    """清理占用 8888/7788 端口的残留进程"""
    from redhawk.cleanup import cleanup as do_cleanup, find_conflicts

    conflicts = find_conflicts()
    if not conflicts:
        typer.echo("[*] 无残留进程，端口干净")
        return
    typer.echo(f"[*] 发现 {len(conflicts)} 个占用端口的进程:")
    for c in conflicts:
        mark = "✅可清理" if c["safe_to_kill"] else "⚠️非RedHawk进程"
        typer.echo(f"    PID {c['pid']}  端口 {c['port']}  {c['process']:<16} {mark}")
    r = do_cleanup(force=force)
    typer.echo(f"[+] 已清理 {r['killed_count']} 个，跳过 {r['skipped_count']} 个")
    for s in r["skipped"]:
        typer.echo(f"    ⚠️ 跳过 PID {s['pid']}（{s['process']}）— 用 --force 强制")
    typer.echo("[*] 提示：不要清理正在运行的 RedHawk 服务自身（当前进程已自动排除）")


# =============== web ===============
def _port_free(port: int) -> bool:
    """探测本机端口是否可绑定（False = 被占用）。"""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


@app.command()
def web(
    port: int = typer.Option(7788, "--port", help="监听端口"),
    db_path: str = typer.Option(DEFAULT_DB, "--db"),
):
    """启动 Web 控制台（默认 http://127.0.0.1:7788）

    启动前自动检测端口占用：若 7788 被 RedHawk 残留进程占用则自动清理
    （对齐桌面版行为），非 RedHawk 进程占用则明确报错退出。
    """
    import os
    if not _port_free(port):
        # 先尝试自动清理占用 8888/7788 的 RedHawk 残留进程
        from redhawk.cleanup import cleanup as do_cleanup
        r = do_cleanup()
        if r["killed_count"]:
            typer.echo(f"[*] 已自动清理 {r['killed_count']} 个残留进程（占用 RedHawk 端口），重新尝试绑定 {port}")
        if not _port_free(port):
            typer.secho(
                f"[!] 端口 {port} 仍被占用（非 RedHawk 残留进程，cleanup 已跳过）。"
                f"请关闭占用程序后重试，或用 --port 换端口。",
                fg=typer.colors.RED,
            )
            raise typer.Exit(1)
    os.environ["REDHAWK_DB"] = db_path
    os.environ.setdefault("REDHAWK_TOOLS", _tools_dir())
    from redhawk.web import main as web_main
    import sys
    sys.argv = ["redhawk-web", "--port", str(port)]
    typer.echo(f"[*] RedHawk 控制台: http://127.0.0.1:{port}  (Ctrl+C 停止)")
    web_main()


# =============== kb（知识库） ===============
@app.command()
def kb_import(
    source: str = typer.Option(..., "--source", help="知识目录（.md/.txt）"),
    db_path: str = typer.Option(DEFAULT_DB, "--db"),
):
    """导入知识文档（切块入库）"""
    db = _get_db(db_path)
    from redhawk.kb import import_docs
    r = import_docs(db, source)
    if r["status"] == "ok":
        typer.echo(f"[+] 已导入 {r['imported']} 篇 / {r['chunks']} 块（跳过 {r['skipped']}）")
    else:
        typer.secho(f"[!] {r.get('error')}", fg=typer.colors.RED)
    db.close()


@app.command()
def ask(
    question: str = typer.Argument(..., help="问题，如 '内网横向移动有什么思路'"),
    top_k: int = typer.Option(5, "--top-k"),
    db_path: str = typer.Option(DEFAULT_DB, "--db"),
):
    """知识助手：RAG 检索 + LLM 回答（过 AI 护栏；无 key 时输出检索片段）"""
    # 1) AI 护栏：越权/危险意图先拦截
    from redhawk.ai_guard import pre_filter
    ok, reason = pre_filter(question)
    if not ok:
        typer.secho(f"[!] 已拒绝: {reason}", fg=typer.colors.RED)
        raise typer.Exit(1)

    db = _get_db(db_path)
    from redhawk.kb import ask as kb_ask
    r = kb_ask(db, question, top_k)
    if not r["hits"]:
        typer.echo("[*] 知识库无相关内容（先用 rh kb-import 导入资料）")
        db.close()
        return

    # 2) 展示来源
    typer.echo(f"[*] 检索到 {r['hit_count']} 条相关（来源:）")
    for i, h in enumerate(r["hits"], 1):
        src = h["source"] or h["title"]
        typer.echo(f"    {i}. {h['title']}  ({src})")

    # 3) LLM 增强回答（有 key 时）
    import os
    if os.environ.get("REDHAWK_LLM_API_KEY"):
        from redhawk.ai_guard import post_filter
        context = "\n\n---\n\n".join(
            f"[来源 {i}: {h['source'] or h['title']}]\n{h['content'][:600]}"
            for i, h in enumerate(r["hits"], 1)
        )
        try:
            from redhawk.llm import chat
            answer = chat(
                system="你是红队知识助手。基于提供的知识片段回答，必须标注来源编号。"
                       "只回答已授权范围内的技术问题，拒绝攻击未授权目标。",
                user=f"知识片段:\n{context}\n\n问题: {question}",
            )
            typer.echo(f"\n[+] 回答:\n{post_filter(answer)}")
        except Exception as e:
            typer.echo(f"\n[!] LLM 调用失败（{e}），展示检索片段:")
            for i, h in enumerate(r["hits"], 1):
                typer.echo(f"\n--- 片段 {i} ({h['source'] or h['title']}) ---")
                typer.echo(h["content"][:400])
    else:
        # 离线模式：展示检索片段（带来源）
        typer.echo("\n[*] 离线模式（设置 REDHAWK_LLM_API_KEY 启用 LLM 回答），展示检索片段:")
        for i, h in enumerate(r["hits"], 1):
            typer.echo(f"\n--- 片段 {i} ({h['source'] or h['title']}) ---")
            typer.echo(h["content"][:400])
    db.close()


def main():
    app()


if __name__ == "__main__":
    main()
