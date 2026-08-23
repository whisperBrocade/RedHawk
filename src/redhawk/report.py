"""RedHawk — 报告生成器：中文 Markdown，引用证据 ID。

绝对理性：报告只包含 findings 中的真实数据（工具输出 + AI 研判），
不引入 LLM 自由发挥的内容——证据可溯源。
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from redhawk.db import DB

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sev_key(f: dict[str, Any]) -> int:
    return SEV_ORDER.get((f.get("severity") or "info").lower(), 5)


def _verdict_summary(f: dict[str, Any]) -> str:
    v = f.get("ai_verdict")
    if not v:
        return "未研判"
    try:
        vd = json.loads(v)
    except (json.JSONDecodeError, TypeError):
        return "研判异常"
    gate = vd.get("gate", "")
    if str(gate).startswith("rejected"):
        return f"⛔ 证据闸门拒绝: {gate.split(':', 1)[-1].strip()[:60]}"
    real = "✅ 真实" if vd.get("is_real") else "❌ 误报/证据不足"
    conf = vd.get("confidence", "?")
    ev = ",".join(vd.get("evidence_ids", []) or [])
    return f"{real} (置信度 {conf}) 证据:{ev} 引擎:{vd.get('engine','?')}"


def generate_report(db: DB, task_id: int, output_path: str | None = None) -> str:
    """生成任务报告。返回报告路径。"""
    task = db.query_one("SELECT * FROM tasks WHERE id=?", (task_id,))
    if not task:
        raise ValueError(f"任务 #{task_id} 不存在")
    target = db.query_one("SELECT * FROM targets WHERE id=?", (task["target_id"],))
    findings = db.query("SELECT * FROM findings WHERE task_id=? ORDER BY id", (task_id,))
    assets = db.query(
        "SELECT kind, value, detail FROM assets WHERE task_id=? ORDER BY id", (task_id,)
    )
    findings_sorted = sorted(findings, key=_sev_key)

    # 统计
    total = len(findings)
    verified = sum(1 for f in findings if (f.get("ai_status") or "") == "verified")
    unverified = sum(1 for f in findings if (f.get("ai_status") or "") == "unverified")
    real_count = 0
    for f in findings:
        v = f.get("ai_verdict")
        if v:
            try:
                if json.loads(v).get("is_real"):
                    real_count += 1
            except (json.JSONDecodeError, TypeError):
                pass

    lines: list[str] = []
    lines.append("# RedHawk 渗透测试报告")
    lines.append("")
    lines.append(f"> 任务 #{task_id} · 模板 `{task['template']}` · 生成时间 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("## 1. 目标信息")
    lines.append("")
    lines.append(f"- 目标: `{target['name']}`（ID {target['id']}）" if target else "- 目标: 未知")
    if target:
        lines.append(f"- 授权范围: `{target['scope']}`")
    lines.append(f"- 任务状态: `{task['status']}`")
    lines.append("")

    lines.append("## 2. 资产发现")
    lines.append("")
    if assets:
        for a in assets:
            lines.append(f"- `[{a['kind']}]` {a['value']}")
    else:
        lines.append("- （无资产记录）")
    lines.append("")

    lines.append("## 3. 漏洞发现")
    lines.append("")
    lines.append(f"- 原始发现: {total} 条 | AI 研判通过: {verified} | 证据不足: {unverified} | 判定真实可利用: {real_count}")
    lines.append("")
    if not findings_sorted:
        lines.append("- （未发现漏洞）")
    for f in findings_sorted:
        lines.append(f"### e{f['id']:03d} · [{f['severity'].upper()}] {f['title'] or '(无标题)'}")
        lines.append("")
        lines.append(f"- 资产: `{f['asset_ref'] or '-'}`")
        lines.append(f"- 来源工具: `{f['tool_key']}`")
        lines.append(f"- 漏洞类型: `{f['vuln_type']}`")
        lines.append(f"- AI 研判: {_verdict_summary(f)}")
        detail = f.get("detail")
        if detail:
            lines.append(f"- 证据原文: ```json\n{detail[:1000]}\n```")
        lines.append("")

    lines.append("## 4. 合规声明")
    lines.append("")
    lines.append("> 本报告由 RedHawk 生成，所有结论均有工具输出证据支撑（证据 ID 见各条目）。")
    lines.append("> 本工具仅限授权测试使用，未授权使用后果自负。")
    lines.append("")

    content = "\n".join(lines)
    if not output_path:
        output_path = f"reports/task_{task_id}.md"
    import os
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    # 入库
    with db.tx():
        db.conn.execute(
            "INSERT INTO reports (task_id, title, format, content, ai_generated, status) VALUES (?,?,?,?,?,?)",
            (task_id, f"任务 #{task_id} 报告", "md", content[:100000], 1, "draft"),
        )
    db.audit("user", "report_generate", str(task_id), {"path": output_path})
    return output_path
