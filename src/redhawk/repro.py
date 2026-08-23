"""RedHawk — 漏洞复现报告生成器（AI 自动）。

聚合：任务 findings（AI 研判通过的）+ traffic 流量证据（命中该资产的请求/响应）
产出：Markdown 复现报告，含 复现步骤 / 请求包 / 响应特征 / 修复建议。

绝对理性：报告只引用 findings 证据 + 真实流量，AI 只做结构化组织，不编造。
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from redhawk.db import DB

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# 漏洞类型 → 复现模板（修复建议来自规则库，AI 可选增强）
REPRO_TEMPLATES: dict[str, dict[str, Any]] = {
    "weak_password": {
        "verify": "使用已知凭据尝试登录目标服务，确认可成功认证",
        "fix": "强制强口令策略 + 禁止默认口令 + 启用账号锁定与多因子认证",
        "impact": "攻击者可直接获取服务访问权限，可能导致数据泄露或横向移动",
    },
    "unauthorized_access": {
        "verify": "直接访问目标接口/管理页面，确认无需认证即可获取数据或操作",
        "fix": "启用认证与授权（RBAC）+ 关闭未使用的管理接口 + 网络层访问控制",
        "impact": "未授权访问敏感数据或管理功能，可能被利用获取更高权限",
    },
    "sql_injection": {
        "verify": "在参数中注入单引号或经典 payload，观察报错/时间延迟/布尔差异",
        "fix": "参数化查询 + 输入白名单校验 + 最小权限数据库账号 + WAF",
        "impact": "可读取/篡改/删除数据库数据，严重时可达 RCE",
    },
    "xss": {
        "verify": "在输入点提交 <script>alert(1)</script>，确认浏览器执行",
        "fix": "输出编码 + CSP 头 + 输入校验 + HttpOnly Cookie",
        "impact": "窃取会话、钓鱼、篡改页面，危害用户浏览器",
    },
    "ssrf": {
        "verify": "在 URL 参数提交 http://127.0.0.1 或内网地址，观察响应差异",
        "fix": "URL 白名单 + 禁止内网地址 + DNS 重绑定防护",
        "impact": "探测/访问内网服务，可联合利用扩大攻击面",
    },
    "rce": {
        "verify": "执行无害命令（如 id、whoami）确认命令回显",
        "fix": "及时补丁 + 禁用危险函数 + 最小化执行权限 + 沙箱",
        "impact": "完全控制目标主机，最高危害等级",
    },
    "default": {
        "verify": "按漏洞类型人工复核漏洞是否可复现",
        "fix": "请根据具体漏洞类型参考厂商修复建议",
        "impact": "视漏洞类型而定",
    },
}


def _sev_key(f: dict[str, Any]) -> int:
    return SEV_ORDER.get((f.get("severity") or "info").lower(), 5)


def _matched_traffic(db: DB, asset_ref: str, limit: int = 5) -> list[dict]:
    """找与该资产相关的流量记录（URL 匹配）。"""
    if not asset_ref:
        return []
    host_part = asset_ref.replace("http://", "").replace("https://", "").split("/")[0]
    rows = db.query(
        """SELECT id, method, url, status, req_body, resp_body FROM traffic
           WHERE url LIKE ? OR url LIKE ? ORDER BY id DESC LIMIT ?""",
        (f"%{host_part}%", f"%{asset_ref}%", limit),
    )
    return rows


def generate_repro_report(db: DB, task_id: int, output_path: str | None = None,
                          ai_enhance: bool = False) -> str:
    """生成漏洞复现报告。返回路径。"""
    task = db.query_one("SELECT * FROM tasks WHERE id=?", (task_id,))
    if not task:
        raise ValueError(f"任务 #{task_id} 不存在")
    target = db.query_one("SELECT * FROM targets WHERE id=?", (task["target_id"],))
    findings = db.query("SELECT * FROM findings WHERE task_id=?", (task_id,))
    # 只保留 AI 研判通过且判定真实的
    confirmed = []
    for f in findings:
        v = f.get("ai_verdict")
        if v:
            try:
                if json.loads(v).get("is_real"):
                    confirmed.append(f)
            except (json.JSONDecodeError, TypeError):
                continue
    if not confirmed:
        # 没有 AI 研判结果时，用全部高危/严重
        confirmed = [f for f in findings if (f.get("severity") or "").lower() in ("critical", "high")]
    confirmed.sort(key=_sev_key)

    lines: list[str] = []
    lines.append("# RedHawk 漏洞复现报告")
    lines.append("")
    lines.append(f"> 任务 #{task_id} · 模板 `{task['template']}` · 生成 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append(f"- 目标: `{target['name']}`（{target['scope']}）" if target else "- 目标: 未知")
    lines.append(f"- 确认漏洞数: {len(confirmed)}")
    lines.append("")

    if not confirmed:
        lines.append("## 结论")
        lines.append("")
        lines.append("未发现 AI 研判确认的可复现漏洞（或尚未执行 `rh verdict-run`）。")
        lines.append("")
    else:
        lines.append("## 漏洞清单")
        lines.append("")
        for i, f in enumerate(confirmed, 1):
            lines.append(f"{i}. [{f['severity'].upper()}] **{f['title'] or f['vuln_type']}** — `{f['asset_ref'] or '-'}`")
        lines.append("")

        for f in confirmed:
            lines.append("---")
            lines.append("")
            tpl = REPRO_TEMPLATES.get((f.get("vuln_type") or "").lower(), REPRO_TEMPLATES["default"])
            lines.append(f"## {f['title'] or f['vuln_type']}（e{f['id']:03d}）")
            lines.append("")
            lines.append(f"- **资产**: `{f['asset_ref'] or '-'}`")
            lines.append(f"- **漏洞类型**: `{f['vuln_type']}`")
            lines.append(f"- **严重度**: `{f['severity']}`")
            lines.append(f"- **影响**: {tpl['impact']}")
            lines.append("")
            lines.append(f"### 复现步骤")
            lines.append("")
            lines.append(f"1. {tpl['verify']}")
            lines.append(f"2. 对 `{f['asset_ref'] or '目标'}` 发送对应的探测请求")
            lines.append("3. 观察响应是否符合漏洞特征（见下方证据）")
            lines.append("")

            # 相关流量证据
            traffic = _matched_traffic(db, f.get("asset_ref") or "")
            if traffic:
                lines.append(f"### 相关流量证据（{len(traffic)} 条）")
                lines.append("")
                for t in traffic[:3]:
                    lines.append(f"**请求 {t['id']}**: `{t['method']} {t['url']}` → HTTP {t['status']}")
                    if t.get("req_body"):
                        lines.append(f"```http\n{t['method']} {t['url']}\n\n{t['req_body'][:400]}\n```")
                    if t.get("resp_body"):
                        lines.append(f"```\n{t['resp_body'][:400]}\n```")
                    lines.append("")
            else:
                lines.append("> ⚠️ 未捕获到该资产的流量记录（可先启动抓包代理重测）")
                lines.append("")
            lines.append(f"### 修复建议")
            lines.append("")
            lines.append(f"> {tpl['fix']}")
            lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## 合规声明")
    lines.append("")
    lines.append("> 本报告由 RedHawk 自动生成，基于工具扫描证据与流量记录。仅限授权测试使用。")
    lines.append("")

    content = "\n".join(lines)
    if not output_path:
        output_path = f"reports/repro_task_{task_id}.md"
    import os
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    with db.tx():
        db.conn.execute(
            "INSERT INTO reports (task_id, title, format, content, ai_generated, status) VALUES (?,?,?,?,?,?)",
            (task_id, f"任务 #{task_id} 漏洞复现报告", "md", content[:100000], 1, "final"),
        )
    db.audit("ai", "repro_report", str(task_id), {"findings": len(confirmed)})
    return output_path
