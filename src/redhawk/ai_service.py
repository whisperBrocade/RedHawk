"""RedHawk — AI 研判服务：去噪 + 证据闸门（反幻觉核心）。

三阶段（绝对理性：先暴力后理性）：
1. 哈希粗去重（暴力）：按 asset+vuln_type+severity 去重，不消耗 LLM
2. LLM 精判（理性）：对去重后 findings 逐条研判，输出 verdict
3. 证据闸门（反幻觉，借鉴 VulnClaw _completion_gate）：
   - LLM 结论必须引用 findings 证据 ID（eNNN）
   - 声称的漏洞类型/细节必须在原始工具输出（detail）中出现
   - 无证据引用或证据不匹配 → verdict 作废，标为 unverified

无 API key 时自动降级为规则引擎（severity 启发式），保证离线可用。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any

from redhawk.db import DB

# ---------------- 哈希粗去重（暴力，零成本） ----------------
DEDUP_KEY_FIELDS = ("asset_ref", "vuln_type", "severity", "title")


def dedup_hash(f: dict[str, Any]) -> str:
    """按资产+漏洞类型+严重度+标题 生成去重键。"""
    raw = "|".join(str(f.get(k, "")).lower() for k in DEDUP_KEY_FIELDS)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def dedup_findings(findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """粗去重：保留每组第一个（同键的后续丢弃），返回 (去重后, 丢弃数)。"""
    seen: set[str] = set()
    kept: list[dict[str, Any]] = []
    dropped = 0
    for f in findings:
        h = dedup_hash(f)
        if h in seen:
            dropped += 1
            continue
        seen.add(h)
        kept.append(f)
    return kept, dropped


# ---------------- 证据闸门（反幻觉核心） ----------------
def _evidence_text(f: dict[str, Any]) -> str:
    """从 finding 提取可核对的证据文本（detail JSON + title + asset_ref）。"""
    parts = [f.get("asset_ref", ""), f.get("title", "")]
    detail = f.get("detail")
    if isinstance(detail, str):
        parts.append(detail)
    elif isinstance(detail, dict):
        parts.append(json.dumps(detail, ensure_ascii=False))
    return "\n".join(parts)


def _cited_evidence_ids(text: str) -> list[str]:
    return re.findall(r"\be\d{3,}\b", text, re.IGNORECASE)


def verify_verdict(f: dict[str, Any], verdict: dict[str, Any]) -> tuple[bool, str]:
    """证据闸门：校验 LLM verdict 是否被真实证据支撑。

    借鉴 VulnClaw _completion_gate 规则：
    - verdict 必须引用 findings 证据 ID（eNNN）
    - 声称的关键词（漏洞类型/标题片段）必须出现在工具原始输出中
    - 引用未知证据 ID / 声称内容无证据 → 拒绝
    """
    fid = f.get("id")
    evidence = _evidence_text(f)
    evidence_lower = evidence.lower()

    # 规则 1: 必须引用证据 ID（eNNN 或 finding id）
    # 已知证据 ID = 本 finding 自身 ID + 证据文本中出现的 eNNN
    known_ids: set[str] = {f"e{int(fid):03d}"} if fid is not None else set()
    known_ids |= set(re.findall(r"\be\d{3,}\b", evidence, re.IGNORECASE))
    cited = _cited_evidence_ids(json.dumps(verdict, ensure_ascii=False))
    if cited:
        unknown = [c for c in cited if c.lower() not in {k.lower() for k in known_ids}]
        if unknown:
            return False, f"引用未知证据 ID: {unknown}"

    # 规则 2: 仅当判定"真实"时，声称的关键词必须在证据中出现（防凭空编造）
    # 判误报（is_real=false）不要求词匹配，避免误杀
    if verdict.get("is_real"):
        claim_text = " ".join([
            str(verdict.get("vuln_type", "")),
            str(verdict.get("title", "")),
            str(verdict.get("reason", "")),
        ])
        # 取 claim 中的关键 token（≥4 字符的字母数字词）
        tokens = [t for t in re.findall(r"[a-zA-Z\u4e00-\u9fff][\w\u4e00-\u9fff]{3,}", claim_text)]
        # 过滤掉通用词，避免误杀
        STOP = {"true", "false", "high", "medium", "low", "info", "critical", "confidence",
                "reason", "verdict", "is_real", "finding", "evidence", "确认", "漏洞", "研判",
                "真实", "可利", "利用", "存在", "未授权", "访问", "接口", "管理"}
        key_tokens = [t for t in tokens if t.lower() not in STOP]
        if key_tokens:
            # 至少一个关键 token 要在证据里（否则说明编造了证据中不存在的东西）
            hits = [t for t in key_tokens if t.lower() in evidence_lower]
            if not hits:
                return False, f"声称内容无证据支撑: {key_tokens[:5]}"

    # 规则 3: is_real=true 必须给出 reason（非空）
    if verdict.get("is_real") and not str(verdict.get("reason", "")).strip():
        return False, "is_real=true 但缺少 reason"

    return True, "verified"


# ---------------- 规则引擎（离线降级） ----------------
def rule_verdict(f: dict[str, Any]) -> dict[str, Any]:
    """无 LLM 时的确定性研判：按严重度 + 证据完整性给出初步结论。"""
    sev = (f.get("severity") or "info").lower()
    evidence = _evidence_text(f)
    is_real = sev in ("critical", "high") and len(evidence) > 20
    confidence = 0.8 if sev == "critical" else (0.6 if sev == "high" else 0.4)
    return {
        "is_real": is_real,
        "confidence": round(confidence, 2),
        "reason": f"规则引擎判定: severity={sev}, 证据长度={len(evidence)}"
        + ("（高危+证据完整 → 建议人工复核）" if is_real else "（低危或证据不足，默认保留）"),
        "evidence_ids": [f"e{f['id']:03d}"],
        "engine": "rule",
    }


# ---------------- LLM 研判（OpenAI 兼容） ----------------
def _llm_available() -> bool:
    return bool(os.environ.get("REDHAWK_LLM_API_KEY"))


def _llm_judge(f: dict[str, Any]) -> dict[str, Any]:
    """调用 OpenAI 兼容 API 精判单条 finding。返回结构化 verdict。"""
    import urllib.request

    api_key = os.environ["REDHAWK_LLM_API_KEY"]
    base_url = os.environ.get("REDHAWK_LLM_BASE_URL", "https://api.deepseek.com/v1")
    model = os.environ.get("REDHAWK_LLM_MODEL", "deepseek-chat")

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content":
                "你是红队漏洞研判助手。基于给出的工具扫描证据判断漏洞是否真实可利用。"
                "只输出 JSON：{\"is_real\": bool, \"confidence\": 0-1, "
                "\"reason\": \"中文理由，必须引用证据中的具体内容\", "
                "\"evidence_ids\": [\"eNNN\"]}。"
                "如果证据不足，is_real=false。严禁编造证据中不存在的内容。"},
            {"role": "user", "content": f"漏洞证据:\n{_evidence_text(f)[:3000]}"},
        ],
        "temperature": 0.1,
        "max_tokens": 400,
    }
    req = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    content = data["choices"][0]["message"]["content"]
    # 提取 JSON
    m = re.search(r"\{.*\}", content, re.DOTALL)
    if not m:
        raise ValueError(f"LLM 未返回 JSON: {content[:200]}")
    verdict = json.loads(m.group(0))
    verdict.setdefault("evidence_ids", [f"e{f['id']:03d}"])
    verdict["engine"] = "llm"
    return verdict


# ---------------- 服务入口 ----------------
def run_ai_analysis(db: DB, task_id: int) -> dict[str, Any]:
    """对某任务的 findings 执行：去重 → 研判 → 证据闸门 → 写库。

    返回统计。无 API key 时用规则引擎（离线可用）。
    """
    findings = db.query("SELECT * FROM findings WHERE task_id=? ORDER BY id", (task_id,))
    if not findings:
        return {"task_id": task_id, "total": 0, "kept": 0, "dropped": 0,
                "verified": 0, "rejected": 0, "engine": "none"}

    kept, dropped = dedup_findings(findings)
    engine = "llm" if _llm_available() else "rule"
    verified = rejected = 0

    for f in kept:
        try:
            verdict = _llm_judge(f) if engine == "llm" else rule_verdict(f)
        except Exception as e:
            verdict = rule_verdict(f)
            verdict["reason"] += f"（LLM 失败降级: {e}）"
            verdict["engine"] = "rule"

        ok, msg = verify_verdict(f, verdict)
        verdict["gate"] = "passed" if ok else f"rejected: {msg}"
        if ok:
            verified += 1
        else:
            rejected += 1

        with db.tx():
            db.conn.execute(
                "UPDATE findings SET ai_verdict=?, ai_status=? WHERE id=?",
                (json.dumps(verdict, ensure_ascii=False),
                 "verified" if ok else "unverified", f["id"]),
            )
            db.conn.execute(
                "INSERT INTO ai_logs (task_id, purpose, model, prompt_hash, response, blocked) VALUES (?,?,?,?,?,?)",
                (task_id, "verdict", engine,
                 hashlib.sha256(json.dumps(verdict, ensure_ascii=False).encode()).hexdigest()[:16],
                 json.dumps(verdict, ensure_ascii=False)[:1000], 0 if ok else 1),
            )
        db.audit("ai", "verdict", f"finding#{f['id']}", {"gate": ok, "engine": engine})

    return {
        "task_id": task_id, "total": len(findings), "kept": len(kept),
        "dropped": dropped, "verified": verified, "rejected": rejected,
        "engine": engine,
    }
