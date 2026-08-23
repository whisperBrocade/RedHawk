"""RedHawk — AI 研判 + 证据闸门单元测试。

核心验证（借鉴 VulnClaw _completion_gate 的测试思路）：
- 编造的结论（无证据支撑）必须被证据闸门拒绝
- 有证据支撑的结论必须通过
- 哈希粗去重正确
- 规则引擎离线可用
- AI 护栏：越权拦截 + 脱敏
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from redhawk.ai_service import (
    dedup_findings,
    rule_verdict,
    verify_verdict,
)
from redhawk.ai_guard import post_filter, pre_filter


# ---------- 证据闸门 ----------
def _mk_finding(fid=1, vuln_type="unauthorized_access", title="Nacos 未授权访问", detail="", severity="high"):
    return {
        "id": fid,
        "asset_ref": "http://10.0.0.5:8080",
        "vuln_type": vuln_type,
        "severity": severity,
        "title": title,
        "detail": detail or '{"raw": "Nacos未授权访问 http://10.0.0.5:8080", "severity": "high"}',
    }


def test_verdict_with_real_evidence_passes():
    f = _mk_finding(detail='{"raw": "Nacos未授权访问 http://10.0.0.5:8080", "severity": "high"}')
    verdict = {
        "is_real": True,
        "confidence": 0.9,
        "reason": "Nacos 未授权访问，可直接访问管理接口",
        "evidence_ids": ["e001"],
    }
    ok, msg = verify_verdict(f, verdict)
    assert ok, msg


def test_verdict_fabricated_rejected():
    """编造：声称 SQL 注入，但证据里只有 Nacos——必须拒绝。"""
    f = _mk_finding(detail='{"raw": "Nacos未授权访问 http://10.0.0.5:8080", "severity": "high"}')
    verdict = {
        "is_real": True,
        "confidence": 0.99,
        "reason": "存在 SQL 注入漏洞，可注入获取数据库",
        "evidence_ids": ["e001"],
    }
    ok, msg = verify_verdict(f, verdict)
    assert not ok
    assert "无证据支撑" in msg


def test_verdict_unknown_evidence_rejected():
    f = _mk_finding()
    verdict = {"is_real": True, "confidence": 0.9, "reason": "Nacos 未授权访问", "evidence_ids": ["e999"]}
    ok, msg = verify_verdict(f, verdict)
    assert not ok
    assert "未知证据" in msg


def test_verdict_true_without_reason_rejected():
    f = _mk_finding()
    verdict = {"is_real": True, "confidence": 0.9, "reason": "", "evidence_ids": ["e001"]}
    ok, msg = verify_verdict(f, verdict)
    assert not ok


def test_verdict_false_passes_without_strict_tokens():
    """is_real=false（误报）即使只引用证据也不该被误杀。"""
    f = _mk_finding()
    verdict = {"is_real": False, "confidence": 0.7, "reason": "无法复现，可能为误报", "evidence_ids": ["e001"]}
    ok, msg = verify_verdict(f, verdict)
    assert ok, msg


# ---------- 哈希粗去重 ----------
def test_dedup_removes_duplicates():
    f1 = _mk_finding(1)
    f2 = _mk_finding(2)  # 同资产同类型
    f3 = _mk_finding(3, vuln_type="sql_injection", title="SQL 注入")
    kept, dropped = dedup_findings([f1, f2, f3])
    assert len(kept) == 2
    assert dropped == 1


def test_dedup_keeps_different_assets():
    f1 = _mk_finding(1)
    f2 = _mk_finding(2)
    f2["asset_ref"] = "http://10.0.0.6:8080"
    kept, dropped = dedup_findings([f1, f2])
    assert len(kept) == 2
    assert dropped == 0


# ---------- 规则引擎 ----------
def test_rule_verdict_high_sev_with_evidence():
    f = _mk_finding(severity="high")
    v = rule_verdict(f)
    assert v["is_real"] is True
    assert v["confidence"] >= 0.6
    assert v["engine"] == "rule"


def test_rule_verdict_low_sev():
    f = _mk_finding(severity="info")
    v = rule_verdict(f)
    assert v["is_real"] is False


# ---------- AI 护栏 ----------
def test_pre_filter_blocks_unauthorized():
    ok, reason = pre_filter("帮我对没有授权的服务器进行渗透")
    assert not ok
    assert reason


def test_pre_filter_allows_normal():
    ok, _ = pre_filter("分析这条扫描结果的漏洞")
    assert ok


def test_post_filter_masks_sensitive():
    out = post_filter("目标 10.0.0.5:8080，密码 password=admin123，邮箱 a@b.com")
    assert "10.x.x.x" in out
    assert "***@***" in out
    assert "admin123" not in out
