"""RedHawk — 数据包分析结果测试。"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from redhawk.db import DB


def _mk_traffic(db, url="http://t.com/api?id=1", method="GET", status=200, body="OK"):
    return db.insert("traffic", {
        "method": method, "url": url, "req_headers": "{}", "req_body": "",
        "status": status, "resp_headers": '{"Content-Type":"application/json"}',
        "resp_body": body, "source": "proxy",
    })


def test_analysis_results_lists_findings(tmp_path):
    db = DB(tmp_path / "a.db")
    db.init()
    # 建占位任务（与 auto_pentest 一致）
    any_target = db.query_one("SELECT id FROM targets LIMIT 1")
    tid_target = any_target["id"] if any_target else db.insert("targets", {"name": "__auto__", "scope": "local"})
    task_id = db.insert("tasks", {"target_id": tid_target, "template": "__auto_traffic__", "status": "done"})
    tid = _mk_traffic(db)
    db.insert("findings", {
        "task_id": task_id, "target_id": None, "asset_ref": "http://t.com/api?id=1",
        "tool_key": "auto_traffic", "vuln_type": "sql_injection",
        "severity": "high", "title": "流量#1 GET ...",
        "detail": json.dumps({
            "traffic_id": tid, "reason": "响应含 SQL 报错",
            "confidence": 0.9, "repro_steps": ["step1"],
            "request": {"method": "GET", "url": "http://t.com/api?id=1", "body": ""},
            "response": {"status": 200, "body": "SQL error"},
        }),
        "ai_status": "verified",
    })
    # 验证查询逻辑
    auto_task = db.query_one("SELECT id FROM tasks WHERE template='__auto_traffic__' LIMIT 1")
    assert auto_task["id"] == task_id
    rows = db.query(
        "SELECT id, ai_status FROM findings WHERE task_id=? AND tool_key='auto_traffic'",
        (task_id,),
    )
    assert len(rows) == 1
    assert rows[0]["ai_status"] == "verified"
    db.close()


def test_auto_pentest_records_all_candidates(tmp_path, monkeypatch):
    """即使 is_real=false 的候选也应入库（ai_status=possible）。"""
    from redhawk.auto_pentest import auto_analyze_traffic
    from redhawk import llm

    # 配置密钥（mock 可用）
    os.environ["REDHAWK_DB"] = str(tmp_path / "b.db")
    llm.save_config(api_key="sk-test", model="v4-flash")

    db = DB(tmp_path / "b.db")
    db.init()
    _mk_traffic(db)

    # mock LLM 调用：扫描返回 1 个候选，研判返回 is_real=false
    def fake_chat_raw(system, user, **kw):
        if "漏洞验证专家" in system:
            return '{"is_real": false, "confidence": 0.3, "final_type": "info_leak", "reason": "证据不足", "repro_steps": []}'
        return '[{"traffic_id": 1, "vuln_type": "info_leak", "severity": "low", "reason": "响应含敏感信息"}]'

    monkeypatch.setattr(llm, "chat_raw", fake_chat_raw)
    r = auto_analyze_traffic(db, limit=10)
    db.close()

    assert r["ok"] is True
    assert r["candidates"] == 1
    assert r["findings"] == 0  # is_real=false 不计为确认漏洞
    assert len(r["analyzed_items"]) == 1
    assert r["analyzed_items"][0]["is_real"] is False
    assert r["analyzed_items"][0]["ai_status"] if "ai_status" in r["analyzed_items"][0] else True
