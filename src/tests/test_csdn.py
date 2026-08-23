"""RedHawk — CSDN 知识库检索测试。"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from redhawk.csdn import _clean, search, search_text


def test_clean_removes_em_tags():
    assert _clean("<em>内网</em><em>横向移动</em>方法") == "内网横向移动方法"
    assert _clean("  多个   空格  ") == "多个 空格"
    assert _clean("") == ""
    assert _clean(None) == ""


def test_search_real_csdn():
    """真实调用 CSDN 接口（网络可用时）。"""
    results = search("内网横向移动", top_k=3)
    if results and "error" in results[0]:
        import pytest
        pytest.skip("CSDN 接口不可用: " + results[0]["error"])
    assert len(results) > 0
    r = results[0]
    assert r["title"], "标题不能为空"
    assert r["url"].startswith("http"), "链接格式错误"
    assert "<em>" not in r["title"], "高亮标签未清洗"


def test_search_text_format():
    text = search_text("sqlmap", top_k=2)
    assert isinstance(text, str)
    assert "CSDN" in text or "无结果" in text


def test_kb_ask_csdn_fallback(tmp_path):
    """本地空库时 ask 应走 CSDN 兜底。"""
    import tempfile
    from redhawk.db import DB
    from redhawk.kb import ask

    db = DB(os.path.join(tempfile.mkdtemp(), "k.db"))
    db.init()
    r = ask(db, "内网横向移动", top_k=3, csdn_fallback=True)
    db.close()
    # source 应为 csdn（本地空库）或 none（CSDN 也失败）
    assert r["source"] in ("csdn", "none")
    if r.get("csdn"):
        assert r["hit_count"] > 0
        assert "title" in r["csdn"][0]
