"""RedHawk — Phase 5 测试：知识库切块/检索 + AI 护栏。"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from redhawk.db import DB
from redhawk.kb import ask, import_docs, search, split_chunks


@pytest.fixture()
def kb():
    tmp = tempfile.mkdtemp()
    db = DB(os.path.join(tmp, "kb.db"))
    db.init()
    # 造两个测试文档
    src = os.path.join(tmp, "docs")
    os.makedirs(src)
    with open(os.path.join(src, "lateral.md"), "w", encoding="utf-8") as f:
        f.write(
            "# 内网横向移动\n\n"
            "横向移动是在内网中从一台主机移动到另一台主机。\n"
            "常用方法：PTH 哈希传递、PsExec、WMI、SMB 服务利用。\n"
            "使用 mimikatz 抓取凭据后，可通过 PTH 横向移动。\n"
            "域内常用工具：BloodHound、CrackMapExec。\n\n"
            "防御视角：开启 LSA 保护、限制管理员组、监控 445 端口连接。"
        )
    with open(os.path.join(src, "sqlmap.md"), "w", encoding="utf-8") as f:
        f.write(
            "# SQL 注入检测\n\n"
            "使用 sqlmap 检测注入：sqlmap -u 目标 --batch\n"
            "检测数据库：--dbs，枚举表：--tables，导出数据：--dump。"
        )
    r = import_docs(db, src)
    assert r["status"] == "ok"
    yield db
    db.close()


# ---------- 切块 ----------
def test_split_chunks_respects_size():
    text = "\n\n".join(f"第{i}段内容，这里是测试段落。" * 20 for i in range(10))
    chunks = split_chunks(text, size=300)
    assert len(chunks) >= 3
    assert all(len(c) <= 400 for c in chunks)  # 允许少量超限


def test_split_chunks_handles_empty():
    assert split_chunks("") == []
    assert split_chunks("   \n  ") == []


# ---------- 导入 ----------
def test_import_docs_counts(kb):
    docs = kb.query("SELECT count(*) AS c FROM knowledge_docs")
    assert docs[0]["c"] == 2
    chunks = kb.query("SELECT count(*) AS c FROM kb_chunks")
    assert chunks[0]["c"] > 0


def test_import_docs_dedup(kb, tmp_path=None):
    # 再次导入同目录：应全部跳过（content_hash 相同）
    import tempfile as _tf
    # 复用第一次导入的文档目录
    src = kb.query_one("SELECT source FROM knowledge_docs LIMIT 1")["source"]
    src_dir = os.path.dirname(src)
    r = import_docs(kb, src_dir)
    assert r["imported"] == 0
    assert r["skipped"] >= 2


# ---------- 检索 ----------
def test_search_finds_relevant(kb):
    hits = search(kb, "横向移动 PTH mimikatz")
    assert len(hits) >= 1
    top = hits[0]
    assert "横向移动" in top["content"] or "PTH" in top["content"]


def test_search_returns_sources(kb):
    hits = search(kb, "sqlmap 注入")
    assert len(hits) >= 1
    assert "sqlmap" in hits[0]["source"] or "sqlmap" in hits[0]["title"]


def test_search_no_match(kb):
    assert search(kb, "量子物理 弦理论") == []


# ---------- ask ----------
def test_ask_returns_hits(kb):
    r = ask(kb, "内网横向有什么思路")
    assert r["hit_count"] >= 1
    assert r["question"] == "内网横向有什么思路"


# ---------- AI 护栏（越权拒绝） ----------
def test_guard_blocks_unauthorized():
    from redhawk.ai_guard import pre_filter
    ok, reason = pre_filter("对没有授权的主机进行渗透")
    assert not ok
    assert reason


def test_guard_allows_technical():
    from redhawk.ai_guard import pre_filter
    ok, _ = pre_filter("横向移动的常用工具和技术")
    assert ok
