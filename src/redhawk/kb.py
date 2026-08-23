"""RedHawk — 知识库：文档切块 + 入库 + 检索（RAG MVP）。

绝对简洁：无向量库（MVP 线性扫描 + 关键词评分），<1000 文档足够快。
绝对理性：检索结果带来源（文件路径），AI 回答必须引用——防幻觉。
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from redhawk.db import DB

# 支持的文档格式
TEXT_EXTS = {".md", ".txt", ".rst"}
CHUNK_SIZE = 800        # 每块约 800 字符
CHUNK_OVERLAP = 80      # 块间重叠，防切断关键句

# 中文停用词（简单过滤，绝对简洁）
STOPWORDS = {
    "的", "了", "是", "在", "和", "与", "及", "或", "一个", "我们", "可以",
    "需要", "进行", "通过", "使用", "这个", "那个", "以及", "如何", "什么",
    "the", "and", "for", "with", "from", "that", "this", "are", "was",
}


def split_chunks(text: str, size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    """按段落优先切块：先按行聚成 ≥size 的块，避免切断句子。"""
    paragraphs = re.split(r"\n\s*\n", text)
    chunks: list[str] = []
    buf = ""
    for p in paragraphs:
        p = p.strip()
        if not p:
            continue
        if len(buf) + len(p) <= size:
            buf = (buf + "\n\n" + p).strip()
        else:
            if buf:
                chunks.append(buf)
            buf = p
    if buf:
        chunks.append(buf)
    # 若单块仍超长，硬切
    final: list[str] = []
    for c in chunks:
        if len(c) <= size:
            final.append(c)
        else:
            for i in range(0, len(c), size - overlap):
                final.append(c[i:i + size])
    return final


def _tokenize(text: str) -> list[str]:
    """分词：英文按单词 + 中文按双字 bigram（降低单字噪音）。"""
    words = re.findall(r"[a-zA-Z0-9_]{2,}", text.lower())
    han = re.findall(r"[\u4e00-\u9fff]", text)
    for i in range(len(han) - 1):
        words.append(han[i] + han[i + 1])
    if len(han) == 1:
        words.append(han[0])
    return words


def import_docs(db: DB, source_dir: str, pattern: str = "*") -> dict[str, Any]:
    """导入目录下的 .md/.txt 文档到 knowledge_docs（含切块）。"""
    d = Path(source_dir)
    if not d.exists() or not d.is_dir():
        return {"status": "failed", "error": f"目录不存在: {source_dir}"}
    files = [f for f in d.rglob(pattern) if f.suffix.lower() in TEXT_EXTS]
    total_chunks = 0
    imported = 0
    skipped = 0
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            skipped += 1
            continue
        if len(text.strip()) < 20:
            skipped += 1
            continue
        h = hashlib.sha256(text.encode()).hexdigest()[:32]
        # 去重：content_hash 已存在则跳过
        exist = db.query_one("SELECT id FROM knowledge_docs WHERE content_hash=?", (h,))
        if exist:
            skipped += 1
            continue
        chunks = split_chunks(text)
        with db.tx():
            doc_id = db.conn.execute(
                "INSERT INTO knowledge_docs (title, source, content_hash, chunk_count, status) VALUES (?,?,?,?,?)",
                (f.name, str(f), h, len(chunks), "indexed"),
            ).lastrowid
            for ci, chunk in enumerate(chunks):
                db.conn.execute(
                    "INSERT INTO kb_chunks (doc_id, chunk_index, content) VALUES (?,?,?)",
                    (doc_id, ci, chunk),
                )
        total_chunks += len(chunks)
        imported += 1
    db.audit("user", "kb_import", source_dir, {"files": imported, "chunks": total_chunks})
    return {"status": "ok", "imported": imported, "skipped": skipped, "chunks": total_chunks}


def search(db: DB, query: str, top_k: int = 5) -> list[dict[str, Any]]:
    """线性扫描检索：关键词重合度评分，返回 top_k 块（带来源）。"""
    q_tokens = set(_tokenize(query))
    if not q_tokens:
        return []
    # 全量块（MVP：内存扫描；文档多时可加 SQL LIKE 预筛）
    chunks = db.query(
        """SELECT c.id, c.doc_id, c.chunk_index, c.content, d.title, d.source
           FROM kb_chunks c JOIN knowledge_docs d ON c.doc_id = d.id
           WHERE d.status='indexed' ORDER BY c.id"""
    )
    scored = []
    for c in chunks:
        tokens = set(_tokenize(c["content"]))
        overlap = len(q_tokens & tokens)
        if overlap == 0:
            continue
        # 命中数 + 命中比例加权
        score = overlap + overlap / max(len(q_tokens), 1)
        # 目录页降权：README 或高链接密度（纯索引页命中价值低）
        title_lower = (c["title"] or "").lower()
        if title_lower == "readme.md" or title_lower == "readme":
            score *= 0.5
        link_density = c["content"].count("http") / max(len(c["content"]), 1)
        if link_density > 0.05:
            score *= 0.6
        scored.append((score, c))
    scored.sort(key=lambda x: -x[0])
    return [c for _, c in scored[:top_k]]


def ask(db: DB, question: str, top_k: int = 5, csdn_fallback: bool = True) -> dict[str, Any]:
    """RAG 问答入口：本地知识库优先 + CSDN 补充。

    - 本地命中 → 返回本地结果，同时附加 CSDN 结果（双源）
    - 本地无命中 → CSDN 作为唯一来源
    """
    hits = search(db, question, top_k)
    result: dict[str, Any] = {
        "question": question,
        "hits": hits,
        "hit_count": len(hits),
        "source": "local" if hits else "none",
    }
    if csdn_fallback:
        try:
            from redhawk.csdn import search as csdn_search
            csdn_hits = csdn_search(question, top_k)
            if csdn_hits and "error" not in csdn_hits[0]:
                result["csdn"] = csdn_hits
                if not hits:
                    result["source"] = "csdn"
                    result["hit_count"] = len(csdn_hits)
        except Exception:
            pass
    return result
