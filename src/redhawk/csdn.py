"""RedHawk — CSDN 知识库检索（知识助手兜底源）。

本地 Pentest_Note 未命中时，调取 CSDN 搜索获取网络安全文章。
- 接口: so.csdn.net/api/v3/search（无需登录）
- 结果: 标题/摘要/作者/链接/时间，清洗 <em> 高亮标签
- 安全: 仅返回公开搜索结果的元数据，不抓正文
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from typing import Any

SEARCH_API = "https://so.csdn.net/api/v3/search"
MAX_RESULTS = 8
TIMEOUT = 15


def _clean(text: str) -> str:
    """去除 <em></em> 高亮标签与多余空白。"""
    if not text:
        return ""
    text = re.sub(r"</?em>", "", text)
    return re.sub(r"\s+", " ", text).strip()


def search(query: str, top_k: int = MAX_RESULTS, proxy: str | None = None) -> list[dict[str, Any]]:
    """CSDN 搜索。返回 [{title, url, description, author, type, time}]。"""
    params = urllib.parse.urlencode({"q": query, "t": "all", "p": 1})
    url = f"{SEARCH_API}?{params}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) RedHawk/1.0",
        "Referer": "https://so.csdn.net/",
    }
    opener = urllib.request.build_opener()
    if proxy:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        )
    opener.addheaders = list(headers.items())

    try:
        with opener.open(url, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as e:
        return [{"error": f"CSDN 检索失败: {e}"}]

    vos = data.get("result_vos") or []
    results: list[dict[str, Any]] = []
    for item in vos:
        if not isinstance(item, dict):
            continue
        title = _clean(item.get("title", ""))
        url = item.get("url", "")
        if not title or not url:
            continue
        # 过滤明显无关类型（问答/广告等），保留文章/下载/博客
        results.append({
            "title": title[:120],
            "url": url[:300],
            "description": _clean(item.get("description", ""))[:200],
            "author": item.get("nickname") or item.get("author") or "",
            "type": item.get("type", ""),
            "time": item.get("create_time_str", ""),
        })
        if len(results) >= top_k:
            break
    return results


def search_text(query: str, top_k: int = MAX_RESULTS) -> str:
    """搜索并格式化为可读文本（供 LLM 上下文 / 终端展示）。"""
    results = search(query, top_k)
    if not results or "error" in results[0]:
        return results[0].get("error", "无结果") if results else "无结果"
    lines = [f"CSDN 检索到 {len(results)} 条（关键词: {query}）:", ""]
    for i, r in enumerate(results, 1):
        lines.append(f"{i}. {r['title']}")
        lines.append(f"   作者: {r['author']} | 类型: {r['type']} | {r['time']}")
        lines.append(f"   {r['description']}")
        lines.append(f"   {r['url']}")
        lines.append("")
    return "\n".join(lines)
