"""RedHawk v2 — 流量记录器（W1：摘要入库，v1 schema 兼容）。

对应 06 号文档 §八。W1 阶段与 v1 intercept.save_traffic 完全兼容
（traffic 表 v1 schema，body 截断 MAX_BODY）；W3 起 traffic_blobs
流式存储在此接入（摘要进表、全文进 blob）。

对外接口（与 v1 一致，web.py / tests 零改动）：
    save_traffic / list_traffic / get_traffic
"""

from __future__ import annotations

import json

from redhawk.db import DB

# 单条报文记录上限（v1 语义）。W3 起超过部分转 content-addressed blob。
MAX_BODY = 2 * 1024 * 1024


def save_traffic(
    db: DB,
    method: str,
    url: str,
    req_headers: dict,
    req_body: str,
    status: int,
    resp_headers: dict,
    resp_body: str,
    source: str = "proxy",
) -> int:
    """记录一条请求/响应到 traffic 表，返回 id。签名与 v1 完全一致。"""
    return db.insert("traffic", {
        "method": method,
        "url": url[:2000],
        "req_headers": json.dumps(req_headers, ensure_ascii=False)[:8000],
        "req_body": req_body[:MAX_BODY],
        "status": status,
        "resp_headers": json.dumps(resp_headers, ensure_ascii=False)[:8000],
        "resp_body": resp_body[:MAX_BODY],
        "source": source,
    })


def list_traffic(db: DB, limit: int = 50, source: str | None = None) -> list[dict]:
    sql = "SELECT id, method, url, status, source, created_at FROM traffic"
    params: list = []
    if source:
        # 支持逗号分隔多来源：source=proxy,proxy_https
        srcs = [s.strip() for s in source.split(",") if s.strip()]
        if len(srcs) == 1:
            sql += " WHERE source=?"
            params.append(srcs[0])
        elif srcs:
            sql += " WHERE source IN (" + ",".join("?" * len(srcs)) + ")"
            params.extend(srcs)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    return db.query(sql, tuple(params))


def get_traffic(db: DB, traffic_id: int) -> dict | None:
    return db.query_one("SELECT * FROM traffic WHERE id=?", (traffic_id,))
