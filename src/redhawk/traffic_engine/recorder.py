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

# 浏览器 UA 特征（区分"用户主动浏览"与"后台程序自动流量"）
BROWSER_UA_PATTERNS = [
    "%user-agent%chrome%",
    "%user-agent%edg%",
    "%user-agent%firefox%",
    "%user-agent%safari%",
    "%user-agent%opera%",
    "%user-agent%opr%",
    "%user-agent%trident%",
    "%user-agent%msie%",
]


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


def _client_conditions(client: str | None, params: list) -> str:
    """按客户端类型拼过滤条件：
    - browser：浏览器 UA（用户主动访问，流量记录）
    - other：非浏览器 UA（后台程序/系统服务自动流量，流量劫取）
    返回 SQL 片段（含占位符），并扩充 params。
    """
    if client not in ("browser", "other"):
        return ""
    ua_cond = "(" + " OR ".join("req_headers LIKE ?" for _ in BROWSER_UA_PATTERNS) + ")"
    if client == "browser":
        params.extend(BROWSER_UA_PATTERNS)
        return ua_cond
    params.extend(BROWSER_UA_PATTERNS)
    return "NOT " + ua_cond


def list_traffic(db: DB, limit: int = 50, source: str | None = None,
                 client: str | None = None) -> list[dict]:
    """查询流量。source 支持逗号分隔多来源；client 支持 browser/other（按 UA 区分）。"""
    conds: list = []
    params: list = []
    if source:
        srcs = [s.strip() for s in source.split(",") if s.strip()]
        if len(srcs) == 1:
            conds.append("source=?")
            params.append(srcs[0])
        elif srcs:
            conds.append("source IN (" + ",".join("?" * len(srcs)) + ")")
            params.extend(srcs)
    c = _client_conditions(client, params)
    if c:
        conds.append(c)
    sql = "SELECT id, method, url, status, source, created_at FROM traffic"
    if conds:
        sql += " WHERE " + " AND ".join(conds)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    return db.query(sql, tuple(params))


def get_traffic(db: DB, traffic_id: int) -> dict | None:
    return db.query_one("SELECT * FROM traffic WHERE id=?", (traffic_id,))
