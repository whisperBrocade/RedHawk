"""RedHawk v2 — 流量记录器（W1：摘要入库，v1 schema 兼容）。

对应 06 号文档 §八。W1 阶段与 v1 intercept.save_traffic 完全兼容
（traffic 表 v1 schema，body 截断 MAX_BODY）；W3 起 traffic_blobs
流式存储在此接入（摘要进表、全文进 blob）。

对外接口（与 v1 一致，web.py / tests 零改动）：
    save_traffic / list_traffic / get_traffic
"""

from __future__ import annotations

import json
import logging

from redhawk.db import DB
from redhawk.traffic_engine.stream_store import BlobWriter, blob_dir

log = logging.getLogger("redhawk.traffic_engine.recorder")

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


def collect_body(body: str, blob: BlobWriter | None, data: bytes,
                 max_body: int = MAX_BODY) -> tuple[str, BlobWriter | None]:
    """流式 body 收集：返回 (摘要, blob 或 None)。

    前 max_body 字符进摘要（traffic 表快查）；超限部分（含恰好填满边界）
    全文进 content-addressed blob——任何大小都不丢。
    """
    if blob is not None:
        blob.write(data)
        return body, blob
    chunk = data.decode("utf-8", errors="replace")
    if len(body) + len(chunk) <= max_body:
        return body + chunk, None
    room = max_body - len(body)
    body = body + chunk[:room]
    b = BlobWriter()
    b.write(body.encode("utf-8", errors="replace"))
    rest = data[len(chunk[:room].encode("utf-8", errors="replace")):]
    if rest:
        b.write(rest)
    return body, b


def register_blob(db: DB, sha256: str, size: int) -> int:
    """登记 blob 到 traffic_blobs 表（sha256 唯一，幂等）。返回 blob id。"""
    with db.tx():
        db.conn.execute(
            "INSERT OR IGNORE INTO traffic_blobs (sha256, path, size) VALUES (?,?,?)",
            (sha256, str(blob_dir() / sha256), size),
        )
    row = db.query_one("SELECT id FROM traffic_blobs WHERE sha256=?", (sha256,))
    return row["id"] if row else 0


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
    req_blob_sha: str | None = None,
    resp_blob_sha: str | None = None,
    req_blob_size: int = 0,
    resp_blob_size: int = 0,
    proto: str = "http1",
    http_version: str | None = None,
    error: str | None = None,
) -> int:
    """记录一条请求/响应到 traffic 表，返回 id。

    签名向后兼容 v1；大 body 场景传 blob sha/size（全文进 blob，表内存摘要）。
    error 非空表示此条记录不完整（上游超时/流重置/连接关闭等），写入原因供排查。
    """
    data = {
        "method": method,
        "url": url[:2000],
        "req_headers": json.dumps(req_headers, ensure_ascii=False)[:8000],
        "req_body": req_body[:MAX_BODY],
        "status": status,
        "resp_headers": json.dumps(resp_headers, ensure_ascii=False)[:8000],
        "resp_body": resp_body[:MAX_BODY],
        "source": source,
        "proto": proto,
        "http_version": http_version,
        "req_blob_size": req_blob_size,
        "resp_blob_size": resp_blob_size,
        "error": error,
    }
    if req_blob_sha:
        data["req_blob_id"] = register_blob(db, req_blob_sha, req_blob_size)
    if resp_blob_sha:
        data["resp_blob_id"] = register_blob(db, resp_blob_sha, resp_blob_size)
    return db.insert("traffic", data)


def save_traffic_retry(db: DB, method: str, url: str, req_headers: dict,
                       req_body: str, status: int, resp_headers: dict,
                       resp_body: str, source: str = "proxy",
                       req_blob_sha: str | None = None,
                       resp_blob_sha: str | None = None,
                       req_blob_size: int = 0,
                       resp_blob_size: int = 0,
                       proto: str = "http1",
                       http_version: str | None = None,
                       error: str | None = None) -> int | None:
    """save_traffic + 一次重试 + 失败记审计：记录丢失不再静默。

    DB 锁竞争 / IO 错误等偶发失败重试一次；仍失败则写 audit_logs
    （actor='traffic_engine'，action='save_traffic_failed'，target=出错 URL），
    不阻断转发。返回 traffic id 或 None。
    """
    last_exc: Exception | None = None
    for attempt in (1, 2):
        try:
            return save_traffic(
                db, method, url, req_headers, req_body, status, resp_headers,
                resp_body, source, req_blob_sha=req_blob_sha,
                resp_blob_sha=resp_blob_sha, req_blob_size=req_blob_size,
                resp_blob_size=resp_blob_size, proto=proto,
                http_version=http_version, error=error,
            )
        except Exception as e:
            last_exc = e
    try:
        db.audit("traffic_engine", "save_traffic_failed", url[:2000],
                 {"error": repr(last_exc), "method": method, "status": status})
    except Exception:
        log.warning("save_traffic failed and audit log also failed: %r",
                    last_exc, exc_info=True)
    return None


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
                 client: str | None = None, q: str | None = None) -> list[dict]:
    """查询流量。source 逗号分隔多来源；client browser/other（按 UA）；q 按 URL 关键词搜索。"""
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
    if q and q.strip():
        kw = q.strip()
        conds.append("(url LIKE ? OR method LIKE ?)")
        params.extend([f"%{kw}%", f"%{kw}%"])
    sql = "SELECT id, method, url, status, source, created_at FROM traffic"
    if conds:
        sql += " WHERE " + " AND ".join(conds)
    if q and q.strip():
        # 搜索排序：时间为主（新在前）；同时间（同秒）内关键词在 URL 位置越靠前
        # （域名段优先，如 www.baidu.com 排在 .../baidu/... 前）越优先
        sql += " ORDER BY created_at DESC, instr(lower(url), lower(?)) ASC, id DESC LIMIT ?"
        params.append(q.strip())
    else:
        sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    return db.query(sql, tuple(params))


def get_traffic(db: DB, traffic_id: int) -> dict | None:
    return db.query_one("SELECT * FROM traffic WHERE id=?", (traffic_id,))
