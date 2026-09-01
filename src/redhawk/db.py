"""RedHawk — 数据库层：SQLite 单文件 + 12 张表。

绝对简洁：标准库 sqlite3，无 ORM，无迁移框架。
表结构与 RedHawk-01 设计文档一致。
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  name          TEXT NOT NULL,
  scope         TEXT NOT NULL,
  owner         TEXT,
  status        TEXT DEFAULT 'active',
  created_at    TEXT DEFAULT (datetime('now','localtime')),
  updated_at    TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS authorizations (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id     INTEGER NOT NULL REFERENCES targets(id),
  scope_expr    TEXT NOT NULL,
  method        TEXT DEFAULT 'allowed',
  source        TEXT DEFAULT 'manual',
  note          TEXT,
  created_at    TEXT DEFAULT (datetime('now','localtime')),
  UNIQUE(target_id, scope_expr)
);

CREATE TABLE IF NOT EXISTS tasks (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id     INTEGER NOT NULL REFERENCES targets(id),
  template      TEXT NOT NULL,
  status        TEXT DEFAULT 'pending',
  current_phase TEXT,
  options       TEXT DEFAULT '{}',
  started_at    TEXT,
  finished_at   TEXT,
  created_at    TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS task_steps (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id       INTEGER NOT NULL REFERENCES tasks(id),
  phase         TEXT NOT NULL,
  tool_key      TEXT NOT NULL,
  status        TEXT DEFAULT 'pending',
  input         TEXT,
  output        TEXT,
  result_ref    TEXT,
  started_at    TEXT,
  finished_at   TEXT,
  error         TEXT
);

CREATE TABLE IF NOT EXISTS tools (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  key           TEXT UNIQUE NOT NULL,
  name          TEXT NOT NULL,
  category      TEXT NOT NULL,
  version       TEXT,
  runtime       TEXT NOT NULL,
  exec_path     TEXT,
  adapter       TEXT NOT NULL,
  default_opts  TEXT DEFAULT '{}',
  install_url   TEXT,
  sha256        TEXT,
  status        TEXT DEFAULT 'not_installed',
  installed_at  TEXT
);

CREATE TABLE IF NOT EXISTS assets (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id       INTEGER REFERENCES tasks(id),
  target_id     INTEGER REFERENCES targets(id),
  kind          TEXT NOT NULL,
  value         TEXT NOT NULL,
  detail        TEXT,
  source_tool   TEXT,
  first_seen    TEXT DEFAULT (datetime('now','localtime')),
  last_seen     TEXT DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_assets_target ON assets(target_id, kind);

CREATE TABLE IF NOT EXISTS findings (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id       INTEGER NOT NULL REFERENCES tasks(id),
  target_id     INTEGER REFERENCES targets(id),
  asset_ref     TEXT,
  tool_key      TEXT NOT NULL,
  vuln_type     TEXT NOT NULL,
  severity      TEXT DEFAULT 'info',
  title         TEXT,
  detail        TEXT,
  ai_verdict    TEXT,
  ai_status     TEXT DEFAULT 'pending',
  status        TEXT DEFAULT 'open',
  created_at    TEXT DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_findings_task ON findings(task_id);
CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity);

CREATE TABLE IF NOT EXISTS dicts (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  name          TEXT NOT NULL UNIQUE,
  category      TEXT NOT NULL,
  path          TEXT NOT NULL,
  size          INTEGER,
  encrypted     INTEGER DEFAULT 1,
  sha256        TEXT,
  updated_at    TEXT
);

CREATE TABLE IF NOT EXISTS knowledge_docs (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  title         TEXT NOT NULL,
  source        TEXT,
  content_hash  TEXT,
  chunk_count   INTEGER DEFAULT 0,
  status        TEXT DEFAULT 'pending',
  created_at    TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS kb_chunks (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  doc_id        INTEGER NOT NULL REFERENCES knowledge_docs(id),
  chunk_index   INTEGER DEFAULT 0,
  content       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_kb_chunks_doc ON kb_chunks(doc_id);

CREATE TABLE IF NOT EXISTS traffic (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  method        TEXT NOT NULL,
  url           TEXT NOT NULL,
  req_headers   TEXT,
  req_body      TEXT,
  status        INTEGER,
  resp_headers  TEXT,
  resp_body     TEXT,
  source        TEXT DEFAULT 'proxy',
  created_at    TEXT DEFAULT (datetime('now','localtime')),
  req_blob_id   INTEGER,                -- v2：大 body 的 blob 引用
  resp_blob_id  INTEGER,
  req_blob_size INTEGER DEFAULT 0,
  resp_blob_size INTEGER DEFAULT 0,
  proto         TEXT DEFAULT 'http1',   -- http1 | http2 | ws_handshake | sse
  http_version  TEXT,                   -- 'HTTP/1.1' | 'HTTP/2'
  error         TEXT                    -- 非空=此条记录不完整（超时/流重置/连接关闭等），含原因
);
CREATE INDEX IF NOT EXISTS idx_traffic_ts ON traffic(created_at);

CREATE TABLE IF NOT EXISTS traffic_blobs (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  sha256        TEXT UNIQUE NOT NULL,
  path          TEXT NOT NULL,
  size          INTEGER NOT NULL,
  created_at    TEXT DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_blobs_sha ON traffic_blobs(sha256);

CREATE TABLE IF NOT EXISTS reports (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id       INTEGER REFERENCES tasks(id),
  title         TEXT,
  format        TEXT DEFAULT 'md',
  content       TEXT,
  ai_generated  INTEGER DEFAULT 1,
  status        TEXT DEFAULT 'draft',
  created_at    TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS ai_logs (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id       INTEGER REFERENCES tasks(id),
  purpose       TEXT NOT NULL,
  model         TEXT,
  prompt_hash   TEXT,
  response      TEXT,
  tokens_in     INTEGER,
  tokens_out    INTEGER,
  blocked       INTEGER DEFAULT 0,
  created_at    TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            TEXT DEFAULT (datetime('now','localtime')),
  actor         TEXT,
  action        TEXT NOT NULL,
  target        TEXT,
  detail        TEXT,
  ip            TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts);
"""


class DB:
    """极简 SQLite 封装：单连接 + 行工厂 + 线程锁（Web 后台任务场景）。"""

    def __init__(self, path: str | Path = "redhawk.db"):
        import threading
        self.path = str(path)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        # 简单线程锁：Web 后台任务共享连接时保护（绝对简洁，不引连接池）
        self._lock = threading.Lock()

    def init(self) -> None:
        self.conn.executescript(SCHEMA)
        self._ensure_columns()
        self.conn.commit()

    def _ensure_columns(self) -> None:
        """老库平滑升级：traffic 表补 v2 增量列（新库建表已含）。"""
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(traffic)")}
        for name, ddl in (
            ("req_blob_id", "INTEGER"),
            ("resp_blob_id", "INTEGER"),
            ("req_blob_size", "INTEGER DEFAULT 0"),
            ("resp_blob_size", "INTEGER DEFAULT 0"),
            ("proto", "TEXT DEFAULT 'http1'"),
            ("http_version", "TEXT"),
            ("error", "TEXT"),
        ):
            if name not in cols:
                self.conn.execute(f"ALTER TABLE traffic ADD COLUMN {name} {ddl}")

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                yield self.conn
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise

    # ---- 通用小工具 ----
    def insert(self, table: str, data: dict[str, Any]) -> int:
        with self._lock:
            cols = ", ".join(data.keys())
            ph = ", ".join("?" * len(data))
            cur = self.conn.execute(
                f"INSERT INTO {table} ({cols}) VALUES ({ph})", list(data.values())
            )
            self.conn.commit()
            return cur.lastrowid

    def query(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]

    def query_one(self, sql: str, params: tuple = ()) -> dict[str, Any] | None:
        with self._lock:
            row = self.conn.execute(sql, params).fetchone()
            return dict(row) if row else None

    # ---- 审计埋点 ----
    def audit(self, actor: str, action: str, target: str = "", detail: dict | None = None, ip: str = "") -> None:
        with self.tx():
            self.conn.execute(
                "INSERT INTO audit_logs (actor, action, target, detail, ip) VALUES (?,?,?,?,?)",
                (actor, action, target, json.dumps(detail or {}, ensure_ascii=False), ip),
            )

    def close(self) -> None:
        self.conn.close()


def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
