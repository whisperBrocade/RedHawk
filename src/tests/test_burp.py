"""RedHawk — Burp 工作台 & 复现报告测试。"""

import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from redhawk.intercept import (
    ProxyServer,
    parse_raw_request,
    save_traffic,
)
from redhawk.repro import REPRO_TEMPLATES, _matched_traffic, _sev_key


# ---------- 原始请求解析 ----------
def test_parse_raw_request_basic():
    raw = "POST /api/login HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\r\n{\"user\":\"admin\"}"
    r = parse_raw_request(raw)
    assert r["method"] == "POST"
    assert r["url"] == "/api/login"
    assert r["headers"]["Host"] == "127.0.0.1"
    assert r["body"] == '{"user":"admin"}'


def test_parse_raw_request_get():
    raw = "GET /index.php?id=1 HTTP/1.1\nHost: t.com\n\n"
    r = parse_raw_request(raw)
    assert r["method"] == "GET"
    assert r["url"] == "/index.php?id=1"
    assert r["body"] == ""


def test_parse_raw_request_invalid():
    with pytest.raises(ValueError):
        parse_raw_request("not a request")


# ---------- 代理服务器 ----------
def test_proxy_server_lifecycle(tmp_path):
    from redhawk.db import DB
    db = DB(tmp_path / "t.db")
    db.init()
    srv = ProxyServer(db, port=8899)
    r = srv.start()
    assert r["status"] == "running"
    assert srv.running is True
    srv.stop()
    assert srv.running is False
    db.close()


# ---------- 流量记录 ----------
def test_save_and_query_traffic(tmp_path):
    from redhawk.db import DB
    db = DB(tmp_path / "t.db")
    db.init()
    tid = save_traffic(db, "POST", "http://t/api", {"X-T": "1"}, '{"a":1}',
                       200, {"Content-Type": "application/json"}, '{"ok":true}', "repeater")
    assert tid >= 1
    row = db.query_one("SELECT * FROM traffic WHERE id=?", (tid,))
    assert row["method"] == "POST"
    assert row["status"] == 200
    assert row["source"] == "repeater"
    db.close()


# ---------- 复现报告 ----------
def test_repro_template_keys():
    assert "weak_password" in REPRO_TEMPLATES
    assert "sql_injection" in REPRO_TEMPLATES
    assert "default" in REPRO_TEMPLATES


def test_sev_key_ordering():
    assert _sev_key({"severity": "critical"}) < _sev_key({"severity": "high"})
    assert _sev_key({"severity": "high"}) < _sev_key({"severity": "info"})
    assert _sev_key({}) == 4  # 默认按 info 处理（SEV_ORDER: info=4）


def test_matched_traffic_filters(tmp_path):
    from redhawk.db import DB
    db = DB(tmp_path / "t.db")
    db.init()
    save_traffic(db, "GET", "http://10.0.0.5:8080/nacos", {}, "", 200, {}, "<html>", "proxy")
    save_traffic(db, "GET", "http://other.com/", {}, "", 200, {}, "<html>", "proxy")
    hits = _matched_traffic(db, "http://10.0.0.5:8080/nacos")
    assert len(hits) == 1
    assert "10.0.0.5" in hits[0]["url"]
    db.close()
