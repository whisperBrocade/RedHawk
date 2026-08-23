"""RedHawk — Gatekeeper 授权拦截边界用例（Phase 0 验收）。

场景：登记 scope="*.example.com, 10.0.0.0/24, 192.168.1.100, https://api.test.dev"
验证 10+ 个边界：通配符、CIDR、精确 IP、精确域名、URL、端口、大小写、子域、越权拦截+留痕。
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from redhawk.db import DB
from redhawk.gatekeeper import Gatekeeper

SCOPE = "*.example.com, 10.0.0.0/24, 192.168.1.100, https://api.test.dev, localhost"


@pytest.fixture()
def gk():
    tmp = tempfile.mkdtemp()
    db = DB(os.path.join(tmp, "test.db"))
    db.init()
    g = Gatekeeper(db)
    g.register_target("lab", SCOPE)
    yield g
    db.close()


# ---------- 应放行 ----------
@pytest.mark.parametrize("host", [
    "example.com",          # *.example.com 也匹配根域
    "www.example.com",      # 子域
    "a.b.example.com",      # 多级子域
    "10.0.0.1",             # CIDR 内
    "10.0.0.255",           # CIDR 边界（广播位也匹配 /24）
    "192.168.1.100",        # 精确 IP
    "api.test.dev",         # URL 提取 host
    "https://api.test.dev:8443",  # URL + 端口
    "LOCALHOST",            # 大小写不敏感
    "localhost",            # 精确
])
def test_allow(gk, host):
    ok, reason = gk.check(1, host)
    assert ok, f"应放行 {host}: {reason}"


# ---------- 应拦截 ----------
@pytest.mark.parametrize("host", [
    "evil.com",             # 完全无关
    "example.org",          # 相近但不同 TLD
    "notexample.com",       # 前缀相似但非子域
    "10.1.0.1",             # CIDR 外
    "192.168.1.101",        # 精确 IP 外
    "192.168.1.100.evil.com",  # 伪装
    "10.0.0.5:6379",        # 端口（应剥掉再判断，仍放行）——见下方单独用例
    "http://evil.com/x",    # 无关 URL
])
def test_block(gk, host):
    if host == "10.0.0.5:6379":
        pytest.skip("端口剥离逻辑单独验证")
    ok, reason = gk.check(1, host)
    assert not ok, f"应拦截 {host}: {reason}"


def test_port_stripped_then_allow(gk):
    ok, _ = gk.check(1, "10.0.0.5:6379")
    assert ok, "带端口 IP 应剥离端口后放行"


def test_enforce_blocks_and_audits(gk):
    err = gk.enforce(1, "evil.com", "task_run")
    assert err is not None and err.startswith("[BLOCKED]")
    logs = gk.db.query("SELECT * FROM audit_logs WHERE action='blocked'")
    assert len(logs) == 1
    assert logs[0]["target"] == "evil.com"


def test_enforce_allows_without_audit(gk):
    err = gk.enforce(1, "www.example.com", "task_run")
    assert err is None
    logs = gk.db.query("SELECT * FROM audit_logs WHERE action='blocked'")
    assert len(logs) == 0


def test_unknown_target_blocked(gk):
    ok, reason = gk.check(999, "example.com")
    assert not ok and "不存在" in reason


def test_archived_target_blocked(gk):
    gk.db.conn.execute("UPDATE targets SET status='archived' WHERE id=1")
    gk.db.conn.commit()
    ok, reason = gk.check(1, "example.com")
    assert not ok and "已归档" in reason


def test_no_auth_target_blocked(gk):
    tid = gk.register_target("empty", "10.9.9.9")
    gk.db.conn.execute("DELETE FROM authorizations WHERE target_id=?", (tid,))
    gk.db.conn.commit()
    ok, reason = gk.check(tid, "10.9.9.9")
    assert not ok and "未登记任何授权范围" in reason
