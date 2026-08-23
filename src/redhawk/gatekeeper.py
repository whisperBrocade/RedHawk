"""RedHawk — Gatekeeper 授权闸门（合规第一优先级）。

绝对理性：目标不在授权范围 → 硬拦截，无灰色地带。
支持匹配：域名通配符（*.example.com）、CIDR（10.0.0.0/24）、精确 IP/域名/URL。
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from urllib.parse import urlparse

from redhawk.db import DB


class Gatekeeper:
    def __init__(self, db: DB):
        self.db = db

    # ================= 授权登记 =================
    def register_target(self, name: str, scope: str, owner: str = "") -> int:
        """登记目标：scope 为逗号分隔的表达式列表，如 '*.example.com, 10.0.0.0/24'。"""
        scopes = [s.strip() for s in scope.split(",") if s.strip()]
        with self.db.tx():
            cur = self.db.conn.execute(
                "INSERT INTO targets (name, scope, owner) VALUES (?,?,?)",
                (name, scope, owner),
            )
            tid = cur.lastrowid
            for expr in scopes:
                self.db.conn.execute(
                    "INSERT INTO authorizations (target_id, scope_expr, method, source, note) VALUES (?,?,?,?,?)",
                    (tid, expr, "allowed", "manual", "目标登记"),
                )
        self.db.audit("user", "target_register", name, {"scope": scope, "target_id": tid})
        return tid

    def list_targets(self) -> list[dict]:
        return self.db.query("SELECT * FROM targets ORDER BY id DESC")

    def get_target(self, target_id: int) -> dict | None:
        return self.db.query_one("SELECT * FROM targets WHERE id=?", (target_id,))

    def get_authorizations(self, target_id: int) -> list[dict]:
        return self.db.query(
            "SELECT * FROM authorizations WHERE target_id=? AND method='allowed'", (target_id,)
        )

    # ================= 匹配引擎 =================
    @staticmethod
    def _normalize(host: str) -> str:
        """提取 host（去协议/路径/端口）。"""
        host = host.strip()
        if "://" in host:
            host = urlparse(host).hostname or host
        else:
            host = host.split("/")[0]
        # 去端口
        try:
            host = host.rsplit(":", 1)[0] if ":" in host and host.count(":") == 1 else host
        except Exception:
            pass
        return host.strip().lower().rstrip(".")

    @staticmethod
    def _is_ip(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _match_expr(self, host: str, expr: str) -> bool:
        """单个授权表达式是否覆盖 host。"""
        expr = expr.strip().lower().rstrip(".")
        if not expr:
            return False
        # 1) CIDR
        if "/" in expr:
            try:
                net = ipaddress.ip_network(expr, strict=False)
                ip = ipaddress.ip_address(host)
                return ip in net
            except ValueError:
                pass
        # 2) 通配符（*.example.com → 也匹配 example.com 本身 + 任意子域）
        if "*" in expr:
            if fnmatch.fnmatch(host, expr):
                return True
            if expr.startswith("*."):
                return fnmatch.fnmatch(host, expr[2:])
            return False
        # 3) 精确 IP/域名（表达式同样归一化：去协议/端口）
        expr_norm = self._normalize(expr)
        return host == expr_norm

    def check(self, target_id: int, host: str) -> tuple[bool, str]:
        """检查 host 是否在 target 授权范围内。返回 (允许, 原因)。"""
        host = self._normalize(host)
        target = self.get_target(target_id)
        if not target:
            return False, f"目标 #{target_id} 不存在"
        if target["status"] != "active":
            return False, f"目标 #{target_id} 已归档（status={target['status']}）"
        auths = self.get_authorizations(target_id)
        if not auths:
            return False, "该目标未登记任何授权范围"
        for a in auths:
            if self._match_expr(host, a["scope_expr"]):
                return True, f"匹配授权: {a['scope_expr']}"
        return False, f"{host} 不在授权范围内"

    def enforce(self, target_id: int, host: str, action: str, detail: dict | None = None) -> str | None:
        """强制闸门：越权返回错误信息并留痕，否则返回 None（放行）。"""
        ok, reason = self.check(target_id, host)
        if ok:
            return None
        self.db.audit(
            "gatekeeper",
            "blocked",
            host,
            {"target_id": target_id, "action": action, "reason": reason, **(detail or {})},
        )
        return f"[BLOCKED] {reason} (action={action})"
