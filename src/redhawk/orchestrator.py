"""RedHawk — 编排器：任务流执行 + 进度查询 + 证据入库。

流程：
1. 校验目标 + 授权（Gatekeeper 硬闸门）
2. 加载 playbook，展开 stages
3. 逐步执行工具适配器，每步写 task_steps
4. 结果入库：assets / findings
5. 支持进度查询与失败重试
"""

from __future__ import annotations

import json
import time
from typing import Any

from redhawk.adapters.base import BaseAdapter, ToolResult
from redhawk.db import DB, now
from redhawk.gatekeeper import Gatekeeper
from redhawk.playbook import get_stages, list_playbooks, load_playbook

# 适配器注册表（绝对简洁：一个 dict 即可扩展）
ADAPTERS: dict[str, type[BaseAdapter]] = {}


def register_adapter(cls: type[BaseAdapter]) -> type[BaseAdapter]:
    ADAPTERS[cls.tool_key] = cls
    return cls


def get_adapter(tool_key: str, exec_path: str | None = None, default_opts: dict | None = None) -> BaseAdapter:
    if tool_key not in ADAPTERS:
        raise ValueError(f"未注册的适配器: {tool_key}（已注册: {list(ADAPTERS)}）")
    return ADAPTERS[tool_key](exec_path=exec_path, default_opts=default_opts)


class Orchestrator:
    def __init__(self, db: DB, gatekeeper: Gatekeeper):
        self.db = db
        self.gatekeeper = gatekeeper

    # ---------- 任务创建 ----------
    def create_task(self, target_id: int, template: str, options: dict | None = None) -> int:
        target = self.gatekeeper.get_target(target_id)
        if not target:
            raise ValueError(f"目标 #{target_id} 不存在")
        try:
            pb = load_playbook(template)
        except Exception as e:
            raise ValueError(str(e))
        tid = self.db.insert("tasks", {
            "target_id": target_id,
            "template": pb["name"],
            "status": "pending",
            "options": json.dumps(options or {}, ensure_ascii=False),
        })
        # 预写步骤
        for i, stage in enumerate(get_stages(pb)):
            self.db.insert("task_steps", {
                "task_id": tid,
                "phase": stage["phase"],
                "tool_key": stage["tool"],
                "status": "pending",
                "input": json.dumps({"target": stage.get("input", ""), "options": stage.get("options", {})}, ensure_ascii=False),
            })
        self.db.audit("user", "task_create", target["name"], {"task_id": tid, "template": pb["name"]})
        return tid

    # ---------- 执行 ----------
    def run_task(self, task_id: int, exec_paths: dict[str, str] | None = None) -> dict[str, Any]:
        task = self.db.query_one("SELECT * FROM tasks WHERE id=?", (task_id,))
        if not task:
            raise ValueError(f"任务 #{task_id} 不存在")
        target = self.gatekeeper.get_target(task["target_id"])
        if not target:
            raise ValueError("目标不存在")

        self.db.conn.execute(
            "UPDATE tasks SET status='running', started_at=? WHERE id=?",
            (now(), task_id),
        )
        self.db.conn.commit()

        # 目标（从 scope 取第一个授权表达式作为扫描对象；可被 options 覆盖）
        opts = json.loads(task["options"] or "{}")
        scan_target = opts.get("target") or target["scope"].split(",")[0].strip()
        # 授权硬闸门：对目标本身校验（如果它是具体 host）
        blocked = self.gatekeeper.enforce(target["id"], scan_target, "task_run")
        if blocked:
            self.db.conn.execute(
                "UPDATE tasks SET status='blocked', finished_at=? WHERE id=?", (now(), task_id)
            )
            self.db.conn.commit()
            return {"task_id": task_id, "status": "blocked", "error": blocked}

        steps = self.db.query(
            "SELECT * FROM task_steps WHERE task_id=? ORDER BY id", (task_id,)
        )
        results: list[dict] = []
        for step in steps:
            step_result = self._run_step(step, scan_target, exec_paths or {})
            results.append(step_result)
            if step_result["status"] == "failed":
                self.db.conn.execute(
                    "UPDATE tasks SET status='failed', current_phase=?, finished_at=? WHERE id=?",
                    (step["phase"], now(), task_id),
                )
                self.db.conn.commit()
                return {"task_id": task_id, "status": "failed", "phase": step["phase"], "steps": results}

        self.db.conn.execute(
            "UPDATE tasks SET status='done', current_phase=?, finished_at=? WHERE id=?",
            (steps[-1]["phase"] if steps else None, now(), task_id),
        )
        self.db.conn.commit()
        return {"task_id": task_id, "status": "done", "steps": results}

    def _run_step(self, step: dict, scan_target: str, exec_paths: dict) -> dict:
        tool = step["tool_key"]
        self.db.conn.execute(
            "UPDATE task_steps SET status='running', started_at=? WHERE id=?",
            (now(), step["id"]),
        )
        self.db.conn.commit()

        try:
            adapter = get_adapter(tool, exec_path=exec_paths.get(tool))
            # 从 step.input 读取 playbook 定义的 options
            try:
                step_input = json.loads(step["input"] or "{}")
                opts = step_input.get("options", {}) if isinstance(step_input, dict) else {}
            except (json.JSONDecodeError, TypeError):
                opts = {}
            result: ToolResult = adapter.run(scan_target, opts)
        except Exception as e:
            self._finish_step(step, "failed", error=str(e))
            return {"step_id": step["id"], "tool": tool, "status": "failed", "error": str(e)}

        if not result.ok:
            self._finish_step(step, "failed", output=result.raw, error=result.error)
            return {"step_id": step["id"], "tool": tool, "status": "failed",
                    "error": result.error, "raw": result.raw[:500]}

        # 入库
        self._ingest(step, result)
        self._finish_step(step, "done", output=result.raw)
        return {"step_id": step["id"], "tool": tool, "status": "done",
                "items": len(result.items), "duration_s": round(result.duration_s, 2)}

    def _ingest(self, step: dict, result: ToolResult) -> None:
        task = self.db.query_one("SELECT * FROM tasks WHERE id=?", (step["task_id"],))
        target_id = task["target_id"] if task else None
        phase = step["phase"]
        for item in result.items:
            kind = item.get("kind", "asset")
            value = item.get("value", "")
            if kind == "finding" or (kind == "vuln_hint"):
                sev = (item.get("detail") or {}).get("severity", "info")
                self.db.insert("findings", {
                    "task_id": step["task_id"],
                    "target_id": target_id,
                    "asset_ref": value,
                    "tool_key": step["tool_key"],
                    "vuln_type": kind,
                    "severity": sev,
                    "title": (item.get("detail") or {}).get("name", value[:120]),
                    "detail": json.dumps(item, ensure_ascii=False),
                })
            else:
                self.db.insert("assets", {
                    "task_id": step["task_id"],
                    "target_id": target_id,
                    "kind": kind,
                    "value": value,
                    "detail": json.dumps(item.get("detail", {}), ensure_ascii=False),
                    "source_tool": step["tool_key"],
                })

    def _finish_step(self, step: dict, status: str, output: str = "", error: str | None = None) -> None:
        self.db.conn.execute(
            "UPDATE task_steps SET status=?, output=?, error=?, finished_at=? WHERE id=?",
            (status, output[:2000], error, now(), step["id"]),
        )
        self.db.conn.commit()

    # ---------- 进度查询 ----------
    def get_progress(self, task_id: int) -> dict[str, Any]:
        task = self.db.query_one("SELECT * FROM tasks WHERE id=?", (task_id,))
        if not task:
            return {"error": "任务不存在"}
        steps = self.db.query(
            "SELECT id, phase, tool_key, status, started_at, finished_at, error FROM task_steps WHERE task_id=? ORDER BY id",
            (task_id,),
        )
        done = sum(1 for s in steps if s["status"] in ("done", "failed"))
        return {
            "task_id": task_id,
            "status": task["status"],
            "current_phase": task["current_phase"],
            "steps_total": len(steps),
            "steps_done": done,
            "steps": steps,
        }

    def get_findings(self, task_id: int, severity: str | None = None) -> list[dict]:
        sql = "SELECT * FROM findings WHERE task_id=?"
        params: list = [task_id]
        if severity:
            sql += " AND severity=?"
            params.append(severity)
        sql += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
        return self.db.query(sql, tuple(params))


def available_templates() -> list[str]:
    return list_playbooks()
