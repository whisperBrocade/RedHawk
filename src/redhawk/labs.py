"""RedHawk — 靶场模式：一键拉起本地靶场（DVWA / pikachu）。

绝对简洁：docker compose 预设，新手无风险练习。
需要 Docker Desktop（可选功能，不影响核心）。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

COMPOSE_DIR = Path(__file__).resolve().parent.parent / "labs"

LABS = {
    "dvwa": {
        "name": "DVWA（Damn Vulnerable Web Application）",
        "compose": "dvwa.yaml",
        "url": "http://127.0.0.1:4280",
        "default_creds": "admin / password",
    },
    "pikachu": {
        "name": "Pikachu（皮卡丘靶场）",
        "compose": "pikachu.yaml",
        "url": "http://127.0.0.1:4281",
        "default_creds": "-",
    },
}


def list_labs() -> list[dict]:
    return [{"key": k, **v} for k, v in LABS.items()]


def up(lab: str) -> dict:
    if lab not in LABS:
        return {"status": "failed", "error": f"未知靶场: {lab}（可用: {list(LABS)}）"}
    info = LABS[lab]
    compose_file = COMPOSE_DIR / info["compose"]
    if not compose_file.exists():
        return {"status": "failed", "error": f"compose 文件缺失: {compose_file}"}
    try:
        r = subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "up", "-d"],
            capture_output=True, text=True, timeout=300,
        )
        if r.returncode != 0:
            return {"status": "failed", "error": r.stderr[-400:] or r.stdout[-400:]}
        return {"status": "up", "url": info["url"], "creds": info["default_creds"]}
    except FileNotFoundError:
        return {"status": "failed", "error": "Docker 未安装或不在 PATH（需 Docker Desktop）"}
    except Exception as e:
        return {"status": "failed", "error": str(e)}


def down(lab: str) -> dict:
    if lab not in LABS:
        return {"status": "failed", "error": f"未知靶场: {lab}"}
    compose_file = COMPOSE_DIR / LABS[lab]["compose"]
    try:
        r = subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "down"],
            capture_output=True, text=True, timeout=120,
        )
        return {"status": "down" if r.returncode == 0 else "failed",
                "error": None if r.returncode == 0 else r.stderr[-300:]}
    except Exception as e:
        return {"status": "failed", "error": str(e)}
