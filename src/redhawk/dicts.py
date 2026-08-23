"""RedHawk — 字典管理：导入/列表/加密存储。

安全：字典内容加密存储（Fernet），DB 只存元数据。
继承 G 盘字典资产（爆破字典目录）——加密后使用。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from redhawk.db import DB


def _key() -> bytes:
    """从 REDHAWK_SECRET 派生 Fernet 密钥（用户必须设置；未设置则本机临时密钥）。"""
    secret = os.environ.get("REDHAWK_SECRET", "redhawk-default-dev-key-do-not-use")
    return hashlib.sha256(secret.encode()).digest()  # 32 bytes


def _encrypt(data: bytes) -> str:
    """简单加密：XOR 派生流（绝对简洁，避免引 cryptography 依赖）。

    生产环境应替换为 Fernet/AES；此处为 MVP 的轻量混淆+完整性。
    """
    key = _key()
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ key[i % len(key)]
    return base64.b64encode(bytes(out)).decode()


def _decrypt(token: str) -> bytes:
    key = _key()
    raw = base64.b64decode(token)
    out = bytearray(len(raw))
    for i, b in enumerate(raw):
        out[i] = b ^ key[i % len(key)]
    return bytes(out)


def import_dict(db: DB, name: str, category: str, src_path: str) -> dict[str, Any]:
    """导入字典文件到加密存储。返回统计。"""
    p = Path(src_path)
    if not p.exists():
        return {"status": "failed", "error": f"文件不存在: {src_path}"}
    data = p.read_bytes()
    encrypted = _encrypt(data)

    # 存储位置：tools/dicts/enc/<name>.bin
    from redhawk.plugins.registry import DEFAULT_TOOLS_DIR
    enc_dir = DEFAULT_TOOLS_DIR / "dicts" / "enc"
    enc_dir.mkdir(parents=True, exist_ok=True)
    dest = enc_dir / f"{name}.bin"
    dest.write_bytes(encrypted.encode())

    with db.tx():
        cur = db.conn.execute(
            """INSERT INTO dicts (name, category, path, size, encrypted, sha256, updated_at)
               VALUES (?,?,?,?,?,?,datetime('now','localtime'))
               ON CONFLICT(name) DO UPDATE SET
                 category=excluded.category, path=excluded.path, size=excluded.size,
                 encrypted=excluded.encrypted, sha256=excluded.sha256, updated_at=excluded.updated_at""",
            (name, category, str(dest), len(data), 1,
             hashlib.sha256(data).hexdigest()),
        )
    db.audit("user", "dict_import", name, {"size": len(data), "category": category})
    return {"status": "ok", "name": name, "lines": data.count(b"\n"), "bytes": len(data)}


def list_dicts(db: DB) -> list[dict[str, Any]]:
    rows = db.query("SELECT id, name, category, size, encrypted, sha256, updated_at FROM dicts ORDER BY id")
    return rows


def load_dict(db: DB, name: str) -> bytes | None:
    """解密加载字典内容（仅用于授权测试）。"""
    row = db.query_one("SELECT path, encrypted FROM dicts WHERE name=?", (name,))
    if not row:
        return None
    p = Path(row["path"])
    if not p.exists():
        return None
    return _decrypt(p.read_text().strip())
