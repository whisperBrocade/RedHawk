"""RedHawk v2 — content-addressed blob 流式存储（W3）。

对应 06 号文档 §八。大 body（> REDHAWK_MAX_MEM_BUF）边收边写落盘，
sha256 命名 + 原子改名 + 同内容只存一份；traffic 表只存摘要与 blob 引用。

目录：<数据根>/blobs/<sha256>（数据根 = REDHAWK_DB 同目录）
"""

from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path


def blob_dir() -> Path:
    db_path = os.environ.get("REDHAWK_DB", "")
    if db_path:
        base = Path(db_path).parent
    else:
        base = Path(__file__).resolve().parent.parent.parent / "data"
    d = base / "blobs"
    d.mkdir(parents=True, exist_ok=True)
    return d


class BlobWriter:
    """流式写入器：临时文件 → sha256 → 原子改名（去重）。

    用法：write(...) 边收边写；finalize() 完成返回 sha256（同内容已存在则复用）；
    异常时 abort() 丢弃临时文件。
    """

    def __init__(self):
        self._tmp = blob_dir() / ("tmp_" + uuid.uuid4().hex)
        self._f = open(self._tmp, "wb")
        self._h = hashlib.sha256()
        self.size = 0

    def write(self, data: bytes) -> None:
        if not data:
            return
        self._f.write(data)
        self._h.update(data)
        self.size += len(data)

    def finalize(self) -> str:
        """完成写入。返回内容 sha256；临时文件改名（去重时丢弃）。"""
        try:
            self._f.close()
        except Exception:
            pass
        digest = self._h.hexdigest()
        final = blob_dir() / digest
        if final.exists():
            try:
                self._tmp.unlink()
            except OSError:
                pass
        else:
            os.replace(self._tmp, final)
        return digest

    def abort(self) -> None:
        try:
            self._f.close()
        except Exception:
            pass
        try:
            self._tmp.unlink()
        except OSError:
            pass
