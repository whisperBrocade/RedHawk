"""RedHawk — 插件仓库：安装/更新/列出安全工具。

绝对简洁：插件 = manifest.json 一条记录。
安全：下载后 sha256 校验（防投毒）+ 信任区提示。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

MANIFEST_PATH = Path(__file__).parent / "manifest.json"
DEFAULT_TOOLS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "tools"


def load_manifest() -> list[dict[str, Any]]:
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        return json.load(f)["tools"]


def find_tool(key: str) -> dict[str, Any]:
    for t in load_manifest():
        if t["key"] == key:
            return t
    raise KeyError(f"插件不存在: {key}（可用: {[t['key'] for t in load_manifest()]}）")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(url: str, dest: str, proxy: str | None = None) -> None:
    """下载文件（可选代理）。"""
    opener = urllib.request.build_opener()
    if proxy:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        )
    opener.addheaders = [("User-Agent", "Mozilla/5.0 RedHawk")]
    with opener.open(url, timeout=180) as resp, open(dest, "wb") as f:
        shutil.copyfileobj(resp, f)


def install_tool(key: str, tools_dir: str | Path | None = None, proxy: str | None = None) -> dict:
    """安装工具到 <tools_dir>/<key>/。返回结果 dict。"""
    t = find_tool(key)
    td = Path(tools_dir) if tools_dir else DEFAULT_TOOLS_DIR
    dest_dir = td / key
    dest_dir.mkdir(parents=True, exist_ok=True)
    inst = t.get("install", {})

    # 手动安装型：只登记，不下载
    if inst.get("type") == "manual":
        return {"key": key, "status": "manual", "note": inst.get("note", "")}

    try:
        # 1) GitHub release 单文件
        if inst.get("type") == "github_release":
            url = inst["url"]
            out = dest_dir / inst.get("rename", key)
            _download(url, str(out), proxy)
            if t.get("sha256") and sha256_file(str(out)) != t["sha256"]:
                out.unlink(missing_ok=True)
                return {"key": key, "status": "failed", "error": "sha256 校验失败（可能被篡改/投毒）"}
            return _register(t, dest_dir, str(out))

        # 2) GitHub release zip
        if inst.get("type") == "github_release_zip":
            url = inst["url"]
            zpath = dest_dir / (inst["asset"] or "pkg.zip")
            _download(url, str(zpath), proxy)
            with zipfile.ZipFile(zpath) as z:
                z.extractall(dest_dir)
            zpath.unlink(missing_ok=True)
            binary = dest_dir / inst.get("binary_in_zip", key + ".exe")
            if not binary.exists():
                return {"key": key, "status": "failed", "error": f"zip 内未找到 {binary.name}"}
            return _register(t, dest_dir, str(binary))

        # 3) pip 安装
        if inst.get("type") == "pip":
            r = subprocess.run(
                ["pip", "install", inst["package"]], capture_output=True, text=True, timeout=300
            )
            if r.returncode != 0:
                return {"key": key, "status": "failed", "error": r.stderr[-300:]}
            return {"key": key, "status": "installed", "via": "pip"}

        return {"key": key, "status": "failed", "error": f"未知安装类型: {inst.get('type')}"}
    except Exception as e:
        return {"key": key, "status": "failed", "error": str(e)}


def _register(t: dict, dest_dir: Path, exec_path: str) -> dict:
    """登记到 tools 表（由调用方 DB 写入；此处返回元数据）。"""
    return {
        "key": t["key"],
        "status": "installed",
        "path": exec_path,
        "category": t["category"],
        "adapter": t["adapter"],
        "runtime": t["runtime"],
    }


def list_installed(tools_dir: str | Path | None = None) -> list[dict]:
    """列出本地已安装的工具（按目录探测二进制）。"""
    td = Path(tools_dir) if tools_dir else DEFAULT_TOOLS_DIR
    out = []
    for t in load_manifest():
        key = t["key"]
        d = td / key
        binaries = list(d.glob("*.exe")) if d.exists() else []
        out.append({
            "key": key,
            "name": t["name"],
            "category": t["category"],
            "installed": bool(binaries) or (t.get("install", {}).get("type") == "pip"),
            "path": str(binaries[0]) if binaries else "",
            "runtime": t["runtime"],
        })
    return out
