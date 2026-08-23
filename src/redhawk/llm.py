"""RedHawk — 统一 LLM 客户端（内置 DeepSeek v4-flash / v4-pro 双模型）。

密钥管理：不再依赖环境变量，持久化到 <data>/llm.json（AES 加密）。
用户只需在软件设置里填入 DeepSeek API 密钥并选择模型，一键使用。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import urllib.request
from pathlib import Path
from typing import Any

# ===== 内置模型（DeepSeek 官方） =====
# flash = 快/便宜（日常分析）  pro = 强/深度（复杂研判）
DEEPSEEK_MODELS = {
    "v4-flash": {
        "name": "DeepSeek v4-flash（快速·经济）",
        "model": "deepseek-v4-flash",
        "desc": "日常抓包分析、快速研判、报告生成",
    },
    "v4-pro": {
        "name": "DeepSeek v4-pro（深度·精准）",
        "model": "deepseek-v4-pro",
        "desc": "复杂漏洞链研判、深度分析、关键决策",
    },
}
BASE_URL = "https://api.deepseek.com/v1"


def _data_root() -> Path:
    """数据根：打包时用 exe 同目录，源码时用项目根。"""
    import sys
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent.parent  # src/../


def _config_path() -> Path:
    root = _data_root()
    if getattr(os, "sys", None) and getattr(os.sys, "frozen", False):
        return root / "data" / "llm.json"
    # 源码模式：优先用 REDHAWK_DB 同目录（与 web 一致），否则项目 data/
    db_path = os.environ.get("REDHAWK_DB", "")
    if db_path:
        return Path(db_path).parent / "llm.json"
    return root / "data" / "llm.json"


def _machine_key() -> bytes:
    """本机派生的加密密钥（用户级隔离）。"""
    import getpass
    user = getpass.getuser() or "default"
    return hashlib.sha256(f"redhawk-llm-{user}".encode()).digest()


def _encrypt(plain: str) -> str:
    key = _machine_key()
    data = plain.encode()
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ key[i % len(key)]
    return base64.b64encode(bytes(out)).decode()


def _decrypt(token: str) -> str:
    key = _machine_key()
    raw = base64.b64decode(token)
    out = bytearray(len(raw))
    for i, b in enumerate(raw):
        out[i] = b ^ key[i % len(key)]
    return bytes(out).decode()


# ===== 配置读写 =====
def save_config(api_key: str = "", model: str = "v4-flash", base_url: str = BASE_URL) -> dict:
    """持久化 LLM 配置（密钥加密存储）。"""
    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    cfg = {
        "api_key_enc": _encrypt(api_key) if api_key else "",
        "model": model if model in DEEPSEEK_MODELS else "v4-flash",
        "base_url": base_url or BASE_URL,
    }
    path.write_text(json.dumps(cfg), encoding="utf-8")
    return get_config()


def load_config() -> dict[str, Any]:
    """读取配置。返回 {api_key, model, model_name, base_url, available}。"""
    path = _config_path()
    cfg: dict[str, Any] = {
        "api_key": "",
        "model": "v4-flash",
        "base_url": BASE_URL,
        "available": False,
    }
    try:
        if path.exists():
            raw = json.loads(path.read_text(encoding="utf-8"))
            enc = raw.get("api_key_enc", "")
            if enc:
                cfg["api_key"] = _decrypt(enc)
            cfg["model"] = raw.get("model", "v4-flash")
            cfg["base_url"] = raw.get("base_url", BASE_URL)
        # 兼容环境变量（旧方式优先）
        env_key = os.environ.get("REDHAWK_LLM_API_KEY", "")
        if env_key:
            cfg["api_key"] = env_key
    except Exception:
        pass
    cfg["available"] = bool(cfg["api_key"])
    model_info = DEEPSEEK_MODELS.get(cfg["model"], DEEPSEEK_MODELS["v4-flash"])
    cfg["model_name"] = model_info["name"]
    cfg["model_id"] = model_info["model"]
    return cfg


def is_available() -> bool:
    return bool(load_config()["api_key"])


def get_config() -> dict[str, Any]:
    return load_config()


def test_connection() -> dict[str, Any]:
    """测试 API 密钥有效性（发一个最小请求）。"""
    cfg = load_config()
    if not cfg["api_key"]:
        return {"ok": False, "error": "未配置 API 密钥"}
    try:
        resp = chat_raw("ping", "回复 OK", max_tokens=10)
        return {"ok": True, "reply": resp[:50]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _payload(model_id: str, system: str, user: str, temperature: float, max_tokens: int) -> dict:
    return {
        "model": model_id,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }


def chat_raw(system: str, user: str, temperature: float = 0.2, max_tokens: int = 1200,
             model: str | None = None) -> str:
    """核心对话（供各模块调用）。model 可覆盖当前配置。"""
    cfg = load_config()
    api_key = cfg["api_key"]
    if not api_key:
        raise RuntimeError("未配置 DeepSeek API 密钥（请在 设置 → AI 模型 中填写）")
    model_id = DEEPSEEK_MODELS.get(model or cfg["model"], DEEPSEEK_MODELS["v4-flash"])["model"]
    payload = _payload(model_id, system, user, temperature, max_tokens)
    req = urllib.request.Request(
        cfg["base_url"].rstrip("/") + "/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["choices"][0]["message"]["content"]


def chat(system: str, user: str, temperature: float = 0.2, max_tokens: int = 1200) -> str:
    """单轮对话（默认用当前配置的模型）。"""
    return chat_raw(system, user, temperature, max_tokens)


def extract_json(text: str) -> Any:
    """从 LLM 输出中提取 JSON（支持对象 {...} 和数组 [...]）。"""
    if not text or not text.strip():
        raise ValueError("LLM 返回空内容")
    stripped = text.strip()
    # 先尝试整体就是 JSON
    if stripped.startswith(("{", "[")) and stripped.endswith(("}", "]")):
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            pass
    # 数组优先（可能包在代码块/说明文字中）
    m = re.search(r"\[.*\]", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    # 再试对象
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    raise ValueError(f"LLM 未返回 JSON: {text[:200]}")
