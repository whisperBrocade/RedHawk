"""RedHawk — DeepSeek 双模型配置 + 一键自动化测试。"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

# 隔离配置路径：指向临时目录
os.environ["REDHAWK_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")

from redhawk import llm


def test_models_defined():
    assert "v4-flash" in llm.DEEPSEEK_MODELS
    assert "v4-pro" in llm.DEEPSEEK_MODELS
    assert llm.DEEPSEEK_MODELS["v4-flash"]["model"] == "deepseek-v4-flash"
    assert llm.DEEPSEEK_MODELS["v4-pro"]["model"] == "deepseek-v4-pro"


def test_encrypt_roundtrip():
    token = llm._encrypt("sk-test-12345")
    assert token != "sk-test-12345"  # 已加密
    assert llm._decrypt(token) == "sk-test-12345"


def test_save_and_load_config():
    # 保存
    cfg = llm.save_config(api_key="sk-secret-abc", model="v4-pro")
    assert cfg["model"] == "v4-pro"
    assert cfg["available"] is True
    # 加载（跨"进程"模拟：重新读取文件）
    cfg2 = llm.load_config()
    assert cfg2["api_key"] == "sk-secret-abc"
    assert cfg2["model"] == "v4-pro"
    assert cfg2["model_id"] == "deepseek-v4-pro"
    assert cfg2["available"] is True


def test_invalid_model_falls_back():
    cfg = llm.save_config(api_key="sk-x", model="nonexistent")
    assert cfg["model"] == "v4-flash"  # 回退默认


def test_config_file_encrypted():
    """配置文件里不应出现明文密钥。"""
    cfg_path = llm._config_path()
    llm.save_config(api_key="sk-topsecret-xyz", model="v4-flash")
    raw = cfg_path.read_text(encoding="utf-8")
    assert "sk-topsecret-xyz" not in raw  # 密钥加密存储


def test_no_key_not_available():
    llm.save_config(api_key="", model="v4-flash")
    assert llm.is_available() is False


def test_extract_json_array():
    """LLM 返回 [] 数组（无漏洞）应被正确解析，而非报错。"""
    assert llm.extract_json("[]") == []
    assert llm.extract_json("[1, 2, 3]") == [1, 2, 3]
    assert llm.extract_json('```json\n[{"a": 1}]\n```') == [{"a": 1}]
    assert llm.extract_json('说明文字\n[{"traffic_id": 3, "severity": "high"}]\n结束') == [
        {"traffic_id": 3, "severity": "high"}]


def test_extract_json_object():
    assert llm.extract_json('{"is_real": true}') == {"is_real": True}
    assert llm.extract_json('前后 {"ok": 1} 后') == {"ok": 1}


def test_extract_json_invalid():
    import pytest
    with pytest.raises(ValueError):
        llm.extract_json("完全没有 JSON")
    with pytest.raises(ValueError):
        llm.extract_json("")


def test_auto_analyze_no_key_returns_error(tmp_path):
    from redhawk.db import DB
    from redhawk.auto_pentest import auto_analyze_traffic

    llm.save_config(api_key="", model="v4-flash")
    db = DB(tmp_path / "a.db")
    db.init()
    r = auto_analyze_traffic(db, limit=10)
    assert r["ok"] is False
    assert "密钥" in r["error"]
    db.close()
