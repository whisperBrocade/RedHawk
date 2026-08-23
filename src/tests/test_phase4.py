"""RedHawk — Phase 4 测试：新适配器 + 插件仓库 + 字典加密。"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from redhawk.adapters.ffuf import FfufAdapter
from redhawk.adapters.sqlmap import SqlmapAdapter
from redhawk.adapters.subfinder import SubfinderAdapter
from redhawk.adapters.xray import XrayAdapter
from redhawk.dicts import _decrypt, _encrypt
from redhawk.plugins.registry import find_tool, list_installed, load_manifest


# ---------- subfinder ----------
def test_subfinder_parses_domains():
    raw = "api.example.com\nwww.example.com\nnot-a-domain\n\nsub.example.com\n"
    items = SubfinderAdapter().parse(raw)
    vals = [i["value"] for i in items]
    assert "api.example.com" in vals
    assert "www.example.com" in vals
    assert "sub.example.com" in vals
    assert "not-a-domain" not in vals


def test_subfinder_parses_json_line():
    raw = '{"host": "a.example.com", "source": "crt.sh"}\n'
    items = SubfinderAdapter().parse(raw)
    assert items[0]["value"] == "a.example.com"
    assert items[0]["detail"]["source"] == "crt.sh"


# ---------- ffuf ----------
FFUF_JSON = """{"input":{"FUZZ":"admin"},"position":0,"status":200,"length":3210,"words":420,"lines":80,"url":"http://t/admin","redirectlocation":""}
{"input":{"FUZZ":"config.php~"},"status":403,"length":312,"words":25,"lines":7,"url":"http://t/config.php~","redirectlocation":""}
not json line
"""


def test_ffuf_parses_json():
    items = FfufAdapter().parse(FFUF_JSON)
    assert len(items) == 2
    assert items[0]["value"] == "http://t/admin"
    assert items[0]["detail"]["status"] == 200
    assert items[1]["detail"]["status"] == 403


def test_ffuf_skips_garbage():
    assert FfufAdapter().parse("not json at all\n") == []


# ---------- sqlmap ----------
SQLMAP_SAMPLE = """
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: and 1=1

Parameter: id (GET)
    Type: time-based blind
    Title: MySQL > 5.0.12 AND time-based blind
    Payload: and sleep(5)--
"""


def test_sqlmap_detects_injection():
    items = SqlmapAdapter().parse(SQLMAP_SAMPLE)
    assert len(items) == 1
    assert items[0]["kind"] == "finding"
    assert items[0]["value"] == "sql_injection"
    assert "id" in items[0]["detail"]["parameters"]
    assert "boolean-based blind" in items[0]["detail"]["types"]


def test_sqlmap_no_injection():
    assert SqlmapAdapter().parse("no injection found\n") == []


# ---------- xray ----------
XRAY_SAMPLE = """[INFO] 2026-08-23 10:00:00 found: [poc-yaml-thinkphp-rce] (http://t/index.php) severity: high
[INFO] 2026-08-23 10:00:01 found: [poc-yaml-fastjson] (http://t/api) severity: critical
[INFO] normal log line
"""


def test_xray_parses_findings():
    items = XrayAdapter().parse(XRAY_SAMPLE)
    assert len(items) == 2
    assert items[0]["detail"]["poc"] == "poc-yaml-thinkphp-rce"
    assert items[0]["detail"]["severity"] == "high"
    assert items[1]["detail"]["severity"] == "critical"


def test_xray_no_findings():
    assert XrayAdapter().parse("just logs\n") == []


# ---------- 插件清单 ----------
def test_manifest_complete():
    tools = load_manifest()
    keys = [t["key"] for t in tools]
    for required in ("fscan", "nuclei", "subfinder", "httpx", "ffuf",
                     "sqlmap", "xray", "hydra", "nmap", "rad"):
        assert required in keys, f"manifest 缺少 {required}"
    for t in tools:
        assert t.get("adapter"), f"{t['key']} 缺少 adapter"
        assert t.get("category"), f"{t['key']} 缺少 category"


def test_find_tool():
    t = find_tool("fscan")
    assert t["key"] == "fscan"
    assert t["sha256"].startswith("5aef")


def test_list_installed_shape():
    rows = list_installed()
    assert isinstance(rows, list)
    assert all("installed" in r and "key" in r for r in rows)


# ---------- 字典加解密 ----------
def test_dict_roundtrip():
    data = b"password123\nadmin\nroot\n"
    token = _encrypt(data)
    assert token != data.decode(errors="ignore")  # 已加密
    assert _decrypt(token) == data


def test_dict_encryption_hides_content():
    data = b"supersecretpassword"
    token = _encrypt(data)
    assert b"supersecret" not in token.encode()
