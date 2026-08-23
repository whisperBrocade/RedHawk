"""RedHawk — 独立版 & 公网挖掘测试。"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from redhawk.adapters.httpx import HttpxAdapter
from redhawk.playbook import load_playbook

HTPPX_JSONL = """{"url":"http://x.com","status_code":200,"title":"X Corp","webserver":"nginx","tech":["react"]}
{"url":"https://api.x.com","status_code":401,"title":"","webserver":null,"tech":[]}
not json line
"""


def test_httpx_parses_jsonl():
    items = HttpxAdapter().parse(HTPPX_JSONL)
    assert len(items) == 2
    assert items[0]["value"] == "http://x.com"
    assert items[0]["detail"]["status"] == 200
    assert items[0]["detail"]["title"] == "X Corp"
    assert items[1]["detail"]["status"] == 401


def test_httpx_skips_garbage():
    assert HttpxAdapter().parse("garbage\n") == []


def test_web_recon_playbook_exists():
    pb = load_playbook("web_recon")
    stages = [s["tool"] for s in pb["stages"]]
    assert stages == ["subfinder", "httpx", "nuclei"]
    assert pb["stages"][0]["phase"] == "recon"
    assert pb["stages"][2]["phase"] == "scan"


def test_web_recon_has_rate_limit():
    pb = load_playbook("web_recon")
    nuclei_stage = pb["stages"][2]
    assert nuclei_stage["options"]["rate_limit"] == 150  # 公网限速防封


def test_desktop_module_imports():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "redhawk"))
    import importlib
    m = importlib.import_module("redhawk.desktop")
    assert hasattr(m, "main")
    assert hasattr(m, "start_server")
