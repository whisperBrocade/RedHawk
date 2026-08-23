"""RedHawk — 赏金平台导航测试。"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from redhawk.src_platforms import ENTERPRISE_SRC, SRC_PLATFORMS


def test_groups_exist():
    groups = [g["group"] for g in SRC_PLATFORMS]
    for expected in ("公益 SRC", "众测平台", "国外赏金平台"):
        assert expected in groups


def test_platforms_have_name_url():
    total = 0
    for g in SRC_PLATFORMS:
        for p in g["items"]:
            assert p["name"], "平台名不能为空"
            assert p["url"].startswith("http"), f"{p['name']} URL 格式错误"
            total += 1
    assert total >= 10  # 至少 10 个平台


def test_known_platforms():
    names = [p["name"] for g in SRC_PLATFORMS for p in g["items"]]
    for expected in ("补天", "漏洞盒子", "HackerOne", "CNVD"):
        assert expected in names


def test_enterprise_src():
    assert ENTERPRISE_SRC["url"].startswith("http")
    assert "企业" in ENTERPRISE_SRC["name"]
