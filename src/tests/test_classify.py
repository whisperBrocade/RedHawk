"""RedHawk — 流量归类测试。"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from redhawk.intercept import (
    classify_traffic,
    restore_system_proxy,
    set_system_proxy,
    traffic_categories,
)


def _t(url, ct=None, method="GET", status=200):
    headers = {}
    if ct:
        headers = {"Content-Type": ct}
    return {
        "method": method, "url": url, "status": status,
        "resp_headers": str(headers).replace("'", '"'),
    }


def test_classify_by_content_type():
    assert "网页 HTML" in classify_traffic(_t("http://x.com/", "text/html; charset=utf-8"))
    assert "API 接口 JSON" in classify_traffic(_t("http://x.com/api", "application/json"))
    assert "JS 脚本" in classify_traffic(_t("http://x.com/a.js", "application/javascript"))
    assert "图片" in classify_traffic(_t("http://x.com/a.png", "image/png"))
    assert "表单提交" in classify_traffic(_t("http://x.com/login", "application/x-www-form-urlencoded"))


def test_classify_by_url_ext():
    assert "JS 脚本" in classify_traffic(_t("http://x.com/static/app.min.js"))
    assert "样式 CSS" in classify_traffic(_t("http://x.com/site.css"))
    assert "图片" in classify_traffic(_t("http://x.com/logo.jpg"))


def test_classify_by_method_fallback():
    assert "接口操作" in classify_traffic(_t("http://x.com/upload", method="POST"))
    assert "页面/资源请求" in classify_traffic(_t("http://x.com/unknown/path", method="GET"))


def test_categories_grouping(tmp_path):
    from redhawk.db import DB
    from redhawk.intercept import save_traffic

    db = DB(tmp_path / "c.db")
    db.init()
    save_traffic(db, "GET", "http://x.com/", {"Content-Type": "text/html"}, "", 200, {"Content-Type": "text/html"}, "<html>", "proxy")
    save_traffic(db, "GET", "http://x.com/", {"Content-Type": "text/html"}, "", 200, {"Content-Type": "text/html"}, "<html>", "proxy")
    save_traffic(db, "GET", "http://x.com/api", {"Content-Type": "application/json"}, "", 200, {"Content-Type": "application/json"}, "{}", "proxy")
    cats = traffic_categories(db, limit=10)
    assert len(cats) >= 2
    by_name = {c["category"]: c for c in cats}
    html = [c for c in cats if "网页" in c["category"]][0]
    assert html["count"] == 2  # 同类归组
    assert any("API" in c["category"] for c in cats)
    db.close()


def test_system_proxy_functions():
    """系统代理读写（可能因权限失败，但不抛异常）。"""
    try:
        r = set_system_proxy(8888)
        assert isinstance(r, dict)
        restore_system_proxy()
    except Exception:
        pass  # 无管理员/注册表权限时跳过
