"""RedHawk — 适配器 parse 逻辑单元测试（不依赖真实工具二进制）。

用真实 fscan/nuclei 输出样例验证解析正确性——精准度高原则：
解析器必须从工具输出中准确提取资产/漏洞，不丢不漏。
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from redhawk.adapters.fscan import FscanAdapter
from redhawk.adapters.nuclei import NucleiAdapter


# ---------- fscan ----------
FSCAN_SAMPLE = """[*] 10.0.0.5:8080                 nacos    [Product:Nacos Server]
[*] 10.0.0.5:3306                 mysql    [Product:MySQL 5.7]
[*] http://10.0.0.5:8080               http     [Product:Open Lighting Architecture daemon]
[*] WebTitle: http://10.0.0.5:8080 code:200 len:1234  title:Nacos
[+] http://10.0.0.5               code:200 len:2307  title:站点创建成功
[!] MySQL 10.0.0.5:3306 root:root
[+] SMBInfo 10.0.0.5:445 [Windows 11] DESKTOP-TEST SMBv2
[*] Nacos未授权访问  http://10.0.0.5:8080
"""


def test_fscan_parses_ports():
    items = FscanAdapter().parse(FSCAN_SAMPLE)
    ports = [i for i in items if i["kind"] == "port"]
    assert len(ports) == 2
    assert ports[0]["value"] == "10.0.0.5"
    assert ports[0]["detail"]["port"] == 8080
    assert ports[0]["detail"]["service"] == "nacos"
    assert "Nacos" in ports[0]["detail"]["product"]


def test_fscan_parses_webtitle():
    items = FscanAdapter().parse(FSCAN_SAMPLE)
    titles = [i for i in items if i["kind"] == "web_title"]
    assert len(titles) == 2
    assert any(t["detail"]["title"] == "Nacos" for t in titles)
    assert any(t["detail"]["title"] == "站点创建成功" for t in titles)


def test_fscan_parses_weak_password():
    items = FscanAdapter().parse(FSCAN_SAMPLE)
    weaks = [i for i in items if i["kind"] == "weak_password"]
    assert len(weaks) == 1
    assert weaks[0]["detail"]["user"] == "root"
    assert weaks[0]["detail"]["password"] == "root"


def test_fscan_parses_http_service_and_smb():
    items = FscanAdapter().parse(FSCAN_SAMPLE)
    assert any(i["kind"] == "http_service" for i in items)
    assert any(i["kind"] == "smb_info" for i in items)


def test_fscan_parses_vuln_hints():
    items = FscanAdapter().parse(FSCAN_SAMPLE)
    vulns = [i for i in items if i["kind"] == "vuln_hint"]
    assert len(vulns) == 1
    assert "未授权" in vulns[0]["value"]


def test_fscan_empty_input():
    assert FscanAdapter().parse("") == []


# ---------- nuclei ----------
NUCLEI_JSONL = """{"template-id":"cve-2021-44228","info":{"name":"Log4j RCE","severity":"critical"},"matched-at":"http://10.0.0.5:8080/","type":"http","host":"10.0.0.5"}
{"template-id":"misconfig-headers","info":{"name":"Missing security headers","severity":"low"},"matched-at":"http://10.0.0.5/","type":"http","host":"10.0.0.5"}
[INF] This is a non-JSON banner line
{"template-id":"cve-2024-1234","info":{"name":"Tomcat auth bypass","severity":"high"},"matched-at":"http://10.0.0.5:8080/manager","type":"http","host":"10.0.0.5"}
"""


def test_nuclei_parses_jsonl_findings():
    items = NucleiAdapter().parse(NUCLEI_JSONL)
    assert len(items) == 3  # 非 JSONL 行被跳过
    assert items[0]["detail"]["severity"] == "critical"
    assert items[0]["detail"]["template"] == "cve-2021-44228"
    assert items[0]["value"] == "http://10.0.0.5:8080/"


def test_nuclei_severity_lowercased():
    items = NucleiAdapter().parse(NUCLEI_JSONL)
    assert all(i["detail"]["severity"] == i["detail"]["severity"].lower() for i in items)


def test_nuclei_empty_and_garbage():
    assert NucleiAdapter().parse("") == []
    assert NucleiAdapter().parse("not json at all\nstill not\n") == []
