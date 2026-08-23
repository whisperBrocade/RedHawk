"""RedHawk — 漏洞赏金平台 / SRC 导航数据。

来源: 八方网域 SRC导航文档 (bbs.bafangwy.com/project-8/doc-523/)
用途: 左侧任务栏「赏金平台」面板 — 漏洞挖掘者快速直达各平台。
"""

SRC_PLATFORMS = [
    {
        "group": "公益 SRC",
        "items": [
            {"name": "补天", "url": "https://www.butian.net/", "desc": "企业 SRC 众测"},
            {"name": "漏洞盒子", "url": "https://www.vulbox.com/", "desc": "漏洞众测平台"},
        ],
    },
    {
        "group": "众测平台",
        "items": [
            {"name": "CNVD 众测", "url": "https://zc.cnvd.org.cn/project/index", "desc": "国家信息安全漏洞共享-众测"},
            {"name": "春秋云测", "url": "https://www.ichunqiu.com/cqyc", "desc": "众测平台"},
            {"name": "360 众测", "url": "https://zhongce.360.net/", "desc": "360 众测"},
            {"name": "雷神众测", "url": "https://www.bountyteam.com/", "desc": "雷神众测"},
        ],
    },
    {
        "group": "教育 SRC",
        "items": [
            {"name": "教育 SRC", "url": "https://src.sjtu.edu.cn/", "desc": "上海交通大学 SRC"},
        ],
    },
    {
        "group": "国外赏金平台",
        "items": [
            {"name": "HackerOne", "url": "https://www.hackerone.com/", "desc": "全球最大赏金平台"},
            {"name": "Bugcrowd", "url": "https://www.bugcrowd.com/", "desc": "众测平台"},
            {"name": "OpenBugBounty", "url": "https://www.openbugbounty.org/", "desc": "公开漏洞赏金"},
            {"name": "Intigriti", "url": "https://www.intigriti.com", "desc": "欧洲赏金平台"},
            {"name": "Apple Security", "url": "https://security.apple.com/bounty/categories", "desc": "苹果赏金"},
            {"name": "Meta WhiteHat", "url": "https://www.facebook.com/whitehat", "desc": "Meta/Facebook 赏金"},
            {"name": "Microsoft MSRC", "url": "https://www.microsoft.com/en-us/msrc/bounty", "desc": "微软赏金"},
            {"name": "Google Bug Hunters", "url": "https://bughunters.google.com/about", "desc": "谷歌赏金"},
            {"name": "GitHub Security", "url": "https://bounty.github.com/", "desc": "GitHub 赏金"},
        ],
    },
    {
        "group": "其他平台",
        "items": [
            {"name": "CNVD", "url": "https://www.cnvd.org.cn/", "desc": "国家信息安全漏洞共享平台"},
            {"name": "国家网络空间安全云社区", "url": "https://nccsec.cn/index", "desc": "网络安全云社区"},
        ],
    },
]

# 企业 SRC 大全入口（独立文档）
ENTERPRISE_SRC = {
    "name": "企业 SRC 平台大全",
    "url": "https://wiki.bafangwy.com/doc/253/",
    "desc": "完整企业 SRC 导航（跳转外部文档）",
}
