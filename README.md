<div align="center">

# 🦅 RedHawk（红隼）

> **AI 驱动的红队安全工作台** — 抓包 / 发包 / 扫描 / AI 研判 / 复现报告，一体化全链路。

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-119%20passed-green.svg)](src/tests)
[![Platform](https://img.shields.io/badge/Platform-Windows-blue.svg)](https://www.microsoft.com/windows)
[![Security](https://img.shields.io/badge/Scope-Authorized_Only-red.svg)](#-免责声明)

*红隼 · 落叶 · 万物生歌 · AI 驱动红队武器*

</div>

---

## 🎯 这是什么

RedHawk 是一款**面向授权安全测试的 AI 一体化工作台**：

- 🕸 **抓包**：启动即接管系统代理，自动捕获本机 HTTP/HTTPS 流量（HTTPS 通过自签 CA 中间人解密）
- 📮 **发包**：Burp 风格 Repeater，任意请求构造 + 返回包查看 + 原始请求解析
- 🎯 **扫描**：playbook 驱动自动化（fscan 资产发现 → nuclei 漏洞验证 → AI 研判）
- 🤖 **AI 研判**：内置 **DeepSeek v4-flash / v4-pro 双模型**，一键分析流量识别漏洞，**证据级反幻觉闸门**（结论必须引用真实流量证据）
- 📊 **数据包分析**：每个数据包的漏洞类型/严重度/置信度/研判理由/原始证据，详细列表管理
- 📄 **复现报告**：AI 自动生成 复现步骤 / 请求包 / 修复建议
- 📚 **知识助手**：本地渗透手册（Pentest_Note）+ CSDN 知识库双源检索

**核心设计**：绝对理性（砍掉一切不必要）· 绝对暴力（能枚举就枚举）· 绝对简洁（SQLite 单文件、JSON 全链路、单命令运行）。

---

## ✨ 特性

| 特性 | 说明 |
|---|---|
| 🧠 **AI 双模型** | DeepSeek v4-flash（快速）/ v4-pro（深度），密钥加密存储本机 |
| 🛡️ **证据级反幻觉** | AI 结论必须引用流量 ID/证据，编造即作废 |
| 🔐 **授权硬闸门** | 目标不在授权范围 → 进程拒绝启动，全量审计留痕 |
| 🕸 **系统代理接管** | 一键接管 Windows 系统代理，主机所有 HTTP 流量自动进入，停止自动还原 |
| 🔒 **HTTPS 解密** | 自签 CA + 动态域名证书中间人（Burp 同方案） |
| 🗂 **流量归类** | 按 Content-Type/URL 自动分组（HTML/API/JS/图片...） |
| ⚡ **一键全自动** | 流量 → AI 识别漏洞 → 深度研判 → 复现报告，一次点击 |
| 🖥 **独立桌面版** | 27MB 单 exe，脱离浏览器（pywebview 内嵌窗口） |
| 🎨 **三主题 UI** | 白色 / 暖色 / 红黑，图标随主题变色 |
| 🔌 **插件化** | YAML playbook 加流程 = 加文件；工具适配器 JSON 统一契约 |

---

## 🚀 快速开始

### 环境要求
- Windows 10/11，Python 3.10+

### 方式一：源码运行

```bash
# 1. 安装依赖
pip install typer pyyaml fastapi uvicorn pywebview cryptography

# 2. 安装本项目
cd src
pip install -e .

# 3. 启动 Web 工作台
rh web
# 浏览器打开 http://127.0.0.1:7788
```

### 方式二：独立桌面版
```bash
# 打包成单文件 exe（或直接运行源码）
cd src
pip install pyinstaller
pyinstaller redhawk.spec --noconfirm --clean
# 产物: dist/RedHawk.exe，双击即用
```

### 安装渗透工具（自动下载）
```bash
rh plugins install --key fscan
rh plugins install --key nuclei
rh plugins list
```

---

## 🧭 使用流程（30 秒上手）

```
1. 左侧「AI 模型」→ 填 DeepSeek API Key → 保存 → 测试连接（可选但推荐）
2. 「抓包代理」→ 点 ▶ 启动 → 正常上网 → 流量自动记录
3. 「发包 Repeater」→ 手动构造请求看返回包
4. 「任务扫描」→ 登记目标 → 选 playbook → 运行 → AI 研判 → 复现报告
5. 「⚡ 一键 AI 抓包分析」→ 流量自动分析 → 跳转「数据包分析」界面
```

> 完整使用方式见软件内「📖 使用指南」。

---

## 🏗 架构

```
┌──────────────────────────────────────────────┐
│  Web 工作台（单 HTML）/ 独立桌面版（pywebview）  │
├──────────────────────────────────────────────┤
│  抓包代理(HTTP/HTTPS中间人) · Repeater · 流量  │
├──────────────────────────────────────────────┤
│  playbook 引擎 · 工具适配器(fscan/nuclei/...)  │
├──────────────────────────────────────────────┤
│  AI 引擎（DeepSeek 双模型）· 证据闸门 · 报告    │
├──────────────────────────────────────────────┤
│  SQLite(13表) · 授权闸门 · 审计 · 知识库(RAG)  │
└──────────────────────────────────────────────┘
```

**技术栈**：Python · FastAPI · SQLite · Typer · pywebview · PyInstaller · cryptography

---

## 📁 项目结构

```
src/
├── redhawk/
│   ├── web.py            # FastAPI 后端（30+ 端点）
│   ├── intercept.py      # 抓包代理 + HTTPS 中间人 + 发包
│   ├── certgen.py        # CA 生成 / 动态域名证书
│   ├── ai_service.py     # AI 研判 + 证据闸门
│   ├── auto_pentest.py   # 一键自动化分析
│   ├── llm.py            # DeepSeek 双模型 + 密钥加密
│   ├── orchestrator.py   # playbook 编排
│   ├── adapters/         # fscan/nuclei/subfinder/httpx/ffuf/sqlmap/xray...
│   ├── plugins/          # 插件仓库（manifest + registry）
│   ├── playbooks/        # YAML 流程定义
│   ├── kb.py             # 知识库 RAG + CSDN
│   ├── repro.py          # 漏洞复现报告
│   ├── desktop.py        # 独立桌面版入口
│   └── static/index.html # 前端工作台
└── tests/                # 119 个单元测试
```

---

## 📸 截图

<!-- 上传后替换为真实截图：
![工作台](docs/screenshot-dashboard.png)
![抓包](docs/screenshot-proxy.png)
![AI分析](docs/screenshot-analysis.png)
-->

*(待补充截图 — 欢迎贡献)*

---

## 🧪 测试

```bash
cd src
python -m pytest tests/ -v
# 119 passed, 1 skipped
```

---

## 🤝 贡献

欢迎 PR！请先阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。主要方向：
- 新工具适配器
- playbook 模板
- AI 研判提示词优化
- 前端体验改进

---

## 📜 免责声明

**RedHawk 是面向安全研究、CTF 竞赛、教学演示与授权渗透测试的专业工具。**

1. 使用前必须获得目标系统的**明确、书面授权**
2. 遵守所在国家/地区的**全部法律法规**（《网络安全法》《数据安全法》《个人信息保护法》等）
3. 因未授权使用、误用、滥用产生的一切法律后果由**使用者自行承担**
4. 作者对本工具的任何使用方式**不承担任何担保与责任**

> ⚠️ **未经授权对任何系统进行渗透测试、漏洞利用、数据访问均属违法行为。请勿用于非法用途。**

详见 [SECURITY.md](SECURITY.md) 与 [DISCLAIMER.md](DISCLAIMER.md)。

---

## 📄 License

[MIT License](LICENSE)

---

<div align="center">

*红隼 · 落叶 · 万物生歌* · Built with ❤️

</div>
