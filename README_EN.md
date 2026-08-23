<div align="center">

# 🦅 RedHawk

> **AI-Powered Red Team Workbench** — Traffic Capture / Repeater / Scanning / AI Analysis / Reproduction Reports, all-in-one.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-119%20passed-green.svg)](src/tests)
[![Platform](https://img.shields.io/badge/Platform-Windows-blue.svg)](https://www.microsoft.com/windows)
[![Security](https://img.shields.io/badge/Scope-Authorized_Only-red.svg)](#-disclaimer)

</div>

---

## 🎯 What is it

RedHawk is an **AI-integrated workbench for authorized security testing**:

- 🕸 **Traffic Capture**: One-click system proxy takeover, auto-captures HTTP/HTTPS traffic (HTTPS decrypted via self-signed CA MITM)
- 📮 **Repeater**: Burp-style request builder with raw request parsing
- 🎯 **Scanning**: Playbook-driven automation (fscan asset discovery → nuclei vulnerability validation → AI verdict)
- 🤖 **AI Analysis**: Built-in **DeepSeek v4-flash / v4-pro**, one-click traffic analysis with **evidence-gated anti-hallucination** (conclusions must cite real traffic evidence)
- 📊 **Packet Analysis**: Per-packet vulnerability type/severity/confidence/reason/raw evidence
- 📄 **Reproduction Reports**: AI-generated repro steps / request packets / fix suggestions
- 📚 **Knowledge Assistant**: Local pentest handbook (Pentest_Note) + CSDN knowledge base

**Design Philosophy**: Absolute Rationality · Absolute Brute Force · Absolute Simplicity

---

## ✨ Features

| Feature | Description |
|---|---|
| 🧠 **AI Dual Models** | DeepSeek v4-flash (fast) / v4-pro (deep), API key encrypted locally |
| 🛡️ **Evidence Gate** | AI conclusions must cite traffic IDs; fabrication rejected |
| 🔐 **Authorization Gate** | Targets outside scope → blocked + full audit trail |
| 🕸 **System Proxy Takeover** | One-click, auto-restore on stop |
| 🔒 **HTTPS Decryption** | Self-signed CA + dynamic per-domain certs (Burp-style MITM) |
| 🗂 **Traffic Categorization** | Auto-group by Content-Type/URL |
| ⚡ **One-click Automation** | Traffic → AI → findings → reproduction report |
| 🖥 **Standalone Desktop** | 27MB single exe, no browser needed (pywebview) |
| 🎨 **Three Themes** | White / Warm / Red-Black, icons adapt to theme |

---

## 🚀 Quick Start

### Requirements
- Windows 10/11, Python 3.10+

### Source Run

```bash
pip install typer pyyaml fastapi uvicorn pywebview cryptography
cd src
pip install -e .
rh web    # open http://127.0.0.1:7788
```

### Install Pentest Tools

```bash
rh plugins install --key fscan
rh plugins install --key nuclei
```

### Desktop Build

```bash
pip install pyinstaller
pyinstaller redhawk.spec --noconfirm --clean
# dist/RedHawk.exe
```

---

## 🏗 Architecture

```
┌──────────────────────────────────────────────┐
│  Web Workbench (single HTML) / Desktop       │
├──────────────────────────────────────────────┤
│  Proxy (HTTP/HTTPS MITM) · Repeater · Traffic│
├──────────────────────────────────────────────┤
│  Playbook Engine · Tool Adapters            │
├──────────────────────────────────────────────┤
│  AI Engine (DeepSeek) · Evidence Gate · Report│
├──────────────────────────────────────────────┤
│  SQLite · Auth Gate · Audit · KB (RAG)       │
└──────────────────────────────────────────────┘
```

**Stack**: Python · FastAPI · SQLite · Typer · pywebview · PyInstaller · cryptography

---

## 🧪 Tests

```bash
cd src
python -m pytest tests/ -v   # 119 passed, 1 skipped
```

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). New adapters, playbooks, AI prompts, UI improvements welcome.

---

## 📜 Disclaimer

**RedHawk is a professional tool for security research, CTF, education, and authorized penetration testing.**

1. You must have **explicit written authorization** for target systems
2. You must comply with **all applicable laws** (Cybersecurity Law, Data Security Law, PIPL, etc.)
3. All consequences of unauthorized use are **solely the user's responsibility**
4. The author provides **no warranty or liability** for any use

> ⚠️ **Unauthorized penetration testing, exploitation, or data access is illegal. Do not use for illegal purposes.**

See [DISCLAIMER.md](DISCLAIMER.md) and [SECURITY.md](SECURITY.md).

---

## 📄 License

[MIT License](LICENSE)
