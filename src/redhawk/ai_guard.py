"""RedHawk — AI 护栏：AI 自身的红队。

职责：
1. pre_filter：拒绝越权/敏感内容输入（未授权目标、攻击指导）
2. post_filter：输出脱敏（IP/凭据打码）
3. system_prompt：构建带授权边界的系统提示词
"""

from __future__ import annotations

import re

# 越权/危险意图关键词（输入侧拦截）
BLOCKED_INPUT_PATTERNS = [
    r"未授权",
    r"没有授权",
    r"无授权",
    r"绕过.*(?:认证|授权|登录)",
    r"破解.*(?:密码|账号)",
    r"撞库",
    r"拖库",
    r"删库",
    r"勒索",
    r"攻击.*(?:政府|银行|医院|学校)",  # 敏感行业
]

# 敏感数据模式（输出侧脱敏）
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b")
KEY_RE = re.compile(r"(?i)\b(sk-[a-z0-9]{8,}|api[_-]?key\s*[=:]\s*\S+|password\s*[=:]\s*\S+|token\s*[=:]\s*\S+)")


def pre_filter(text: str) -> tuple[bool, str]:
    """输入检查。返回 (是否放行, 原因)。"""
    for pat in BLOCKED_INPUT_PATTERNS:
        if re.search(pat, text):
            return False, f"命中敏感模式: {pat}"
    return True, ""


def post_filter(text: str) -> str:
    """输出脱敏：IP/邮箱/密钥打码。"""
    text = IP_RE.sub(lambda m: f"{m.group(0).split('.')[0]}.x.x.x", text)
    text = EMAIL_RE.sub("***@***", text)
    text = KEY_RE.sub(lambda m: m.group(1).split("=")[0].strip() + "=***", text)
    return text


def build_system_prompt(scope: str = "", role: str = "红队研判助手") -> str:
    """带授权边界的系统提示词。scope 为目标授权范围。"""
    lines = [
        f"你是{role}。",
        "仅对已授权目标提供分析与建议。",
    ]
    if scope:
        lines.append(f"当前授权范围: {scope}。超出该范围的目标一律拒绝分析。")
    lines += [
        "结论必须基于提供的工具扫描证据，严禁编造。",
        "敏感信息（IP/凭据）输出时自动脱敏。",
    ]
    return "\n".join(lines)
