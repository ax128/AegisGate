"""
Unified mapping from block reason code to description and summary.

Every security block (request side or response side) goes through this module, which translates the
internal reason code into a consistent "problem reason + summary" text that auditing and response
rendering both reuse.

This was ``confirmation_flow`` until the yes/no approval flow was removed. Dangerous content is
always masked or split automatically now, so nothing here produces confirmation copy or its
metadata structures — the old name outlived the feature it was named after.
"""

from __future__ import annotations

# Phase: request = request-side block, response = response-side block
PHASE_REQUEST = "request"
PHASE_RESPONSE = "response"

# reason_key -> (problem description, summary prefix/template)
REASON_DESCRIPTIONS: dict[str, tuple[str, str]] = {
    # request side
    "request_secret_exfiltration": (
        "请求疑似包含敏感信息外泄意图（如泄露 prompt、密钥、内部信息）",
        "触发信号：request_secret_exfiltration",
    ),
    "request_leak_check_failed": (
        "请求内容命中泄露检测规则",
        "触发信号：request_leak_check_failed",
    ),
    "request_privilege_abuse": (
        "请求疑似包含越权或提权意图",
        "触发信号：request_privilege_abuse",
    ),
    "request_rule_bypass": (
        "请求疑似试图绕过安全规则",
        "触发信号：request_rule_bypass",
    ),
    "request_strong_intent_attack": (
        "请求疑似包含强攻击意图",
        "触发信号：request_strong_intent_attack",
    ),
    "request_shape_anomaly": (
        "请求结构异常，疑似投毒或注入",
        "触发信号：request_shape_anomaly",
    ),
    "request_blocked": (
        "请求被安全策略拦截",
        "触发信号：request_blocked",
    ),
    # response side
    "response_high_risk": (
        "高风险响应",
        "检测到高风险指令/投毒信号",
    ),
    "response_high_risk_command": (
        "高风险命令响应",
        "检测到高风险命令输出信号",
    ),
    "response_forbidden_command": (
        "命中强制拦截命令",
        "触发信号：response_forbidden_command",
    ),
    "response_tool_call_violation": (
        "工具调用命中高风险限制",
        "触发信号：response_tool_call_violation",
    ),
    "response_system_prompt_leak": (
        "疑似系统提示泄露",
        "触发信号：response_system_prompt_leak",
    ),
    "response_unicode_bidi": (
        "疑似 Unicode 双向字符投毒",
        "触发信号：response_unicode_bidi",
    ),
    "response_post_restore_masked": (
        "恢复后疑似敏感信息外传",
        "触发信号：response_post_restore_masked",
    ),
    "response_post_restore_blocked": (
        "恢复后高风险外传阻断",
        "触发信号：response_post_restore_blocked",
    ),
    "response_sanitized": (
        "响应内容已触发安全清洗",
        "触发信号：response_sanitized",
    ),
}


def get_reason_and_summary(
    phase: str,
    disposition_reasons: list[str],
    security_tags: set[str],
) -> tuple[str, str]:
    """
    Derive the unified problem reason and summary from the phase and context.
    phase: PHASE_REQUEST | PHASE_RESPONSE
    """
    reason_key = disposition_reasons[0] if disposition_reasons else (
        "request_blocked" if phase == PHASE_REQUEST else "response_high_risk"
    )
    reason_text, summary_prefix = REASON_DESCRIPTIONS.get(
        reason_key, (reason_key, f"触发信号：{reason_key}")
    )
    if phase == PHASE_RESPONSE:
        tags = [t for t in sorted(security_tags) if t.startswith("response_")]
        summary = f"{summary_prefix}" + (
            f"（{'、'.join(tags[:3])}）" if tags else ""
        )
    else:
        summary = summary_prefix
    return reason_text, summary
