"""
风险可控 / 高风险确认放行 统一框架。

所有「需用户确认后放行」的拦截（请求侧/响应侧）均经此模块格式化：
- 统一原因码与描述（问题原因、简述）
- 统一确认文案与元数据结构
- 调用方负责：落库 pending、返回响应；本模块只提供文案与结构。
"""

from __future__ import annotations

from typing import Any

from aegisgate.core.confirmation import confirmation_template

# 阶段：request = 请求侧拦截，response = 响应侧拦截
PHASE_REQUEST = "request"
PHASE_RESPONSE = "response"

# reason_key -> (问题原因描述, 简述前缀/模板)
REASON_DESCRIPTIONS: dict[str, tuple[str, str]] = {
    # 请求侧
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
    # 响应侧
    "response_high_risk": (
        "高风险响应",
        "检测到高风险指令/投毒信号",
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
    "awaiting_user_confirmation": (
        "等待用户确认",
        "需用户确认后放行",
    ),
}


def get_reason_and_summary(
    phase: str,
    disposition_reasons: list[str],
    security_tags: set[str],
) -> tuple[str, str]:
    """
    根据阶段与上下文得到统一的问题原因与简述。
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


def build_confirmation_message(
    confirm_id: str,
    reason: str,
    summary: str,
    phase: str = PHASE_RESPONSE,
    note: str = "",
    action_token: str = "",
) -> str:
    """
    生成统一的安全确认文案（中英双语）。
    phase 仅用于可选差异化，目前共用同一模板。
    """
    base = confirmation_template(confirm_id=confirm_id, reason=reason, summary=summary, action_token=action_token)
    if note:
        return f"{note}\n\n{base}"
    return base


def build_confirmation_metadata(
    confirm_id: str,
    status: str,
    reason: str,
    summary: str,
    phase: str = PHASE_RESPONSE,
    payload_omitted: bool = False,
    action_token: str = "",
) -> dict[str, Any]:
    """
    生成响应中 aegisgate.confirmation 的统一结构。
    便于客户端解析：问题原因、描述、是否需确认、confirm_id、阶段等。
    """
    return {
        "required": status == "pending",
        "confirm_id": confirm_id,
        "status": status,
        "reason": reason,
        "summary": summary,
        "phase": phase,
        "payload_omitted": payload_omitted,
        "action_token": action_token,
    }
