"""Confirmation workflow helpers."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from typing import Any


YES_WORDS = {
    "yes",
    "y",
    "ok",
    "okay",
    "confirm",
    "proceed",
    "continue",
    "是",
    "是的",
    "确认",
    "同意",
    "继续",
    "执行",
    "好的",
}

NO_WORDS = {
    "no",
    "n",
    "cancel",
    "stop",
    "reject",
    "否",
    "不是",
    "取消",
    "拒绝",
    "不要",
    "停止",
}


@dataclass(slots=True)
class ConfirmationDecision:
    value: str
    has_yes: bool
    has_no: bool


def make_confirm_id() -> str:
    return f"cfm-{uuid.uuid4().hex[:12]}"


def payload_hash(payload: dict[str, Any]) -> str:
    body = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def _tokenize_text(text: str) -> set[str]:
    normalized = text.strip().lower()
    if not normalized:
        return set()
    tokens = re.split(r"[\s,，。.!！？;；:/\\\|\(\)\[\]{}\"'`<>]+", normalized)
    return {token for token in tokens if token}


def parse_confirmation_decision(text: str) -> ConfirmationDecision:
    tokens = _tokenize_text(text)
    has_yes = any(token in YES_WORDS for token in tokens)
    has_no = any(token in NO_WORDS for token in tokens)
    if has_no and not has_yes:
        return ConfirmationDecision(value="no", has_yes=False, has_no=True)
    if has_yes and not has_no:
        return ConfirmationDecision(value="yes", has_yes=True, has_no=False)
    if has_yes and has_no:
        return ConfirmationDecision(value="ambiguous", has_yes=True, has_no=True)
    return ConfirmationDecision(value="unknown", has_yes=False, has_no=False)


def confirmation_template(confirm_id: str, reason: str, summary: str) -> str:
    return (
        f"拦截原因：{reason}\n"
        f"可疑简述：{summary}\n\n"
        "⚠️ 安全确认（高风险操作）\n"
        "根据上述原因，本次请求已被网关暂停执行。请确认后再决定是否放行。\n\n"
        "请你仅回复以下之一：\n\n"
        "回复 是 / yes：确认执行刚才的请求（只执行一次）\n\n"
        "回复 否 / no：取消执行\n\n"
        f"确认编号：{confirm_id}\n"
        "（请不要提供密码、密钥、token、cookie 等敏感信息。）\n\n"
        "⚠️ Safety Confirmation (High-Risk Action)\n"
        "For the reason above, this request has been paused by the gateway. Confirm to approve or cancel.\n\n"
        "Reply with ONLY one of the following:\n\n"
        "yes: approve and execute the previous request (one-time)\n\n"
        "no: cancel\n\n"
        f"Confirmation ID: {confirm_id}\n"
        "(Do not provide passwords, API keys, tokens, or cookies.)"
    )
