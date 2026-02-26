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


def make_action_bind_token(seed: str) -> str:
    raw = str(seed or "").encode("utf-8")
    return f"act-{hashlib.sha256(raw).hexdigest()[:10]}"


def _tokenize_text(text: str) -> set[str]:
    normalized = text.strip().lower()
    if not normalized:
        return set()
    tokens = re.split(r"[\s,，。.!！？;；:/\\\|\(\)\[\]{}\"'`<>：（）【】「」『』《》]+", normalized)
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


def confirmation_template(confirm_id: str, reason: str, summary: str, action_token: str = "") -> str:
    token_suffix = f" {action_token}" if action_token else ""
    action_line_cn = f"动作摘要码：{action_token}\n" if action_token else ""
    action_line_en = f"Action Bind Token: {action_token}\n" if action_token else ""
    return (
        f"拦截原因：{reason}\n"
        f"可疑简述：{summary}\n\n"
        "⚠️ 安全确认（高风险操作）\n"
        "根据上述原因，本次请求已被网关暂停执行。请确认后再决定是否放行。\n\n"
        "请单独发送以下可复制消息之一（不要附加其它内容）：\n\n"
        f"放行（复制这一行）：yes {confirm_id}{token_suffix}\n\n"
        f"取消（复制这一行）：no {confirm_id}{token_suffix}\n\n"
        f"确认编号：{confirm_id}\n"
        f"{action_line_cn}"
        "（请不要提供密码、密钥、token、cookie 等敏感信息。）\n\n"
        "⚠️ Safety Confirmation (High-Risk Action)\n"
        "For the reason above, this request has been paused by the gateway. Confirm to approve or cancel.\n\n"
        "Send ONLY one standalone copy-ready line below:\n\n"
        f"Approve (copy this line): yes {confirm_id}{token_suffix}\n\n"
        f"Cancel (copy this line): no {confirm_id}{token_suffix}\n\n"
        f"Confirmation ID: {confirm_id}\n"
        f"{action_line_en}"
        "(Do not provide passwords, API keys, tokens, or cookies.)"
    )
