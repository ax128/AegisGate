"""Confirmation workflow helpers.

NOTE: The yes/no approval flow has been removed. All dangerous content is now
automatically sanitized (redacted or split with ---). The confirmation template
is informational only — it tells the user what was detected and how the content
was processed, but does NOT offer a release/approve option.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from typing import Any


# YES_WORDS is intentionally empty — approval is no longer supported.
YES_WORDS: set[str] = set()

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
    return f"act-{hashlib.sha256(raw).hexdigest()[:16]}"


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
    """Informational-only template. No yes/no approval options."""
    return (
        f"⚠️ [AegisGate] 安全拦截通知\n"
        f"---\n"
        f"拦截原因：{reason}\n"
        f"可疑简述：{summary}\n"
        f"处理方式：危险片段已自动遮挡/分割，不支持放行\n"
        f"事件编号：{confirm_id}\n"
        f"---\n"
        f"危险内容已被自动处理（遮挡或以 --- 分割）。如需查看完整原文，请联系安全管理员。\n\n"
        f"⚠️ [AegisGate] Security Interception Notice\n"
        f"---\n"
        f"Reason: {reason}\n"
        f"Summary: {summary}\n"
        f"Action: Dangerous fragments auto-redacted/split — approval is not available\n"
        f"Event ID: {confirm_id}\n"
        f"---\n"
        f"Dangerous content has been automatically processed (redacted or split with ---). "
        f"Contact your security administrator to review the original content."
    )
