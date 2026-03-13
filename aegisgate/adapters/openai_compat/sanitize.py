"""Request/response redaction and sanitization helpers.

These functions handle PII redaction for responses API structured input,
function output sanitization, and request payload log sanitization.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

from aegisgate.config.security_rules import load_security_rules
from aegisgate.util.base64_detect import looks_like_base64_blob
from aegisgate.util.masking import mask_for_log
from aegisgate.util.redaction_whitelist import (
    normalize_whitelist_keys,
    protected_spans_for_text,
    range_overlaps_protected,
)

_RESPONSES_SENSITIVE_OUTPUT_TYPES = frozenset(
    {
        "function_call_output",
        "tool_result",
        "tool_output",
        "computer_call_output",
    }
)
_RESPONSES_RELAXED_REDACTION_ROLES = frozenset({"system", "developer", "assistant", "user", "tool"})
_RESPONSES_RELAXED_PII_IDS = frozenset(
    {
        "TOKEN",
        "JWT",
        "URL_TOKEN_QUERY",
        "PRIVATE_KEY_PEM",
        "AWS_ACCESS_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "SLACK_TOKEN",
        "EXCHANGE_API_SECRET",
        "CRYPTO_WIF_KEY",
        "CRYPTO_XPRV",
        "CRYPTO_SEED_PHRASE",
    }
)
_RESPONSES_NON_CONTENT_KEYS = frozenset({"id", "call_id", "type", "role", "name", "status"})
_RESPONSES_SKIP_REDACTION_FIELDS = frozenset(
    {
        "encrypted_content",
        "encrypted_payload",
        "encrypted_text",
        "ciphertext",
        "cipher",
        "iv",
        "nonce",
        "tag",
        "auth_tag",
        "mac",
        "hmac",
        "signature",
        "sig",
        "ephemeral_key",
        "ephemeral_public_key",
    }
)
_MAX_REDACTION_HIT_LOG_ITEMS = 24

_SYSTEM_EXEC_RUNTIME_LINE_RE = re.compile(
    r"^\s*System:\s*\[[^\]]+\]\s*Exec\s+(?:completed|failed)\b",
    re.IGNORECASE,
)

_UPSTREAM_EOF_RECOVERY_NOTICE = (
    "[AegisGate] 上游流提前断开（未收到 [DONE]）。已返回可恢复内容，建议重试获取完整结果。"
)


def _looks_like_gateway_confirmation_text(text: str) -> bool:
    body = str(text or "")
    if not body:
        return False
    lowered = body.lower()
    return (
        ("⚠️ 安全确认（高风险操作）" in body and "确认编号：" in body)
        or ("safety confirmation (high-risk action)" in lowered and "confirmation id:" in lowered)
        or ("放行（复制这一行）：yes cfm-" in body and "取消（复制这一行）：no cfm-" in body)
    )


def _looks_like_gateway_upstream_recovery_notice_text(text: str) -> bool:
    body = str(text or "")
    if not body:
        return False
    lowered = body.lower()
    return (
        _UPSTREAM_EOF_RECOVERY_NOTICE in body
        or "[aegisgate] 上游流提前断开（未收到 [done]）" in lowered
        or "upstream stream closed early (missing [done])" in lowered
    )


def _looks_like_gateway_internal_history_text(text: str) -> bool:
    return _looks_like_gateway_confirmation_text(text) or _looks_like_gateway_upstream_recovery_notice_text(text)


def _strip_system_exec_runtime_lines(text: str) -> str:
    body = str(text or "")
    if not body:
        return ""
    lines = body.splitlines()
    kept = [line for line in lines if not _SYSTEM_EXEC_RUNTIME_LINE_RE.match(line)]
    return "\n".join(kept).strip()


def _sanitize_payload_for_log(value: Any) -> Any:
    """Remove verbose fields (for example tool schema parameters) from request debug logs."""
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            if key == "parameters":
                continue
            if key == "tools":
                sanitized[key] = []
                continue
            sanitized[key] = _sanitize_payload_for_log(item)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_payload_for_log(item) for item in value]
    return value


@lru_cache(maxsize=1)
def _responses_function_output_redaction_patterns() -> tuple[tuple[str, re.Pattern[str]], ...]:
    rules = load_security_rules()
    redaction_rules = rules.get("redaction", {})
    compiled: list[tuple[str, re.Pattern[str]]] = []
    for item in redaction_rules.get("pii_patterns", []):
        if not isinstance(item, dict):
            continue
        pattern_id = str(item.get("id", "PII")).upper()
        regex = item.get("regex")
        if not regex:
            continue
        try:
            compiled.append((pattern_id, re.compile(str(regex))))
        except re.error:
            continue
    field_patterns = redaction_rules.get("field_value_patterns", [])
    if field_patterns:
        for idx, item in enumerate(field_patterns, start=1):
            if isinstance(item, dict):
                pattern_id = str(item.get("id", f"FIELD_SECRET_{idx}")).upper()
                regex = item.get("regex")
            else:
                pattern_id = f"FIELD_SECRET_{idx}"
                regex = item
            if not regex:
                continue
            try:
                compiled.append((pattern_id, re.compile(str(regex), re.IGNORECASE)))
            except re.error:
                continue
    else:
        min_len = max(8, int(redaction_rules.get("field_value_min_len", 12)))
        defaults: list[tuple[str, str]] = [
            (
                "FIELD_SECRET",
                rf"(?i)\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|password|passwd|client[_-]?secret|private[_-]?key|secret(?:_key)?)\b\s*[:=]\s*(?:bearer\s+)?[A-Za-z0-9._~+/=-]{{{min_len},}}",
            ),
            (
                "AUTH_BEARER",
                rf"(?i)\bauthorization\b\s*:\s*bearer\s+[A-Za-z0-9._~+/=-]{{{min_len},}}",
            ),
        ]
        for pattern_id, regex in defaults:
            try:
                compiled.append((pattern_id, re.compile(regex, re.IGNORECASE)))
            except re.error:
                continue
    return tuple(compiled)


@lru_cache(maxsize=1)
def _responses_relaxed_redaction_patterns() -> tuple[tuple[str, re.Pattern[str]], ...]:
    selected: list[tuple[str, re.Pattern[str]]] = []
    for pattern_id, pattern in _responses_function_output_redaction_patterns():
        if pattern_id in _RESPONSES_RELAXED_PII_IDS:
            selected.append((pattern_id, pattern))
    return tuple(selected)


def _sanitize_text_for_upstream_with_hits(
    text: str,
    *,
    role: str,
    path: str,
    field: str,
    whitelist_keys: set[str] | None = None,
) -> tuple[str, list[dict[str, Any]]]:
    if not text:
        return "", []
    if looks_like_base64_blob(text):
        return text, []
    if "[REDACTED:" in text:
        return _strip_system_exec_runtime_lines(text), []

    cleaned = _strip_system_exec_runtime_lines(text)
    if not cleaned:
        return "", []

    patterns = (
        _responses_relaxed_redaction_patterns()
        if role in _RESPONSES_RELAXED_REDACTION_ROLES
        else _responses_function_output_redaction_patterns()
    )
    hits: list[dict[str, Any]] = []
    whitelist = set(normalize_whitelist_keys(whitelist_keys))
    normalized_field = str(field or "").strip().lower()
    if normalized_field and normalized_field in whitelist:
        return cleaned, []
    for pattern_id, pattern in patterns:
        protected_spans = protected_spans_for_text(cleaned, whitelist)
        match_count = 0
        first_raw = ""

        def _repl(match: re.Match[str]) -> str:
            nonlocal match_count, first_raw
            if protected_spans and range_overlaps_protected(
                protected_spans,
                start=match.start(),
                end=match.end(),
            ):
                return match.group(0)
            if not first_raw:
                first_raw = match.group(0)
            match_count += 1
            return f"[REDACTED:{pattern_id}]"

        cleaned = pattern.sub(_repl, cleaned)
        if match_count <= 0:
            continue
        hits.append(
            {
                "path": path,
                "field": field,
                "role": role or "unknown",
                "pattern": pattern_id,
                "count": match_count,
                "masked_value": mask_for_log(first_raw),
            }
        )
    return cleaned, hits


def _sanitize_function_output_value(value: Any) -> Any:
    if isinstance(value, str):
        cleaned, _ = _sanitize_text_for_upstream_with_hits(
            value,
            role="tool",
            path="input[*].output",
            field="output",
        )
        return cleaned
    if isinstance(value, list):
        return [_sanitize_function_output_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _sanitize_function_output_value(item) for key, item in value.items()}
    return value


def _should_skip_responses_field_redaction(field: str) -> bool:
    normalized = str(field or "").strip().lower()
    if not normalized:
        return False
    if normalized in _RESPONSES_NON_CONTENT_KEYS:
        return True
    if normalized in _RESPONSES_SKIP_REDACTION_FIELDS:
        return True
    return normalized.endswith(
        (
            "_ciphertext",
            "_encrypted",
            "_encrypted_content",
            "_auth_tag",
            "_nonce",
            "_iv",
            "_mac",
            "_signature",
        )
    )


def _sanitize_responses_input_for_upstream_with_hits(
    value: Any,
    *,
    whitelist_keys: set[str] | None = None,
) -> tuple[Any, list[dict[str, Any]]]:
    """Sanitize structured responses history before forwarding upstream."""
    hits: list[dict[str, Any]] = []
    seen: set[int] = set()

    def _sanitize(node: Any, *, path: str, role: str = "", field: str = "") -> Any:
        if isinstance(node, str):
            if _should_skip_responses_field_redaction(field):
                return node
            cleaned, node_hits = _sanitize_text_for_upstream_with_hits(
                node,
                role=role,
                path=path,
                field=field or "text",
                whitelist_keys=whitelist_keys,
            )
            hits.extend(node_hits)
            return cleaned

        if isinstance(node, list):
            out: list[Any] = []
            for idx, item in enumerate(node):
                sanitized_item = _sanitize(item, path=f"{path}[{idx}]", role=role, field=field)
                if sanitized_item is None:
                    continue
                out.append(sanitized_item)
            return out

        if isinstance(node, dict):
            node_id = id(node)
            if node_id in seen:
                return node
            seen.add(node_id)

            node_type = str(node.get("type", "")).strip().lower()
            node_role = str(node.get("role", role)).strip().lower()

            if node_role in {"assistant", "system", "developer"}:
                content = node.get("content")
                if isinstance(content, str) and _looks_like_gateway_internal_history_text(content):
                    return None

            copied: dict[str, Any] = dict(node)
            for key, item in node.items():
                child_path = f"{path}.{key}" if path else key

                if node_type in _RESPONSES_SENSITIVE_OUTPUT_TYPES and key in {"output", "content", "result"}:
                    copied[key] = _sanitize(item, path=child_path, role="tool", field=key)
                    continue

                if key == "content" and node_role in {"assistant", "system", "developer"} and isinstance(item, list):
                    filtered_parts: list[Any] = []
                    for idx, part in enumerate(item):
                        if isinstance(part, dict):
                            text = part.get("text")
                            if isinstance(text, str) and _looks_like_gateway_internal_history_text(text):
                                continue
                        sanitized_part = _sanitize(
                            part,
                            path=f"{child_path}[{idx}]",
                            role=node_role,
                            field="content",
                        )
                        if sanitized_part is None:
                            continue
                        filtered_parts.append(sanitized_part)
                    if not filtered_parts:
                        return None
                    copied[key] = filtered_parts
                    continue

                copied[key] = _sanitize(item, path=child_path, role=node_role, field=key)
            return copied

        return node

    sanitized = _sanitize(value, path="input")
    dedup: dict[tuple[str, str, str, str], int] = {}
    for item in hits:
        key = (
            str(item.get("path") or ""),
            str(item.get("field") or ""),
            str(item.get("role") or ""),
            str(item.get("pattern") or ""),
        )
        dedup[key] = dedup.get(key, 0) + int(item.get("count") or 0)
    merged_hits = [
        {"path": path, "field": field, "role": role, "pattern": pattern, "count": count}
        for (path, field, role, pattern), count in dedup.items()
    ]
    return sanitized, merged_hits


def _sanitize_responses_input_for_upstream(value: Any, *, whitelist_keys: set[str] | None = None) -> Any:
    sanitized, _ = _sanitize_responses_input_for_upstream_with_hits(value, whitelist_keys=whitelist_keys)
    return sanitized
