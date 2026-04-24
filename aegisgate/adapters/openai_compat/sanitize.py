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
_RESPONSES_RELAXED_REDACTION_ROLES = frozenset(
    {"system", "developer", "assistant", "user", "tool"}
)
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
_RESPONSES_NON_CONTENT_KEYS = frozenset(
    {"id", "call_id", "tool_call_id", "type", "role", "name", "status"}
)
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
_REDACTED_MARKER_RE = re.compile(r"\[REDACTED:[A-Z0-9_]+\]")

_UPSTREAM_EOF_RECOVERY_NOTICE = "[AegisGate] 上游流提前断开（未收到 [DONE]）。已返回可恢复内容，建议重试获取完整结果。"
_GATEWAY_INTERNAL_HISTORY_PLACEHOLDER = "[REDACTED:GATEWAY_INTERNAL_HISTORY]"

_MEDIA_LOCATOR_FIELDS = frozenset({"image_url", "file_id"})
_MEDIA_URL_FIELDS = frozenset({"url", "uri"})
_MEDIA_SOURCE_URL_BLOCK_TYPES = frozenset(
    {
        "image",
        "input_image",
        "document",
        "input_document",
        "audio",
        "input_audio",
        "video",
        "input_video",
        "file",
        "input_file",
    }
)
_CONTENT_BLOCK_PATH_RE = re.compile(r"(?:^|\.)content\[\d+\]$")
_SYSTEM_BLOCK_PATH_RE = re.compile(r"^system\[\d+\]$")


def _is_media_block_container_path(path: str) -> bool:
    lowered = (path or "").lower()
    return bool(
        _CONTENT_BLOCK_PATH_RE.search(lowered) or _SYSTEM_BLOCK_PATH_RE.match(lowered)
    )


def _is_media_locator_field(
    *,
    path: str,
    field: str | None,
    media_block_type: str | None = None,
) -> bool:
    normalized = str(field or "").strip().lower()
    if not normalized:
        return False
    if normalized in _MEDIA_LOCATOR_FIELDS:
        return True
    if normalized in _MEDIA_URL_FIELDS:
        lowered = (path or "").lower()
        # Chat: messages[*].content[*].image_url.url
        # Responses: input[*].content[*].image_url (string) or nested image_url.url
        if ".image_url." in lowered:
            return True
        if lowered.endswith(".source.url") or lowered.endswith(".source.uri"):
            normalized_block_type = str(media_block_type or "").strip().lower()
            return normalized_block_type in _MEDIA_SOURCE_URL_BLOCK_TYPES
    return False


def _looks_like_gateway_confirmation_text(text: str | None) -> bool:
    body = str(text or "")
    if not body:
        return False
    lowered = body.lower()
    return (
        ("⚠️ 安全确认（高风险操作）" in body and "确认编号：" in body)
        or (
            "safety confirmation (high-risk action)" in lowered
            and "confirmation id:" in lowered
        )
        or (
            "放行（复制这一行）：yes cfm-" in body
            and "取消（复制这一行）：no cfm-" in body
        )
    )


def _looks_like_gateway_upstream_recovery_notice_text(text: str | None) -> bool:
    body = str(text or "")
    if not body:
        return False
    lowered = body.lower()
    return (
        _UPSTREAM_EOF_RECOVERY_NOTICE in body
        or "[aegisgate] 上游流提前断开（未收到 [done]）" in lowered
        or "upstream stream closed early (missing [done])" in lowered
    )


def _looks_like_gateway_internal_history_text(text: str | None) -> bool:
    return _looks_like_gateway_confirmation_text(
        text
    ) or _looks_like_gateway_upstream_recovery_notice_text(text)


def _strip_system_exec_runtime_lines(text: str | None) -> str:
    body = str(text or "")
    if not body:
        return ""
    lines = body.splitlines()
    kept = [line for line in lines if not _SYSTEM_EXEC_RUNTIME_LINE_RE.match(line)]
    return "\n".join(kept).strip()


def _merge_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not spans:
        return []
    ordered = sorted(spans, key=lambda item: item[0])
    merged: list[tuple[int, int]] = []
    for start, end in ordered:
        if end <= start:
            continue
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
            continue
        merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return merged


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
def _responses_function_output_redaction_patterns() -> tuple[
    tuple[str, re.Pattern[str]], ...
]:
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
        marker_spans = [
            (match.start(), match.end())
            for match in _REDACTED_MARKER_RE.finditer(cleaned)
        ]
        protected_spans = _merge_spans(protected_spans + marker_spans)
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
        return {
            key: _sanitize_function_output_value(item) for key, item in value.items()
        }
    return value


def _sanitize_chat_messages_for_upstream_with_hits(
    messages: list[Any],
    *,
    whitelist_keys: set[str] | None = None,
) -> tuple[list[Any], list[dict[str, Any]]]:
    """Sanitize structured chat message content without flattening payload shape."""
    hits: list[dict[str, Any]] = []

    def _sanitize_structured_part(
        node: Any,
        *,
        path: str,
        role: str,
        field: str,
        media_block_type: str | None = None,
    ) -> Any:
        if isinstance(node, str):
            # Media locator fields (image_url/file_id) must be forwarded as-is.
            # We still scan and record redaction hits for audit visibility.
            if _is_media_locator_field(
                path=path,
                field=field,
                media_block_type=media_block_type,
            ):
                _, node_hits = _sanitize_text_for_upstream_with_hits(
                    node,
                    role=role,
                    path=path,
                    field=field,
                    whitelist_keys=whitelist_keys,
                )
                hits.extend(node_hits)
                return node

            cleaned, node_hits = _sanitize_text_for_upstream_with_hits(
                node,
                role=role,
                path=path,
                field=field,
                whitelist_keys=whitelist_keys,
            )
            hits.extend(node_hits)
            return cleaned

        if isinstance(node, list):
            return [
                _sanitize_structured_part(
                    item,
                    path=f"{path}[{idx}]",
                    role=role,
                    field=field,
                    media_block_type=media_block_type,
                )
                for idx, item in enumerate(node)
            ]

        if not isinstance(node, dict):
            return node

        next_media_block_type = media_block_type
        if _is_media_block_container_path(path):
            block_type = str(node.get("type", "")).strip().lower()
            if block_type:
                next_media_block_type = block_type

        copied: dict[str, Any] = dict(node)
        for key, item in node.items():
            child_path = f"{path}.{key}" if path else key
            if isinstance(item, (str, list, dict)):
                copied[key] = _sanitize_structured_part(
                    item,
                    path=child_path,
                    role=role,
                    field=key,
                    media_block_type=next_media_block_type,
                )
        return copied

    sanitized_messages: list[Any] = []
    for idx, message in enumerate(messages):
        if not isinstance(message, dict):
            sanitized_messages.append(message)
            continue
        copied_message = dict(message)
        role = str(message.get("role", "")).strip().lower() or "user"
        for key, item in message.items():
            if key == "role":
                continue
            if isinstance(item, (str, list, dict)):
                copied_message[key] = _sanitize_structured_part(
                    item,
                    path=f"messages[{idx}].{key}",
                    role=role,
                    field=key,
                    media_block_type=None,
                )
        sanitized_messages.append(copied_message)

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
    return sanitized_messages, merged_hits


def _sanitize_messages_system_for_upstream_with_hits(
    value: Any,
    *,
    whitelist_keys: set[str] | None = None,
) -> tuple[Any, list[dict[str, Any]]]:
    hits: list[dict[str, Any]] = []

    def _sanitize_system_part(
        node: Any,
        *,
        path: str,
        field: str,
        media_block_type: str | None = None,
    ) -> Any:
        if isinstance(node, str):
            if _is_media_locator_field(
                path=path,
                field=field,
                media_block_type=media_block_type,
            ):
                _, node_hits = _sanitize_text_for_upstream_with_hits(
                    node,
                    role="system",
                    path=path,
                    field=field,
                    whitelist_keys=whitelist_keys,
                )
                hits.extend(node_hits)
                return node

            cleaned, node_hits = _sanitize_text_for_upstream_with_hits(
                node,
                role="system",
                path=path,
                field=field,
                whitelist_keys=whitelist_keys,
            )
            hits.extend(node_hits)
            return cleaned

        if isinstance(node, list):
            return [
                _sanitize_system_part(
                    item,
                    path=f"{path}[{idx}]",
                    field=field,
                    media_block_type=media_block_type,
                )
                for idx, item in enumerate(node)
            ]

        if not isinstance(node, dict):
            return node

        next_media_block_type = media_block_type
        if _is_media_block_container_path(path):
            block_type = str(node.get("type", "")).strip().lower()
            if block_type:
                next_media_block_type = block_type

        copied: dict[str, Any] = dict(node)
        for key, item in node.items():
            child_path = f"{path}.{key}" if path else key
            if isinstance(item, (str, list, dict)):
                copied[key] = _sanitize_system_part(
                    item,
                    path=child_path,
                    field=key,
                    media_block_type=next_media_block_type,
                )
        return copied

    sanitized = _sanitize_system_part(value, path="system", field="system")
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


def _should_skip_responses_field_redaction(field: str | None) -> bool:
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

    def _sanitize(
        node: Any,
        *,
        path: str,
        role: str = "",
        field: str = "",
        media_block_type: str | None = None,
    ) -> Any:
        if isinstance(node, str):
            if role in {
                "assistant",
                "system",
                "developer",
            } and _looks_like_gateway_internal_history_text(node):
                return _GATEWAY_INTERNAL_HISTORY_PLACEHOLDER
            if _is_media_locator_field(
                path=path,
                field=field,
                media_block_type=media_block_type,
            ):
                _, node_hits = _sanitize_text_for_upstream_with_hits(
                    node,
                    role=role,
                    path=path,
                    field=field or "text",
                    whitelist_keys=whitelist_keys,
                )
                hits.extend(node_hits)
                return node
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
                sanitized_item = _sanitize(
                    item,
                    path=f"{path}[{idx}]",
                    role=role,
                    field=field,
                    media_block_type=media_block_type,
                )
                out.append(sanitized_item)
            return out

        if isinstance(node, dict):
            node_id = id(node)
            if node_id in seen:
                return node
            seen.add(node_id)

            node_type = str(node.get("type", "")).strip().lower()
            node_role = str(node.get("role", role)).strip().lower()
            next_media_block_type = media_block_type
            if _is_media_block_container_path(path) and node_type:
                next_media_block_type = node_type

            copied: dict[str, Any] = dict(node)

            for key, item in node.items():
                child_path = f"{path}.{key}" if path else key

                # Skip redaction of function_call arguments — these are
                # model-generated tool invocations in conversation history.
                # Redacting file paths in them (e.g. SYS_HOME_PATH) corrupts
                # the context and prevents coding agents from referencing
                # their own prior tool calls.
                if node_type == "function_call" and key == "arguments":
                    copied[key] = item
                    continue

                if node_type in _RESPONSES_SENSITIVE_OUTPUT_TYPES and key in {
                    "output",
                    "content",
                    "result",
                }:
                    copied[key] = _sanitize(
                        item,
                        path=child_path,
                        role="tool",
                        field=key,
                        media_block_type=next_media_block_type,
                    )
                    continue

                if (
                    key == "content"
                    and node_role in {"assistant", "system", "developer"}
                    and isinstance(item, list)
                ):
                    copied[key] = [
                        _sanitize(
                            part,
                            path=f"{child_path}[{idx}]",
                            role=node_role,
                            field="content",
                            media_block_type=next_media_block_type,
                        )
                        for idx, part in enumerate(item)
                    ]
                    continue

                copied[key] = _sanitize(
                    item,
                    path=child_path,
                    role=node_role,
                    field=key,
                    media_block_type=next_media_block_type,
                )

            # Sanitize tool/function name to match upstream pattern ^[a-zA-Z0-9_-]+
            if (
                node_type in {"function_call", "function", "function_call_output"}
                and "name" in copied
                and isinstance(copied["name"], str)
            ):
                sanitized_name = re.sub(r"[^a-zA-Z0-9_-]", "_", copied["name"])
                copied["name"] = sanitized_name or "_"

            return copied

        return node

    sanitized = _sanitize(value, path="input", media_block_type=None)
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


def _sanitize_responses_input_for_upstream(
    value: Any, *, whitelist_keys: set[str] | None = None
) -> Any:
    sanitized, _ = _sanitize_responses_input_for_upstream_with_hits(
        value, whitelist_keys=whitelist_keys
    )
    return sanitized


def _shape_signature(value: Any) -> tuple[tuple[str, str], ...]:
    """Return a deterministic structural signature for nested JSON-like payloads."""

    signature: list[tuple[str, str]] = []

    def _walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            signature.append((path, "dict"))
            for key, item in node.items():
                child = f"{path}.{key}" if path else str(key)
                _walk(item, child)
            return
        if isinstance(node, list):
            signature.append((path, f"list:{len(node)}"))
            for idx, item in enumerate(node):
                _walk(item, f"{path}[{idx}]")
            return
        signature.append((path, type(node).__name__))

    _walk(value, "$")
    return tuple(signature)


def _preserves_json_shape(original: Any, sanitized: Any) -> bool:
    return _shape_signature(original) == _shape_signature(sanitized)
