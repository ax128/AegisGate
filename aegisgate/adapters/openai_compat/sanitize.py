"""Request/response redaction and sanitization helpers.

These functions handle PII redaction for responses API structured input,
function output sanitization, and request payload log sanitization.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from functools import lru_cache
from typing import Any

from aegisgate.config.redact_values import load_redact_values, replace_exact_values_from
from aegisgate.config.security_rules import (
    is_low_false_positive_route,
    load_security_rules,
    rule_enabled,
    select_relaxed_pii_patterns,
)
from aegisgate.config.settings import settings
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
_NON_CONTENT_KEYS = frozenset(
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
# Upper bound on hit rows kept in memory while walking one payload. Only
# _MAX_REDACTION_HIT_LOG_ITEMS of them ever reach the audit log; the rest exist
# to make the total count meaningful, and a generic provider payload can hold
# far more string leaves than that number is worth.
_MAX_COLLECTED_REDACTION_HITS = 2048
# Nesting depth ceiling for the shared structured walker. Real payloads sit well
# under 30 levels; the ceiling exists so a hostile body fails as a 400 instead
# of exhausting the interpreter stack.
_MAX_STRUCTURED_DEPTH = 128

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


def active_exact_values() -> tuple[str, ...]:
    """The configured exact values, snapshotted once for one payload walk.

    ``load_redact_values`` is mtime-cached but still stats the file on every
    call, and the forward path walks every string leaf of a request — a coding
    agent's payload has a lot of them. Entry points resolve this once and thread
    it down; an empty tuple makes the per-leaf step a single truth test.
    """
    if not settings.enable_exact_value_redaction:
        return ()
    return tuple(load_redact_values())


def _apply_exact_values(
    text: str, values: Sequence[str] | None
) -> tuple[str, list[dict[str, Any]]]:
    """Exact-value replacement for one leaf, plus the hit row it produces.

    ``None`` means the caller did not snapshot the list, so resolve it here —
    that keeps entry points that do not thread it working rather than silently
    skipping exact values.
    """
    resolved = active_exact_values() if values is None else values
    if not resolved:
        return text, []
    replaced, count = replace_exact_values_from(text, resolved)
    if count <= 0:
        return text, []
    return replaced, [{"count": count}]


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
        if not rule_enabled(item):
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
                if not rule_enabled(item):
                    continue
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
    return tuple(select_relaxed_pii_patterns(_responses_function_output_redaction_patterns()))


def _sanitize_text_for_upstream_with_hits(
    text: str,
    *,
    role: str,
    path: str,
    field: str,
    whitelist_keys: set[str] | None = None,
    relaxed_patterns: bool,
    exact_values: Sequence[str] | None = None,
) -> tuple[str, list[dict[str, Any]]]:
    """Redact one string leaf.

    ``relaxed_patterns`` says whether to use the relaxed (credential-only by
    default) id set or the full one, and it is **required**: it used to default
    to a role check, and every role a real request carries is in the relaxed-role
    set — so "derive from role" meant "always relaxed", regardless of route. The
    pipeline picks by route, so on any route that is not on the
    low-false-positive list the two layers disagreed: the scoring pass saw the
    full set while the pass that actually rewrote the outbound body saw the
    relaxed one. Making this a required argument is what stops that from
    reappearing by omission.
    """
    if not text:
        return "", []
    if looks_like_base64_blob(text):
        return text, []

    cleaned = _strip_system_exec_runtime_lines(text)
    if not cleaned:
        return "", []

    # Exact values run before the PII regexes, matching the pipeline's own order
    # (ExactValueRedactionFilter sits ahead of RedactionFilter). The filter only
    # ever rewrote flattened InternalRequest text, which structured chat /
    # responses payloads do not forward — so a configured value went upstream in
    # cleartext on exactly the routes that carry structured content.
    cleaned, exact_hits = _apply_exact_values(cleaned, exact_values)

    use_relaxed = relaxed_patterns
    patterns = (
        _responses_relaxed_redaction_patterns()
        if use_relaxed
        else _responses_function_output_redaction_patterns()
    )
    # Note the order: the exact-value pass above runs even for a whitelisted
    # field. That matches the pipeline layer — ExactValueRedactionFilter does not
    # consult the per-request whitelist either — so the operator's "never let
    # these strings out" list means the same thing on both layers.
    hits: list[dict[str, Any]] = [
        {
            "path": path,
            "field": field,
            "role": role or "unknown",
            "pattern": "EXACT_VALUE",
            "count": hit["count"],
            "masked_value": "[configured]",
        }
        for hit in exact_hits
    ]
    whitelist = set(normalize_whitelist_keys(whitelist_keys))
    normalized_field = str(field or "").strip().lower()
    if normalized_field and normalized_field in whitelist:
        return cleaned, hits
    def _compute_protected_spans(text: str) -> list[tuple[int, int]]:
        marker_spans = [
            (match.start(), match.end())
            for match in _REDACTED_MARKER_RE.finditer(text)
        ]
        return _merge_spans(protected_spans_for_text(text, whitelist) + marker_spans)

    # Spans only move when a substitution actually rewrites `cleaned`, so compute
    # them once and refresh after a pattern that changed the text. Recomputing per
    # pattern re-scanned the same string once for every PII pattern (11+ by default)
    # on every string node of every message.
    protected_spans = _compute_protected_spans(cleaned)
    for pattern_id, pattern in patterns:
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
        protected_spans = _compute_protected_spans(cleaned)
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


def _skip_non_content_field(field: str | None) -> bool:
    """Structural / tool-linkage fields that must be forwarded verbatim."""
    return str(field or "").strip().lower() in _NON_CONTENT_KEYS


def _never_skip_field(field: str | None) -> bool:  # noqa: ARG001
    return False


def _record_hits(hits: list[dict[str, Any]], node_hits: list[dict[str, Any]]) -> None:
    """Append node hits, keeping the accumulator bounded.

    Hits exist for the audit log, which samples _MAX_REDACTION_HIT_LOG_ITEMS
    rows anyway.  On a generic provider payload with tens of thousands of string
    leaves an unbounded accumulator is pure memory growth on the hot path, so it
    stops collecting once the cap is reached — the log line still reports that
    the sample was truncated.
    """
    room = _MAX_COLLECTED_REDACTION_HITS - len(hits)
    if room <= 0:
        return
    hits.extend(node_hits[:room])


def _merge_redaction_hits(hits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse per-match hits into one row per (path, field, role, pattern)."""
    dedup: dict[tuple[str, str, str, str], int] = {}
    for item in hits:
        key = (
            str(item.get("path") or ""),
            str(item.get("field") or ""),
            str(item.get("role") or ""),
            str(item.get("pattern") or ""),
        )
        dedup[key] = dedup.get(key, 0) + int(item.get("count") or 0)
    return [
        {"path": path, "field": field, "role": role, "pattern": pattern, "count": count}
        for (path, field, role, pattern), count in dedup.items()
    ]


def _sanitize_structured_node(
    node: Any,
    *,
    path: str,
    role: str,
    field: str,
    hits: list[dict[str, Any]],
    whitelist_keys: set[str] | None = None,
    media_block_type: str | None = None,
    skip_field: Callable[[str | None], bool] = _skip_non_content_field,
    relaxed_patterns: bool,
    exact_values: Sequence[str] | None = None,
    depth: int = 0,
) -> Any:
    """Walk a JSON-like node and redact every string leaf, preserving the shape.

    Shared by the chat / messages-system / tool-definition / generic-payload
    entry points so they cannot drift apart on skip rules or hit accounting.

    Raises ``ValueError("payload_depth_shape_violation")`` past
    _MAX_STRUCTURED_DEPTH so a hostile nesting depth surfaces as the regular 400
    shape-violation response instead of an uncaught RecursionError 500.
    """
    if depth > _MAX_STRUCTURED_DEPTH:
        raise ValueError("payload_depth_shape_violation")

    if isinstance(node, str):
        if skip_field(field):
            return node
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
                relaxed_patterns=relaxed_patterns,
                exact_values=exact_values,
            )
            _record_hits(hits, node_hits)
            return node

        cleaned, node_hits = _sanitize_text_for_upstream_with_hits(
            node,
            role=role,
            path=path,
            field=field,
            whitelist_keys=whitelist_keys,
            relaxed_patterns=relaxed_patterns,
            exact_values=exact_values,
        )
        _record_hits(hits, node_hits)
        return cleaned

    if isinstance(node, list):
        return [
            _sanitize_structured_node(
                item,
                path=f"{path}[{idx}]",
                role=role,
                field=field,
                hits=hits,
                whitelist_keys=whitelist_keys,
                media_block_type=media_block_type,
                skip_field=skip_field,
                relaxed_patterns=relaxed_patterns,
                exact_values=exact_values,
                depth=depth + 1,
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
        if isinstance(item, (str, list, dict)):
            copied[key] = _sanitize_structured_node(
                item,
                path=f"{path}.{key}" if path else key,
                role=role,
                field=key,
                hits=hits,
                whitelist_keys=whitelist_keys,
                media_block_type=next_media_block_type,
                skip_field=skip_field,
                relaxed_patterns=relaxed_patterns,
                exact_values=exact_values,
                depth=depth + 1,
            )
    return copied


def _sanitize_function_output_value(
    value: Any, exact_values: Sequence[str] | None = None
) -> Any:
    resolved = active_exact_values() if exact_values is None else exact_values
    if isinstance(value, str):
        cleaned, _ = _sanitize_text_for_upstream_with_hits(
            value,
            role="tool",
            path="input[*].output",
            field="output",
            relaxed_patterns=True,
            exact_values=resolved,
        )
        return cleaned
    if isinstance(value, list):
        return [_sanitize_function_output_value(item, resolved) for item in value]
    if isinstance(value, dict):
        return {
            key: _sanitize_function_output_value(item, resolved)
            for key, item in value.items()
        }
    return value


def _sanitize_chat_messages_for_upstream_with_hits(
    messages: list[Any],
    *,
    route: str,
    whitelist_keys: set[str] | None = None,
) -> tuple[list[Any], list[dict[str, Any]]]:
    """Sanitize structured chat message content without flattening payload shape.

    ``route`` rather than a bool: the mapping from route to pattern set is the
    pipeline's rule, and duplicating it at each call site is how the two layers
    drifted apart in the first place. Callers pass where the request came in;
    this decides what that means.
    """
    relaxed = is_low_false_positive_route(route)
    exact_values = active_exact_values()
    hits: list[dict[str, Any]] = []

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
                copied_message[key] = _sanitize_structured_node(
                    item,
                    path=f"messages[{idx}].{key}",
                    role=role,
                    field=key,
                    hits=hits,
                    whitelist_keys=whitelist_keys,
                    relaxed_patterns=relaxed,
                    exact_values=exact_values,
                )
        sanitized_messages.append(copied_message)

    return sanitized_messages, _merge_redaction_hits(hits)


def _sanitize_messages_system_for_upstream_with_hits(
    value: Any,
    *,
    route: str,
    whitelist_keys: set[str] | None = None,
) -> tuple[Any, list[dict[str, Any]]]:
    relaxed = is_low_false_positive_route(route)
    hits: list[dict[str, Any]] = []
    sanitized = _sanitize_structured_node(
        value,
        path="system",
        role="system",
        field="system",
        hits=hits,
        whitelist_keys=whitelist_keys,
        skip_field=_never_skip_field,
        relaxed_patterns=relaxed,
        exact_values=active_exact_values(),
    )
    return sanitized, _merge_redaction_hits(hits)


def _sanitize_instructions_for_upstream_with_hits(
    value: Any,
    *,
    route: str,
    whitelist_keys: set[str] | None = None,
) -> tuple[Any, list[dict[str, Any]]]:
    """Redact the Responses-API ``instructions`` field before forwarding.

    ``instructions`` carries the system prompt on the Responses path, which is
    where coding clients put environment details, absolute paths and internal
    service URLs — it has to go through the same redaction as ``input``.
    """
    relaxed = is_low_false_positive_route(route)
    hits: list[dict[str, Any]] = []
    sanitized = _sanitize_structured_node(
        value,
        path="instructions",
        role="system",
        field="instructions",
        hits=hits,
        whitelist_keys=whitelist_keys,
        relaxed_patterns=relaxed,
        exact_values=active_exact_values(),
    )
    return sanitized, _merge_redaction_hits(hits)


def _sanitize_tool_definitions_for_upstream_with_hits(
    tools: Any,
    *,
    route: str,
    whitelist_keys: set[str] | None = None,
) -> tuple[Any, list[dict[str, Any]]]:
    """Redact tool/function definitions before forwarding.

    Descriptions, parameter defaults and enum values routinely carry sample
    credentials and internal hostnames. Tool names stay verbatim (they are in
    the non-content key set) so the upstream tool-call linkage is unaffected.
    """
    relaxed = is_low_false_positive_route(route)
    hits: list[dict[str, Any]] = []
    sanitized = _sanitize_structured_node(
        tools,
        path="tools",
        role="system",
        field="tools",
        hits=hits,
        whitelist_keys=whitelist_keys,
        relaxed_patterns=relaxed,
        exact_values=active_exact_values(),
    )
    return sanitized, _merge_redaction_hits(hits)


def _sanitize_generic_payload_for_upstream_with_hits(
    payload: Any,
    *,
    whitelist_keys: set[str] | None = None,
    relaxed_patterns: bool = False,
) -> tuple[Any, list[dict[str, Any]]]:
    """Redact an arbitrary provider payload forwarded by the generic proxy.

    The generic ``/v1/<subpath>`` routes (embeddings, rerank, provider-native
    endpoints) have no known message schema, so every string leaf is walked with
    the same skip rules the Responses path uses for cipher blobs and structural
    keys.

    ``relaxed_patterns`` must mirror what RedactionFilter uses for the same
    route.  It defaults to False — the full id set — because generic routes are
    not in LOW_FALSE_POSITIVE_V1_ROUTES: deriving the set from the node role
    instead would silently drop EMAIL/PHONE/ID/CARD here while the pipeline
    scored the very same request with all of them.
    """
    hits: list[dict[str, Any]] = []
    sanitized = _sanitize_structured_node(
        payload,
        path="$",
        role="user",
        field="",
        hits=hits,
        whitelist_keys=whitelist_keys,
        skip_field=_should_skip_responses_field_redaction,
        relaxed_patterns=relaxed_patterns,
        exact_values=active_exact_values(),
    )
    return sanitized, _merge_redaction_hits(hits)


def _should_skip_responses_field_redaction(field: str | None) -> bool:
    normalized = str(field or "").strip().lower()
    if not normalized:
        return False
    if normalized in _NON_CONTENT_KEYS:
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
    route: str,
    whitelist_keys: set[str] | None = None,
) -> tuple[Any, list[dict[str, Any]]]:
    """Sanitize structured responses history before forwarding upstream."""
    relaxed = is_low_false_positive_route(route)
    exact_values = active_exact_values()
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
                    relaxed_patterns=relaxed,
                    exact_values=exact_values,
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
                relaxed_patterns=relaxed,
                exact_values=exact_values,
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
    return sanitized, _merge_redaction_hits(hits)


def _sanitize_responses_input_for_upstream(
    value: Any, *, whitelist_keys: set[str] | None = None
) -> Any:
    sanitized, _ = _sanitize_responses_input_for_upstream_with_hits(
        value, whitelist_keys=whitelist_keys
    )
    return sanitized


def _preserves_json_shape(original: Any, sanitized: Any) -> bool:
    """Return True when *sanitized* has exactly the structure of *original*.

    Compares the two trees directly and returns on the first difference.  The
    earlier implementation materialised a ``(path, type)`` tuple for every node
    of both trees before comparing them, which on the generic proxy — where the
    whole body is walked and bodies run to tens of megabytes — cost two extra
    full traversals plus the allocations, on the request hot path.
    """
    if isinstance(original, dict):
        if not isinstance(sanitized, dict) or len(original) != len(sanitized):
            return False
        for key, item in original.items():
            if key not in sanitized:
                return False
            if not _preserves_json_shape(item, sanitized[key]):
                return False
        return True
    if isinstance(sanitized, dict):
        return False

    if isinstance(original, list):
        if not isinstance(sanitized, list) or len(original) != len(sanitized):
            return False
        return all(
            _preserves_json_shape(item, other)
            for item, other in zip(original, sanitized)
        )
    if isinstance(sanitized, list):
        return False

    return type(original) is type(sanitized)
