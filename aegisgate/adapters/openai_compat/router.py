"""OpenAI-compatible routes."""

from __future__ import annotations

import copy
import json
import logging
import asyncio
import re
import threading
import time
from functools import lru_cache
from typing import Any, AsyncGenerator, AsyncIterable, Generator, Iterable, Mapping
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse

from aegisgate.adapters.openai_compat.mapper import (
    to_chat_response,
    to_internal_chat,
    to_internal_responses,
    to_responses_output,
)
from aegisgate.adapters.openai_compat.stream_utils import (
    _build_streaming_response,
    _extract_sse_data_payload,
    _extract_stream_event_type,
    _extract_stream_text_from_event,
    _stream_block_reason,
    _stream_block_sse_chunk,
    _stream_confirmation_sse_chunk,
    _stream_done_sse_chunk,
    _stream_error_sse_chunk,
)
from aegisgate.adapters.openai_compat.upstream import (
    _build_forward_headers,
    _build_upstream_url,
    _effective_gateway_headers,
    _forward_json,
    _forward_stream_lines,
    _is_upstream_whitelisted,
    _resolve_upstream_base,
    _safe_error_detail,
    close_upstream_async_client,
)
from aegisgate.config.settings import settings
from aegisgate.config.security_rules import load_security_rules
from aegisgate.util.masking import mask_for_log
from aegisgate.core.audit import write_audit
from aegisgate.core.confirmation import (
    make_confirm_id,
    make_action_bind_token,
    parse_confirmation_decision,
    payload_hash,
)
from aegisgate.core.confirmation_flow import (
    PHASE_REQUEST,
    PHASE_RESPONSE,
    build_confirmation_message as _flow_confirmation_message,
    build_confirmation_metadata as _flow_confirmation_metadata,
    get_reason_and_summary as _flow_reason_and_summary,
)
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalMessage, InternalRequest, InternalResponse
from aegisgate.core.semantic import SemanticServiceClient
from aegisgate.core.pipeline import Pipeline
from aegisgate.filters.anomaly_detector import AnomalyDetector
from aegisgate.filters.injection_detector import PromptInjectionDetector
from aegisgate.filters.post_restore_guard import PostRestoreGuard
from aegisgate.filters.privilege_guard import PrivilegeGuard
from aegisgate.filters.request_sanitizer import RequestSanitizer
from aegisgate.filters.rag_poison_guard import RagPoisonGuard
from aegisgate.filters.redaction import RedactionFilter
from aegisgate.filters.restoration import RestorationFilter
from aegisgate.filters.sanitizer import OutputSanitizer
from aegisgate.filters.tool_call_guard import ToolCallGuard
from aegisgate.policies.policy_engine import PolicyEngine
from aegisgate.storage import create_store
from aegisgate.util.debug_excerpt import debug_log_original
from aegisgate.util.logger import logger


router = APIRouter()
store = create_store()
policy_engine = PolicyEngine()
semantic_service_client = SemanticServiceClient(
    service_url=settings.semantic_service_url,
    cache_ttl_seconds=settings.semantic_cache_ttl_seconds,
    max_cache_entries=settings.semantic_cache_max_entries,
    failure_threshold=settings.semantic_circuit_failure_threshold,
    open_seconds=settings.semantic_circuit_open_seconds,
)
_GATEWAY_PREFIX = "/v1"
_STREAM_WINDOW_MAX_CHARS = 8000
_STREAM_SEMANTIC_CHECK_INTERVAL = 4
_TRUNCATED_SUFFIX = " [TRUNCATED]"
_PENDING_PAYLOAD_OMITTED_KEY = "_aegisgate_pending_payload_omitted"
_PENDING_PAYLOAD_KIND_KEY = "_aegisgate_pending_kind"
_PENDING_PAYLOAD_KIND_RESPONSE = "response_payload"
_PENDING_PAYLOAD_FORMAT_KEY = "_aegisgate_pending_format"
_PENDING_PAYLOAD_ROUTE_KEY = "_aegisgate_pending_route"
_PENDING_PAYLOAD_MODEL_KEY = "_aegisgate_pending_model"
_PENDING_PAYLOAD_REQUEST_ID_KEY = "_aegisgate_pending_request_id"
_PENDING_PAYLOAD_SESSION_ID_KEY = "_aegisgate_pending_session_id"
_PENDING_PAYLOAD_CONTENT_KEY = "content"
_PENDING_FORMAT_CHAT_JSON = "chat_json"
_PENDING_FORMAT_RESPONSES_JSON = "responses_json"
_PENDING_FORMAT_CHAT_STREAM_TEXT = "chat_stream_text"
_PENDING_FORMAT_RESPONSES_STREAM_TEXT = "responses_stream_text"
_CONFIRMATION_RELEASE_EMPTY_TEXT = (
    "[AegisGate] 已放行该确认，但被拦截响应未包含可回放文本（可能仅包含工具调用事件）。"
    "请重新发送上一条业务请求以继续执行。"
)
_UPSTREAM_EOF_RECOVERY_NOTICE = (
    "[AegisGate] 上游流提前断开（未收到 [DONE]）。已返回可恢复内容，建议重试获取完整结果。"
)
_GENERIC_EXTRACT_MAX_CHARS = 16000
_CONFIRMATION_HIT_CONTEXT_CHARS = 40
_GENERIC_BINARY_RE = re.compile(r"[A-Za-z0-9+/]{512,}={0,2}")
_SYSTEM_EXEC_RUNTIME_LINE_RE = re.compile(
    r"^\s*System:\s*\[[^\]]+\]\s*Exec\s+(?:completed|failed)\b",
    re.IGNORECASE,
)
_pipeline_local = threading.local()


def _build_pipeline() -> Pipeline:
    request_filters = [
        RedactionFilter(store),
        RequestSanitizer(),
        RagPoisonGuard(),
    ]
    response_filters = [
        AnomalyDetector(),
        PromptInjectionDetector(),
        RagPoisonGuard(),
        PrivilegeGuard(),
        ToolCallGuard(),
        RestorationFilter(store),
        PostRestoreGuard(),
        OutputSanitizer(),
    ]
    return Pipeline(request_filters=request_filters, response_filters=response_filters)


def _get_pipeline() -> Pipeline:
    pipeline = getattr(_pipeline_local, "pipeline", None)
    if pipeline is None:
        pipeline = _build_pipeline()
        _pipeline_local.pipeline = pipeline
    return pipeline


async def close_semantic_async_client() -> None:
    await semantic_service_client.aclose()


def _should_stream(payload: dict[str, Any]) -> bool:
    return bool(payload.get("stream") is True)


def _trim_stream_window(current: str, chunk: str) -> str:
    merged = f"{current}{chunk}"
    if len(merged) <= _STREAM_WINDOW_MAX_CHARS:
        return merged
    return merged[-_STREAM_WINDOW_MAX_CHARS:]


def _build_upstream_eof_replay_text(cached_text: str) -> str:
    text = (cached_text or "").strip()
    if not text:
        return _UPSTREAM_EOF_RECOVERY_NOTICE
    return f"{text}\n\n{_UPSTREAM_EOF_RECOVERY_NOTICE}"


# 调试时完整请求内容最大输出长度，避免日志过长
_DEBUG_REQUEST_BODY_MAX_CHARS = 32000
_DEBUG_HEADERS_REDACT = frozenset(
    {"gateway-key", "authorization", "x-aegis-signature", "x-aegis-timestamp", "x-aegis-nonce"}
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
        "COOKIE_SESSION",
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
        # encryption/cipher blobs should be forwarded as-is to avoid breaking payload semantics
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


def _sanitize_payload_for_log(value: Any) -> Any:
    """Remove verbose fields (for example tool schema parameters) from request debug logs."""
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            if key == "parameters":
                continue
            if key == "tools":
                # Keep field for troubleshooting but omit tool list details from debug logs.
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
) -> tuple[str, list[dict[str, Any]]]:
    if not text:
        return "", []
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
    for pattern_id, pattern in patterns:
        match_list = list(pattern.finditer(cleaned))
        if not match_list:
            continue
        first_raw = match_list[0].group(0)
        hits.append(
            {
                "path": path,
                "field": field,
                "role": role or "unknown",
                "pattern": pattern_id,
                "count": len(match_list),
                "masked_value": mask_for_log(first_raw),
            }
        )
        cleaned = pattern.sub(f"[REDACTED:{pattern_id}]", cleaned)
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


def _log_request_if_debug(request: Request, payload: dict[str, Any], route: str) -> None:
    """当 AEGIS_LOG_LEVEL=debug 时打请求概要（method/path/route/headers）；正文按 log_full_request_body 决定是否打印、分段打印。"""
    if not logger.isEnabledFor(logging.DEBUG):
        return
    headers_safe = {}
    for k, v in request.headers.items():
        key_lower = k.lower()
        if key_lower in _DEBUG_HEADERS_REDACT or "key" in key_lower or "secret" in key_lower or "token" in key_lower:
            headers_safe[k] = "***"
        else:
            headers_safe[k] = v
    payload_for_log = _sanitize_payload_for_log(payload)
    try:
        body_str = json.dumps(payload_for_log, ensure_ascii=False, indent=2)
    except (TypeError, ValueError):
        body_str = str(payload_for_log)
    total_len = len(body_str)
    logger.debug(
        "incoming request method=%s path=%s route=%s headers=%s body_size=%d",
        request.method,
        request.url.path,
        route,
        headers_safe,
        total_len,
    )
    if not settings.log_full_request_body:
        return
    if total_len <= _DEBUG_REQUEST_BODY_MAX_CHARS:
        logger.debug("incoming request body (%d chars):\n%s", total_len, body_str)
        return
    offset = 0
    segment = 0
    while offset < total_len:
        chunk = body_str[offset : offset + _DEBUG_REQUEST_BODY_MAX_CHARS]
        segment += 1
        logger.debug(
            "incoming request body segment %d (chars %d-%d of %d):\n%s",
            segment,
            offset + 1,
            min(offset + _DEBUG_REQUEST_BODY_MAX_CHARS, total_len),
            total_len,
            chunk,
        )
        offset += _DEBUG_REQUEST_BODY_MAX_CHARS


def _flatten_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "".join(part for part in (_flatten_text(item) for item in value) if part)
    if isinstance(value, dict):
        if isinstance(value.get("text"), str):
            return value["text"]
        for key in ("content", "message", "output", "choices"):
            if key in value:
                chunk = _flatten_text(value[key])
                if chunk:
                    return chunk
    return ""


def _extract_chat_output_text(upstream_body: dict[str, Any] | str) -> str:
    if isinstance(upstream_body, str):
        return upstream_body
    choices = upstream_body.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            text = _flatten_text(first.get("message", {}).get("content", ""))
            if text:
                return text
    for key in ("output_text", "text", "output"):
        if key in upstream_body:
            text = _flatten_text(upstream_body[key])
            if text:
                return text
    return json.dumps(upstream_body, ensure_ascii=False)


def _extract_responses_output_text(upstream_body: dict[str, Any] | str) -> str:
    if isinstance(upstream_body, str):
        return upstream_body
    for key in ("output_text", "output", "text", "choices"):
        if key in upstream_body:
            text = _flatten_text(upstream_body[key])
            if text:
                return text
    return json.dumps(upstream_body, ensure_ascii=False)


def _is_structured_content(value: Any) -> bool:
    return isinstance(value, (list, dict))


def _build_chat_upstream_payload(payload: dict[str, Any], sanitized_req_messages: list) -> dict[str, Any]:
    upstream_payload = dict(payload)
    original_messages = payload.get("messages", [])
    updated_messages: list[dict[str, Any]] = []
    for idx, message in enumerate(sanitized_req_messages):
        merged: dict[str, Any] = {}
        if idx < len(original_messages) and isinstance(original_messages[idx], dict):
            merged = dict(original_messages[idx])
        merged["role"] = message.role
        original_content = merged.get("content")
        if _is_structured_content(original_content):
            # Preserve multimodal structure (image/audio/video/file parts) for upstream compatibility.
            merged["content"] = original_content
        else:
            merged["content"] = message.content
        if message.source:
            merged["source"] = message.source
        if message.metadata:
            merged["metadata"] = message.metadata
        updated_messages.append(merged)
    upstream_payload["messages"] = updated_messages
    return upstream_payload


def _build_responses_upstream_payload(
    payload: dict[str, Any],
    sanitized_req_messages: list,
    *,
    request_id: str = "-",
    session_id: str = "-",
    route: str = "-",
) -> dict[str, Any]:
    upstream_payload = dict(payload)
    if sanitized_req_messages:
        original_input = payload.get("input")
        if _is_structured_content(original_input):
            sanitized_input, redaction_hits = _sanitize_responses_input_for_upstream_with_hits(original_input)
            upstream_payload["input"] = sanitized_input
            if redaction_hits:
                sample = redaction_hits[:_MAX_REDACTION_HIT_LOG_ITEMS]
                # WARNING 级别：含敏感字段的请求属于安全审计事件
                logger.warning(
                    "responses input redaction request_id=%s session_id=%s route=%s hits=%d positions=%s truncated=%s",
                    request_id,
                    session_id,
                    route,
                    len(redaction_hits),
                    sample,
                    len(redaction_hits) > _MAX_REDACTION_HIT_LOG_ITEMS,
                )
        else:
            upstream_payload["input"] = _strip_system_exec_runtime_lines(str(sanitized_req_messages[0].content))
    return upstream_payload


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


def _sanitize_responses_input_for_upstream_with_hits(value: Any) -> tuple[Any, list[dict[str, Any]]]:
    """
    Sanitize structured responses history before forwarding upstream.
    This pass is idempotent and records redaction hit positions.
    """
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


def _sanitize_responses_input_for_upstream(value: Any) -> Any:
    sanitized, _ = _sanitize_responses_input_for_upstream_with_hits(value)
    return sanitized


def _extract_generic_analysis_text(value: Any) -> str:
    chunks: list[str] = []
    remaining = _GENERIC_EXTRACT_MAX_CHARS

    def _append_text(raw: str) -> None:
        nonlocal remaining
        if remaining <= 0:
            return
        text = raw.strip()
        if not text:
            return
        if text.lower().startswith(("data:image/", "data:audio/", "data:video/")):
            text = "[BINARY_CONTENT]"
        elif len(text) > 1024 and _GENERIC_BINARY_RE.search(text):
            text = "[BINARY_CONTENT]"
        if len(text) > remaining:
            text = text[:remaining]
        chunks.append(text)
        remaining -= len(text)

    def _walk(node: Any) -> None:
        if remaining <= 0:
            return
        if isinstance(node, str):
            _append_text(node)
            return
        if isinstance(node, (int, float, bool)):
            _append_text(str(node))
            return
        if isinstance(node, list):
            for item in node:
                _walk(item)
                if remaining <= 0:
                    break
            return
        if isinstance(node, dict):
            for key, item in node.items():
                if key in {"image", "image_url", "audio", "video", "file", "input_image", "input_audio"}:
                    _append_text("[BINARY_CONTENT]")
                    continue
                _walk(item)
                if remaining <= 0:
                    break

    _walk(value)
    return " ".join(chunks).strip()


def _render_chat_response(upstream_body: dict[str, Any] | str, final_resp: InternalResponse) -> dict[str, Any]:
    if isinstance(upstream_body, dict):
        out = copy.deepcopy(upstream_body)
        choices = out.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0]
            if not isinstance(first, dict):
                first = {}
            message = first.get("message")
            if not isinstance(message, dict):
                message = {"role": "assistant"}
            message["content"] = final_resp.output_text
            first["message"] = message
            choices[0] = first
            out["choices"] = choices
            out.setdefault("id", final_resp.request_id)
            out.setdefault("object", "chat.completion")
            out.setdefault("model", final_resp.model)
            if final_resp.metadata.get("aegisgate"):
                out["aegisgate"] = final_resp.metadata["aegisgate"]
            return out
    return to_chat_response(final_resp)


def _passthrough_chat_response(upstream_body: dict[str, Any] | str, req: Any) -> dict[str, Any]:
    if isinstance(upstream_body, dict):
        return upstream_body
    return to_chat_response(
        InternalResponse(
            request_id=req.request_id,
            session_id=req.session_id,
            model=req.model,
            output_text=str(upstream_body),
        )
    )


def _render_responses_output(upstream_body: dict[str, Any] | str, final_resp: InternalResponse) -> dict[str, Any]:
    if isinstance(upstream_body, dict):
        out = copy.deepcopy(upstream_body)
        out["output_text"] = final_resp.output_text
        out.setdefault("id", final_resp.request_id)
        out.setdefault("object", "response")
        out.setdefault("model", final_resp.model)
        if final_resp.metadata.get("aegisgate"):
            out["aegisgate"] = final_resp.metadata["aegisgate"]
        return out
    return to_responses_output(final_resp)


def _passthrough_responses_output(upstream_body: dict[str, Any] | str, req: Any) -> dict[str, Any]:
    if isinstance(upstream_body, dict):
        return upstream_body
    return to_responses_output(
        InternalResponse(
            request_id=req.request_id,
            session_id=req.session_id,
            model=req.model,
            output_text=str(upstream_body),
        )
    )


def _serialized_payload_size(payload: dict[str, Any]) -> int:
    try:
        return len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    except Exception:
        return 0


def _validate_payload_limits(payload: dict[str, Any], route: str) -> tuple[bool, int, str, str]:
    max_body = int(settings.max_request_body_bytes)
    if max_body > 0:
        body_size = _serialized_payload_size(payload)
        if body_size > max_body:
            return False, 413, "request_body_too_large", f"payload bytes={body_size} exceeds max={max_body}"

    max_messages = int(settings.max_messages_count)
    if route == "/v1/chat/completions":
        messages = payload.get("messages", [])
        if not isinstance(messages, list):
            return False, 400, "invalid_messages_format", "messages must be a list"
        if max_messages > 0 and len(messages) > max_messages:
            return False, 400, "messages_too_many", f"messages count={len(messages)} exceeds max={max_messages}"

    return True, 200, "", ""


def _cap_response_text(text: str, ctx: RequestContext) -> str:
    max_len = int(settings.max_response_length)
    if max_len <= 0 or len(text) <= max_len:
        return text
    ctx.security_tags.add("response_truncated")
    ctx.enforcement_actions.append("response:length_cap")
    ctx.disposition_reasons.append("response_length_truncated")
    return f"{text[:max_len]}{_TRUNCATED_SUFFIX}"


def _prepare_pending_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], str, bool, int]:
    payload_size = _serialized_payload_size(payload)
    max_pending_bytes = int(settings.max_pending_payload_bytes)
    if max_pending_bytes > 0 and payload_size > max_pending_bytes:
        omitted_payload = {
            _PENDING_PAYLOAD_OMITTED_KEY: True,
            "payload_size_bytes": payload_size,
        }
        return omitted_payload, payload_hash(omitted_payload), True, payload_size
    return payload, payload_hash(payload), False, payload_size


def _build_response_pending_payload(
    *,
    route: str,
    request_id: str,
    session_id: str,
    model: str,
    fmt: str,
    content: Any,
) -> dict[str, Any]:
    return {
        _PENDING_PAYLOAD_KIND_KEY: _PENDING_PAYLOAD_KIND_RESPONSE,
        _PENDING_PAYLOAD_FORMAT_KEY: fmt,
        _PENDING_PAYLOAD_ROUTE_KEY: route,
        _PENDING_PAYLOAD_REQUEST_ID_KEY: request_id,
        _PENDING_PAYLOAD_SESSION_ID_KEY: session_id,
        _PENDING_PAYLOAD_MODEL_KEY: model,
        _PENDING_PAYLOAD_CONTENT_KEY: content,
    }


def _prepare_response_pending_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], str, int]:
    payload_size = _serialized_payload_size(payload)
    return payload, payload_hash(payload), payload_size


def _is_response_pending_payload(payload: Any) -> bool:
    return isinstance(payload, dict) and str(payload.get(_PENDING_PAYLOAD_KIND_KEY, "")).strip() == _PENDING_PAYLOAD_KIND_RESPONSE


def _confirmation_expires_at(now_ts: int, phase: str) -> int:
    if phase == PHASE_RESPONSE:
        return now_ts + max(60, int(settings.pending_data_ttl_seconds))
    return now_ts + max(30, int(settings.confirmation_ttl_seconds))


def _attach_executed_confirmation(output: dict[str, Any], *, confirm_id: str, reason: str, summary: str) -> dict[str, Any]:
    aegis = output.setdefault("aegisgate", {})
    aegis["confirmation"] = {
        "required": False,
        "confirm_id": confirm_id,
        "status": "executed",
        "reason": reason,
        "summary": summary,
        "payload_omitted": False,
    }
    return output


def _render_cached_chat_confirmation_output(
    pending_payload: dict[str, Any],
    *,
    fallback_request_id: str,
    fallback_session_id: str,
    fallback_model: str,
) -> dict[str, Any] | None:
    if not _is_response_pending_payload(pending_payload):
        return None
    fmt = str(pending_payload.get(_PENDING_PAYLOAD_FORMAT_KEY, "")).strip()
    content = pending_payload.get(_PENDING_PAYLOAD_CONTENT_KEY)
    request_id = str(pending_payload.get(_PENDING_PAYLOAD_REQUEST_ID_KEY) or fallback_request_id)
    session_id = str(pending_payload.get(_PENDING_PAYLOAD_SESSION_ID_KEY) or fallback_session_id)
    model = str(pending_payload.get(_PENDING_PAYLOAD_MODEL_KEY) or fallback_model)
    if fmt == _PENDING_FORMAT_CHAT_JSON and isinstance(content, dict):
        return copy.deepcopy(content)
    if fmt == _PENDING_FORMAT_CHAT_STREAM_TEXT and isinstance(content, str):
        replay_text = content if content.strip() else _CONFIRMATION_RELEASE_EMPTY_TEXT
        return to_chat_response(
            InternalResponse(
                request_id=request_id,
                session_id=session_id,
                model=model,
                output_text=replay_text,
            )
        )
    return None


def _render_cached_responses_confirmation_output(
    pending_payload: dict[str, Any],
    *,
    fallback_request_id: str,
    fallback_session_id: str,
    fallback_model: str,
) -> dict[str, Any] | None:
    if not _is_response_pending_payload(pending_payload):
        return None
    fmt = str(pending_payload.get(_PENDING_PAYLOAD_FORMAT_KEY, "")).strip()
    content = pending_payload.get(_PENDING_PAYLOAD_CONTENT_KEY)
    request_id = str(pending_payload.get(_PENDING_PAYLOAD_REQUEST_ID_KEY) or fallback_request_id)
    session_id = str(pending_payload.get(_PENDING_PAYLOAD_SESSION_ID_KEY) or fallback_session_id)
    model = str(pending_payload.get(_PENDING_PAYLOAD_MODEL_KEY) or fallback_model)
    if fmt == _PENDING_FORMAT_RESPONSES_JSON and isinstance(content, dict):
        return copy.deepcopy(content)
    if fmt == _PENDING_FORMAT_RESPONSES_STREAM_TEXT and isinstance(content, str):
        replay_text = content if content.strip() else _CONFIRMATION_RELEASE_EMPTY_TEXT
        return to_responses_output(
            InternalResponse(
                request_id=request_id,
                session_id=session_id,
                model=model,
                output_text=replay_text,
            )
        )
    return None


def _render_cached_chat_confirmation_stream_output(
    *,
    request_id: str,
    model: str,
    content: str,
    confirm_id: str,
    reason: str,
    summary: str,
) -> StreamingResponse:
    replay_text = content if content.strip() else _CONFIRMATION_RELEASE_EMPTY_TEXT
    confirmation_meta = {
        "required": False,
        "confirm_id": confirm_id,
        "status": "executed",
        "reason": reason,
        "summary": summary,
        "payload_omitted": False,
    }

    def _generator() -> Generator[bytes, None, None]:
        payload = {
            "id": request_id,
            "object": "chat.completion.chunk",
            "model": model,
            "choices": [
                {"index": 0, "delta": {"role": "assistant", "content": replay_text}, "finish_reason": "stop"}
            ],
            "aegisgate": {"action": "allow", "confirmation": confirmation_meta},
        }
        yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8")
        yield _stream_done_sse_chunk()

    return _build_streaming_response(_generator())


def _iter_responses_text_stream_replay(
    *,
    request_id: str,
    model: str,
    replay_text: str,
    aegisgate_meta: dict[str, Any],
) -> Generator[bytes, None, None]:
    item_id = f"msg_{(request_id or 'resp')[:12]}"

    def _with_meta(payload: dict[str, Any]) -> dict[str, Any]:
        payload["aegisgate"] = aegisgate_meta
        return payload

    output_item_completed = {
        "type": "message",
        "id": item_id,
        "role": "assistant",
        "status": "completed",
        "content": [{"type": "output_text", "text": replay_text, "annotations": []}],
    }

    events = [
        {
            "type": "response.created",
            "response": {"id": request_id, "object": "response", "model": model, "status": "in_progress", "output": []},
        },
        {
            "type": "response.output_item.added",
            "response_id": request_id,
            "output_index": 0,
            "item": {"type": "message", "id": item_id, "role": "assistant", "status": "in_progress", "content": []},
        },
        {
            "type": "response.content_part.added",
            "response_id": request_id,
            "item_id": item_id,
            "output_index": 0,
            "content_index": 0,
            "part": {"type": "output_text", "text": ""},
        },
        {
            "type": "response.output_text.delta",
            "response_id": request_id,
            "item_id": item_id,
            "output_index": 0,
            "content_index": 0,
            "delta": replay_text,
        },
        {
            "type": "response.output_text.done",
            "response_id": request_id,
            "item_id": item_id,
            "output_index": 0,
            "content_index": 0,
            "text": "",
        },
        {
            "type": "response.content_part.done",
            "response_id": request_id,
            "item_id": item_id,
            "output_index": 0,
            "content_index": 0,
            "part": {"type": "output_text", "text": ""},
        },
        {
            "type": "response.output_item.done",
            "response_id": request_id,
            "output_index": 0,
            "item": output_item_completed,
        },
        {
            "type": "response.completed",
            "response": {
                "id": request_id,
                "object": "response",
                "model": model,
                "status": "completed",
                "output": [output_item_completed],
            },
        },
    ]
    for payload in events:
        yield f"data: {json.dumps(_with_meta(payload), ensure_ascii=False)}\n\n".encode("utf-8")
    yield _stream_done_sse_chunk()


def _iter_responses_stream_finalize(
    *,
    request_id: str,
    model: str,
    aegisgate_meta: dict[str, Any],
) -> Generator[bytes, None, None]:
    payload = {
        "type": "response.completed",
        "response": {
            "id": request_id,
            "object": "response",
            "model": model,
            "status": "completed",
            "output": [],
        },
        "aegisgate": aegisgate_meta,
    }
    yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8")
    yield _stream_done_sse_chunk()


def _render_cached_responses_confirmation_stream_output(
    *,
    request_id: str,
    model: str,
    content: str,
    confirm_id: str,
    reason: str,
    summary: str,
) -> StreamingResponse:
    replay_text = content if content.strip() else _CONFIRMATION_RELEASE_EMPTY_TEXT
    confirmation_meta = {
        "required": False,
        "confirm_id": confirm_id,
        "status": "executed",
        "reason": reason,
        "summary": summary,
        "payload_omitted": False,
    }
    logger.info(
        "confirmation stream replay responses request_id=%s confirm_id=%s events=%s content_chars=%s",
        request_id,
        confirm_id,
        "response.created,response.output_item.added,response.content_part.added,response.output_text.delta,response.output_text.done,response.content_part.done,response.output_item.done,response.completed,[DONE]",
        len(replay_text),
    )

    def _generator() -> Generator[bytes, None, None]:
        yield from _iter_responses_text_stream_replay(
            request_id=request_id,
            model=model,
            replay_text=replay_text,
            aegisgate_meta={"action": "allow", "confirmation": confirmation_meta},
        )

    return _build_streaming_response(_generator())


def _is_pending_payload_omitted(payload: Any) -> bool:
    return isinstance(payload, dict) and bool(payload.get(_PENDING_PAYLOAD_OMITTED_KEY))


def prune_pending_confirmations(now_ts: int) -> int:
    return int(store.prune_pending_confirmations(now_ts))


def clear_pending_confirmations_on_startup() -> int:
    """启动时清空所有待确认记录，使重启后仅新请求的确认有效。"""
    if hasattr(store, "clear_all_pending_confirmations"):
        return store.clear_all_pending_confirmations()
    return 0


async def _maybe_offload(func: Any, *args: Any, **kwargs: Any) -> Any:
    if settings.enable_thread_offload:
        return await asyncio.to_thread(func, *args, **kwargs)
    return func(*args, **kwargs)


async def _run_request_pipeline(pipeline: Pipeline, req: Any, ctx: RequestContext) -> Any:
    return await _maybe_offload(pipeline.run_request, req, ctx)


async def _run_response_pipeline(pipeline: Pipeline, resp: InternalResponse, ctx: RequestContext) -> InternalResponse:
    return await _maybe_offload(pipeline.run_response, resp, ctx)


async def _store_call(method_name: str, *args: Any, **kwargs: Any) -> Any:
    method = getattr(store, method_name)
    return await _maybe_offload(method, *args, **kwargs)


async def _delete_pending_confirmation(confirm_id: str) -> bool:
    method = getattr(store, "delete_pending_confirmation", None)
    if not callable(method):
        return False
    try:
        return bool(await _maybe_offload(method, confirm_id=confirm_id))
    except TypeError:
        return bool(await _maybe_offload(method, confirm_id))
    except Exception as exc:
        logger.warning("delete pending confirmation failed confirm_id=%s error=%s", confirm_id, exc)
        return False


def _extract_chat_user_text(payload: dict[str, Any]) -> str:
    messages = payload.get("messages", [])
    if not isinstance(messages, list):
        return ""
    for item in reversed(messages):
        if not isinstance(item, dict):
            continue
        if item.get("role", "user") != "user":
            continue
        content = item.get("content", "")
        if isinstance(content, list):
            return " ".join(str(part.get("text", "")) if isinstance(part, dict) else str(part) for part in content).strip()
        return str(content).strip()
    return ""


def _extract_latest_user_text_from_responses_input(raw_input: Any) -> str:
    if isinstance(raw_input, str):
        return _strip_system_exec_runtime_lines(raw_input)
    if isinstance(raw_input, list):
        for item in reversed(raw_input):
            if not isinstance(item, dict):
                continue
            if str(item.get("role", "")).strip().lower() != "user":
                continue
            if "content" in item:
                return _strip_system_exec_runtime_lines(_flatten_text(item.get("content")))
            return _strip_system_exec_runtime_lines(_flatten_text(item))
        return _strip_system_exec_runtime_lines(_flatten_text(raw_input))
    if isinstance(raw_input, dict):
        role = str(raw_input.get("role", "")).strip().lower()
        if role == "user":
            if "content" in raw_input:
                return _strip_system_exec_runtime_lines(_flatten_text(raw_input.get("content")))
            return _strip_system_exec_runtime_lines(_flatten_text(raw_input))
        if "input" in raw_input:
            return _extract_latest_user_text_from_responses_input(raw_input.get("input"))
        if "content" in raw_input:
            return _strip_system_exec_runtime_lines(_flatten_text(raw_input.get("content")))
        return _strip_system_exec_runtime_lines(_flatten_text(raw_input))
    return _strip_system_exec_runtime_lines(str(raw_input or ""))


def _extract_responses_user_text(payload: dict[str, Any]) -> str:
    return _extract_latest_user_text_from_responses_input(payload.get("input", ""))


def _request_user_text_for_excerpt(payload: dict[str, Any], route: str) -> str:
    """取请求侧用户输入文本，用于 debug 原文摘要（截断展示）。"""
    if route == "/v1/responses":
        return _extract_responses_user_text(payload)
    return _extract_chat_user_text(payload)


def _request_target_path(request: Request, *, fallback_path: str | None = None) -> str:
    """返回 path+query 形式的上游目标路径，确保 query 参数可透传到上游。"""
    base_path = fallback_path or request.url.path or "/"
    query = request.url.query
    if query:
        return f"{base_path}?{query}"
    return base_path


def _needs_confirmation(ctx: RequestContext) -> bool:
    if ctx.response_disposition in {"block", "sanitize"}:
        return True
    if ctx.requires_human_review:
        return True
    return any(tag.startswith("response_") for tag in ctx.security_tags)


def _confirmation_reason_and_summary(
    ctx: RequestContext,
    phase: str = PHASE_RESPONSE,
    *,
    source_text: str = "",
) -> tuple[str, str]:
    reason, summary = _flow_reason_and_summary(phase, ctx.disposition_reasons, ctx.security_tags)
    return reason, _append_safe_hit_preview(summary, ctx, source_text=source_text)


def _obfuscate_hit_fragment(text: str, *, max_chars: int | None = None) -> str:
    compact = re.sub(r"\s+", " ", str(text or "").strip())
    if not compact:
        return ""
    if max_chars is not None and max_chars > 0 and len(compact) > max_chars:
        compact = f"{compact[:max_chars]}..."

    words = compact.split(" ")
    encoded_words: list[str] = []
    for word in words:
        if not word:
            continue
        lowered = word.lower()
        if lowered.startswith(("ratio=", "max_run=", "line_repeat=", "invisible_count=")):
            encoded_words.append(word)
            continue
        if len(word) <= 3:
            encoded_words.append(word)
            continue
        grouped = [word[i : i + 3] for i in range(0, len(word), 3)]
        encoded_words.append("-".join(grouped))
    return " ".join(encoded_words)


def _collect_confirmation_hit_fragments(ctx: RequestContext) -> list[str]:
    fragments: list[str] = []
    for item in reversed(ctx.report_items):
        if not isinstance(item, dict) or not bool(item.get("hit")):
            continue

        evidence = item.get("evidence")
        if isinstance(evidence, dict):
            for values in evidence.values():
                if not isinstance(values, list):
                    continue
                for raw in values:
                    value = str(raw or "").strip()
                    if not value:
                        continue
                    lowered = value.lower()
                    if lowered.startswith(("ratio=", "max_run=", "line_repeat=", "invisible_count=")):
                        continue
                    # Skip rule IDs (for example `curl_pipe_sh`) and keep text-like evidence.
                    if re.fullmatch(r"[a-z0-9_]{2,40}", lowered):
                        continue
                    fragments.append(value)

    deduped: list[str] = []
    for value in fragments:
        if value not in deduped:
            deduped.append(value)
    return deduped


def _extract_hit_context_segments(source_text: str, hit_text: str, *, context_chars: int = _CONFIRMATION_HIT_CONTEXT_CHARS) -> list[str]:
    source = str(source_text or "")
    hit = str(hit_text or "")
    if not source or not hit:
        return []
    escaped = re.escape(hit)
    matches = list(re.finditer(escaped, source, flags=re.IGNORECASE))
    if not matches:
        return []
    segments: list[str] = []
    for match in matches:
        start = match.start()
        end = match.end()
        left_start = max(0, start - context_chars)
        right_end = min(len(source), end + context_chars)
        left = source[left_start:start]
        mid = source[start:end]
        right = source[end:right_end]
        segment = f"{left}{mid}{right}"
        if left_start > 0:
            segment = f"…{segment}"
        if right_end < len(source):
            segment = f"{segment}…"
        segments.append(segment.strip())
    return segments


def _append_safe_hit_preview(summary: str, ctx: RequestContext, *, source_text: str = "") -> str:
    if not settings.confirmation_show_hit_preview:
        return summary

    fragments = _collect_confirmation_hit_fragments(ctx)
    if not fragments:
        fragments = _collect_source_hit_fragments(source_text)
    if not fragments:
        return summary

    preview_items: list[str] = []
    for item in fragments:
        segments = _extract_hit_context_segments(source_text, item, context_chars=_CONFIRMATION_HIT_CONTEXT_CHARS)
        if segments:
            preview_items.extend(segments)
        else:
            # Fallback when source text is unavailable or cannot be matched.
            preview_items.append(item)

    obfuscated = [_obfuscate_hit_fragment(item) for item in preview_items]
    obfuscated = [item for item in obfuscated if item]
    if not obfuscated:
        return summary
    suffix = f"；命中片段（安全变形）：{'；'.join(obfuscated)}"
    return f"{summary}{suffix}"


@lru_cache(maxsize=1)
def _confirmation_hit_regex_patterns() -> tuple[re.Pattern[str], ...]:
    rules = load_security_rules()
    pattern_strings: list[str] = []

    def _append_rule_patterns(rule_key: str, field: str) -> None:
        for item in rules.get(rule_key, {}).get(field, []):
            regex = item.get("regex") if isinstance(item, dict) else None
            if regex:
                pattern_strings.append(str(regex))

    _append_rule_patterns("anomaly_detector", "command_patterns")
    _append_rule_patterns("privilege_guard", "blocked_patterns")
    # Cover injection-only detections so confirmation can still show source hit preview.
    _append_rule_patterns("injection_detector", "direct_patterns")
    _append_rule_patterns("injection_detector", "system_exfil_patterns")
    _append_rule_patterns("injection_detector", "indirect_injection_patterns")
    _append_rule_patterns("injection_detector", "remote_content_instruction_patterns")
    _append_rule_patterns("request_sanitizer", "strong_intent_patterns")
    _append_rule_patterns("request_sanitizer", "command_patterns")
    _append_rule_patterns("sanitizer", "system_leak_patterns")
    _append_rule_patterns("sanitizer", "force_block_command_patterns")

    # Fixed fallback for text-like risky phrases that may not be present in evidence.
    pattern_strings.extend(
        [
            r"(系统提示词|开发者消息|developer\s+message|system\s+prompt)",
            r"(执行|运行).{0,12}(命令|shell|bash|powershell|cmd|脚本|终端)",
            r"(rm\s+-rf|curl\s+[^|]+\|\s*(?:sh|bash)|cat\s+~/.ssh|powershell(?:\.exe)?\s+-enc)",
        ]
    )

    deduped: list[str] = []
    for pattern in pattern_strings:
        if pattern not in deduped:
            deduped.append(pattern)

    compiled: list[re.Pattern[str]] = []
    for pattern in deduped:
        try:
            compiled.append(re.compile(pattern, re.IGNORECASE))
        except re.error:
            continue
    return tuple(compiled)


def _collect_source_hit_fragments(source_text: str) -> list[str]:
    source = str(source_text or "")
    if not source:
        return []
    patterns = _confirmation_hit_regex_patterns()
    fragments: list[str] = []
    for pattern in patterns:
        for match in pattern.finditer(source):
            value = str(match.group(0) or "").strip()
            if len(value) < 2:
                continue
            if value not in fragments:
                fragments.append(value)
            if len(fragments) >= 12:
                return fragments
    return fragments


def _semantic_gray_zone_enabled(ctx: RequestContext) -> bool:
    if not settings.enable_semantic_module:
        return False
    low = min(float(settings.semantic_gray_low), float(settings.semantic_gray_high))
    high = max(float(settings.semantic_gray_low), float(settings.semantic_gray_high))
    return low < ctx.risk_score < high


async def _apply_semantic_review(ctx: RequestContext, text: str, phase: str) -> None:
    if not _semantic_gray_zone_enabled(ctx):
        return

    result = await semantic_service_client.analyze(text=text, timeout_ms=settings.semantic_timeout_ms)
    ctx.add_report(
        {
            "filter": "semantic_module",
            "phase": phase,
            "hit": bool(result.tags),
            "timed_out": result.timed_out,
            "cache_hit": result.cache_hit,
            "risk_score": result.risk_score,
            "tags": result.tags,
            "reasons": result.reasons,
            "duration_ms": round(result.duration_ms, 3),
        }
    )

    if result.timed_out:
        ctx.security_tags.add("semantic_timeout")
        ctx.enforcement_actions.append("semantic:timeout_degraded")
        return
    if "semantic_circuit_open" in result.reasons:
        ctx.security_tags.add("semantic_circuit_open")
        ctx.enforcement_actions.append("semantic:circuit_open_degraded")
        return
    if "semantic_service_unavailable" in result.reasons:
        ctx.security_tags.add("semantic_service_unavailable")
        ctx.enforcement_actions.append("semantic:service_unavailable_degraded")
        return
    if "semantic_service_unconfigured" in result.reasons:
        ctx.security_tags.add("semantic_service_unconfigured")
        ctx.enforcement_actions.append("semantic:service_unconfigured_degraded")
        return

    if not result.tags:
        return

    for tag in result.tags:
        ctx.security_tags.add(f"{phase}_{tag}")
    for reason in result.reasons:
        ctx.disposition_reasons.append(reason)

    previous = ctx.risk_score
    ctx.risk_score = max(ctx.risk_score, float(result.risk_score))
    if ctx.risk_score > previous:
        ctx.enforcement_actions.append("semantic:risk_escalated")
    if ctx.risk_score >= ctx.risk_threshold:
        ctx.requires_human_review = True


def _to_status_code(reason: str) -> int:
    if reason in {"invalid_parameters"}:
        return 400
    if reason in {"gateway_auth_failed"}:
        return 401
    if reason in {"gateway_misconfigured"}:
        return 500
    return 400


def _extract_confirm_id(text: str) -> str:
    import re

    matches = re.findall(r"\bcfm-[a-f0-9]{12}\b", text.lower())
    if not matches:
        return ""
    return str(matches[-1])


_CONFIRMATION_TEMPLATE_PREFIX_MARKERS: tuple[str, ...] = (
    "copy this line",
    "复制这一行",
    "放行（复制这一行）",
    "取消（复制这一行）",
    "approve (copy this line):",
    "cancel (copy this line):",
    "send only one standalone copy-ready line",
    "请单独发送以下可复制消息之一",
)


def _extract_action_token(text: str) -> str:
    matches = re.findall(r"\bact-[a-f0-9]{8,16}\b", str(text or "").lower())
    if not matches:
        return ""
    return str(matches[-1])


def _extract_bound_confirm_and_action(text: str) -> tuple[str, str]:
    source = str(text or "")
    lowered = source.lower()
    matches = list(
        re.finditer(
            r"(cfm-[a-f0-9]{12})\s*(?:--|——|—|–|[-_:/|：])+\s*(act-[a-f0-9]{8,16})\b",
            lowered,
            flags=re.IGNORECASE,
        )
    )
    if not matches:
        return "", ""
    for match in reversed(matches):
        line_start = source.rfind("\n", 0, match.start()) + 1
        line_end = source.find("\n", match.end())
        if line_end < 0:
            line_end = len(source)
        prefix = source[line_start:match.start()].lower()
        line_lower = source[line_start:line_end].lower()
        if any(marker in prefix or marker in line_lower for marker in _CONFIRMATION_TEMPLATE_PREFIX_MARKERS):
            continue
        confirm_id = str(match.group(1) or "").lower()
        action_token = str(match.group(2) or "").lower()
        return confirm_id, action_token
    return "", ""


def _extract_decision_by_bound_token(user_text: str, confirm_id: str, action_token: str) -> tuple[str, str]:
    source = str(user_text or "")
    cid = str(confirm_id or "").strip().lower()
    act = str(action_token or "").strip().lower()
    if not source or not cid or not act:
        return "unknown", "missing_bind_components"
    bind_re = re.compile(
        rf"{re.escape(cid)}\s*(?:--|——|—|–|[-_:/|：])+\s*{re.escape(act)}\b",
        flags=re.IGNORECASE,
    )
    matches = list(bind_re.finditer(source))
    if not matches:
        return "unknown", "bind_not_found"
    match = matches[-1]
    line_start = source.rfind("\n", 0, match.start()) + 1
    prefix = source[line_start:match.start()]
    marker_scope = prefix.lower()
    if any(marker in marker_scope for marker in _CONFIRMATION_TEMPLATE_PREFIX_MARKERS):
        return "unknown", "system_template_prefix"

    cmd_tokens = re.findall(r"\b(?:yes|y|no|n)\b", prefix, flags=re.IGNORECASE)
    if cmd_tokens:
        cmd = str(cmd_tokens[-1]).lower()
        if cmd in {"yes", "y"}:
            return "yes", "bind_prefix_cmd"
        if cmd in {"no", "n"}:
            return "no", "bind_prefix_cmd"

    decision = parse_confirmation_decision(prefix).value
    if decision in {"yes", "no"}:
        return decision, "bind_prefix_parse"
    return "unknown", "missing_decision_before_bind"


def _pending_action_bind_token(record: Mapping[str, Any]) -> str:
    confirm_id = str(record.get("confirm_id", ""))
    reason = str(record.get("reason", ""))
    summary = str(record.get("summary", ""))
    seed = f"{confirm_id}|{reason}|{summary}"
    return make_action_bind_token(seed)


def _extract_tail_confirmation_command(text: str) -> tuple[str, str]:
    """
    优先解析“最后几行”中的确认命令，避免把整段模板里的 yes/no 一起算成 ambiguous。
    返回 (decision, confirm_id_hint)；decision in {"yes","no","unknown"}。
    """
    lines = [line.strip() for line in str(text or "").splitlines() if line and line.strip()]
    if not lines:
        return "unknown", ""
    cmd_re = re.compile(
        r"^[\s`\"'*_=\-~>#\[\]\(\)\{\}\|:：,，]*?(?P<cmd>yes|y|no|n)\b(?P<tail>.*)$",
        re.IGNORECASE,
    )
    bind_pair_re = re.compile(
        r"(?P<confirm_id>cfm-[a-f0-9]{12})\s*(?:[-—–_:/|：]|\s){1,6}(?P<action>act-[a-f0-9]{8,16})\b",
        re.IGNORECASE,
    )
    wrapped_cmd_re = re.compile(
        r"(?:^|[\]\)\}>:：\|])\s*(?P<cmd>yes|y|no|n)\s+(?P<confirm_id>cfm-[a-f0-9]{12})\b(?:\s+act-[a-f0-9]{8,16})?\s*$",
        re.IGNORECASE,
    )
    template_markers = _CONFIRMATION_TEMPLATE_PREFIX_MARKERS
    for raw in reversed(lines[-6:]):
        line = raw.strip()
        lowered = line.lower()
        if any(marker in lowered for marker in template_markers):
            continue
        bind_match = bind_pair_re.search(line)
        if bind_match:
            confirm_id = str(bind_match.group("confirm_id") or "").lower()
            prefix = line[: bind_match.start()]
            decision = "unknown"
            cmd_tokens = re.findall(r"\b(?:yes|y|no|n)\b", prefix, flags=re.IGNORECASE)
            if cmd_tokens:
                last_cmd = str(cmd_tokens[-1]).lower()
                if last_cmd in {"yes", "y"}:
                    decision = "yes"
                elif last_cmd in {"no", "n"}:
                    decision = "no"
            if decision not in {"yes", "no"}:
                decision = parse_confirmation_decision(prefix).value
            if decision in {"yes", "no"} and confirm_id:
                return decision, confirm_id
        match = cmd_re.match(line)
        if not match:
            wrapped = wrapped_cmd_re.search(line)
            if not wrapped:
                continue
            cmd = str(wrapped.group("cmd") or "").lower()
            confirm_id = str(wrapped.group("confirm_id") or "").lower()
            if cmd in {"yes", "y"}:
                return "yes", confirm_id
            if cmd in {"no", "n"}:
                return "no", confirm_id
            continue
        cmd = str(match.group("cmd") or "").lower()
        tail = str(match.group("tail") or "")
        tail = re.sub(r"[\s`\"'*_=\-~>#\]\)\}\|:：,，.;。!！?？]+$", "", tail)
        confirm_id = _extract_confirm_id(f"{cmd} {tail}")
        if cmd in {"yes", "y"}:
            return "yes", confirm_id
        if cmd in {"no", "n"}:
            return "no", confirm_id
    return "unknown", ""


def _confirmation_tail_preview(text: str, max_lines: int = 4, max_chars: int = 120) -> str:
    lines = [line.strip() for line in str(text or "").splitlines() if line and line.strip()]
    if not lines:
        return "-"
    previews: list[str] = []
    for line in lines[-max_lines:]:
        compact = re.sub(r"\s+", " ", line).strip()
        lowered = compact.lower()
        looks_like_command = (
            bool(re.search(r"\b(?:yes|y|no|n)\b", lowered))
            or "cfm-" in lowered
            or "act-" in lowered
        )
        if looks_like_command:
            if len(compact) > max_chars:
                compact = f"{compact[:max_chars]}..."
            previews.append(compact)
        else:
            previews.append(f"<non-command-line len={len(compact)}>")
    return " || ".join(previews) if previews else "-"


def _parse_explicit_confirmation_command(text: str) -> tuple[str, str]:
    decision, confirm_id = _extract_tail_confirmation_command(text)
    if decision in {"yes", "no"}:
        return decision, confirm_id
    return "unknown", ""


def _extract_decision_before_confirm_id(text: str, confirm_id: str) -> str:
    source = str(text or "")
    cid = str(confirm_id or "").strip().lower()
    if not source or not cid:
        return "unknown"
    lowered = source.lower()
    idx = lowered.rfind(cid)
    if idx < 0:
        return "unknown"
    line_start = source.rfind("\n", 0, idx) + 1
    prefix_in_line = source[line_start:idx]
    marker_scope = prefix_in_line.lower()
    template_markers = _CONFIRMATION_TEMPLATE_PREFIX_MARKERS
    if any(marker in marker_scope for marker in template_markers):
        return "unknown"
    decision = parse_confirmation_decision(prefix_in_line).value
    if decision in {"yes", "no"}:
        return decision
    window_start = max(0, idx - 120)
    decision = parse_confirmation_decision(source[window_start:idx]).value
    if decision in {"yes", "no"}:
        return decision
    return "unknown"


def _has_explicit_confirmation_keyword(text: str) -> bool:
    lines = [line.strip() for line in str(text or "").splitlines() if line and line.strip()]
    if not lines:
        return False
    template_markers = _CONFIRMATION_TEMPLATE_PREFIX_MARKERS
    for line in lines[-6:]:
        lowered = line.lower()
        if any(marker in lowered for marker in template_markers):
            continue
        if re.search(r"\b(?:yes|y|no|n)\b", line, flags=re.IGNORECASE):
            return True
    return False


def _resolve_pending_decision(user_text: str, pending_confirm_id: str, base_decision: str) -> tuple[str, str]:
    by_id_context = _extract_decision_before_confirm_id(user_text, pending_confirm_id)
    if by_id_context not in {"yes", "no"}:
        return base_decision, "base"
    if base_decision in {"yes", "no"} and base_decision != by_id_context:
        return "ambiguous", "conflict"
    return by_id_context, "id_context"


def _header_lookup(headers: Mapping[str, str], target: str) -> str:
    needle = target.strip().lower()
    if not needle:
        return ""
    for key, value in headers.items():
        if key.lower() == needle:
            return str(value).strip()
    return ""


def _resolve_tenant_id(
    *,
    payload: Mapping[str, Any] | None = None,
    headers: Mapping[str, str] | None = None,
    boundary: Mapping[str, Any] | None = None,
) -> str:
    if payload:
        for key in ("tenant_id", "tenant", "org_id"):
            value = str(payload.get(key) or "").strip()
            if value:
                return value
    if headers:
        for key in (settings.tenant_id_header, "x-tenant-id", "x-aegis-tenant-id"):
            value = _header_lookup(headers, key)
            if value:
                return value
    if boundary:
        value = str(boundary.get("tenant_id") or "").strip()
        if value:
            return value
    return "default"


def _executing_recover_before(now_ts: int) -> int | None:
    timeout_seconds = int(settings.confirmation_executing_timeout_seconds)
    if timeout_seconds <= 0:
        return None
    return int(now_ts) - max(5, timeout_seconds)


def _load_single_pending_for_session(
    payload: dict[str, Any],
    now_ts: int,
    *,
    expected_route: str,
    tenant_id: str,
) -> dict[str, Any] | None:
    session_id = str(payload.get("session_id") or payload.get("request_id") or "").strip()
    if not session_id:
        return None
    getter = getattr(store, "get_single_pending_confirmation", None)
    if not callable(getter):
        return None
    recover_before = _executing_recover_before(now_ts)
    record = getter(
        session_id=session_id,
        route=expected_route,
        now_ts=now_ts,
        tenant_id=tenant_id,
        recover_executing_before=recover_before,
    )
    if not record:
        return None
    if str(record.get("status")) != "pending":
        return None
    if int(record.get("expires_at", 0)) <= int(now_ts):
        store.update_pending_confirmation_status(confirm_id=str(record.get("confirm_id", "")), status="expired", now_ts=now_ts)
        return None
    return record


def _resolve_pending_confirmation(
    payload: dict[str, Any],
    user_text: str,
    now_ts: int,
    *,
    expected_route: str,
    tenant_id: str,
) -> dict[str, Any] | None:
    explicit_decision, explicit_confirm_id = _parse_explicit_confirmation_command(user_text)
    bind_confirm_id, bind_action_token = _extract_bound_confirm_and_action(user_text)
    confirm_id = bind_confirm_id or explicit_confirm_id
    if not confirm_id:
        return None

    record = store.get_pending_confirmation(confirm_id)
    if not record:
        return None
    if str(record.get("tenant_id") or "default") != tenant_id:
        return None
    status = str(record.get("status"))
    recover_before = _executing_recover_before(now_ts)
    if status == "executing" and recover_before is not None and int(record.get("updated_at", 0)) <= int(recover_before):
        method = getattr(store, "compare_and_update_pending_confirmation_status", None)
        changed = False
        if callable(method):
            changed = bool(
                method(
                    confirm_id=confirm_id,
                    expected_status="executing",
                    new_status="pending",
                    now_ts=now_ts,
                )
            )
        if changed:
            record = store.get_pending_confirmation(confirm_id) or {}
            status = str(record.get("status"))
    if status != "pending":
        return None
    if int(record.get("expires_at", 0)) <= int(now_ts):
        store.update_pending_confirmation_status(confirm_id=confirm_id, status="expired", now_ts=now_ts)
        return None
    merged = dict(record)
    merged["_aegisgate_bind_action_token"] = bind_action_token
    merged["_aegisgate_explicit_decision"] = explicit_decision
    return merged


def _attach_confirmation_metadata(
    resp: InternalResponse,
    *,
    confirm_id: str,
    status: str,
    reason: str,
    summary: str,
    phase: str = PHASE_RESPONSE,
    payload_omitted: bool = False,
    action_token: str = "",
) -> None:
    resolved_action_token = action_token
    if not resolved_action_token and confirm_id and reason and summary:
        resolved_action_token = make_action_bind_token(f"{confirm_id}|{reason}|{summary}")
    metadata = resp.metadata.setdefault("aegisgate", {})
    metadata["confirmation"] = _flow_confirmation_metadata(
        confirm_id=confirm_id,
        status=status,
        reason=reason,
        summary=summary,
        phase=phase,
        payload_omitted=payload_omitted,
        action_token=resolved_action_token,
    )


def _build_confirmation_message(
    confirm_id: str,
    reason: str,
    summary: str,
    phase: str = PHASE_RESPONSE,
    note: str = "",
    action_token: str = "",
) -> str:
    resolved_action_token = action_token
    if not resolved_action_token and confirm_id and reason and summary:
        resolved_action_token = make_action_bind_token(f"{confirm_id}|{reason}|{summary}")
    return _flow_confirmation_message(
        confirm_id=confirm_id,
        reason=reason,
        summary=summary,
        phase=phase,
        note=note,
        action_token=resolved_action_token,
    )


def _pending_payload_omitted_text(confirm_id: str) -> str:
    return (
        "该确认编号对应的原始请求体过大，网关未缓存完整原文，当前无法直接放行执行。\n"
        f"确认编号：{confirm_id}\n"
        "请重新发送原始请求，再按确认提示操作。\n"
        "后续普通消息不受该确认记录影响（除非再次携带该确认编号）。\n\n"
        "The original payload for this confirmation was too large and was not fully cached.\n"
        f"Confirmation ID: {confirm_id}\n"
        "Please resend the original request, then follow the confirmation prompt again.\n"
        "Subsequent normal messages are not blocked by this confirmation unless you include this ID again."
    )


def _confirmation_already_processed_text(confirm_id: str) -> str:
    return (
        "该确认请求已被处理（可能已执行、取消或过期），请勿重复确认。\n"
        f"确认编号：{confirm_id}\n\n"
        "This confirmation has already been processed (executed, canceled, or expired).\n"
        f"Confirmation ID: {confirm_id}"
    )


def _confirmation_execute_failed_text(confirm_id: str) -> str:
    return (
        "确认已收到，但执行上游请求失败，请稍后重试。\n"
        f"确认编号：{confirm_id}\n\n"
        "Confirmation received, but executing the upstream request failed.\n"
        f"Confirmation ID: {confirm_id}\n"
        "Please retry later."
    )


def _confirmation_action_token_required_text(confirm_id: str, action_token: str) -> str:
    bind = f"{confirm_id}--{action_token}" if action_token else confirm_id
    return (
        "确认消息缺少动作摘要码，无法校验放行目标。\n"
        f"确认编号：{confirm_id}\n"
        f"动作摘要码：{action_token}\n\n"
        "请单独发送以下任一可复制消息：\n"
        f"yes {bind}\n"
        f"no {bind}\n\n"
        "Missing action bind token in confirmation message.\n"
        f"Confirmation ID: {confirm_id}\n"
        f"Action Bind Token: {action_token}\n"
        "Send one standalone line:\n"
        f"yes {bind}\n"
        f"no {bind}"
    )


def _confirmation_action_token_mismatch_text(confirm_id: str, provided: str, expected: str) -> str:
    return (
        "动作摘要码不匹配，已拒绝执行。\n"
        f"确认编号：{confirm_id}\n"
        f"提供：{provided or '-'}\n"
        f"期望：{expected}\n\n"
        "Action bind token mismatch; execution rejected.\n"
        f"Confirmation ID: {confirm_id}\n"
        f"Provided: {provided or '-'}\n"
        f"Expected: {expected}"
    )


def _confirmation_id_mismatch_hint_text(provided_id: str, expected_id: str) -> str:
    return (
        "未找到你提供的确认编号，当前会话存在唯一待确认请求。\n"
        f"你提供的确认编号：{provided_id}\n"
        f"可用确认编号：{expected_id}\n\n"
        "请单独发送以下任一可复制消息：\n"
        f"yes {expected_id}\n"
        f"no {expected_id}\n\n"
        "The provided confirmation ID was not found, but this session has exactly one pending confirmation.\n"
        f"Provided ID: {provided_id}\n"
        f"Expected ID: {expected_id}\n\n"
        "Send one standalone copy-ready line:\n"
        f"yes {expected_id}\n"
        f"no {expected_id}"
    )


def _confirmation_command_requirements_text(
    *,
    detail: str,
    confirm_id: str = "",
    action_token: str = "",
) -> str:
    if confirm_id:
        bind = f"{confirm_id}--{action_token}" if action_token else confirm_id
        yes_line = f"yes {bind}"
        no_line = f"no {bind}"
        id_line_cn = f"确认编号：{confirm_id}\n"
        id_line_en = f"Confirmation ID: {confirm_id}\n"
        token_line_cn = f"动作摘要码：{action_token}\n" if action_token else ""
        token_line_en = f"Action Bind Token: {action_token}\n" if action_token else ""
    else:
        yes_line = "yes cfm-<12hex> [act-<token>]"
        no_line = "no cfm-<12hex> [act-<token>]"
        id_line_cn = ""
        id_line_en = ""
        token_line_cn = ""
        token_line_en = ""
    return (
        "确认指令不符合放行要求，未执行。\n"
        f"原因：{detail}\n"
        f"{id_line_cn}{token_line_cn}"
        "请单独发送以下任一可复制消息：\n"
        f"{yes_line}\n"
        f"{no_line}\n\n"
        "Confirmation command does not meet release requirements; execution was not performed.\n"
        f"Reason: {detail}\n"
        f"{id_line_en}{token_line_en}"
        "Send one standalone copy-ready line:\n"
        f"{yes_line}\n"
        f"{no_line}"
    )


def _confirmation_route_mismatch_text(confirm_id: str, pending_route: str, current_route: str) -> str:
    return (
        "确认编号与当前接口不匹配，无法执行。\n"
        f"确认编号：{confirm_id}\n"
        f"确认原路由：{pending_route}\n"
        f"当前路由：{current_route}\n\n"
        "The confirmation ID does not match the current endpoint.\n"
        f"Confirmation ID: {confirm_id}\n"
        f"Pending route: {pending_route}\n"
        f"Current route: {current_route}"
    )


def _pending_payload_invalid_text(confirm_id: str) -> str:
    return (
        "该确认编号对应的待执行请求数据已损坏，无法放行执行。\n"
        f"确认编号：{confirm_id}\n"
        "请重新发送原始请求。\n\n"
        "The pending payload for this confirmation is invalid and cannot be executed.\n"
        f"Confirmation ID: {confirm_id}\n"
        "Please resend the original request."
    )


def _pending_hash_mismatch_text(confirm_id: str) -> str:
    return (
        "该确认编号的请求校验失败（hash 不一致），为安全起见已拒绝执行。\n"
        f"确认编号：{confirm_id}\n"
        "请重新发送原始请求。\n\n"
        "Pending request hash verification failed for this confirmation.\n"
        f"Confirmation ID: {confirm_id}\n"
        "Please resend the original request."
    )


async def _try_transition_pending_status(
    *,
    confirm_id: str,
    expected_status: str,
    new_status: str,
    now_ts: int,
) -> bool:
    method = getattr(store, "compare_and_update_pending_confirmation_status", None)
    if callable(method):
        result = await _maybe_offload(
            method,
            confirm_id=confirm_id,
            expected_status=expected_status,
            new_status=new_status,
            now_ts=now_ts,
        )
        return bool(result)

    record = await _store_call("get_pending_confirmation", confirm_id)
    if not record:
        return False
    if str(record.get("status")) != expected_status:
        return False
    await _store_call(
        "update_pending_confirmation_status",
        confirm_id=confirm_id,
        status=new_status,
        now_ts=now_ts,
    )
    return True


def _resolve_action(ctx: RequestContext) -> str:
    if ctx.request_disposition == "block" or ctx.response_disposition == "block":
        return "block"
    if ctx.request_disposition == "sanitize" or ctx.response_disposition == "sanitize":
        return "sanitize"
    return "allow"


def _attach_security_metadata(resp: InternalResponse, ctx: RequestContext, boundary: dict | None = None) -> None:
    action = _resolve_action(ctx)
    resp.metadata["aegisgate"] = {
        "action": action,
        "tenant_id": ctx.tenant_id,
        "risk_score": round(ctx.risk_score, 4),
        "risk_threshold": ctx.risk_threshold,
        "requires_human_review": ctx.requires_human_review,
        "request_disposition": ctx.request_disposition,
        "response_disposition": ctx.response_disposition,
        "reasons": sorted(set(ctx.disposition_reasons)),
        "security_tags": sorted(ctx.security_tags),
        "enforcement_actions": ctx.enforcement_actions,
        "security_boundary": boundary or {},
        "poison_traceback": ctx.poison_traceback,
    }


def _write_audit_event(ctx: RequestContext, boundary: dict | None = None) -> None:
    write_audit(
        {
            "request_id": ctx.request_id,
            "session_id": ctx.session_id,
            "tenant_id": ctx.tenant_id,
            "route": ctx.route,
            "risk_score": ctx.risk_score,
            "risk_threshold": ctx.risk_threshold,
            "requires_human_review": ctx.requires_human_review,
            "request_disposition": ctx.request_disposition,
            "response_disposition": ctx.response_disposition,
            "disposition_reasons": ctx.disposition_reasons,
            "security_tags": sorted(ctx.security_tags),
            "enforcement_actions": ctx.enforcement_actions,
            "action": _resolve_action(ctx),
            "security_boundary": boundary or {},
            "poison_traceback": ctx.poison_traceback,
            "report": ctx.report_items,
        }
    )


def _error_response(status_code: int, reason: str, detail: str, ctx: RequestContext, boundary: dict | None = None) -> JSONResponse:
    ctx.response_disposition = "block"
    ctx.disposition_reasons.append(reason)
    ctx.enforcement_actions.append(f"upstream:{reason}")
    # 保证 agent 端能拿到非空原因（error + detail）
    detail_str = ((detail or "").strip() or reason)[:600]
    try:
        _write_audit_event(ctx, boundary=boundary)
    except Exception as exc:  # pragma: no cover - operational guard
        logger.warning("audit write failed on error response request_id=%s error=%s", ctx.request_id, exc)
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "message": detail_str,
                "type": "aegisgate_error",
                "code": reason,
            },
            "error_code": reason,
            "detail": detail_str,
            "request_id": ctx.request_id,
            "aegisgate": {
                "action": _resolve_action(ctx),
                "risk_score": round(ctx.risk_score, 4),
                "reasons": sorted(set(ctx.disposition_reasons)),
                "security_tags": sorted(ctx.security_tags),
            },
        },
    )


def _stream_runtime_reason(error_detail: str) -> str:
    if error_detail.startswith("upstream_http_error"):
        return "upstream_http_error"
    if error_detail.startswith("upstream_unreachable"):
        return "upstream_unreachable"
    return "upstream_stream_error"


async def _execute_chat_stream_once(
    *,
    payload: dict[str, Any],
    request_headers: Mapping[str, str],
    request_path: str,
    boundary: dict | None,
    tenant_id: str = "default",
    forced_upstream_base: str | None = None,
) -> StreamingResponse | JSONResponse:
    req = to_internal_chat(payload)
    ctx = RequestContext(request_id=req.request_id, session_id=req.session_id, route=req.route, tenant_id=tenant_id)
    policy_engine.resolve(ctx, policy_name=payload.get("policy", settings.default_policy))

    try:
        upstream_base = forced_upstream_base or _resolve_upstream_base(request_headers)
        upstream_url = _build_upstream_url(request_path, upstream_base)
    except ValueError as exc:
        logger.warning("invalid upstream base request_id=%s error=%s", ctx.request_id, exc)
        return _error_response(
            status_code=400,
            reason="invalid_upstream_base",
            detail=str(exc),
            ctx=ctx,
            boundary=boundary,
        )

    forward_headers = _build_forward_headers(request_headers)

    if _is_upstream_whitelisted(upstream_base):
        ctx.enforcement_actions.append("upstream_whitelist:direct_allow")
        ctx.security_tags.add("upstream_whitelist_bypass")
        logger.info("chat stream bypassed filters request_id=%s upstream=%s", ctx.request_id, upstream_base)

        async def whitelist_generator() -> AsyncGenerator[bytes, None]:
            try:
                async for line in _forward_stream_lines(upstream_url, payload, forward_headers):
                    yield line
            except RuntimeError as exc:
                detail = str(exc)
                reason = _stream_runtime_reason(detail)
                ctx.response_disposition = "block"
                ctx.disposition_reasons.append(reason)
                ctx.enforcement_actions.append(f"upstream:{reason}")
                yield _stream_error_sse_chunk(detail, code=reason)
                yield _stream_done_sse_chunk()
            except Exception as exc:  # pragma: no cover - fail-safe
                detail = f"gateway_internal_error: {exc}"
                ctx.response_disposition = "block"
                ctx.disposition_reasons.append("gateway_internal_error")
                ctx.enforcement_actions.append("upstream:gateway_internal_error")
                logger.exception("chat stream unexpected failure request_id=%s", ctx.request_id)
                yield _stream_error_sse_chunk(detail, code="gateway_internal_error")
                yield _stream_done_sse_chunk()
            finally:
                _write_audit_event(ctx, boundary=boundary)

        return _build_streaming_response(whitelist_generator())

    request_user_text = _request_user_text_for_excerpt(payload, req.route)
    debug_log_original("request_before_filters", request_user_text, max_len=180)

    pipeline = _get_pipeline()
    sanitized_req = await _run_request_pipeline(pipeline, req, ctx)
    base_reports = list(ctx.report_items)

    if ctx.request_disposition == "block":
        block_reason = ctx.disposition_reasons[-1] if ctx.disposition_reasons else "request_blocked"
        debug_log_original("request_blocked", request_user_text, reason=block_reason)
        reason, summary = _confirmation_reason_and_summary(
            ctx,
            phase=PHASE_REQUEST,
            source_text=request_user_text,
        )
        confirm_id = make_confirm_id()
        now_ts = int(time.time())
        pending_payload, pending_payload_hash, pending_payload_omitted, pending_payload_size = _prepare_pending_payload(
            payload
        )
        await _store_call(
            "save_pending_confirmation",
            confirm_id=confirm_id,
            session_id=req.session_id,
            route=req.route,
            request_id=req.request_id,
            model=req.model,
            upstream_base=upstream_base,
            pending_request_payload=pending_payload,
            pending_request_hash=pending_payload_hash,
            reason=reason,
            summary=summary,
            tenant_id=ctx.tenant_id,
            created_at=now_ts,
            expires_at=_confirmation_expires_at(now_ts, PHASE_REQUEST),
            retained_until=now_ts + max(60, int(settings.pending_data_ttl_seconds)),
        )
        if pending_payload_omitted:
            summary = f"{summary}（请求体过大，未缓存原文：{pending_payload_size} bytes）"
        ctx.disposition_reasons.append("awaiting_user_confirmation")
        ctx.security_tags.add("confirmation_required")
        confirmation_meta = _flow_confirmation_metadata(
            confirm_id=confirm_id, status="pending", reason=reason, summary=summary,
            phase=PHASE_REQUEST, payload_omitted=pending_payload_omitted,
            action_token=make_action_bind_token(f"{confirm_id}|{reason}|{summary}"),
        )
        message_text = _build_confirmation_message(confirm_id=confirm_id, reason=reason, summary=summary, phase=PHASE_REQUEST)

        def request_confirmation_generator() -> Generator[bytes, None, None]:
            try:
                yield _stream_confirmation_sse_chunk(ctx, req.model, req.route, message_text, confirmation_meta)
                yield _stream_done_sse_chunk()
            finally:
                _write_audit_event(ctx, boundary=boundary)

        logger.info("chat stream request blocked, confirmation required request_id=%s confirm_id=%s", ctx.request_id, confirm_id)
        return _build_streaming_response(request_confirmation_generator())

    upstream_payload = _build_chat_upstream_payload(payload, sanitized_req.messages)

    async def guarded_generator() -> AsyncGenerator[bytes, None]:
        stream_window = ""
        stream_cached_parts: list[str] = []
        chunk_count = 0
        saw_done = False
        stream_end_reason = "upstream_eof_no_done"
        try:
            async for line in _forward_stream_lines(upstream_url, upstream_payload, forward_headers):
                payload_text = _extract_sse_data_payload(line)
                if payload_text is None:
                    yield line
                    continue

                if payload_text == "[DONE]":
                    saw_done = True
                    stream_end_reason = "upstream_done"
                    yield line
                    break

                chunk_text = _extract_stream_text_from_event(payload_text)
                if chunk_text:
                    stream_window = _trim_stream_window(stream_window, chunk_text)
                    stream_cached_parts.append(chunk_text)
                    chunk_count += 1

                    # Keep stream memory bounded by carrying request reports + latest stream check only.
                    ctx.report_items = list(base_reports)
                    probe_resp = InternalResponse(
                        request_id=req.request_id,
                        session_id=req.session_id,
                        model=req.model,
                        output_text=stream_window,
                        raw={"stream": True},
                    )
                    await _run_response_pipeline(pipeline, probe_resp, ctx)

                    if settings.enable_semantic_module and chunk_count % max(1, _STREAM_SEMANTIC_CHECK_INTERVAL) == 0:
                        await _apply_semantic_review(ctx, stream_window, phase="response")

                    block_reason = _stream_block_reason(ctx)
                    if block_reason:
                        logger.info(
                            "chat stream block decision request_id=%s reason=%s risk_score=%.4f threshold=%.4f response_disposition=%s requires_human_review=%s security_tags=%s disposition_reasons=%s chunk_count=%s cached_chars=%s",
                            ctx.request_id,
                            block_reason,
                            float(ctx.risk_score),
                            float(ctx.risk_threshold),
                            ctx.response_disposition,
                            bool(ctx.requires_human_review),
                            sorted(ctx.security_tags),
                            list(ctx.disposition_reasons),
                            chunk_count,
                            len(stream_window),
                        )
                        debug_log_original("response_stream_blocked", stream_window, reason=block_reason)
                        if block_reason not in ctx.disposition_reasons:
                            ctx.disposition_reasons.append(block_reason)
                        reason, summary = _confirmation_reason_and_summary(ctx, source_text=stream_window)
                        confirm_id = make_confirm_id()
                        now_ts = int(time.time())
                        cached_text = "".join(stream_cached_parts)
                        pending_payload = _build_response_pending_payload(
                            route=req.route,
                            request_id=req.request_id,
                            session_id=req.session_id,
                            model=req.model,
                            fmt=_PENDING_FORMAT_CHAT_STREAM_TEXT,
                            content=cached_text,
                        )
                        pending_payload, pending_payload_hash, pending_payload_size = _prepare_response_pending_payload(pending_payload)
                        await _store_call(
                            "save_pending_confirmation",
                            confirm_id=confirm_id,
                            session_id=req.session_id,
                            route=req.route,
                            request_id=req.request_id,
                            model=req.model,
                            upstream_base=upstream_base,
                            pending_request_payload=pending_payload,
                            pending_request_hash=pending_payload_hash,
                            reason=reason,
                            summary=summary,
                            tenant_id=ctx.tenant_id,
                            created_at=now_ts,
                            expires_at=_confirmation_expires_at(now_ts, PHASE_RESPONSE),
                            retained_until=now_ts + max(60, int(settings.pending_data_ttl_seconds)),
                        )
                        ctx.response_disposition = "block"
                        ctx.disposition_reasons.append("awaiting_user_confirmation")
                        ctx.security_tags.add("confirmation_required")
                        ctx.enforcement_actions.append("confirmation:pending")
                        confirmation_meta = _flow_confirmation_metadata(
                            confirm_id=confirm_id,
                            status="pending",
                            reason=reason,
                            summary=summary,
                            phase=PHASE_RESPONSE,
                            payload_omitted=False,
                            action_token=make_action_bind_token(f"{confirm_id}|{reason}|{summary}"),
                        )
                        message_text = _build_confirmation_message(
                            confirm_id=confirm_id,
                            reason=reason,
                            summary=summary,
                            phase=PHASE_RESPONSE,
                        )
                        logger.info(
                            "chat stream requires confirmation request_id=%s confirm_id=%s reason=%s",
                            ctx.request_id,
                            confirm_id,
                            block_reason,
                        )
                        logger.info(
                            "confirmation response cached request_id=%s confirm_id=%s route=%s format=%s bytes=%s",
                            ctx.request_id,
                            confirm_id,
                            req.route,
                            _PENDING_FORMAT_CHAT_STREAM_TEXT,
                            pending_payload_size,
                        )
                        yield _stream_confirmation_sse_chunk(
                            ctx,
                            req.model,
                            req.route,
                            message_text,
                            confirmation_meta,
                        )
                        yield _stream_done_sse_chunk()
                        stream_end_reason = "policy_confirmation"
                        break

                yield line
            if not saw_done and stream_end_reason == "upstream_eof_no_done":
                ctx.enforcement_actions.append("upstream:upstream_eof_no_done")
                replay_text = _build_upstream_eof_replay_text(stream_window)
                logger.warning(
                    "chat stream upstream closed without DONE request_id=%s chunk_count=%s cached_chars=%s inject_done=true recovery_chars=%s",
                    ctx.request_id,
                    chunk_count,
                    len(stream_window),
                    len(replay_text),
                )
                payload = {
                    "id": req.request_id,
                    "object": "chat.completion.chunk",
                    "model": req.model,
                    "choices": [
                        {"index": 0, "delta": {"role": "assistant", "content": replay_text}, "finish_reason": "stop"}
                    ],
                    "aegisgate": {
                        "action": "allow",
                        "warning": "upstream_eof_no_done",
                        "recovered": True,
                    },
                }
                yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8")
                yield _stream_done_sse_chunk()
                stream_end_reason = "upstream_eof_no_done_recovered"
        except RuntimeError as exc:
            detail = str(exc)
            reason = _stream_runtime_reason(detail)
            ctx.response_disposition = "block"
            ctx.disposition_reasons.append(reason)
            ctx.enforcement_actions.append(f"upstream:{reason}")
            stream_end_reason = f"error:{reason}"
            logger.error("chat stream upstream failure request_id=%s error=%s", ctx.request_id, detail)
            yield _stream_error_sse_chunk(detail, code=reason)
            yield _stream_done_sse_chunk()
        except Exception as exc:  # pragma: no cover - fail-safe
            detail = f"gateway_internal_error: {exc}"
            ctx.response_disposition = "block"
            ctx.disposition_reasons.append("gateway_internal_error")
            ctx.enforcement_actions.append("upstream:gateway_internal_error")
            stream_end_reason = "error:gateway_internal_error"
            logger.exception("chat stream unexpected failure request_id=%s", ctx.request_id)
            yield _stream_error_sse_chunk(detail, code="gateway_internal_error")
            yield _stream_done_sse_chunk()
        finally:
            logger.info(
                "chat stream finished request_id=%s reason=%s saw_done=%s chunk_count=%s cached_chars=%s",
                ctx.request_id,
                stream_end_reason,
                saw_done,
                chunk_count,
                len(stream_window),
            )
            _write_audit_event(ctx, boundary=boundary)

    return _build_streaming_response(guarded_generator())


async def _execute_responses_stream_once(
    *,
    payload: dict[str, Any],
    request_headers: Mapping[str, str],
    request_path: str,
    boundary: dict | None,
    tenant_id: str = "default",
    forced_upstream_base: str | None = None,
) -> StreamingResponse | JSONResponse:
    req = to_internal_responses(payload)
    ctx = RequestContext(request_id=req.request_id, session_id=req.session_id, route=req.route, tenant_id=tenant_id)
    policy_engine.resolve(ctx, policy_name=payload.get("policy", settings.default_policy))

    try:
        upstream_base = forced_upstream_base or _resolve_upstream_base(request_headers)
        upstream_url = _build_upstream_url(request_path, upstream_base)
    except ValueError as exc:
        logger.warning("invalid upstream base request_id=%s error=%s", ctx.request_id, exc)
        return _error_response(
            status_code=400,
            reason="invalid_upstream_base",
            detail=str(exc),
            ctx=ctx,
            boundary=boundary,
        )

    forward_headers = _build_forward_headers(request_headers)

    if _is_upstream_whitelisted(upstream_base):
        ctx.enforcement_actions.append("upstream_whitelist:direct_allow")
        ctx.security_tags.add("upstream_whitelist_bypass")
        logger.info("responses stream bypassed filters request_id=%s upstream=%s", ctx.request_id, upstream_base)

        async def whitelist_generator() -> AsyncGenerator[bytes, None]:
            try:
                async for line in _forward_stream_lines(upstream_url, payload, forward_headers):
                    yield line
            except RuntimeError as exc:
                detail = str(exc)
                reason = _stream_runtime_reason(detail)
                ctx.response_disposition = "block"
                ctx.disposition_reasons.append(reason)
                ctx.enforcement_actions.append(f"upstream:{reason}")
                yield _stream_error_sse_chunk(detail, code=reason)
                yield _stream_done_sse_chunk()
            except Exception as exc:  # pragma: no cover - fail-safe
                detail = f"gateway_internal_error: {exc}"
                ctx.response_disposition = "block"
                ctx.disposition_reasons.append("gateway_internal_error")
                ctx.enforcement_actions.append("upstream:gateway_internal_error")
                logger.exception("responses stream unexpected failure request_id=%s", ctx.request_id)
                yield _stream_error_sse_chunk(detail, code="gateway_internal_error")
                yield _stream_done_sse_chunk()
            finally:
                _write_audit_event(ctx, boundary=boundary)

        return _build_streaming_response(whitelist_generator())

    request_user_text = _request_user_text_for_excerpt(payload, req.route)
    debug_log_original("request_before_filters", request_user_text, max_len=180)

    pipeline = _get_pipeline()
    sanitized_req = await _run_request_pipeline(pipeline, req, ctx)
    base_reports = list(ctx.report_items)

    if ctx.request_disposition == "block":
        block_reason = ctx.disposition_reasons[-1] if ctx.disposition_reasons else "request_blocked"
        debug_log_original("request_blocked", request_user_text, reason=block_reason)
        reason, summary = _confirmation_reason_and_summary(
            ctx,
            phase=PHASE_REQUEST,
            source_text=request_user_text,
        )
        confirm_id = make_confirm_id()
        now_ts = int(time.time())
        pending_payload, pending_payload_hash, pending_payload_omitted, pending_payload_size = _prepare_pending_payload(
            payload
        )
        await _store_call(
            "save_pending_confirmation",
            confirm_id=confirm_id,
            session_id=req.session_id,
            route=req.route,
            request_id=req.request_id,
            model=req.model,
            upstream_base=upstream_base,
            pending_request_payload=pending_payload,
            pending_request_hash=pending_payload_hash,
            reason=reason,
            summary=summary,
            tenant_id=ctx.tenant_id,
            created_at=now_ts,
            expires_at=_confirmation_expires_at(now_ts, PHASE_REQUEST),
            retained_until=now_ts + max(60, int(settings.pending_data_ttl_seconds)),
        )
        if pending_payload_omitted:
            summary = f"{summary}（请求体过大，未缓存原文：{pending_payload_size} bytes）"
        ctx.disposition_reasons.append("awaiting_user_confirmation")
        ctx.security_tags.add("confirmation_required")
        confirmation_meta = _flow_confirmation_metadata(
            confirm_id=confirm_id, status="pending", reason=reason, summary=summary,
            phase=PHASE_REQUEST, payload_omitted=pending_payload_omitted,
            action_token=make_action_bind_token(f"{confirm_id}|{reason}|{summary}"),
        )
        message_text = _build_confirmation_message(confirm_id=confirm_id, reason=reason, summary=summary, phase=PHASE_REQUEST)

        def request_confirmation_generator() -> Generator[bytes, None, None]:
            try:
                yield _stream_confirmation_sse_chunk(ctx, req.model, req.route, message_text, confirmation_meta)
                yield _stream_done_sse_chunk()
            finally:
                _write_audit_event(ctx, boundary=boundary)

        logger.info("responses stream request blocked, confirmation required request_id=%s confirm_id=%s", ctx.request_id, confirm_id)
        return _build_streaming_response(request_confirmation_generator())

    upstream_payload = _build_responses_upstream_payload(
        payload, sanitized_req.messages,
        request_id=ctx.request_id, session_id=ctx.session_id, route=ctx.route,
    )

    async def guarded_generator() -> AsyncGenerator[bytes, None]:
        stream_window = ""
        stream_cached_parts: list[str] = []
        chunk_count = 0
        saw_any_data_event = False
        saw_terminal_event = False
        saw_done = False
        stream_end_reason = "upstream_eof_no_done"
        blocked_reason: str | None = None
        blocked_confirm_id = ""
        blocked_confirmation_reason = ""
        blocked_confirmation_summary = ""
        blocked_confirmation_meta: dict[str, Any] | None = None
        blocked_message_text = ""
        try:
            async for line in _forward_stream_lines(upstream_url, upstream_payload, forward_headers):
                payload_text = _extract_sse_data_payload(line)
                if payload_text is None:
                    if blocked_reason:
                        continue
                    yield line
                    continue

                if payload_text == "[DONE]":
                    saw_done = True
                    stream_end_reason = "upstream_done"
                    if blocked_reason:
                        break
                    yield line
                    break

                saw_any_data_event = True
                event_type = _extract_stream_event_type(payload_text)
                if event_type in {"response.completed", "response.failed", "error"}:
                    saw_terminal_event = True

                chunk_text = _extract_stream_text_from_event(payload_text)
                if chunk_text:
                    stream_window = _trim_stream_window(stream_window, chunk_text)
                    stream_cached_parts.append(chunk_text)
                    chunk_count += 1

                    if not blocked_reason:
                        ctx.report_items = list(base_reports)
                        probe_resp = InternalResponse(
                            request_id=req.request_id,
                            session_id=req.session_id,
                            model=req.model,
                            output_text=stream_window,
                            raw={"stream": True},
                        )
                        await _run_response_pipeline(pipeline, probe_resp, ctx)

                        if settings.enable_semantic_module and chunk_count % max(1, _STREAM_SEMANTIC_CHECK_INTERVAL) == 0:
                            await _apply_semantic_review(ctx, stream_window, phase="response")

                        decision = _stream_block_reason(ctx)
                        if decision:
                            blocked_reason = decision
                            logger.info(
                                "responses stream block decision request_id=%s reason=%s risk_score=%.4f threshold=%.4f response_disposition=%s requires_human_review=%s security_tags=%s disposition_reasons=%s chunk_count=%s cached_chars=%s",
                                ctx.request_id,
                                blocked_reason,
                                float(ctx.risk_score),
                                float(ctx.risk_threshold),
                                ctx.response_disposition,
                                bool(ctx.requires_human_review),
                                sorted(ctx.security_tags),
                                list(ctx.disposition_reasons),
                                chunk_count,
                                len(stream_window),
                            )
                            debug_log_original("response_stream_blocked", stream_window, reason=blocked_reason)
                            if blocked_reason not in ctx.disposition_reasons:
                                ctx.disposition_reasons.append(blocked_reason)
                            blocked_confirmation_reason, blocked_confirmation_summary = _confirmation_reason_and_summary(
                                ctx,
                                source_text=stream_window,
                            )
                            blocked_confirm_id = make_confirm_id()
                            blocked_confirmation_meta = _flow_confirmation_metadata(
                                confirm_id=blocked_confirm_id,
                                status="pending",
                                reason=blocked_confirmation_reason,
                                summary=blocked_confirmation_summary,
                                phase=PHASE_RESPONSE,
                                payload_omitted=False,
                                action_token=make_action_bind_token(
                                    f"{blocked_confirm_id}|{blocked_confirmation_reason}|{blocked_confirmation_summary}"
                                ),
                            )
                            blocked_message_text = _build_confirmation_message(
                                confirm_id=blocked_confirm_id,
                                reason=blocked_confirmation_reason,
                                summary=blocked_confirmation_summary,
                                phase=PHASE_RESPONSE,
                            )
                            stream_end_reason = "policy_confirmation_draining_upstream"
                            logger.info(
                                "responses stream block drain started request_id=%s confirm_id=%s reason=%s chunk_count=%s cached_chars=%s",
                                ctx.request_id,
                                blocked_confirm_id,
                                blocked_reason,
                                chunk_count,
                                len(stream_window),
                            )

                if blocked_reason:
                    continue

                yield line
            if blocked_reason:
                now_ts = int(time.time())
                cached_text = "".join(stream_cached_parts)
                pending_payload = _build_response_pending_payload(
                    route=req.route,
                    request_id=req.request_id,
                    session_id=req.session_id,
                    model=req.model,
                    fmt=_PENDING_FORMAT_RESPONSES_STREAM_TEXT,
                    content=cached_text,
                )
                pending_payload, pending_payload_hash, pending_payload_size = _prepare_response_pending_payload(pending_payload)
                await _store_call(
                    "save_pending_confirmation",
                    confirm_id=blocked_confirm_id,
                    session_id=req.session_id,
                    route=req.route,
                    request_id=req.request_id,
                    model=req.model,
                    upstream_base=upstream_base,
                    pending_request_payload=pending_payload,
                    pending_request_hash=pending_payload_hash,
                    reason=blocked_confirmation_reason,
                    summary=blocked_confirmation_summary,
                    tenant_id=ctx.tenant_id,
                    created_at=now_ts,
                    expires_at=_confirmation_expires_at(now_ts, PHASE_RESPONSE),
                    retained_until=now_ts + max(60, int(settings.pending_data_ttl_seconds)),
                )
                ctx.response_disposition = "block"
                if "awaiting_user_confirmation" not in ctx.disposition_reasons:
                    ctx.disposition_reasons.append("awaiting_user_confirmation")
                ctx.security_tags.add("confirmation_required")
                ctx.enforcement_actions.append("confirmation:pending")
                logger.info(
                    "responses stream requires confirmation request_id=%s confirm_id=%s reason=%s",
                    ctx.request_id,
                    blocked_confirm_id,
                    blocked_reason,
                )
                logger.info(
                    "confirmation response cached request_id=%s confirm_id=%s route=%s format=%s bytes=%s",
                    ctx.request_id,
                    blocked_confirm_id,
                    req.route,
                    _PENDING_FORMAT_RESPONSES_STREAM_TEXT,
                    pending_payload_size,
                )
                logger.info(
                    "responses stream block drain completed request_id=%s confirm_id=%s saw_done=%s chunk_count=%s cached_chars=%s",
                    ctx.request_id,
                    blocked_confirm_id,
                    saw_done,
                    chunk_count,
                    len(cached_text),
                )
                confirmation_meta = blocked_confirmation_meta or _flow_confirmation_metadata(
                    confirm_id=blocked_confirm_id,
                    status="pending",
                    reason=blocked_confirmation_reason,
                    summary=blocked_confirmation_summary,
                    phase=PHASE_RESPONSE,
                    payload_omitted=False,
                    action_token=make_action_bind_token(
                        f"{blocked_confirm_id}|{blocked_confirmation_reason}|{blocked_confirmation_summary}"
                    ),
                )
                message_text = blocked_message_text or _build_confirmation_message(
                    confirm_id=blocked_confirm_id,
                    reason=blocked_confirmation_reason,
                    summary=blocked_confirmation_summary,
                    phase=PHASE_RESPONSE,
                )
                yield _stream_confirmation_sse_chunk(
                    ctx,
                    req.model,
                    req.route,
                    message_text,
                    confirmation_meta,
                )
                yield _stream_done_sse_chunk()
                stream_end_reason = "policy_confirmation"
            elif not saw_done and stream_end_reason == "upstream_eof_no_done":
                ctx.enforcement_actions.append("upstream:upstream_eof_no_done")
                recovery_meta = {"action": "allow", "warning": "upstream_eof_no_done", "recovered": True}
                if saw_terminal_event:
                    logger.warning(
                        "responses stream upstream closed without DONE request_id=%s chunk_count=%s cached_chars=%s inject_done=true terminal_event=true",
                        ctx.request_id,
                        chunk_count,
                        len(stream_window),
                    )
                    yield _stream_done_sse_chunk()
                elif chunk_count <= 0 and not saw_any_data_event:
                    replay_text = _build_upstream_eof_replay_text("")
                    logger.warning(
                        "responses stream upstream closed without DONE request_id=%s chunk_count=%s cached_chars=%s inject_done=true replay_notice=true",
                        ctx.request_id,
                        chunk_count,
                        len(stream_window),
                    )
                    for chunk in _iter_responses_text_stream_replay(
                        request_id=req.request_id,
                        model=req.model,
                        replay_text=replay_text,
                        aegisgate_meta=recovery_meta,
                    ):
                        yield chunk
                else:
                    logger.warning(
                        "responses stream upstream closed without DONE request_id=%s chunk_count=%s cached_chars=%s inject_done=true finalize_only=true",
                        ctx.request_id,
                        chunk_count,
                        len(stream_window),
                    )
                    for chunk in _iter_responses_stream_finalize(
                        request_id=req.request_id,
                        model=req.model,
                        aegisgate_meta=recovery_meta,
                    ):
                        yield chunk
                stream_end_reason = "upstream_eof_no_done_recovered"
        except RuntimeError as exc:
            detail = str(exc)
            reason = _stream_runtime_reason(detail)
            ctx.response_disposition = "block"
            ctx.disposition_reasons.append(reason)
            ctx.enforcement_actions.append(f"upstream:{reason}")
            stream_end_reason = f"error:{reason}"
            logger.error("responses stream upstream failure request_id=%s error=%s", ctx.request_id, detail)
            yield _stream_error_sse_chunk(detail, code=reason)
            yield _stream_done_sse_chunk()
        except Exception as exc:  # pragma: no cover - fail-safe
            detail = f"gateway_internal_error: {exc}"
            ctx.response_disposition = "block"
            ctx.disposition_reasons.append("gateway_internal_error")
            ctx.enforcement_actions.append("upstream:gateway_internal_error")
            stream_end_reason = "error:gateway_internal_error"
            logger.exception("responses stream unexpected failure request_id=%s", ctx.request_id)
            yield _stream_error_sse_chunk(detail, code="gateway_internal_error")
            yield _stream_done_sse_chunk()
        finally:
            logger.info(
                "responses stream finished request_id=%s reason=%s saw_done=%s chunk_count=%s cached_chars=%s",
                ctx.request_id,
                stream_end_reason,
                saw_done,
                chunk_count,
                len(stream_window),
            )
            _write_audit_event(ctx, boundary=boundary)

    return _build_streaming_response(guarded_generator())


async def _execute_chat_once(
    *,
    payload: dict[str, Any],
    request_headers: Mapping[str, str],
    request_path: str,
    boundary: dict | None,
    tenant_id: str = "default",
    skip_confirmation: bool = False,
    forced_upstream_base: str | None = None,
) -> dict | JSONResponse:
    req = to_internal_chat(payload)
    ctx = RequestContext(request_id=req.request_id, session_id=req.session_id, route=req.route, tenant_id=tenant_id)
    policy_engine.resolve(ctx, policy_name=payload.get("policy", settings.default_policy))

    try:
        upstream_base = forced_upstream_base or _resolve_upstream_base(request_headers)
        upstream_url = _build_upstream_url(request_path, upstream_base)
    except ValueError as exc:
        logger.warning("invalid upstream base request_id=%s error=%s", ctx.request_id, exc)
        return _error_response(
            status_code=400,
            reason="invalid_upstream_base",
            detail=str(exc),
            ctx=ctx,
            boundary=boundary,
        )

    forward_headers = _build_forward_headers(request_headers)

    if _is_upstream_whitelisted(upstream_base):
        try:
            status_code, upstream_body = await _forward_json(upstream_url, payload, forward_headers)
        except RuntimeError as exc:
            logger.error("upstream unreachable request_id=%s error=%s", ctx.request_id, exc)
            return _error_response(
                status_code=502,
                reason="upstream_unreachable",
                detail=str(exc),
                ctx=ctx,
                boundary=boundary,
            )

        if status_code >= 400:
            detail = _safe_error_detail(upstream_body)
            logger.warning("upstream http error request_id=%s status=%s detail=%s", ctx.request_id, status_code, detail)
            return _error_response(
                status_code=status_code,
                reason="upstream_http_error",
                detail=detail,
                ctx=ctx,
                boundary=boundary,
            )

        ctx.enforcement_actions.append("upstream_whitelist:direct_allow")
        ctx.security_tags.add("upstream_whitelist_bypass")
        _write_audit_event(ctx, boundary=boundary)
        logger.info("chat completion bypassed filters request_id=%s upstream=%s", ctx.request_id, upstream_base)
        return _passthrough_chat_response(upstream_body, req)

    pipeline = _get_pipeline()

    # 用户已确认放行（yes）：不再走请求侧过滤，直接转发，避免同一内容再次被拦截
    if forced_upstream_base and skip_confirmation:
        upstream_payload = _build_chat_upstream_payload(payload, req.messages)
        ctx.enforcement_actions.append("confirmation:request_filters_skipped")
    else:
        request_user_text = _request_user_text_for_excerpt(payload, req.route)
        debug_log_original("request_before_filters", request_user_text, max_len=180)

        sanitized_req = await _run_request_pipeline(pipeline, req, ctx)
        if ctx.request_disposition == "block":
            block_reason = ctx.disposition_reasons[-1] if ctx.disposition_reasons else "request_blocked"
            debug_log_original("request_blocked", request_user_text, reason=block_reason)
            reason, summary = _confirmation_reason_and_summary(
                ctx,
                phase=PHASE_REQUEST,
                source_text=request_user_text,
            )
            confirm_id = make_confirm_id()
            now_ts = int(time.time())
            pending_payload, pending_payload_hash, pending_payload_omitted, pending_payload_size = _prepare_pending_payload(
                payload
            )
            await _store_call(
                "save_pending_confirmation",
                confirm_id=confirm_id,
                session_id=req.session_id,
                route=req.route,
                request_id=req.request_id,
                model=req.model,
                upstream_base=upstream_base,
                pending_request_payload=pending_payload,
                pending_request_hash=pending_payload_hash,
                reason=reason,
                summary=summary,
                tenant_id=ctx.tenant_id,
                created_at=now_ts,
                expires_at=_confirmation_expires_at(now_ts, PHASE_REQUEST),
                retained_until=now_ts + max(60, int(settings.pending_data_ttl_seconds)),
            )
            if pending_payload_omitted:
                summary = f"{summary}（请求体过大，未缓存原文：{pending_payload_size} bytes）"
            ctx.disposition_reasons.append("awaiting_user_confirmation")
            ctx.security_tags.add("confirmation_required")
            ctx.enforcement_actions.append("confirmation:pending")
            confirmation_resp = InternalResponse(
                request_id=req.request_id,
                session_id=req.session_id,
                model=req.model,
                output_text=_build_confirmation_message(confirm_id=confirm_id, reason=reason, summary=summary, phase=PHASE_REQUEST),
            )
            _attach_security_metadata(confirmation_resp, ctx, boundary=boundary)
            _attach_confirmation_metadata(
                confirmation_resp,
                confirm_id=confirm_id,
                status="pending",
                reason=reason,
                summary=summary,
                phase=PHASE_REQUEST,
                payload_omitted=pending_payload_omitted,
            )
            _write_audit_event(ctx, boundary=boundary)
            logger.info("chat completion request blocked, confirmation required request_id=%s confirm_id=%s", ctx.request_id, confirm_id)
            return to_chat_response(confirmation_resp)

        upstream_payload = _build_chat_upstream_payload(payload, sanitized_req.messages)

    try:
        status_code, upstream_body = await _forward_json(upstream_url, upstream_payload, forward_headers)
    except RuntimeError as exc:
        logger.error("upstream unreachable request_id=%s error=%s", ctx.request_id, exc)
        return _error_response(
            status_code=502,
            reason="upstream_unreachable",
            detail=str(exc),
            ctx=ctx,
            boundary=boundary,
        )

    if status_code >= 400:
        detail = _safe_error_detail(upstream_body)
        logger.warning("upstream http error request_id=%s status=%s detail=%s", ctx.request_id, status_code, detail)
        return _error_response(
            status_code=status_code,
            reason="upstream_http_error",
            detail=detail,
            ctx=ctx,
            boundary=boundary,
        )

    upstream_text = _extract_chat_output_text(upstream_body)
    capped_upstream_text = _cap_response_text(upstream_text, ctx)
    internal_resp = InternalResponse(
        request_id=req.request_id,
        session_id=req.session_id,
        model=req.model,
        output_text=capped_upstream_text,
        raw=upstream_body if isinstance(upstream_body, dict) else {"raw_text": upstream_body},
    )
    debug_log_original("response_before_filters", internal_resp.output_text)

    final_resp = await _run_response_pipeline(pipeline, internal_resp, ctx)
    if not skip_confirmation:
        await _apply_semantic_review(ctx, final_resp.output_text, phase="response")
    if skip_confirmation and final_resp.output_text.startswith("[AegisGate] response blocked by security policy."):
        final_resp.output_text = capped_upstream_text
        ctx.response_disposition = "allow"
        ctx.disposition_reasons.append("confirmed_release_override")
        ctx.enforcement_actions.append("confirmation:confirmed_release")
        ctx.security_tags.add("confirmed_release")

    if not skip_confirmation and _needs_confirmation(ctx):
        resp_reason = ctx.disposition_reasons[0] if ctx.disposition_reasons else "response_high_risk"
        debug_log_original("response_confirmation_original", final_resp.output_text, reason=resp_reason)
        reason, summary = _confirmation_reason_and_summary(ctx, source_text=final_resp.output_text)
        cached_output = _passthrough_chat_response(upstream_body, req)
        pending_payload = _build_response_pending_payload(
            route=req.route,
            request_id=req.request_id,
            session_id=req.session_id,
            model=req.model,
            fmt=_PENDING_FORMAT_CHAT_JSON,
            content=cached_output,
        )
        pending_payload, pending_payload_hash, pending_payload_size = _prepare_response_pending_payload(pending_payload)
        confirm_id = make_confirm_id()
        now_ts = int(time.time())
        await _store_call(
            "save_pending_confirmation",
            confirm_id=confirm_id,
            session_id=req.session_id,
            route=req.route,
            request_id=req.request_id,
            model=req.model,
            upstream_base=upstream_base,
            pending_request_payload=pending_payload,
            pending_request_hash=pending_payload_hash,
            reason=reason,
            summary=summary,
            tenant_id=ctx.tenant_id,
            created_at=now_ts,
            expires_at=_confirmation_expires_at(now_ts, PHASE_RESPONSE),
            retained_until=now_ts + max(60, int(settings.pending_data_ttl_seconds)),
        )
        ctx.response_disposition = "block"
        ctx.disposition_reasons.append("awaiting_user_confirmation")
        ctx.security_tags.add("confirmation_required")
        ctx.enforcement_actions.append("confirmation:pending")
        logger.info(
            "confirmation response cached request_id=%s confirm_id=%s route=%s format=%s bytes=%s",
            ctx.request_id,
            confirm_id,
            req.route,
            _PENDING_FORMAT_CHAT_JSON,
            pending_payload_size,
        )

        confirmation_resp = InternalResponse(
            request_id=req.request_id,
            session_id=req.session_id,
            model=req.model,
            output_text=_build_confirmation_message(confirm_id=confirm_id, reason=reason, summary=summary),
        )
        _attach_security_metadata(confirmation_resp, ctx, boundary=boundary)
        _attach_confirmation_metadata(
            confirmation_resp,
            confirm_id=confirm_id,
            status="pending",
            reason=reason,
            summary=summary,
            phase=PHASE_RESPONSE,
            payload_omitted=False,
        )
        _write_audit_event(ctx, boundary=boundary)
        logger.info("chat completion requires confirmation request_id=%s confirm_id=%s", ctx.request_id, confirm_id)
        return to_chat_response(confirmation_resp)

    _attach_security_metadata(final_resp, ctx, boundary=boundary)
    _write_audit_event(ctx, boundary=boundary)
    logger.info("chat completion completed request_id=%s", ctx.request_id)
    return _render_chat_response(upstream_body, final_resp)


async def _execute_responses_once(
    *,
    payload: dict[str, Any],
    request_headers: Mapping[str, str],
    request_path: str,
    boundary: dict | None,
    tenant_id: str = "default",
    skip_confirmation: bool = False,
    forced_upstream_base: str | None = None,
) -> dict | JSONResponse:
    req = to_internal_responses(payload)
    ctx = RequestContext(request_id=req.request_id, session_id=req.session_id, route=req.route, tenant_id=tenant_id)
    policy_engine.resolve(ctx, policy_name=payload.get("policy", settings.default_policy))

    try:
        upstream_base = forced_upstream_base or _resolve_upstream_base(request_headers)
        upstream_url = _build_upstream_url(request_path, upstream_base)
    except ValueError as exc:
        logger.warning("invalid upstream base request_id=%s error=%s", ctx.request_id, exc)
        return _error_response(
            status_code=400,
            reason="invalid_upstream_base",
            detail=str(exc),
            ctx=ctx,
            boundary=boundary,
        )

    forward_headers = _build_forward_headers(request_headers)

    if _is_upstream_whitelisted(upstream_base):
        try:
            status_code, upstream_body = await _forward_json(upstream_url, payload, forward_headers)
        except RuntimeError as exc:
            logger.error("upstream unreachable request_id=%s error=%s", ctx.request_id, exc)
            return _error_response(
                status_code=502,
                reason="upstream_unreachable",
                detail=str(exc),
                ctx=ctx,
                boundary=boundary,
            )

        if status_code >= 400:
            detail = _safe_error_detail(upstream_body)
            logger.warning("upstream http error request_id=%s status=%s detail=%s", ctx.request_id, status_code, detail)
            return _error_response(
                status_code=status_code,
                reason="upstream_http_error",
                detail=detail,
                ctx=ctx,
                boundary=boundary,
            )

        ctx.enforcement_actions.append("upstream_whitelist:direct_allow")
        ctx.security_tags.add("upstream_whitelist_bypass")
        _write_audit_event(ctx, boundary=boundary)
        logger.info("responses endpoint bypassed filters request_id=%s upstream=%s", ctx.request_id, upstream_base)
        return _passthrough_responses_output(upstream_body, req)

    pipeline = _get_pipeline()

    # 用户已确认放行（yes）：不再走请求侧过滤，直接转发
    if forced_upstream_base and skip_confirmation:
        upstream_payload = _build_responses_upstream_payload(
            payload, req.messages,
            request_id=ctx.request_id, session_id=ctx.session_id, route=ctx.route,
        )
        ctx.enforcement_actions.append("confirmation:request_filters_skipped")
    else:
        request_user_text = _request_user_text_for_excerpt(payload, req.route)
        debug_log_original("request_before_filters", request_user_text, max_len=180)

        sanitized_req = await _run_request_pipeline(pipeline, req, ctx)
        if ctx.request_disposition == "block":
            block_reason = ctx.disposition_reasons[-1] if ctx.disposition_reasons else "request_blocked"
            debug_log_original("request_blocked", request_user_text, reason=block_reason)
            reason, summary = _confirmation_reason_and_summary(
                ctx,
                phase=PHASE_REQUEST,
                source_text=request_user_text,
            )
            confirm_id = make_confirm_id()
            now_ts = int(time.time())
            pending_payload, pending_payload_hash, pending_payload_omitted, pending_payload_size = _prepare_pending_payload(
                payload
            )
            await _store_call(
                "save_pending_confirmation",
                confirm_id=confirm_id,
                session_id=req.session_id,
                route=req.route,
                request_id=req.request_id,
                model=req.model,
                upstream_base=upstream_base,
                pending_request_payload=pending_payload,
                pending_request_hash=pending_payload_hash,
                reason=reason,
                summary=summary,
                tenant_id=ctx.tenant_id,
                created_at=now_ts,
                expires_at=_confirmation_expires_at(now_ts, PHASE_REQUEST),
                retained_until=now_ts + max(60, int(settings.pending_data_ttl_seconds)),
            )
            if pending_payload_omitted:
                summary = f"{summary}（请求体过大，未缓存原文：{pending_payload_size} bytes）"
            ctx.disposition_reasons.append("awaiting_user_confirmation")
            ctx.security_tags.add("confirmation_required")
            confirmation_resp = InternalResponse(
                request_id=req.request_id,
                session_id=req.session_id,
                model=req.model,
                output_text=_build_confirmation_message(confirm_id=confirm_id, reason=reason, summary=summary, phase=PHASE_REQUEST),
            )
            _attach_security_metadata(confirmation_resp, ctx, boundary=boundary)
            _attach_confirmation_metadata(
                confirmation_resp,
                confirm_id=confirm_id,
                status="pending",
                reason=reason,
                summary=summary,
                phase=PHASE_REQUEST,
                payload_omitted=pending_payload_omitted,
            )
            _write_audit_event(ctx, boundary=boundary)
            logger.info("responses endpoint request blocked, confirmation required request_id=%s confirm_id=%s", ctx.request_id, confirm_id)
            return to_responses_output(confirmation_resp)

        upstream_payload = _build_responses_upstream_payload(
            payload, sanitized_req.messages,
            request_id=ctx.request_id, session_id=ctx.session_id, route=ctx.route,
        )

    try:
        status_code, upstream_body = await _forward_json(upstream_url, upstream_payload, forward_headers)
    except RuntimeError as exc:
        logger.error("upstream unreachable request_id=%s error=%s", ctx.request_id, exc)
        return _error_response(
            status_code=502,
            reason="upstream_unreachable",
            detail=str(exc),
            ctx=ctx,
            boundary=boundary,
        )

    if status_code >= 400:
        detail = _safe_error_detail(upstream_body)
        logger.warning("upstream http error request_id=%s status=%s detail=%s", ctx.request_id, status_code, detail)
        return _error_response(
            status_code=status_code,
            reason="upstream_http_error",
            detail=detail,
            ctx=ctx,
            boundary=boundary,
        )

    upstream_text = _extract_responses_output_text(upstream_body)
    capped_upstream_text = _cap_response_text(upstream_text, ctx)
    internal_resp = InternalResponse(
        request_id=req.request_id,
        session_id=req.session_id,
        model=req.model,
        output_text=capped_upstream_text,
        raw=upstream_body if isinstance(upstream_body, dict) else {"raw_text": upstream_body},
    )
    debug_log_original("response_before_filters", internal_resp.output_text)

    final_resp = await _run_response_pipeline(pipeline, internal_resp, ctx)
    if not skip_confirmation:
        await _apply_semantic_review(ctx, final_resp.output_text, phase="response")
    if skip_confirmation and final_resp.output_text.startswith("[AegisGate] response blocked by security policy."):
        final_resp.output_text = capped_upstream_text
        ctx.response_disposition = "allow"
        ctx.disposition_reasons.append("confirmed_release_override")
        ctx.enforcement_actions.append("confirmation:confirmed_release")
        ctx.security_tags.add("confirmed_release")

    if not skip_confirmation and _needs_confirmation(ctx):
        resp_reason = ctx.disposition_reasons[0] if ctx.disposition_reasons else "response_high_risk"
        debug_log_original("response_confirmation_original", final_resp.output_text, reason=resp_reason)
        reason, summary = _confirmation_reason_and_summary(ctx, source_text=final_resp.output_text)
        cached_output = _passthrough_responses_output(upstream_body, req)
        pending_payload = _build_response_pending_payload(
            route=req.route,
            request_id=req.request_id,
            session_id=req.session_id,
            model=req.model,
            fmt=_PENDING_FORMAT_RESPONSES_JSON,
            content=cached_output,
        )
        pending_payload, pending_payload_hash, pending_payload_size = _prepare_response_pending_payload(pending_payload)
        confirm_id = make_confirm_id()
        now_ts = int(time.time())
        await _store_call(
            "save_pending_confirmation",
            confirm_id=confirm_id,
            session_id=req.session_id,
            route=req.route,
            request_id=req.request_id,
            model=req.model,
            upstream_base=upstream_base,
            pending_request_payload=pending_payload,
            pending_request_hash=pending_payload_hash,
            reason=reason,
            summary=summary,
            tenant_id=ctx.tenant_id,
            created_at=now_ts,
            expires_at=_confirmation_expires_at(now_ts, PHASE_RESPONSE),
            retained_until=now_ts + max(60, int(settings.pending_data_ttl_seconds)),
        )
        ctx.response_disposition = "block"
        ctx.disposition_reasons.append("awaiting_user_confirmation")
        ctx.security_tags.add("confirmation_required")
        ctx.enforcement_actions.append("confirmation:pending")
        logger.info(
            "confirmation response cached request_id=%s confirm_id=%s route=%s format=%s bytes=%s",
            ctx.request_id,
            confirm_id,
            req.route,
            _PENDING_FORMAT_RESPONSES_JSON,
            pending_payload_size,
        )

        confirmation_resp = InternalResponse(
            request_id=req.request_id,
            session_id=req.session_id,
            model=req.model,
            output_text=_build_confirmation_message(confirm_id=confirm_id, reason=reason, summary=summary),
        )
        _attach_security_metadata(confirmation_resp, ctx, boundary=boundary)
        _attach_confirmation_metadata(
            confirmation_resp,
            confirm_id=confirm_id,
            status="pending",
            reason=reason,
            summary=summary,
            phase=PHASE_RESPONSE,
            payload_omitted=False,
        )
        _write_audit_event(ctx, boundary=boundary)
        logger.info("responses endpoint requires confirmation request_id=%s confirm_id=%s", ctx.request_id, confirm_id)
        return to_responses_output(confirmation_resp)

    _attach_security_metadata(final_resp, ctx, boundary=boundary)
    _write_audit_event(ctx, boundary=boundary)
    logger.info("responses endpoint completed request_id=%s", ctx.request_id)
    return _render_responses_output(upstream_body, final_resp)


def _passthrough_any_response(body: dict[str, Any] | str) -> JSONResponse | PlainTextResponse:
    if isinstance(body, dict):
        return JSONResponse(status_code=200, content=body)
    return PlainTextResponse(status_code=200, content=str(body))


async def _execute_generic_stream_once(
    *,
    payload: dict[str, Any],
    request_headers: Mapping[str, str],
    request_path: str,
    boundary: dict | None,
    tenant_id: str = "default",
) -> StreamingResponse | JSONResponse:
    request_id = str(payload.get("request_id") or f"generic-{int(time.time() * 1000)}")
    session_id = str(payload.get("session_id") or request_id)
    model = str(payload.get("model") or payload.get("target_model") or "generic-model")
    ctx = RequestContext(request_id=request_id, session_id=session_id, route=request_path, tenant_id=tenant_id)
    policy_engine.resolve(ctx, policy_name=payload.get("policy", settings.default_policy))
    logger.info("generic proxy stream start request_id=%s route=%s", ctx.request_id, request_path)

    try:
        upstream_base = _resolve_upstream_base(request_headers)
        upstream_url = _build_upstream_url(request_path, upstream_base)
        logger.debug("generic stream upstream request_id=%s base=%s url=%s", ctx.request_id, upstream_base, upstream_url)
    except ValueError as exc:
        logger.warning("invalid upstream base request_id=%s error=%s", ctx.request_id, exc)
        return _error_response(
            status_code=400,
            reason="invalid_upstream_base",
            detail=str(exc),
            ctx=ctx,
            boundary=boundary,
        )

    forward_headers = _build_forward_headers(request_headers)

    if _is_upstream_whitelisted(upstream_base):
        ctx.enforcement_actions.append("upstream_whitelist:direct_allow")
        ctx.security_tags.add("upstream_whitelist_bypass")

        async def whitelist_generator() -> AsyncGenerator[bytes, None]:
            try:
                async for line in _forward_stream_lines(upstream_url, payload, forward_headers):
                    yield line
            except RuntimeError as exc:
                detail = str(exc)
                reason = _stream_runtime_reason(detail)
                ctx.response_disposition = "block"
                ctx.disposition_reasons.append(reason)
                ctx.enforcement_actions.append(f"upstream:{reason}")
                logger.error("generic stream upstream failure request_id=%s error=%s", ctx.request_id, detail)
                yield _stream_error_sse_chunk(detail, code=reason)
                yield _stream_done_sse_chunk()
            except Exception as exc:  # pragma: no cover - fail-safe
                detail = f"gateway_internal_error: {exc}"
                ctx.response_disposition = "block"
                ctx.disposition_reasons.append("gateway_internal_error")
                ctx.enforcement_actions.append("upstream:gateway_internal_error")
                logger.exception("generic stream unexpected failure request_id=%s", ctx.request_id)
                yield _stream_error_sse_chunk(detail, code="gateway_internal_error")
                yield _stream_done_sse_chunk()
            finally:
                _write_audit_event(ctx, boundary=boundary)

        return _build_streaming_response(whitelist_generator())

    analysis_text = _extract_generic_analysis_text(payload)
    debug_log_original("request_before_filters", analysis_text or "[NON_TEXT_PAYLOAD]", max_len=180)
    req = InternalRequest(
        request_id=request_id,
        session_id=session_id,
        route=request_path,
        model=model,
        messages=[InternalMessage(role="user", content=analysis_text or "[NON_TEXT_PAYLOAD]", source="user")],
        metadata={"raw": payload},
    )

    pipeline = _get_pipeline()
    sanitized_req = await _run_request_pipeline(pipeline, req, ctx)
    if ctx.request_disposition == "block":
        block_reason = ctx.disposition_reasons[-1] if ctx.disposition_reasons else "request_blocked"
        debug_log_original("request_blocked", analysis_text or "[NON_TEXT_PAYLOAD]", reason=block_reason)
        return _error_response(
            status_code=403,
            reason="request_blocked",
            detail="generic provider request blocked by security policy",
            ctx=ctx,
            boundary=boundary,
        )
    if ctx.request_disposition == "sanitize" and sanitized_req.messages[0].content != (analysis_text or "[NON_TEXT_PAYLOAD]"):
        return _error_response(
            status_code=403,
            reason="generic_request_sanitize_unsupported",
            detail="generic provider payload requires sanitize but schema-safe rewrite is unavailable",
            ctx=ctx,
            boundary=boundary,
        )

    base_reports = list(ctx.report_items)

    async def guarded_generator() -> AsyncGenerator[bytes, None]:
        stream_window = ""
        chunk_count = 0
        try:
            async for line in _forward_stream_lines(upstream_url, payload, forward_headers):
                payload_text = _extract_sse_data_payload(line)
                if payload_text is not None and payload_text != "[DONE]":
                    chunk_text = _extract_stream_text_from_event(payload_text)
                    if chunk_text:
                        stream_window = _trim_stream_window(stream_window, chunk_text)
                        chunk_count += 1

                        ctx.report_items = list(base_reports)
                        probe_resp = InternalResponse(
                            request_id=req.request_id,
                            session_id=req.session_id,
                            model=req.model,
                            output_text=stream_window,
                            raw={"stream": True, "generic": True},
                        )
                        await _run_response_pipeline(pipeline, probe_resp, ctx)

                        if settings.enable_semantic_module and chunk_count % max(1, _STREAM_SEMANTIC_CHECK_INTERVAL) == 0:
                            await _apply_semantic_review(ctx, stream_window, phase="response")

                        block_reason = _stream_block_reason(ctx)
                        if block_reason:
                            debug_log_original("response_stream_blocked", stream_window, reason=block_reason)
                            ctx.response_disposition = "block"
                            if block_reason not in ctx.disposition_reasons:
                                ctx.disposition_reasons.append(block_reason)
                            ctx.enforcement_actions.append("stream:block")
                            logger.info("generic stream blocked request_id=%s reason=%s", ctx.request_id, block_reason)
                            break

                yield line
        except RuntimeError as exc:
            detail = str(exc)
            reason = _stream_runtime_reason(detail)
            ctx.response_disposition = "block"
            ctx.disposition_reasons.append(reason)
            ctx.enforcement_actions.append(f"upstream:{reason}")
            logger.error("generic stream upstream failure request_id=%s error=%s", ctx.request_id, detail)
            yield _stream_error_sse_chunk(detail, code=reason)
            yield _stream_done_sse_chunk()
        except Exception as exc:  # pragma: no cover - fail-safe
            detail = f"gateway_internal_error: {exc}"
            ctx.response_disposition = "block"
            ctx.disposition_reasons.append("gateway_internal_error")
            ctx.enforcement_actions.append("upstream:gateway_internal_error")
            logger.exception("generic stream unexpected failure request_id=%s", ctx.request_id)
            yield _stream_error_sse_chunk(detail, code="gateway_internal_error")
            yield _stream_done_sse_chunk()
        finally:
            _write_audit_event(ctx, boundary=boundary)

    return _build_streaming_response(guarded_generator())


async def _execute_generic_once(
    *,
    payload: dict[str, Any],
    request_headers: Mapping[str, str],
    request_path: str,
    boundary: dict | None,
    tenant_id: str = "default",
) -> JSONResponse | PlainTextResponse:
    request_id = str(payload.get("request_id") or f"generic-{int(time.time() * 1000)}")
    session_id = str(payload.get("session_id") or request_id)
    model = str(payload.get("model") or payload.get("target_model") or "generic-model")
    ctx = RequestContext(request_id=request_id, session_id=session_id, route=request_path, tenant_id=tenant_id)
    policy_engine.resolve(ctx, policy_name=payload.get("policy", settings.default_policy))
    logger.info("generic proxy start request_id=%s route=%s", ctx.request_id, request_path)

    try:
        upstream_base = _resolve_upstream_base(request_headers)
        upstream_url = _build_upstream_url(request_path, upstream_base)
        logger.debug("generic proxy upstream request_id=%s base=%s url=%s", ctx.request_id, upstream_base, upstream_url)
    except ValueError as exc:
        logger.warning("invalid upstream base request_id=%s error=%s", ctx.request_id, exc)
        return _error_response(
            status_code=400,
            reason="invalid_upstream_base",
            detail=str(exc),
            ctx=ctx,
            boundary=boundary,
        )

    forward_headers = _build_forward_headers(request_headers)
    if _is_upstream_whitelisted(upstream_base):
        try:
            status_code, upstream_body = await _forward_json(upstream_url, payload, forward_headers)
        except RuntimeError as exc:
            logger.error("generic upstream unreachable request_id=%s error=%s", ctx.request_id, exc)
            return _error_response(
                status_code=502,
                reason="upstream_unreachable",
                detail=str(exc),
                ctx=ctx,
                boundary=boundary,
            )
        if status_code >= 400:
            detail = _safe_error_detail(upstream_body)
            return _error_response(
                status_code=status_code,
                reason="upstream_http_error",
                detail=detail,
                ctx=ctx,
                boundary=boundary,
            )
        ctx.enforcement_actions.append("upstream_whitelist:direct_allow")
        ctx.security_tags.add("upstream_whitelist_bypass")
        _write_audit_event(ctx, boundary=boundary)
        return _passthrough_any_response(upstream_body)

    analysis_text = _extract_generic_analysis_text(payload)
    debug_log_original("request_before_filters", analysis_text or "[NON_TEXT_PAYLOAD]", max_len=180)
    req = InternalRequest(
        request_id=request_id,
        session_id=session_id,
        route=request_path,
        model=model,
        messages=[InternalMessage(role="user", content=analysis_text or "[NON_TEXT_PAYLOAD]", source="user")],
        metadata={"raw": payload},
    )

    pipeline = _get_pipeline()
    sanitized_req = await _run_request_pipeline(pipeline, req, ctx)
    logger.debug(
        "generic proxy request evaluated request_id=%s disposition=%s reasons=%s",
        ctx.request_id,
        ctx.request_disposition,
        ctx.disposition_reasons,
    )
    if ctx.request_disposition == "block":
        block_reason = ctx.disposition_reasons[-1] if ctx.disposition_reasons else "request_blocked"
        debug_log_original("request_blocked", analysis_text or "[NON_TEXT_PAYLOAD]", reason=block_reason)
        return _error_response(
            status_code=403,
            reason="request_blocked",
            detail="generic provider request blocked by security policy",
            ctx=ctx,
            boundary=boundary,
        )
    # Generic provider schemas are not rewritten for sanitize. Use block-on-sanitize to avoid unsafe partial mutations.
    if ctx.request_disposition == "sanitize" and sanitized_req.messages[0].content != (analysis_text or "[NON_TEXT_PAYLOAD]"):
        return _error_response(
            status_code=403,
            reason="generic_request_sanitize_unsupported",
            detail="generic provider payload requires sanitize but schema-safe rewrite is unavailable",
            ctx=ctx,
            boundary=boundary,
        )

    try:
        status_code, upstream_body = await _forward_json(upstream_url, payload, forward_headers)
    except RuntimeError as exc:
        logger.error("generic upstream unreachable request_id=%s error=%s", ctx.request_id, exc)
        return _error_response(
            status_code=502,
            reason="upstream_unreachable",
            detail=str(exc),
            ctx=ctx,
            boundary=boundary,
        )

    if status_code >= 400:
        detail = _safe_error_detail(upstream_body)
        return _error_response(
            status_code=status_code,
            reason="upstream_http_error",
            detail=detail,
            ctx=ctx,
            boundary=boundary,
        )

    upstream_text = _extract_generic_analysis_text(upstream_body)
    capped_upstream_text = _cap_response_text(upstream_text, ctx)
    internal_resp = InternalResponse(
        request_id=req.request_id,
        session_id=req.session_id,
        model=req.model,
        output_text=capped_upstream_text,
        raw=upstream_body if isinstance(upstream_body, dict) else {"raw_text": str(upstream_body)},
    )
    await _run_response_pipeline(pipeline, internal_resp, ctx)
    if settings.enable_semantic_module:
        await _apply_semantic_review(ctx, internal_resp.output_text, phase="response")
    logger.debug(
        "generic proxy response evaluated request_id=%s disposition=%s reasons=%s",
        ctx.request_id,
        ctx.response_disposition,
        ctx.disposition_reasons,
    )
    if _needs_confirmation(ctx):
        return _error_response(
            status_code=403,
            reason="generic_response_blocked",
            detail="generic provider response blocked by security policy",
            ctx=ctx,
            boundary=boundary,
        )

    _write_audit_event(ctx, boundary=boundary)
    logger.info("generic proxy completed request_id=%s route=%s", ctx.request_id, request_path)
    return _passthrough_any_response(upstream_body)


@router.post("/chat/completions")
async def chat_completions(payload: dict, request: Request):
    _log_request_if_debug(request, payload, "/v1/chat/completions")
    boundary = getattr(request.state, "security_boundary", {})
    gateway_headers = _effective_gateway_headers(request)
    tenant_id = _resolve_tenant_id(payload=payload, headers=gateway_headers, boundary=boundary)
    request_id = str(payload.get("request_id") or "preview-chat")
    session_id = str(payload.get("session_id") or request_id)
    ctx_preview = RequestContext(
        request_id=request_id,
        session_id=session_id,
        route="/v1/chat/completions",
        tenant_id=tenant_id,
    )

    ok_payload, status_code, reason, detail = _validate_payload_limits(payload, route=ctx_preview.route)
    if not ok_payload:
        return _error_response(
            status_code=status_code,
            reason=reason,
            detail=detail,
            ctx=ctx_preview,
            boundary=boundary,
        )

    req_preview = to_internal_chat(payload)
    ctx_preview.request_id = req_preview.request_id
    ctx_preview.session_id = req_preview.session_id

    now_ts = int(time.time())
    user_text = _extract_chat_user_text(payload)
    decision_value, confirm_id_hint = _parse_explicit_confirmation_command(user_text)
    tail_preview = _confirmation_tail_preview(user_text)
    pending = await _maybe_offload(
        _resolve_pending_confirmation,
        payload,
        user_text,
        now_ts,
        expected_route=req_preview.route,
        tenant_id=tenant_id,
    )
    logger.info(
        "confirmation incoming request_id=%s session_id=%s tenant_id=%s route=%s decision=%s confirm_id_hint=%s pending_found=%s parser=tail_explicit tail_preview=%s",
        req_preview.request_id,
        req_preview.session_id,
        tenant_id,
        req_preview.route,
        decision_value,
        confirm_id_hint or "-",
        bool(pending),
        tail_preview,
    )
    confirmation_bypass_reason = "no_explicit_confirmation_command"

    if pending:
        pending_route = str(pending.get("route", ""))
        confirm_id = str(pending["confirm_id"])
        expected_action_token = _pending_action_bind_token(pending)
        decision_value, decision_source = _extract_decision_by_bound_token(
            user_text,
            confirm_id,
            expected_action_token,
        )
        reason_text = str(pending.get("reason", "高风险响应"))
        summary_text = str(pending.get("summary", "检测到高风险信号"))
        provided_action_token = str(pending.get("_aegisgate_bind_action_token") or _extract_action_token(user_text))
        logger.info(
            "confirmation pending matched request_id=%s session_id=%s tenant_id=%s route=%s confirm_id=%s pending_route=%s decision=%s source=%s action_token_provided=%s",
            req_preview.request_id,
            req_preview.session_id,
            tenant_id,
            req_preview.route,
            confirm_id,
            pending_route,
            decision_value,
            decision_source,
            bool(provided_action_token),
        )
        invalid_reason = ""
        if pending_route != req_preview.route:
            invalid_reason = "route_mismatch"
        elif decision_value not in {"yes", "no"}:
            invalid_reason = f"unsupported_decision_{decision_value}"
        if invalid_reason:
            confirmation_bypass_reason = f"pending_retained_{invalid_reason}"
            logger.info(
                "confirmation command not executable request_id=%s session_id=%s tenant_id=%s route=%s confirm_id=%s decision=%s source=%s invalid_reason=%s action_token_provided=%s action_token_match=%s forward_as_new_request=true pending_retained=true explicit_keyword=%s",
                req_preview.request_id,
                req_preview.session_id,
                tenant_id,
                req_preview.route,
                confirm_id,
                decision_value,
                decision_source,
                invalid_reason,
                bool(provided_action_token),
                bool(provided_action_token and provided_action_token == expected_action_token),
                _has_explicit_confirmation_keyword(user_text),
            )
        elif decision_value == "no":
            changed = await _try_transition_pending_status(
                confirm_id=confirm_id,
                expected_status="pending",
                new_status="canceled",
                now_ts=now_ts,
            )
            if not changed:
                done_resp = InternalResponse(
                    request_id=req_preview.request_id,
                    session_id=req_preview.session_id,
                    model=req_preview.model,
                    output_text=_confirmation_already_processed_text(confirm_id),
                )
                ctx_preview.response_disposition = "block"
                ctx_preview.disposition_reasons.append("confirmation_already_processed")
                _attach_security_metadata(done_resp, ctx_preview, boundary=boundary)
                _attach_confirmation_metadata(
                    done_resp,
                    confirm_id=confirm_id,
                    status="already_processed",
                    reason=reason_text,
                    summary=summary_text,
                )
                _write_audit_event(ctx_preview, boundary=boundary)
                return to_chat_response(done_resp)

            deleted = await _delete_pending_confirmation(confirm_id)
            canceled_resp = InternalResponse(
                request_id=req_preview.request_id,
                session_id=req_preview.session_id,
                model=req_preview.model,
                output_text=f"已取消执行。确认编号：{confirm_id}\nCanceled. Confirmation ID: {confirm_id}",
            )
            ctx_preview.response_disposition = "block"
            ctx_preview.disposition_reasons.append("confirmation_canceled")
            _attach_security_metadata(canceled_resp, ctx_preview, boundary=boundary)
            _attach_confirmation_metadata(
                canceled_resp,
                confirm_id=confirm_id,
                status="canceled",
                reason=reason_text,
                summary=summary_text,
            )
            _write_audit_event(ctx_preview, boundary=boundary)
            logger.info(
                "confirmation canceled request_id=%s session_id=%s tenant_id=%s confirm_id=%s",
                req_preview.request_id,
                req_preview.session_id,
                tenant_id,
                confirm_id,
            )
            logger.info(
                "confirmation pending cache deleted request_id=%s session_id=%s tenant_id=%s confirm_id=%s deleted=%s",
                req_preview.request_id,
                req_preview.session_id,
                tenant_id,
                confirm_id,
                deleted,
            )
            return to_chat_response(canceled_resp)

        elif decision_value == "yes":
            logger.info(
                "confirmation approve request_id=%s session_id=%s tenant_id=%s confirm_id=%s",
                req_preview.request_id,
                req_preview.session_id,
                tenant_id,
                confirm_id,
            )
            locked = await _try_transition_pending_status(
                confirm_id=confirm_id,
                expected_status="pending",
                new_status="executing",
                now_ts=now_ts,
            )
            if not locked:
                done_resp = InternalResponse(
                    request_id=req_preview.request_id,
                    session_id=req_preview.session_id,
                    model=req_preview.model,
                    output_text=_confirmation_already_processed_text(confirm_id),
                )
                ctx_preview.response_disposition = "block"
                ctx_preview.disposition_reasons.append("confirmation_already_processed")
                _attach_security_metadata(done_resp, ctx_preview, boundary=boundary)
                _attach_confirmation_metadata(
                    done_resp,
                    confirm_id=confirm_id,
                    status="already_processed",
                    reason=reason_text,
                    summary=summary_text,
                )
                _write_audit_event(ctx_preview, boundary=boundary)
                return to_chat_response(done_resp)

            pending_payload = pending.get("pending_request_payload", {})
            if not isinstance(pending_payload, dict):
                await _try_transition_pending_status(
                    confirm_id=confirm_id,
                    expected_status="executing",
                    new_status="expired",
                    now_ts=now_ts,
                )
                invalid_resp = InternalResponse(
                    request_id=req_preview.request_id,
                    session_id=req_preview.session_id,
                    model=req_preview.model,
                    output_text=_pending_payload_invalid_text(confirm_id),
                )
                ctx_preview.response_disposition = "block"
                ctx_preview.disposition_reasons.append("pending_payload_invalid")
                _attach_security_metadata(invalid_resp, ctx_preview, boundary=boundary)
                _attach_confirmation_metadata(
                    invalid_resp,
                    confirm_id=confirm_id,
                    status="payload_invalid",
                    reason=reason_text,
                    summary=summary_text,
                )
                _write_audit_event(ctx_preview, boundary=boundary)
                return to_chat_response(invalid_resp)
            if payload_hash(pending_payload) != str(pending.get("pending_request_hash", "")):
                await _try_transition_pending_status(
                    confirm_id=confirm_id,
                    expected_status="executing",
                    new_status="expired",
                    now_ts=now_ts,
                )
                mismatch_resp = InternalResponse(
                    request_id=req_preview.request_id,
                    session_id=req_preview.session_id,
                    model=req_preview.model,
                    output_text=_pending_hash_mismatch_text(confirm_id),
                )
                ctx_preview.response_disposition = "block"
                ctx_preview.disposition_reasons.append("pending_hash_mismatch")
                _attach_security_metadata(mismatch_resp, ctx_preview, boundary=boundary)
                _attach_confirmation_metadata(
                    mismatch_resp,
                    confirm_id=confirm_id,
                    status="hash_mismatch",
                    reason=reason_text,
                    summary=summary_text,
                )
                _write_audit_event(ctx_preview, boundary=boundary)
                return to_chat_response(mismatch_resp)

            if _is_response_pending_payload(pending_payload):
                pending_fmt = str(pending_payload.get(_PENDING_PAYLOAD_FORMAT_KEY, "")).strip()
                pending_content = pending_payload.get(_PENDING_PAYLOAD_CONTENT_KEY)
                if _should_stream(payload) and pending_fmt == _PENDING_FORMAT_CHAT_STREAM_TEXT and isinstance(pending_content, str):
                    await _try_transition_pending_status(
                        confirm_id=confirm_id,
                        expected_status="executing",
                        new_status="executed",
                        now_ts=int(time.time()),
                    )
                    logger.info(
                        "confirmation released cached stream response request_id=%s session_id=%s tenant_id=%s confirm_id=%s",
                        req_preview.request_id,
                        req_preview.session_id,
                        tenant_id,
                        confirm_id,
                    )
                    return _render_cached_chat_confirmation_stream_output(
                        request_id=req_preview.request_id,
                        model=req_preview.model,
                        content=pending_content,
                        confirm_id=confirm_id,
                        reason=reason_text,
                        summary=summary_text,
                    )

                released = _render_cached_chat_confirmation_output(
                    pending_payload,
                    fallback_request_id=req_preview.request_id,
                    fallback_session_id=req_preview.session_id,
                    fallback_model=req_preview.model,
                )
                if not isinstance(released, dict):
                    await _try_transition_pending_status(
                        confirm_id=confirm_id,
                        expected_status="executing",
                        new_status="expired",
                        now_ts=now_ts,
                    )
                    invalid_resp = InternalResponse(
                        request_id=req_preview.request_id,
                        session_id=req_preview.session_id,
                        model=req_preview.model,
                        output_text=_pending_payload_invalid_text(confirm_id),
                    )
                    ctx_preview.response_disposition = "block"
                    ctx_preview.disposition_reasons.append("pending_payload_invalid")
                    _attach_security_metadata(invalid_resp, ctx_preview, boundary=boundary)
                    _attach_confirmation_metadata(
                        invalid_resp,
                        confirm_id=confirm_id,
                        status="payload_invalid",
                        reason=reason_text,
                        summary=summary_text,
                    )
                    _write_audit_event(ctx_preview, boundary=boundary)
                    return to_chat_response(invalid_resp)
                await _try_transition_pending_status(
                    confirm_id=confirm_id,
                    expected_status="executing",
                    new_status="executed",
                    now_ts=int(time.time()),
                )
                logger.info(
                    "confirmation released cached response request_id=%s session_id=%s tenant_id=%s confirm_id=%s",
                    req_preview.request_id,
                    req_preview.session_id,
                    tenant_id,
                    confirm_id,
                )
                return _attach_executed_confirmation(
                    released,
                    confirm_id=confirm_id,
                    reason=reason_text,
                    summary=summary_text,
                )

            if _is_pending_payload_omitted(pending_payload):
                await _try_transition_pending_status(
                    confirm_id=confirm_id,
                    expected_status="executing",
                    new_status="expired",
                    now_ts=now_ts,
                )
                omitted_resp = InternalResponse(
                    request_id=req_preview.request_id,
                    session_id=req_preview.session_id,
                    model=req_preview.model,
                    output_text=_pending_payload_omitted_text(confirm_id),
                )
                ctx_preview.response_disposition = "block"
                ctx_preview.disposition_reasons.append("pending_payload_omitted")
                ctx_preview.security_tags.add("pending_payload_omitted")
                ctx_preview.enforcement_actions.append("confirmation:payload_omitted")
                _attach_security_metadata(omitted_resp, ctx_preview, boundary=boundary)
                _attach_confirmation_metadata(
                    omitted_resp,
                    confirm_id=confirm_id,
                    status="payload_omitted",
                    reason=reason_text,
                    summary=summary_text,
                    payload_omitted=True,
                )
                _write_audit_event(ctx_preview, boundary=boundary)
                return to_chat_response(omitted_resp)

            try:
                executed = await _execute_chat_once(
                    payload=pending_payload,
                    request_headers=gateway_headers,
                    request_path=_request_target_path(request),
                    boundary=boundary,
                    tenant_id=str(pending.get("tenant_id") or tenant_id),
                    skip_confirmation=True,
                    forced_upstream_base=str(pending.get("upstream_base", "")),
                )
            except Exception as exc:
                await _try_transition_pending_status(
                    confirm_id=confirm_id,
                    expected_status="executing",
                    new_status="pending",
                    now_ts=int(time.time()),
                )
                logger.exception(
                    "confirmation execute failed request_id=%s session_id=%s tenant_id=%s confirm_id=%s error=%s",
                    req_preview.request_id,
                    req_preview.session_id,
                    tenant_id,
                    confirm_id,
                    exc,
                )
                failed_resp = InternalResponse(
                    request_id=req_preview.request_id,
                    session_id=req_preview.session_id,
                    model=req_preview.model,
                    output_text=_confirmation_execute_failed_text(confirm_id),
                )
                ctx_preview.response_disposition = "block"
                ctx_preview.disposition_reasons.append("confirmation_execute_failed")
                _attach_security_metadata(failed_resp, ctx_preview, boundary=boundary)
                _attach_confirmation_metadata(
                    failed_resp,
                    confirm_id=confirm_id,
                    status="execute_failed",
                    reason=reason_text,
                    summary=summary_text,
                )
                _write_audit_event(ctx_preview, boundary=boundary)
                return to_chat_response(failed_resp)
            if isinstance(executed, JSONResponse):
                await _try_transition_pending_status(
                    confirm_id=confirm_id,
                    expected_status="executing",
                    new_status="pending",
                    now_ts=int(time.time()),
                )
                return executed
            await _try_transition_pending_status(
                confirm_id=confirm_id,
                expected_status="executing",
                new_status="executed",
                now_ts=int(time.time()),
            )
            logger.info(
                "confirmation executed request_id=%s session_id=%s tenant_id=%s confirm_id=%s",
                req_preview.request_id,
                req_preview.session_id,
                tenant_id,
                confirm_id,
            )
            return _attach_executed_confirmation(
                executed,
                confirm_id=confirm_id,
                reason=reason_text,
                summary=summary_text,
            )
    elif decision_value in {"yes", "no"}:
        if confirm_id_hint:
            confirmation_bypass_reason = "confirmation_command_no_matching_pending"
        else:
            confirmation_bypass_reason = "confirmation_command_without_unique_pending"

    logger.info(
        "confirmation bypass request_id=%s session_id=%s tenant_id=%s route=%s reason=%s forward_as_new_request=true pending_found=%s decision=%s confirm_id_hint=%s tail_preview=%s",
        req_preview.request_id,
        req_preview.session_id,
        tenant_id,
        req_preview.route,
        confirmation_bypass_reason,
        bool(pending),
        decision_value,
        confirm_id_hint or "-",
        tail_preview,
    )

    if _should_stream(payload):
        return await _execute_chat_stream_once(
            payload=payload,
            request_headers=gateway_headers,
            request_path=_request_target_path(request),
            boundary=boundary,
            tenant_id=tenant_id,
            forced_upstream_base=None,
        )

    return await _execute_chat_once(
        payload=payload,
        request_headers=gateway_headers,
        request_path=_request_target_path(request),
        boundary=boundary,
        tenant_id=tenant_id,
        skip_confirmation=False,
        forced_upstream_base=None,
    )


@router.post("/responses")
async def responses(payload: dict, request: Request):
    _log_request_if_debug(request, payload, "/v1/responses")
    boundary = getattr(request.state, "security_boundary", {})
    gateway_headers = _effective_gateway_headers(request)
    tenant_id = _resolve_tenant_id(payload=payload, headers=gateway_headers, boundary=boundary)
    request_id = str(payload.get("request_id") or "preview-responses")
    session_id = str(payload.get("session_id") or request_id)
    ctx_preview = RequestContext(
        request_id=request_id,
        session_id=session_id,
        route="/v1/responses",
        tenant_id=tenant_id,
    )

    ok_payload, status_code, reason, detail = _validate_payload_limits(payload, route=ctx_preview.route)
    if not ok_payload:
        return _error_response(
            status_code=status_code,
            reason=reason,
            detail=detail,
            ctx=ctx_preview,
            boundary=boundary,
        )

    req_preview = to_internal_responses(payload)
    ctx_preview.request_id = req_preview.request_id
    ctx_preview.session_id = req_preview.session_id

    now_ts = int(time.time())
    user_text = _extract_responses_user_text(payload)
    decision_value, confirm_id_hint = _parse_explicit_confirmation_command(user_text)
    tail_preview = _confirmation_tail_preview(user_text)
    pending = await _maybe_offload(
        _resolve_pending_confirmation,
        payload,
        user_text,
        now_ts,
        expected_route=req_preview.route,
        tenant_id=tenant_id,
    )
    logger.info(
        "confirmation incoming request_id=%s session_id=%s tenant_id=%s route=%s decision=%s confirm_id_hint=%s pending_found=%s parser=tail_explicit tail_preview=%s",
        req_preview.request_id,
        req_preview.session_id,
        tenant_id,
        req_preview.route,
        decision_value,
        confirm_id_hint or "-",
        bool(pending),
        tail_preview,
    )
    confirmation_bypass_reason = "no_explicit_confirmation_command"

    if pending:
        pending_route = str(pending.get("route", ""))
        confirm_id = str(pending["confirm_id"])
        expected_action_token = _pending_action_bind_token(pending)
        decision_value, decision_source = _extract_decision_by_bound_token(
            user_text,
            confirm_id,
            expected_action_token,
        )
        reason_text = str(pending.get("reason", "高风险响应"))
        summary_text = str(pending.get("summary", "检测到高风险信号"))
        provided_action_token = str(pending.get("_aegisgate_bind_action_token") or _extract_action_token(user_text))
        logger.info(
            "confirmation pending matched request_id=%s session_id=%s tenant_id=%s route=%s confirm_id=%s pending_route=%s decision=%s source=%s action_token_provided=%s",
            req_preview.request_id,
            req_preview.session_id,
            tenant_id,
            req_preview.route,
            confirm_id,
            pending_route,
            decision_value,
            decision_source,
            bool(provided_action_token),
        )
        invalid_reason = ""
        if pending_route != req_preview.route:
            invalid_reason = "route_mismatch"
        elif decision_value not in {"yes", "no"}:
            invalid_reason = f"unsupported_decision_{decision_value}"
        if invalid_reason:
            confirmation_bypass_reason = f"pending_retained_{invalid_reason}"
            logger.info(
                "confirmation command not executable request_id=%s session_id=%s tenant_id=%s route=%s confirm_id=%s decision=%s source=%s invalid_reason=%s action_token_provided=%s action_token_match=%s forward_as_new_request=true pending_retained=true explicit_keyword=%s",
                req_preview.request_id,
                req_preview.session_id,
                tenant_id,
                req_preview.route,
                confirm_id,
                decision_value,
                decision_source,
                invalid_reason,
                bool(provided_action_token),
                bool(provided_action_token and provided_action_token == expected_action_token),
                _has_explicit_confirmation_keyword(user_text),
            )
        elif decision_value == "no":
            changed = await _try_transition_pending_status(
                confirm_id=confirm_id,
                expected_status="pending",
                new_status="canceled",
                now_ts=now_ts,
            )
            if not changed:
                done_resp = InternalResponse(
                    request_id=req_preview.request_id,
                    session_id=req_preview.session_id,
                    model=req_preview.model,
                    output_text=_confirmation_already_processed_text(confirm_id),
                )
                ctx_preview.response_disposition = "block"
                ctx_preview.disposition_reasons.append("confirmation_already_processed")
                _attach_security_metadata(done_resp, ctx_preview, boundary=boundary)
                _attach_confirmation_metadata(
                    done_resp,
                    confirm_id=confirm_id,
                    status="already_processed",
                    reason=reason_text,
                    summary=summary_text,
                )
                _write_audit_event(ctx_preview, boundary=boundary)
                return to_responses_output(done_resp)

            deleted = await _delete_pending_confirmation(confirm_id)
            canceled_resp = InternalResponse(
                request_id=req_preview.request_id,
                session_id=req_preview.session_id,
                model=req_preview.model,
                output_text=f"已取消执行。确认编号：{confirm_id}\nCanceled. Confirmation ID: {confirm_id}",
            )
            ctx_preview.response_disposition = "block"
            ctx_preview.disposition_reasons.append("confirmation_canceled")
            _attach_security_metadata(canceled_resp, ctx_preview, boundary=boundary)
            _attach_confirmation_metadata(
                canceled_resp,
                confirm_id=confirm_id,
                status="canceled",
                reason=reason_text,
                summary=summary_text,
            )
            _write_audit_event(ctx_preview, boundary=boundary)
            logger.info(
                "confirmation canceled request_id=%s session_id=%s tenant_id=%s confirm_id=%s",
                req_preview.request_id,
                req_preview.session_id,
                tenant_id,
                confirm_id,
            )
            logger.info(
                "confirmation pending cache deleted request_id=%s session_id=%s tenant_id=%s confirm_id=%s deleted=%s",
                req_preview.request_id,
                req_preview.session_id,
                tenant_id,
                confirm_id,
                deleted,
            )
            return to_responses_output(canceled_resp)

        elif decision_value == "yes":
            logger.info(
                "confirmation approve request_id=%s session_id=%s tenant_id=%s confirm_id=%s",
                req_preview.request_id,
                req_preview.session_id,
                tenant_id,
                confirm_id,
            )
            locked = await _try_transition_pending_status(
                confirm_id=confirm_id,
                expected_status="pending",
                new_status="executing",
                now_ts=now_ts,
            )
            if not locked:
                done_resp = InternalResponse(
                    request_id=req_preview.request_id,
                    session_id=req_preview.session_id,
                    model=req_preview.model,
                    output_text=_confirmation_already_processed_text(confirm_id),
                )
                ctx_preview.response_disposition = "block"
                ctx_preview.disposition_reasons.append("confirmation_already_processed")
                _attach_security_metadata(done_resp, ctx_preview, boundary=boundary)
                _attach_confirmation_metadata(
                    done_resp,
                    confirm_id=confirm_id,
                    status="already_processed",
                    reason=reason_text,
                    summary=summary_text,
                )
                _write_audit_event(ctx_preview, boundary=boundary)
                return to_responses_output(done_resp)

            pending_payload = pending.get("pending_request_payload", {})
            if not isinstance(pending_payload, dict):
                await _try_transition_pending_status(
                    confirm_id=confirm_id,
                    expected_status="executing",
                    new_status="expired",
                    now_ts=now_ts,
                )
                invalid_resp = InternalResponse(
                    request_id=req_preview.request_id,
                    session_id=req_preview.session_id,
                    model=req_preview.model,
                    output_text=_pending_payload_invalid_text(confirm_id),
                )
                ctx_preview.response_disposition = "block"
                ctx_preview.disposition_reasons.append("pending_payload_invalid")
                _attach_security_metadata(invalid_resp, ctx_preview, boundary=boundary)
                _attach_confirmation_metadata(
                    invalid_resp,
                    confirm_id=confirm_id,
                    status="payload_invalid",
                    reason=reason_text,
                    summary=summary_text,
                )
                _write_audit_event(ctx_preview, boundary=boundary)
                return to_responses_output(invalid_resp)
            if payload_hash(pending_payload) != str(pending.get("pending_request_hash", "")):
                await _try_transition_pending_status(
                    confirm_id=confirm_id,
                    expected_status="executing",
                    new_status="expired",
                    now_ts=now_ts,
                )
                mismatch_resp = InternalResponse(
                    request_id=req_preview.request_id,
                    session_id=req_preview.session_id,
                    model=req_preview.model,
                    output_text=_pending_hash_mismatch_text(confirm_id),
                )
                ctx_preview.response_disposition = "block"
                ctx_preview.disposition_reasons.append("pending_hash_mismatch")
                _attach_security_metadata(mismatch_resp, ctx_preview, boundary=boundary)
                _attach_confirmation_metadata(
                    mismatch_resp,
                    confirm_id=confirm_id,
                    status="hash_mismatch",
                    reason=reason_text,
                    summary=summary_text,
                )
                _write_audit_event(ctx_preview, boundary=boundary)
                return to_responses_output(mismatch_resp)

            if _is_response_pending_payload(pending_payload):
                pending_fmt = str(pending_payload.get(_PENDING_PAYLOAD_FORMAT_KEY, "")).strip()
                pending_content = pending_payload.get(_PENDING_PAYLOAD_CONTENT_KEY)
                if _should_stream(payload) and pending_fmt == _PENDING_FORMAT_RESPONSES_STREAM_TEXT and isinstance(pending_content, str):
                    await _try_transition_pending_status(
                        confirm_id=confirm_id,
                        expected_status="executing",
                        new_status="executed",
                        now_ts=int(time.time()),
                    )
                    logger.info(
                        "confirmation released cached stream response request_id=%s session_id=%s tenant_id=%s confirm_id=%s",
                        req_preview.request_id,
                        req_preview.session_id,
                        tenant_id,
                        confirm_id,
                    )
                    return _render_cached_responses_confirmation_stream_output(
                        request_id=req_preview.request_id,
                        model=req_preview.model,
                        content=pending_content,
                        confirm_id=confirm_id,
                        reason=reason_text,
                        summary=summary_text,
                    )

                released = _render_cached_responses_confirmation_output(
                    pending_payload,
                    fallback_request_id=req_preview.request_id,
                    fallback_session_id=req_preview.session_id,
                    fallback_model=req_preview.model,
                )
                if not isinstance(released, dict):
                    await _try_transition_pending_status(
                        confirm_id=confirm_id,
                        expected_status="executing",
                        new_status="expired",
                        now_ts=now_ts,
                    )
                    invalid_resp = InternalResponse(
                        request_id=req_preview.request_id,
                        session_id=req_preview.session_id,
                        model=req_preview.model,
                        output_text=_pending_payload_invalid_text(confirm_id),
                    )
                    ctx_preview.response_disposition = "block"
                    ctx_preview.disposition_reasons.append("pending_payload_invalid")
                    _attach_security_metadata(invalid_resp, ctx_preview, boundary=boundary)
                    _attach_confirmation_metadata(
                        invalid_resp,
                        confirm_id=confirm_id,
                        status="payload_invalid",
                        reason=reason_text,
                        summary=summary_text,
                    )
                    _write_audit_event(ctx_preview, boundary=boundary)
                    return to_responses_output(invalid_resp)
                await _try_transition_pending_status(
                    confirm_id=confirm_id,
                    expected_status="executing",
                    new_status="executed",
                    now_ts=int(time.time()),
                )
                logger.info(
                    "confirmation released cached response request_id=%s session_id=%s tenant_id=%s confirm_id=%s",
                    req_preview.request_id,
                    req_preview.session_id,
                    tenant_id,
                    confirm_id,
                )
                return _attach_executed_confirmation(
                    released,
                    confirm_id=confirm_id,
                    reason=reason_text,
                    summary=summary_text,
                )

            if _is_pending_payload_omitted(pending_payload):
                await _try_transition_pending_status(
                    confirm_id=confirm_id,
                    expected_status="executing",
                    new_status="expired",
                    now_ts=now_ts,
                )
                omitted_resp = InternalResponse(
                    request_id=req_preview.request_id,
                    session_id=req_preview.session_id,
                    model=req_preview.model,
                    output_text=_pending_payload_omitted_text(confirm_id),
                )
                ctx_preview.response_disposition = "block"
                ctx_preview.disposition_reasons.append("pending_payload_omitted")
                ctx_preview.security_tags.add("pending_payload_omitted")
                ctx_preview.enforcement_actions.append("confirmation:payload_omitted")
                _attach_security_metadata(omitted_resp, ctx_preview, boundary=boundary)
                _attach_confirmation_metadata(
                    omitted_resp,
                    confirm_id=confirm_id,
                    status="payload_omitted",
                    reason=reason_text,
                    summary=summary_text,
                    payload_omitted=True,
                )
                _write_audit_event(ctx_preview, boundary=boundary)
                return to_responses_output(omitted_resp)

            try:
                executed = await _execute_responses_once(
                    payload=pending_payload,
                    request_headers=gateway_headers,
                    request_path=_request_target_path(request),
                    boundary=boundary,
                    tenant_id=str(pending.get("tenant_id") or tenant_id),
                    skip_confirmation=True,
                    forced_upstream_base=str(pending.get("upstream_base", "")),
                )
            except Exception as exc:
                await _try_transition_pending_status(
                    confirm_id=confirm_id,
                    expected_status="executing",
                    new_status="pending",
                    now_ts=int(time.time()),
                )
                logger.exception(
                    "confirmation execute failed request_id=%s session_id=%s tenant_id=%s confirm_id=%s error=%s",
                    req_preview.request_id,
                    req_preview.session_id,
                    tenant_id,
                    confirm_id,
                    exc,
                )
                failed_resp = InternalResponse(
                    request_id=req_preview.request_id,
                    session_id=req_preview.session_id,
                    model=req_preview.model,
                    output_text=_confirmation_execute_failed_text(confirm_id),
                )
                ctx_preview.response_disposition = "block"
                ctx_preview.disposition_reasons.append("confirmation_execute_failed")
                _attach_security_metadata(failed_resp, ctx_preview, boundary=boundary)
                _attach_confirmation_metadata(
                    failed_resp,
                    confirm_id=confirm_id,
                    status="execute_failed",
                    reason=reason_text,
                    summary=summary_text,
                )
                _write_audit_event(ctx_preview, boundary=boundary)
                return to_responses_output(failed_resp)
            if isinstance(executed, JSONResponse):
                await _try_transition_pending_status(
                    confirm_id=confirm_id,
                    expected_status="executing",
                    new_status="pending",
                    now_ts=int(time.time()),
                )
                return executed
            await _try_transition_pending_status(
                confirm_id=confirm_id,
                expected_status="executing",
                new_status="executed",
                now_ts=int(time.time()),
            )
            logger.info(
                "confirmation executed request_id=%s session_id=%s tenant_id=%s confirm_id=%s",
                req_preview.request_id,
                req_preview.session_id,
                tenant_id,
                confirm_id,
            )
            return _attach_executed_confirmation(
                executed,
                confirm_id=confirm_id,
                reason=reason_text,
                summary=summary_text,
            )
    elif decision_value in {"yes", "no"}:
        if confirm_id_hint:
            confirmation_bypass_reason = "confirmation_command_no_matching_pending"
        else:
            confirmation_bypass_reason = "confirmation_command_without_unique_pending"

    logger.info(
        "confirmation bypass request_id=%s session_id=%s tenant_id=%s route=%s reason=%s forward_as_new_request=true pending_found=%s decision=%s confirm_id_hint=%s tail_preview=%s",
        req_preview.request_id,
        req_preview.session_id,
        tenant_id,
        req_preview.route,
        confirmation_bypass_reason,
        bool(pending),
        decision_value,
        confirm_id_hint or "-",
        tail_preview,
    )

    if _should_stream(payload):
        return await _execute_responses_stream_once(
            payload=payload,
            request_headers=gateway_headers,
            request_path=_request_target_path(request),
            boundary=boundary,
            tenant_id=tenant_id,
            forced_upstream_base=None,
        )

    return await _execute_responses_once(
        payload=payload,
        request_headers=gateway_headers,
        request_path=_request_target_path(request),
        boundary=boundary,
        tenant_id=tenant_id,
        skip_confirmation=False,
        forced_upstream_base=None,
    )


@router.post("/{subpath:path}")
async def generic_provider_proxy(subpath: str, payload: dict, request: Request):
    normalized = subpath.strip("/")
    route_base_path = f"/v1/{normalized}" if normalized else "/v1"
    route_path = _request_target_path(request, fallback_path=route_base_path)
    _log_request_if_debug(request, payload, route_path)
    logger.info("generic proxy route hit subpath=%s", normalized)
    if normalized in {"chat/completions", "responses"}:
        return JSONResponse(status_code=404, content={"error": "not_found"})

    boundary = getattr(request.state, "security_boundary", {})
    gateway_headers = _effective_gateway_headers(request)
    tenant_id = _resolve_tenant_id(payload=payload, headers=gateway_headers, boundary=boundary)

    if _should_stream(payload):
        return await _execute_generic_stream_once(
            payload=payload,
            request_headers=gateway_headers,
            request_path=route_path,
            boundary=boundary,
            tenant_id=tenant_id,
        )

    return await _execute_generic_once(
        payload=payload,
        request_headers=gateway_headers,
        request_path=route_path,
        boundary=boundary,
        tenant_id=tenant_id,
    )
