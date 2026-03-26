"""OpenAI-compatible routes."""

from __future__ import annotations

import copy
import json
import logging
import asyncio
import re
import time
from functools import lru_cache
from typing import Any, AsyncGenerator, Generator, Mapping
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse

from aegisgate.adapters.openai_compat.mapper import (
    chat_response_to_messages_response,
    messages_payload_to_chat_payload,
    to_chat_response,
    to_internal_chat,
    to_internal_messages,
    to_internal_responses,
    to_messages_response,
    to_responses_output,
)
from aegisgate.adapters.openai_compat.compat_bridge import (
    coerce_chat_output_to_responses_output,
    coerce_chat_stream_to_messages_stream,
    coerce_chat_stream_to_responses_stream,
    coerce_responses_output_to_chat_output,
    coerce_responses_stream_to_chat_stream,
    passthrough_chat_response,
    passthrough_responses_output,
)
from aegisgate.adapters.openai_compat.offload import run_payload_transform_offloop
from aegisgate.adapters.openai_compat.payload_compat import (
    sanitize_for_chat,
    sanitize_for_responses,
)
from aegisgate.adapters.openai_compat.pipeline_runtime import (  # noqa: F401 - router re-exports for gateway startup hooks
    _get_pipeline,
    clear_pending_confirmations_on_startup,
    close_runtime_dependencies,
    prune_pending_confirmations,
    reload_runtime_dependencies,
    store,
)
from aegisgate.adapters.openai_compat.stream_utils import (
    _build_streaming_response,
    _extract_sse_data_payload,
    _extract_sse_data_payload_from_chunk,
    _extract_stream_event_type,
    _extract_stream_text_from_event,
    _iter_sse_frames,
    _stream_block_reason,
    _stream_block_sse_chunk,  # noqa: F401 - re-exported for tests
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
)
from aegisgate.config.settings import settings
from aegisgate.config.security_rules import load_security_rules
from aegisgate.adapters.openai_compat.sanitize import (  # noqa: F401 — re-exports
    _MAX_REDACTION_HIT_LOG_ITEMS,
    _RESPONSES_SENSITIVE_OUTPUT_TYPES,
    _SYSTEM_EXEC_RUNTIME_LINE_RE,
    _UPSTREAM_EOF_RECOVERY_NOTICE,
    _looks_like_gateway_confirmation_text,
    _looks_like_gateway_internal_history_text,
    _looks_like_gateway_upstream_recovery_notice_text,
    _responses_function_output_redaction_patterns,
    _responses_relaxed_redaction_patterns,
    _sanitize_function_output_value,
    _sanitize_payload_for_log,
    _sanitize_responses_input_for_upstream,
    _sanitize_responses_input_for_upstream_with_hits,
    _sanitize_text_for_upstream_with_hits,
    _should_skip_responses_field_redaction,
    _strip_system_exec_runtime_lines,
)
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
from aegisgate.core.dangerous_response_log import mark_text_with_spans, write_dangerous_response_sample
from aegisgate.core.models import InternalMessage, InternalRequest, InternalResponse
from aegisgate.core.semantic import SemanticServiceClient
from aegisgate.policies.policy_engine import PolicyEngine
from aegisgate.storage.offload import run_store_io
from aegisgate.util.debug_excerpt import debug_log_original, info_log_sanitized
from aegisgate.util.logger import logger
from aegisgate.util.redaction_whitelist import normalize_whitelist_keys


router = APIRouter()
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
_STREAM_BLOCK_HOLDBACK_EVENTS = 4
_STREAM_SEMANTIC_CHECK_INTERVAL = 4
_STREAM_FILTER_CHECK_INTERVAL = 4  # run response pipeline every N chunks (not every chunk)
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
_GENERIC_EXTRACT_MAX_CHARS = 16000
_CONFIRMATION_HIT_CONTEXT_CHARS = 40
_GENERIC_BINARY_RE = re.compile(r"[A-Za-z0-9+/]{512,}={0,2}")
_REDACTION_WHITELIST_HEADER = "x-aegis-redaction-whitelist"
_DANGER_FRAGMENT_NOTICE = "【AegisGate已处理危险疑似片段】"
_RESPONSES_STREAM_DEBUG_EVENT_TYPES = frozenset({"response.failed", "error"})
_TRACE_REQUEST_ID_HEADER = "x-aegis-request-id"

# Filter modes set via URL path: token__redact or token__passthrough
_REDACT_ONLY_FILTERS = frozenset({"exact_value_redaction", "redaction", "restoration"})


def _filter_mode_from_headers(headers: Mapping[str, str]) -> str | None:
    return headers.get("x-aegis-filter-mode") or headers.get("X-Aegis-Filter-Mode")


def _should_log_responses_stream_event(event_type: str) -> bool:
    return bool(event_type) and event_type in _RESPONSES_STREAM_DEBUG_EVENT_TYPES


def _with_trace_forward_headers(headers: Mapping[str, str], request_id: str) -> dict[str, str]:
    forwarded = dict(headers)
    if request_id:
        forwarded[_TRACE_REQUEST_ID_HEADER] = request_id
    return forwarded


def _apply_filter_mode(ctx: RequestContext, headers: Mapping[str, str]) -> str | None:
    """根据 x-aegis-filter-mode header 调整 ctx.enabled_filters。返回 mode 或 None。"""
    mode = _filter_mode_from_headers(headers)
    if not mode:
        return None
    if mode == "redact":
        ctx.enabled_filters = ctx.enabled_filters & _REDACT_ONLY_FILTERS
        ctx.security_tags.add("filter_mode:redact")
        logger.info("filter_mode=redact applied request_id=%s active_filters=%s", ctx.request_id, sorted(ctx.enabled_filters))
    elif mode == "passthrough":
        ctx.enabled_filters = set()
        ctx.security_tags.add("filter_mode:passthrough")
        logger.info("filter_mode=passthrough applied request_id=%s (all filters skipped)", ctx.request_id)
    return mode


async def _forward_json_passthrough(
    *,
    ctx: RequestContext,
    payload: dict[str, Any],
    upstream_url: str,
    forward_headers: Mapping[str, str],
    boundary: dict | None,
    on_success: Any,
    log_label: str,
) -> Any:
    try:
        status_code, upstream_body = await _forward_json(upstream_url, payload, forward_headers)
    except RuntimeError as exc:
        logger.error("%s upstream unreachable request_id=%s error=%s", log_label, ctx.request_id, exc)
        return _error_response(
            status_code=502,
            reason="upstream_unreachable",
            detail=str(exc),
            ctx=ctx,
            boundary=boundary,
        )

    if status_code >= 400:
        detail = _safe_error_detail(upstream_body)
        logger.warning("%s upstream http error request_id=%s status=%s detail=%s", log_label, ctx.request_id, status_code, detail)
        return _error_response(
            status_code=status_code,
            reason="upstream_http_error",
            detail=detail,
            ctx=ctx,
            boundary=boundary,
        )

    ctx.enforcement_actions.append("filter_mode:passthrough_direct")
    _write_audit_event(ctx, boundary=boundary)
    logger.info("%s bypassed filters request_id=%s mode=passthrough", log_label, ctx.request_id)
    return on_success(upstream_body)


def _build_passthrough_stream_response(
    *,
    ctx: RequestContext,
    payload: dict[str, Any],
    upstream_url: str,
    forward_headers: Mapping[str, str],
    boundary: dict | None,
    log_label: str,
) -> StreamingResponse:
    ctx.enforcement_actions.append("filter_mode:passthrough_direct")
    logger.info("%s bypassed filters request_id=%s mode=passthrough", log_label, ctx.request_id)

    async def passthrough_generator() -> AsyncGenerator[bytes, None]:
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
            logger.exception("%s unexpected failure request_id=%s", log_label, ctx.request_id)
            yield _stream_error_sse_chunk(detail, code="gateway_internal_error")
            yield _stream_done_sse_chunk()
        finally:
            _write_audit_event(ctx, boundary=boundary)

    return _build_streaming_response(passthrough_generator())


async def close_semantic_async_client() -> None:
    await semantic_service_client.aclose()


def reload_semantic_client_settings() -> None:
    semantic_service_client.reconfigure(
        service_url=settings.semantic_service_url,
        cache_ttl_seconds=settings.semantic_cache_ttl_seconds,
        max_cache_entries=settings.semantic_cache_max_entries,
        failure_threshold=settings.semantic_circuit_failure_threshold,
        open_seconds=settings.semantic_circuit_open_seconds,
    )


def _should_stream(payload: dict[str, Any]) -> bool:
    return bool(payload.get("stream") is True)


def _looks_like_responses_payload(payload: dict[str, Any]) -> bool:
    return "input" in payload and "messages" not in payload


def _looks_like_chat_payload(payload: dict[str, Any]) -> bool:
    return "messages" in payload and "input" not in payload


def _looks_like_messages_payload(payload: dict[str, Any]) -> bool:
    """Detect Anthropic /v1/messages format: has 'messages' + 'max_tokens' (required by Anthropic), no 'input'."""
    return "messages" in payload and "max_tokens" in payload and "input" not in payload


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
        "incoming request method=%s path=%s route=%s body_size=%d",
        request.method,
        request.url.path,
        route,
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
        # Responses API: function_call / computer_call / bash items have no "text" key.
        # Produce a compact, safe summary so callers never fall through to a full-body json.dumps.
        item_type = str(value.get("type", ""))
        if item_type == "function_call":
            name = str(value.get("name", "?"))
            args = str(value.get("arguments", ""))[:200]
            return f"[function_call:{name}({args})]"
        if item_type in ("computer_call", "bash"):
            action = json.dumps(value.get("action", {}), ensure_ascii=False)[:200]
            return f"[{item_type}:{action}]"
        for key in ("content", "message", "output", "choices", "summary"):
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
            msg = first.get("message", {})
            if not isinstance(msg, dict):
                msg = {}
            text = _flatten_text(msg.get("content", ""))
            if text:
                return text
            # function_call / tool_calls finish reason: produce compact summary
            finish_reason = str(first.get("finish_reason", ""))
            tool_calls = msg.get("tool_calls")
            if isinstance(tool_calls, list):
                parts = []
                for tc in tool_calls[:5]:
                    fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                    if not isinstance(fn, dict):
                        fn = {}
                    tc_name = str(fn.get("name", "?"))
                    tc_args = str(fn.get("arguments", ""))[:200]
                    combined = f"{tc_name} {tc_args}".strip()
                    if _looks_executable_payload_dangerous(combined):
                        parts.append(f"[tool_call:{_DANGER_FRAGMENT_NOTICE}]")
                    else:
                        parts.append(f"[tool_call:{tc_name}({tc_args})]")
                if parts:
                    return " ".join(parts)
            if finish_reason:
                return f"[finish_reason={finish_reason}]"
    for key in ("output_text", "text", "output"):
        if key in upstream_body:
            text = _flatten_text(upstream_body[key])
            if text:
                return text
    # Safe fallback: never dump the full body — it may contain large system prompts / inputs
    error = upstream_body.get("error")
    if error:
        return f"[error={json.dumps(error, ensure_ascii=False)[:300]}]"
    return "[no_text_content]"


def _extract_responses_output_text(upstream_body: dict[str, Any] | str) -> str:
    if isinstance(upstream_body, str):
        return upstream_body
    for key in ("output_text", "output", "text", "choices"):
        if key in upstream_body:
            text = _flatten_text(upstream_body[key])
            if text:
                return text
    # Safe fallback: never dump the full body — responses API body includes the entire
    # `instructions` field (system prompt, can be 40k+ chars) which would cause filter slowdowns.
    status = str(upstream_body.get("status", "unknown"))
    error = upstream_body.get("error")
    if error:
        return f"[status={status} error={json.dumps(error, ensure_ascii=False)[:300]}]"
    return f"[status={status}]"


def _passthrough_chat_response(upstream_body: dict[str, Any] | str, req: Any) -> dict[str, Any]:
    return passthrough_chat_response(
        upstream_body,
        request_id=req.request_id,
        session_id=req.session_id,
        model=req.model,
    )


def _passthrough_responses_output(upstream_body: dict[str, Any] | str, req: Any) -> dict[str, Any]:
    return passthrough_responses_output(
        upstream_body,
        request_id=req.request_id,
        session_id=req.session_id,
        model=req.model,
    )


def _coerce_responses_output_to_chat_output(
    result: dict[str, Any] | JSONResponse,
    *,
    fallback_request_id: str,
    fallback_session_id: str,
    fallback_model: str,
) -> dict[str, Any] | JSONResponse:
    return coerce_responses_output_to_chat_output(
        result,
        fallback_request_id=fallback_request_id,
        fallback_session_id=fallback_session_id,
        fallback_model=fallback_model,
        text_extractor=_extract_responses_output_text,
    )


def _coerce_chat_output_to_responses_output(
    result: dict[str, Any] | JSONResponse,
    *,
    fallback_request_id: str,
    fallback_session_id: str,
    fallback_model: str,
) -> dict[str, Any] | JSONResponse:
    return coerce_chat_output_to_responses_output(
        result,
        fallback_request_id=fallback_request_id,
        fallback_session_id=fallback_session_id,
        fallback_model=fallback_model,
        text_extractor=_extract_chat_output_text,
    )


def _coerce_responses_stream_to_chat_stream(
    response: StreamingResponse,
    *,
    request_id: str,
    model: str,
) -> StreamingResponse:
    return coerce_responses_stream_to_chat_stream(
        response,
        request_id=request_id,
        model=model,
        response_text_extractor=_extract_responses_output_text,
    )


def _coerce_chat_stream_to_responses_stream(
    response: StreamingResponse,
    *,
    request_id: str,
    model: str,
) -> StreamingResponse:
    return coerce_chat_stream_to_responses_stream(
        response,
        request_id=request_id,
        model=model,
    )


def _is_structured_content(value: Any) -> bool:
    return isinstance(value, (list, dict))


_GATEWAY_INTERNAL_KEYS = frozenset({"request_id", "session_id", "policy", "metadata"})


def _build_chat_upstream_payload(payload: dict[str, Any], sanitized_req_messages: list) -> dict[str, Any]:
    upstream_payload = sanitize_for_chat(
        {k: v for k, v in payload.items() if k not in _GATEWAY_INTERNAL_KEYS},
    )
    original_messages = payload.get("messages", [])
    updated_messages: list[dict[str, Any]] = []
    for idx, message in enumerate(sanitized_req_messages):
        if idx < len(original_messages) and isinstance(original_messages[idx], dict):
            # Start from the original message dict — preserves all upstream-
            # specific fields (name, tool_call_id, etc.) we don't know about.
            merged: dict[str, Any] = dict(original_messages[idx])
        else:
            merged = {"role": message.role}
        merged["role"] = message.role
        original_content = merged.get("content")
        if _is_structured_content(original_content):
            # Preserve multimodal structure (image/audio/video/file parts).
            merged["content"] = original_content
        else:
            merged["content"] = message.content
        # Do NOT inject non-standard fields (source, metadata) into upstream
        # messages — unknown fields may cause upstream API rejections.
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
    whitelist_keys: set[str] | None = None,
) -> dict[str, Any]:
    upstream_payload = sanitize_for_responses(
        {k: v for k, v in payload.items() if k not in _GATEWAY_INTERNAL_KEYS},
    )
    if sanitized_req_messages:
        original_input = payload.get("input")
        if _is_structured_content(original_input):
            sanitized_input, redaction_hits = _sanitize_responses_input_for_upstream_with_hits(
                original_input,
                whitelist_keys=whitelist_keys,
            )
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


def _build_chat_passthrough_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return sanitize_for_chat({k: v for k, v in payload.items() if k not in _GATEWAY_INTERNAL_KEYS})


def _build_responses_passthrough_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return sanitize_for_responses({k: v for k, v in payload.items() if k not in _GATEWAY_INTERNAL_KEYS})


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


def _serialized_payload_size(payload: dict[str, Any]) -> int:
    try:
        return len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    except Exception:
        return 0


def _validate_payload_limits(
    payload: dict[str, Any],
    route: str,
    *,
    body_size_bytes: int | None = None,
) -> tuple[bool, int, str, str]:
    max_body = int(settings.max_request_body_bytes)
    if max_body > 0:
        body_size = body_size_bytes if body_size_bytes is not None else _serialized_payload_size(payload)
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

    events: list[dict[str, Any]] = [
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


async def _maybe_offload(func: Any, *args: Any, **kwargs: Any) -> Any:
    if settings.enable_thread_offload:
        return await asyncio.to_thread(func, *args, **kwargs)
    return func(*args, **kwargs)


async def _run_payload_transform(func: Any, *args: Any, **kwargs: Any) -> Any:
    """Keep payload mapping/sanitization off the event loop."""
    return await run_payload_transform_offloop(func, *args, **kwargs)


def _run_request_pipeline_sync(req: Any, ctx: RequestContext) -> Any:
    """Run request pipeline in pool thread (threading.local binds to THIS thread)."""
    return _get_pipeline().run_request(req, ctx)


def _run_response_pipeline_sync(resp: InternalResponse, ctx: RequestContext) -> InternalResponse:
    """Run response pipeline in pool thread (threading.local binds to THIS thread)."""
    return _get_pipeline().run_response(resp, ctx)


async def _run_request_pipeline(
    pipeline: Any,  # noqa: ARG001 - kept for test/mocking compatibility
    req: Any,
    ctx: RequestContext,
) -> Any:
    # Always offload filter pipeline to a thread pool to avoid blocking the
    # asyncio event loop.  CPU-intensive regex scanning on large payloads can
    # stall the entire gateway when run inline.
    timeout_s = settings.filter_pipeline_timeout_s
    if timeout_s <= 0:
        return await asyncio.to_thread(_run_request_pipeline_sync, req, ctx)
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_run_request_pipeline_sync, req, ctx),
            timeout=timeout_s,
        )
    except asyncio.TimeoutError:
        logger.error(
            "request_pipeline timeout exceeded request_id=%s timeout_s=%s action=%s",
            ctx.request_id,
            timeout_s,
            settings.request_pipeline_timeout_action,
        )
        ctx.security_tags.add("filter_pipeline_timeout")
        ctx.enforcement_actions.append("request_pipeline:timeout")
        if settings.request_pipeline_timeout_action == "pass":
            return req
        # Default "block": reject the request instead of passing unfiltered content.
        ctx.response_disposition = "block"
        ctx.disposition_reasons.append("request_filter_timeout")
        return req


async def _run_response_pipeline(
    pipeline: Any,  # noqa: ARG001 - kept for test/mocking compatibility
    resp: InternalResponse,
    ctx: RequestContext,
) -> InternalResponse:
    # Always offload to thread pool — see _run_request_pipeline comment.
    timeout_s = settings.filter_pipeline_timeout_s
    if timeout_s <= 0:
        return await asyncio.to_thread(_run_response_pipeline_sync, resp, ctx)
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_run_response_pipeline_sync, resp, ctx),
            timeout=timeout_s,
        )
    except asyncio.TimeoutError:
        logger.error(
            "response_pipeline timeout exceeded request_id=%s timeout_s=%s output_len=%s",
            ctx.request_id,
            timeout_s,
            len(resp.output_text),
        )
        ctx.security_tags.add("filter_pipeline_timeout")
        ctx.enforcement_actions.append("response_pipeline:timeout")
        ctx.response_disposition = "block"
        ctx.disposition_reasons.append("filter_timeout")
        resp.output_text = "[AegisGate] response filter timed out."
        return resp


async def _store_call(method_name: str, *args: Any, **kwargs: Any) -> Any:
    method = getattr(store, method_name)
    return await run_store_io(method, *args, **kwargs)


async def _delete_pending_confirmation(confirm_id: str) -> bool:
    try:
        return bool(await run_store_io(store.delete_pending_confirmation, confirm_id=confirm_id))
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


def _extract_messages_user_text(payload: dict[str, Any]) -> str:
    """Extract user text from Anthropic /v1/messages payload for security analysis."""
    # Same structure as chat — messages is a list with role/content
    return _extract_chat_user_text(payload)


def _request_user_text_for_excerpt(payload: dict[str, Any], route: str) -> str:
    """取请求侧用户输入文本，用于 debug 原文摘要（截断展示）。"""
    if route == "/v1/responses":
        return _extract_responses_user_text(payload)
    if route == "/v1/messages":
        return _extract_messages_user_text(payload)
    return _extract_chat_user_text(payload)


def _request_target_path(request: Request, *, fallback_path: str | None = None) -> str:
    """返回 path+query 形式的上游目标路径，确保 query 参数可透传到上游。"""
    scope_override = request.scope.get("aegis_upstream_route_path")
    base_path = str(scope_override or fallback_path or request.url.path or "/")
    query = request.url.query
    if query:
        return f"{base_path}?{query}"
    return base_path


def _needs_confirmation(ctx: RequestContext) -> bool:
    if ctx.response_disposition == "block":
        return True
    if ctx.requires_human_review:
        return True
    return any(tag.startswith("response_") for tag in ctx.security_tags)


def _confirmation_approval_enabled() -> bool:
    """Whether the yes/no approval flow is enabled.

    Always returns False — the approval flow has been removed.
    All dangerous content is now auto-sanitized (redacted or split with ---).
    """
    return False


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
    _append_rule_patterns("injection_detector", "tool_call_injection_patterns")
    _append_rule_patterns("request_sanitizer", "strong_intent_patterns")
    _append_rule_patterns("request_sanitizer", "command_patterns")
    _append_rule_patterns("sanitizer", "command_patterns")
    _append_rule_patterns("sanitizer", "encoded_payload_patterns")
    _append_rule_patterns("sanitizer", "system_leak_patterns")
    _append_rule_patterns("sanitizer", "force_block_command_patterns")
    _append_rule_patterns("sanitizer", "unsafe_markup_patterns")
    _append_rule_patterns("sanitizer", "unsafe_uri_patterns")
    _append_rule_patterns("injection_detector", "spam_noise_patterns")
    _append_rule_patterns("post_restore_guard", "secret_patterns")

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


_SANITIZE_HIT_CONTEXT_CHARS = 20

_CRITICAL_DANGER_PLACEHOLDER = _DANGER_FRAGMENT_NOTICE


@lru_cache(maxsize=1)
def _critical_danger_patterns() -> tuple[re.Pattern[str], ...]:
    """Compile patterns for commands so dangerous that the original text must
    never appear in the response — not even in obfuscated form."""
    rules = load_security_rules()
    pattern_strings: list[str] = []

    critical_anomaly_ids = {
        "sqli_union_select",
        "sqli_tautology",
        "sqli_time_blind",
        "command_injection_chain",
        "path_traversal",
        "xxe_external_entity",
        "ssti_or_log4shell",
        "ssrf_metadata",
    }

    # anomaly_detector command_patterns (critical executable / exfiltration forms only).
    for item in rules.get("anomaly_detector", {}).get("command_patterns", []):
        if not isinstance(item, dict) or str(item.get("id", "")) not in critical_anomaly_ids:
            continue
        regex = item.get("regex")
        if regex:
            pattern_strings.append(str(regex))

    # output_sanitizer force_block_command_patterns (docker destroy, HTTP smuggling, etc.)
    for item in rules.get("sanitizer", {}).get("force_block_command_patterns", []):
        regex = item.get("regex") if isinstance(item, dict) else None
        if regex:
            pattern_strings.append(str(regex))

    # privilege_guard blocked_patterns (read /etc/passwd, dump secrets, etc.)
    for item in rules.get("privilege_guard", {}).get("blocked_patterns", []):
        regex = item.get("regex") if isinstance(item, dict) else None
        if regex:
            pattern_strings.append(str(regex))

    # Hardcoded critical shell commands that must always be fully redacted.
    pattern_strings.extend([
        r"rm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s",
        r"rm\s+-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*\s",
        r"mkfs\b",
        r"dd\s+if=.*of=",
        r"chmod\s+-R\s+777\s+/",
        r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;",  # fork bomb
        r">\s*/dev/sd[a-z]",
        r"curl\s+[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash)\b",
        r"wget\s+[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash)\b",
        r"python[23]?\s+-c\s+['\"].*(?:exec|eval|import\s+os)",
        r"nc\s+-[a-z]*e\s",  # netcat reverse shell
        r"bash\s+-i\s+>&\s*/dev/tcp/",  # bash reverse shell
        r"powershell(?:\.exe)?\s+(?:-enc|-e\b|-encodedcommand)",
    ])

    deduped: list[str] = []
    for p in pattern_strings:
        if p not in deduped:
            deduped.append(p)

    compiled: list[re.Pattern[str]] = []
    for p in deduped:
        try:
            compiled.append(re.compile(p, re.IGNORECASE))
        except re.error:
            continue
    return tuple(compiled)


def _contains_critical_danger(text: str) -> bool:
    """Return True if *text* matches any critical danger pattern."""
    if not text:
        return False
    for pattern in _critical_danger_patterns():
        if pattern.search(text):
            return True
    return False


def _obfuscate_preserving_structure(text: str) -> str:
    """Insert '-' every 3 non-whitespace chars while preserving layout."""
    if not text:
        return ""

    parts: list[str] = []
    token: list[str] = []

    def _flush_token() -> None:
        if not token:
            return
        value = "".join(token)
        parts.append("-".join(value[i : i + 3] for i in range(0, len(value), 3)))
        token.clear()

    for ch in text:
        if ch.isspace():
            _flush_token()
            parts.append(ch)
            continue
        token.append(ch)
    _flush_token()
    return "".join(parts)


def _collect_dangerous_regions(
    source_text: str,
    ctx: RequestContext,
    *,
    context_chars: int = 0,
) -> list[tuple[int, int, bool]]:
    if not source_text:
        return []

    regions: list[tuple[int, int, bool]] = []

    for frag in _collect_confirmation_hit_fragments(ctx):
        escaped = re.escape(frag)
        for match in re.finditer(escaped, source_text, flags=re.IGNORECASE):
            if match.start() == match.end():
                continue
            regions.append((match.start(), match.end(), _contains_critical_danger(match.group(0))))

    for pattern in _confirmation_hit_regex_patterns():
        for match in pattern.finditer(source_text):
            if match.start() == match.end():
                continue
            regions.append((match.start(), match.end(), _contains_critical_danger(match.group(0))))
            if len(regions) >= 128:
                break
        if len(regions) >= 128:
            break

    if not regions:
        return []

    scoped: list[tuple[int, int, bool]] = []
    for start, end, critical in regions:
        left = max(0, start - context_chars)
        right = min(len(source_text), end + context_chars)
        scoped.append((left, right, critical))

    scoped.sort(key=lambda item: (item[0], item[1]))
    merged: list[tuple[int, int, bool]] = [scoped[0]]
    for left, right, critical in scoped[1:]:
        prev_left, prev_right, prev_critical = merged[-1]
        if left <= prev_right:
            merged[-1] = (prev_left, max(prev_right, right), prev_critical or critical)
            continue
        merged.append((left, right, critical))
    return merged


def _collect_hit_regions(source_text: str, ctx: RequestContext) -> list[tuple[int, int, bool]]:
    return _collect_dangerous_regions(
        source_text,
        ctx,
        context_chars=_SANITIZE_HIT_CONTEXT_CHARS,
    )


def _mark_dangerous_fragments_for_log(source_text: str, ctx: RequestContext) -> tuple[str, list[str]]:
    regions = _collect_dangerous_regions(source_text, ctx, context_chars=0)
    if not regions:
        return source_text, []

    fragments: list[str] = []
    spans: list[tuple[int, int]] = []
    for start, end, _critical in regions:
        spans.append((start, end))
        fragment = source_text[start:end]
        if fragment and fragment not in fragments:
            fragments.append(fragment)
    return mark_text_with_spans(source_text, spans), fragments


def _maybe_log_dangerous_response_sample(
    ctx: RequestContext,
    source_text: str,
    *,
    route: str,
    model: str,
    source: str,
    log_key: str,
) -> None:
    if not settings.enable_dangerous_response_log:
        return
    if not source_text:
        return

    marker = f"dangerous_response_log:{log_key}"
    if marker in ctx.security_tags:
        return

    marked_text, fragments = _mark_dangerous_fragments_for_log(source_text, ctx)
    if not fragments:
        return

    write_dangerous_response_sample(
        {
            "request_id": ctx.request_id,
            "session_id": ctx.session_id,
            "route": route,
            "model": model,
            "source": source,
            "response_disposition": ctx.response_disposition,
            "reasons": list(dict.fromkeys(ctx.disposition_reasons)),
            "fragment_count": len(fragments),
            "dangerous_fragments": fragments,
            "content": marked_text,
        }
    )
    ctx.security_tags.add(marker)


def _sanitize_hit_fragments(source_text: str, ctx: RequestContext) -> str:
    """Replace only dangerous regions while preserving the surrounding structure."""
    if not source_text:
        return source_text

    regions = _collect_hit_regions(source_text, ctx)
    if not regions:
        return source_text

    parts: list[str] = []
    cursor = 0
    for left, right, critical in regions:
        parts.append(source_text[cursor:left])
        segment = source_text[left:right]
        if critical:
            parts.append(_CRITICAL_DANGER_PLACEHOLDER)
        else:
            parts.append(f"{_DANGER_FRAGMENT_NOTICE}{_obfuscate_preserving_structure(segment)}")
        cursor = right
    parts.append(source_text[cursor:])
    return "".join(parts)


def _build_sanitized_full_response(ctx: RequestContext, source_text: str = "") -> str:
    """Return the full LLM response with only dangerous fragments transformed."""
    return _sanitize_hit_fragments(source_text, ctx) if source_text else ""


def _build_sanitized_warning_note(ctx: RequestContext, source_text: str = "") -> str:
    """Non-confirmation mode no longer appends a tail warning block."""
    return ""


@lru_cache(maxsize=1)
def _tool_call_guard_patterns() -> tuple[re.Pattern[str], ...]:
    rules = load_security_rules()
    guard_rules = rules.get("tool_call_guard", {})
    patterns: list[re.Pattern[str]] = []
    for field in ("dangerous_param_patterns", "semantic_approval_patterns"):
        for item in guard_rules.get(field, []):
            regex = item.get("regex") if isinstance(item, dict) else None
            if not regex:
                continue
            try:
                patterns.append(re.compile(str(regex), re.IGNORECASE))
            except re.error:
                continue
    return tuple(patterns)


def _looks_executable_payload_dangerous(text: str) -> bool:
    if not text:
        return False
    if _contains_critical_danger(text):
        return True
    for pattern in _tool_call_guard_patterns():
        if pattern.search(text):
            return True
    return False


def _placeholderize_value(value: Any) -> Any:
    if isinstance(value, str):
        return _CRITICAL_DANGER_PLACEHOLDER
    if isinstance(value, list):
        return [_placeholderize_value(item) for item in value]
    if isinstance(value, dict):
        return {
            key: (_placeholderize_value(item) if key not in {"id", "call_id", "status", "type", "role"} else item)
            for key, item in value.items()
        }
    return value


def _sanitize_nested_text_value(value: Any, ctx: RequestContext) -> Any:
    if isinstance(value, str):
        return _sanitize_hit_fragments(value, ctx)
    if isinstance(value, list):
        return [_sanitize_nested_text_value(item, ctx) for item in value]
    if isinstance(value, dict):
        patched = copy.deepcopy(value)
        for key, item in list(patched.items()):
            if isinstance(item, (str, list, dict)):
                patched[key] = _sanitize_nested_text_value(item, ctx)
        return patched
    return value


def _patch_chat_tool_call(tool_call: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
    patched = copy.deepcopy(tool_call)
    function = patched.get("function")
    name = ""
    arguments = ""
    if isinstance(function, dict):
        name = str(function.get("name", ""))
        arguments = str(function.get("arguments", ""))
    combined = f"{name} {arguments}".strip()
    if _looks_executable_payload_dangerous(combined):
        patched["function"] = {
            "name": _CRITICAL_DANGER_PLACEHOLDER,
            "arguments": json.dumps({"_blocked": _CRITICAL_DANGER_PLACEHOLDER}, ensure_ascii=False),
        }
        return patched
    if isinstance(function, dict):
        if isinstance(function.get("name"), str):
            function["name"] = _sanitize_hit_fragments(str(function["name"]), ctx)
        if isinstance(function.get("arguments"), str):
            function["arguments"] = _sanitize_hit_fragments(str(function["arguments"]), ctx)
        patched["function"] = function
    return patched


def _patch_chat_message(message: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
    patched = copy.deepcopy(message)
    content = patched.get("content")
    if isinstance(content, (str, list, dict)):
        patched["content"] = _sanitize_nested_text_value(content, ctx)
    tool_calls = patched.get("tool_calls")
    if isinstance(tool_calls, list):
        patched["tool_calls"] = [
            _patch_chat_tool_call(item, ctx) if isinstance(item, dict) else item
            for item in tool_calls
        ]
    return patched


def _patch_responses_output_item(item: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
    patched = copy.deepcopy(item)
    item_type = str(patched.get("type", "")).strip().lower()

    if item_type == "message":
        content = patched.get("content")
        if isinstance(content, list):
            updated: list[Any] = []
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    part = copy.deepcopy(part)
                    part["text"] = _sanitize_hit_fragments(str(part["text"]), ctx)
                elif isinstance(part, (str, list, dict)):
                    part = _sanitize_nested_text_value(part, ctx)
                updated.append(part)
            patched["content"] = updated
        return patched

    if item_type == "function_call":
        combined = f"{patched.get('name', '')} {patched.get('arguments', '')}".strip()
        if _looks_executable_payload_dangerous(combined):
            patched["name"] = _CRITICAL_DANGER_PLACEHOLDER
            patched["arguments"] = json.dumps({"_blocked": _CRITICAL_DANGER_PLACEHOLDER}, ensure_ascii=False)
            return patched
        if isinstance(patched.get("name"), str):
            patched["name"] = _sanitize_hit_fragments(str(patched["name"]), ctx)
        if isinstance(patched.get("arguments"), str):
            patched["arguments"] = _sanitize_hit_fragments(str(patched["arguments"]), ctx)
        return patched

    if item_type in {"bash", "computer_call"}:
        action = patched.get("action")
        action_text = json.dumps(action, ensure_ascii=False) if isinstance(action, (dict, list)) else str(action or "")
        if _looks_executable_payload_dangerous(action_text):
            patched["action"] = _placeholderize_value(action)
            return patched
        if isinstance(action, (str, list, dict)):
            patched["action"] = _sanitize_nested_text_value(action, ctx)
        return patched

    # Unknown/unfamiliar output item types (e.g. "reasoning", "web_search_call",
    # "mcp_call", future types) — return as-is to preserve structure.
    # Only sanitize items whose type is empty (legacy compatibility).
    if item_type:
        return patched

    for key in ("text", "summary", "output_text"):
        if isinstance(patched.get(key), str):
            patched[key] = _sanitize_hit_fragments(str(patched[key]), ctx)
    return patched


def _patch_chat_response_body(upstream_body: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
    out = copy.deepcopy(upstream_body)
    choices = out.get("choices")
    if isinstance(choices, list):
        updated_choices: list[Any] = []
        for choice in choices:
            if not isinstance(choice, dict):
                updated_choices.append(choice)
                continue
            updated = copy.deepcopy(choice)
            message = updated.get("message")
            if isinstance(message, dict):
                updated["message"] = _patch_chat_message(message, ctx)
            updated_choices.append(updated)
        out["choices"] = updated_choices
    return out


def _patch_responses_body(upstream_body: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
    out = copy.deepcopy(upstream_body)
    if isinstance(out.get("output_text"), str):
        out["output_text"] = _sanitize_hit_fragments(str(out["output_text"]), ctx)
    output = out.get("output")
    if isinstance(output, list):
        out["output"] = [
            _patch_responses_output_item(item, ctx) if isinstance(item, dict) else item
            for item in output
        ]
    return out


def _patch_chat_stream_payload(payload: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
    patched = copy.deepcopy(payload)
    choices = patched.get("choices")
    if not isinstance(choices, list):
        return patched
    updated_choices: list[Any] = []
    for choice in choices:
        if not isinstance(choice, dict):
            updated_choices.append(choice)
            continue
        updated = copy.deepcopy(choice)
        delta = updated.get("delta")
        if isinstance(delta, dict):
            if isinstance(delta.get("content"), str):
                delta["content"] = _sanitize_hit_fragments(str(delta["content"]), ctx)
            tool_calls = delta.get("tool_calls")
            if isinstance(tool_calls, list):
                delta["tool_calls"] = [
                    _patch_chat_tool_call(item, ctx) if isinstance(item, dict) else item
                    for item in tool_calls
                ]
            updated["delta"] = delta
        message = updated.get("message")
        if isinstance(message, dict):
            updated["message"] = _patch_chat_message(message, ctx)
        updated_choices.append(updated)
    patched["choices"] = updated_choices
    return patched


_RESPONSES_TEXT_DELTA_EVENT_TYPES = frozenset({
    "response.output_text.delta",
    "response.output_text.done",
    "response.refusal.delta",
    "response.refusal.done",
    "response.reasoning_summary_text.delta",
    "response.reasoning_summary_text.done",
})


def _patch_responses_stream_payload(payload: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
    patched = copy.deepcopy(payload)
    event_type = str(patched.get("type", ""))

    # Only sanitize "delta"/"text" for known text-content event types.
    # Argument/code delta events (function_call_arguments.delta, mcp_call_arguments.delta,
    # code_interpreter_call_code.delta, etc.) carry raw JSON/code fragments —
    # modifying them could corrupt structure. Unknown events pass through unchanged.
    if event_type in _RESPONSES_TEXT_DELTA_EVENT_TYPES:
        if isinstance(patched.get("delta"), str):
            patched["delta"] = _sanitize_hit_fragments(str(patched["delta"]), ctx)
        if isinstance(patched.get("text"), str):
            patched["text"] = _sanitize_hit_fragments(str(patched["text"]), ctx)

    if isinstance(patched.get("output_text"), str):
        patched["output_text"] = _sanitize_hit_fragments(str(patched["output_text"]), ctx)
    output = patched.get("output")
    if isinstance(output, list):
        patched["output"] = [
            _patch_responses_output_item(output_item, ctx) if isinstance(output_item, dict) else output_item
            for output_item in output
        ]
    part = patched.get("part")
    if isinstance(part, dict) and isinstance(part.get("text"), str):
        part["text"] = _sanitize_hit_fragments(str(part["text"]), ctx)
        patched["part"] = part
    item = patched.get("item")
    if isinstance(item, dict):
        patched["item"] = _patch_responses_output_item(item, ctx)
    response = patched.get("response")
    if isinstance(response, dict):
        if isinstance(response.get("output_text"), str):
            response["output_text"] = _sanitize_hit_fragments(str(response["output_text"]), ctx)
        output = response.get("output")
        if isinstance(output, list):
            response["output"] = [
                _patch_responses_output_item(output_item, ctx) if isinstance(output_item, dict) else output_item
                for output_item in output
            ]
        patched["response"] = response
    return patched


def _sanitize_stream_event_line(line: bytes, *, route: str, ctx: RequestContext) -> bytes:
    payload_text = _extract_sse_data_payload_from_chunk(line)
    if payload_text is None or payload_text == "[DONE]":
        return line
    raw_lines = line.splitlines(keepends=True)
    data_line_index = next(
        (index for index, raw_line in enumerate(raw_lines) if _extract_sse_data_payload(raw_line) is not None),
        None,
    )
    if data_line_index is None:
        return line
    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError:
        return line
    if not isinstance(payload, dict):
        return line
    if route == "/v1/responses":
        patched = _patch_responses_stream_payload(payload, ctx)
    else:
        patched = _patch_chat_stream_payload(payload, ctx)
    raw_lines[data_line_index] = f"data: {json.dumps(patched, ensure_ascii=False)}\n".encode("utf-8")
    output = b"".join(raw_lines)
    if not output.endswith(b"\n"):
        output += b"\n"
    if not output.endswith(b"\n\n"):
        output += b"\n"
    return output


def _extract_stream_tool_calls(payload_text: str, *, route: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, dict):
        return []

    collected: list[dict[str, Any]] = []
    if route == "/v1/chat/completions":
        choices = payload.get("choices")
        if not isinstance(choices, list):
            return []
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            for key in ("delta", "message"):
                node = choice.get(key)
                if not isinstance(node, dict):
                    continue
                tool_calls = node.get("tool_calls")
                if not isinstance(tool_calls, list):
                    continue
                for item in tool_calls:
                    if isinstance(item, dict):
                        collected.append(copy.deepcopy(item))
        return collected

    item = payload.get("item")
    if isinstance(item, dict) and str(item.get("type", "")).strip().lower() in {"function_call", "computer_call", "bash"}:
        collected.append(copy.deepcopy(item))

    response = payload.get("response")
    if isinstance(response, dict):
        output = response.get("output")
        if isinstance(output, list):
            for output_item in output:
                if not isinstance(output_item, dict):
                    continue
                if str(output_item.get("type", "")).strip().lower() in {"function_call", "computer_call", "bash"}:
                    collected.append(copy.deepcopy(output_item))
    return collected


def _render_non_confirmation_chat_response(
    upstream_body: dict[str, Any] | str,
    final_resp: InternalResponse,
    ctx: RequestContext,
) -> dict[str, Any]:
    if isinstance(upstream_body, dict):
        out = _patch_chat_response_body(upstream_body, ctx)
        out.setdefault("id", final_resp.request_id)
        out.setdefault("object", "chat.completion")
        out.setdefault("model", final_resp.model)
        if final_resp.metadata.get("aegisgate"):
            out["aegisgate"] = final_resp.metadata["aegisgate"]
        return out

    final_resp.output_text = _build_sanitized_full_response(ctx, source_text=final_resp.output_text)
    return to_chat_response(final_resp)


def _render_non_confirmation_responses_output(
    upstream_body: dict[str, Any] | str,
    final_resp: InternalResponse,
    ctx: RequestContext,
) -> dict[str, Any]:
    if isinstance(upstream_body, dict):
        out = _patch_responses_body(upstream_body, ctx)
        out.setdefault("id", final_resp.request_id)
        out.setdefault("object", "response")
        out.setdefault("model", final_resp.model)
        if final_resp.metadata.get("aegisgate"):
            out["aegisgate"] = final_resp.metadata["aegisgate"]
        return out

    final_resp.output_text = _build_sanitized_full_response(ctx, source_text=final_resp.output_text)
    return to_responses_output(final_resp)

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


def _extract_redaction_whitelist_keys(headers: Mapping[str, str] | None = None) -> set[str]:
    if not headers:
        return set()
    raw = _header_lookup(headers, _REDACTION_WHITELIST_HEADER)
    return set(normalize_whitelist_keys(raw))


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
        changed = bool(
            store.compare_and_update_pending_confirmation_status(
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
    result = await run_store_io(
        store.compare_and_update_pending_confirmation_status,
        confirm_id=confirm_id,
        expected_status=expected_status,
        new_status=new_status,
        now_ts=now_ts,
    )
    return bool(result)


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
    from aegisgate.core.stats import record as stats_record
    stats_record(ctx)


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
    req = await _run_payload_transform(to_internal_chat, payload)
    ctx = RequestContext(request_id=req.request_id, session_id=req.session_id, route=req.route, tenant_id=tenant_id)
    ctx.redaction_whitelist_keys = _extract_redaction_whitelist_keys(request_headers)
    policy_engine.resolve(ctx, policy_name=payload.get("policy", settings.default_policy))
    filter_mode = _apply_filter_mode(ctx, request_headers)
    passthrough_payload = _build_chat_passthrough_payload(payload) if filter_mode == "passthrough" else payload

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

    forward_headers = _with_trace_forward_headers(_build_forward_headers(request_headers), ctx.request_id)

    if filter_mode == "passthrough":
        return _build_passthrough_stream_response(
            ctx=ctx,
            payload=passthrough_payload,
            upstream_url=upstream_url,
            forward_headers=forward_headers,
            boundary=boundary,
            log_label="chat stream",
        )

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

        if not _confirmation_approval_enabled():
            block_text = f"[AegisGate] {reason}: {summary}"
            ctx.enforcement_actions.append("auto_block:no_confirmation")

            def request_block_generator() -> Generator[bytes, None, None]:
                try:
                    yield _stream_confirmation_sse_chunk(ctx, req.model, req.route, block_text, None)
                    yield _stream_done_sse_chunk()
                finally:
                    _write_audit_event(ctx, boundary=boundary)

            logger.info("chat stream request blocked (no confirmation) request_id=%s", ctx.request_id)
            return _build_streaming_response(request_block_generator())

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

    upstream_payload = await _run_payload_transform(_build_chat_upstream_payload, payload, sanitized_req.messages)

    async def guarded_generator() -> AsyncGenerator[bytes, None]:
        stream_window = ""
        stream_cached_parts: list[str] = []
        pending_frames: list[bytes] = []
        chunk_count = 0
        saw_done = False
        stream_end_reason = "upstream_eof_no_done"
        blocked_reason: str | None = None
        try:
            async for line in _iter_sse_frames(_forward_stream_lines(upstream_url, upstream_payload, forward_headers)):
                payload_text = _extract_sse_data_payload_from_chunk(line)
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
                    while pending_frames:
                        yield pending_frames.pop(0)
                    yield line
                    break

                chunk_text = _extract_stream_text_from_event(payload_text)
                tool_calls = _extract_stream_tool_calls(payload_text, route=req.route)
                is_content_event = bool(chunk_text or tool_calls)

                if chunk_text:
                    stream_window = _trim_stream_window(stream_window, chunk_text)
                    stream_cached_parts.append(chunk_text)
                    chunk_count += 1

                if is_content_event:
                    pending_frames.append(line)

                should_probe = bool(tool_calls) or bool(
                    chunk_text and (chunk_count <= _STREAM_FILTER_CHECK_INTERVAL or chunk_count % _STREAM_FILTER_CHECK_INTERVAL == 0)
                )
                if should_probe:
                    ctx.report_items = list(base_reports)
                    probe_resp = InternalResponse(
                        request_id=req.request_id,
                        session_id=req.session_id,
                        model=req.model,
                        output_text=stream_window,
                        raw={"stream": True},
                        metadata={"tool_calls": tool_calls} if tool_calls else {},
                    )
                    await _run_response_pipeline(pipeline, probe_resp, ctx)

                    if chunk_text and settings.enable_semantic_module and chunk_count % max(1, _STREAM_SEMANTIC_CHECK_INTERVAL) == 0:
                        await _apply_semantic_review(ctx, stream_window, phase="response")

                if should_probe:
                    decision = _stream_block_reason(ctx)
                    if decision:
                        blocked_reason = decision
                        logger.info(
                            "chat stream block decision request_id=%s reason=%s risk_score=%.4f threshold=%.4f response_disposition=%s requires_human_review=%s security_tags=%s disposition_reasons=%s chunk_count=%s cached_chars=%s",
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

                        if _confirmation_approval_enabled():
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
                                blocked_reason,
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

                        ctx.response_disposition = "sanitize"
                        ctx.enforcement_actions.append("auto_sanitize:stream_buffered_patch")
                        stream_end_reason = "policy_auto_sanitize_buffered"
                        break

                if blocked_reason:
                    continue

                if is_content_event:
                    while len(pending_frames) > _STREAM_BLOCK_HOLDBACK_EVENTS:
                        yield pending_frames.pop(0)
                    continue

                while pending_frames:
                    yield pending_frames.pop(0)
                yield line

            if blocked_reason and not _confirmation_approval_enabled():
                _maybe_log_dangerous_response_sample(
                    ctx,
                    stream_window,
                    route=req.route,
                    model=req.model,
                    source="chat_stream_buffered_patch",
                    log_key="chat_stream_buffered_patch",
                )
                logger.info("chat stream auto-sanitized (buffered) request_id=%s reason=%s", ctx.request_id, blocked_reason)
                sanitized_window = _build_sanitized_full_response(ctx, source_text=stream_window) if stream_window else ""
                info_log_sanitized("chat_stream_sanitized", sanitized_window, request_id=ctx.request_id, reason=blocked_reason)
                while pending_frames:
                    yield _sanitize_stream_event_line(pending_frames.pop(0), route=req.route, ctx=ctx)
                yield _stream_done_sse_chunk()
                stream_end_reason = "policy_auto_sanitize"
            if not saw_done and stream_end_reason == "upstream_eof_no_done":
                while pending_frames:
                    yield pending_frames.pop(0)
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
    req = await _run_payload_transform(to_internal_responses, payload)
    ctx = RequestContext(request_id=req.request_id, session_id=req.session_id, route=req.route, tenant_id=tenant_id)
    ctx.redaction_whitelist_keys = _extract_redaction_whitelist_keys(request_headers)
    policy_engine.resolve(ctx, policy_name=payload.get("policy", settings.default_policy))
    filter_mode = _apply_filter_mode(ctx, request_headers)
    passthrough_payload = _build_responses_passthrough_payload(payload) if filter_mode == "passthrough" else payload

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

    forward_headers = _with_trace_forward_headers(_build_forward_headers(request_headers), ctx.request_id)

    if filter_mode == "passthrough":
        return _build_passthrough_stream_response(
            ctx=ctx,
            payload=passthrough_payload,
            upstream_url=upstream_url,
            forward_headers=forward_headers,
            boundary=boundary,
            log_label="responses stream",
        )

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

        if not _confirmation_approval_enabled():
            block_text = f"[AegisGate] {reason}: {summary}"
            ctx.enforcement_actions.append("auto_block:no_confirmation")

            def request_block_generator() -> Generator[bytes, None, None]:
                try:
                    yield _stream_confirmation_sse_chunk(ctx, req.model, req.route, block_text, None)
                    yield _stream_done_sse_chunk()
                finally:
                    _write_audit_event(ctx, boundary=boundary)

            logger.info("responses stream request blocked (no confirmation) request_id=%s", ctx.request_id)
            return _build_streaming_response(request_block_generator())

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

    upstream_payload = await _run_payload_transform(
        _build_responses_upstream_payload,
        payload,
        sanitized_req.messages,
        request_id=ctx.request_id,
        session_id=ctx.session_id,
        route=ctx.route,
        whitelist_keys=ctx.redaction_whitelist_keys,
    )
    _input_items = upstream_payload.get("input")
    _input_count = len(_input_items) if isinstance(_input_items, list) else 0
    _payload_bytes = len(json.dumps(upstream_payload, ensure_ascii=False).encode("utf-8"))
    logger.info(
        "responses upstream forward request_id=%s model=%s input_items=%d payload_bytes=%d",
        ctx.request_id, upstream_payload.get("model", "?"), _input_count, _payload_bytes,
    )

    async def guarded_generator() -> AsyncGenerator[bytes, None]:
        stream_window = ""
        stream_cached_parts: list[str] = []
        pending_frames: list[bytes] = []
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
        last_terminal_event_type = ""
        failure_terminal_logged = False
        terminal_no_text_logged = False
        try:
            async for line in _iter_sse_frames(_forward_stream_lines(upstream_url, upstream_payload, forward_headers)):
                payload_text = _extract_sse_data_payload_from_chunk(line)
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
                    while pending_frames:
                        yield pending_frames.pop(0)
                    yield line
                    break

                saw_any_data_event = True
                event_type = _extract_stream_event_type(payload_text)
                if _should_log_responses_stream_event(event_type):
                    logger.debug(
                        "responses stream event request_id=%s type=%s bytes=%d",
                        ctx.request_id, event_type, len(payload_text),
                    )
                if event_type in {"response.completed", "response.failed", "error"}:
                    saw_terminal_event = True
                    last_terminal_event_type = event_type
                    _has_non_text_output = '"function_call"' in payload_text or '"reasoning"' in payload_text
                    if event_type in {"response.failed", "error"} and not failure_terminal_logged:
                        logger.debug(
                            "responses stream terminal_event request_id=%s event_type=%s chunk_count=%s cached_chars=%s non_text_output=%s payload_bytes=%s",
                            ctx.request_id, event_type, chunk_count, len(stream_window), _has_non_text_output, len(payload_text),
                        )
                        failure_terminal_logged = True
                    if chunk_count <= 0 and not _has_non_text_output and not terminal_no_text_logged:
                        logger.warning(
                            "responses stream terminal_event with no text_delta request_id=%s event_type=%s payload_bytes=%s",
                            ctx.request_id, event_type, len(payload_text),
                        )
                        terminal_no_text_logged = True

                chunk_text = _extract_stream_text_from_event(payload_text)
                tool_calls = _extract_stream_tool_calls(payload_text, route=req.route)
                is_content_event = bool(chunk_text or tool_calls)
                if chunk_text:
                    stream_window = _trim_stream_window(stream_window, chunk_text)
                    stream_cached_parts.append(chunk_text)
                    chunk_count += 1

                if is_content_event:
                    pending_frames.append(line)

                should_probe = (not blocked_reason) and bool(
                    tool_calls or (chunk_text and (chunk_count <= _STREAM_FILTER_CHECK_INTERVAL or chunk_count % _STREAM_FILTER_CHECK_INTERVAL == 0))
                )
                if should_probe:
                    ctx.report_items = list(base_reports)
                    probe_resp = InternalResponse(
                        request_id=req.request_id,
                        session_id=req.session_id,
                        model=req.model,
                        output_text=stream_window,
                        raw={"stream": True},
                        metadata={"tool_calls": tool_calls} if tool_calls else {},
                    )
                    await _run_response_pipeline(pipeline, probe_resp, ctx)

                    if chunk_text and settings.enable_semantic_module and chunk_count % max(1, _STREAM_SEMANTIC_CHECK_INTERVAL) == 0:
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

                        # Only prepare confirmation metadata when confirmation flow is enabled.
                        if _confirmation_approval_enabled():
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
                            logger.info(
                                "responses stream block drain started request_id=%s confirm_id=%s reason=%s chunk_count=%s cached_chars=%s",
                                ctx.request_id,
                                blocked_confirm_id,
                                blocked_reason,
                                chunk_count,
                                len(stream_window),
                            )

                        stream_end_reason = (
                            "policy_confirmation_draining_upstream"
                            if _confirmation_approval_enabled()
                            else "policy_auto_sanitize_buffered"
                        )
                        # Break immediately so the client does not stall
                        # waiting for the upstream to finish generating.
                        # The cached content up to this point is sufficient
                        # for both sanitization and confirmation storage.
                        break

                if blocked_reason:
                    continue

                if is_content_event:
                    while len(pending_frames) > _STREAM_BLOCK_HOLDBACK_EVENTS:
                        yield pending_frames.pop(0)
                    continue

                while pending_frames:
                    yield pending_frames.pop(0)
                yield line
            if blocked_reason:
                if not _confirmation_approval_enabled():
                    ctx.response_disposition = "sanitize"
                    ctx.enforcement_actions.append("auto_sanitize:stream_buffered_patch")
                    _maybe_log_dangerous_response_sample(
                        ctx,
                        stream_window,
                        route=req.route,
                        model=req.model,
                        source="responses_stream_buffered_patch",
                        log_key="responses_stream_buffered_patch",
                    )
                    logger.info("responses stream auto-sanitized (buffered) request_id=%s reason=%s", ctx.request_id, blocked_reason)
                    sanitized_window = _build_sanitized_full_response(ctx, source_text=stream_window) if stream_window else ""
                    info_log_sanitized("responses_stream_sanitized", sanitized_window, request_id=ctx.request_id, reason=blocked_reason)
                    while pending_frames:
                        yield _sanitize_stream_event_line(pending_frames.pop(0), route=req.route, ctx=ctx)
                    yield _stream_done_sse_chunk()
                    stream_end_reason = "policy_auto_sanitize"
                else:
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
                while pending_frames:
                    yield pending_frames.pop(0)
                if saw_terminal_event:
                    terminal_event_reason = last_terminal_event_type or "terminal_event"
                    ctx.enforcement_actions.append(f"upstream:{terminal_event_reason}")
                    yield _stream_done_sse_chunk()
                    stream_end_reason = f"terminal_event_no_done_recovered:{terminal_event_reason}"
                elif chunk_count <= 0 and not saw_any_data_event:
                    ctx.enforcement_actions.append("upstream:upstream_eof_no_done")
                    recovery_meta = {"action": "allow", "warning": "upstream_eof_no_done", "recovered": True}
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
                    stream_end_reason = "upstream_eof_no_done_recovered"
                else:
                    ctx.enforcement_actions.append("upstream:upstream_eof_no_done")
                    recovery_meta = {"action": "allow", "warning": "upstream_eof_no_done", "recovered": True}
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
    req = await _run_payload_transform(to_internal_chat, payload)
    ctx = RequestContext(request_id=req.request_id, session_id=req.session_id, route=req.route, tenant_id=tenant_id)
    ctx.redaction_whitelist_keys = _extract_redaction_whitelist_keys(request_headers)
    policy_engine.resolve(ctx, policy_name=payload.get("policy", settings.default_policy))
    filter_mode = _apply_filter_mode(ctx, request_headers)
    passthrough_payload = _build_chat_passthrough_payload(payload) if filter_mode == "passthrough" else payload

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

    forward_headers = _with_trace_forward_headers(_build_forward_headers(request_headers), ctx.request_id)

    if filter_mode == "passthrough":
        return await _forward_json_passthrough(
            ctx=ctx,
            payload=passthrough_payload,
            upstream_url=upstream_url,
            forward_headers=forward_headers,
            boundary=boundary,
            on_success=lambda upstream_body: passthrough_chat_response(
                upstream_body,
                request_id=req.request_id,
                session_id=req.session_id,
                model=req.model,
            ),
            log_label="chat completion",
        )

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
        return passthrough_chat_response(
            upstream_body,
            request_id=req.request_id,
            session_id=req.session_id,
            model=req.model,
        )

    # 用户已确认放行（yes）：不再走请求侧过滤，直接转发，避免同一内容再次被拦截
    pipeline = _get_pipeline()
    if forced_upstream_base and skip_confirmation:
        upstream_payload = await _run_payload_transform(_build_chat_upstream_payload, payload, req.messages)
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

            if not _confirmation_approval_enabled():
                # Direct block notice without confirmation flow.
                block_text = f"[AegisGate] {reason}: {summary}"
                block_resp = InternalResponse(
                    request_id=req.request_id, session_id=req.session_id,
                    model=req.model, output_text=block_text,
                )
                ctx.enforcement_actions.append("auto_block:no_confirmation")
                _attach_security_metadata(block_resp, ctx, boundary=boundary)
                _write_audit_event(ctx, boundary=boundary)
                logger.info("chat completion request blocked (no confirmation) request_id=%s", ctx.request_id)
                info_log_sanitized("chat_completion_request_blocked", block_text, request_id=ctx.request_id, reason=block_reason)
                return to_chat_response(block_resp)

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

        upstream_payload = await _run_payload_transform(_build_chat_upstream_payload, payload, sanitized_req.messages)

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
    logger.debug(
        "response_before_filters (chat) input_len=%s request_id=%s",
        len(internal_resp.output_text),
        req.request_id,
    )
    debug_log_original("response_before_filters", internal_resp.output_text)

    final_resp = await _run_response_pipeline(pipeline, internal_resp, ctx)
    if not skip_confirmation:
        await _apply_semantic_review(ctx, final_resp.output_text, phase="response")
    if skip_confirmation and ctx.response_disposition in {"block", "sanitize"}:
        _maybe_log_dangerous_response_sample(
            ctx,
            final_resp.output_text,
            route=req.route,
            model=req.model,
            source="chat_confirmed_release",
            log_key="chat_confirmed_release",
        )
        final_resp.output_text = _build_sanitized_full_response(ctx, source_text=final_resp.output_text)
        ctx.response_disposition = "allow"
        ctx.disposition_reasons.append("confirmed_release_override")
        ctx.enforcement_actions.append("confirmation:confirmed_release")
        ctx.enforcement_actions.append("confirmed_sanitize:hit_fragments_obfuscated")
        ctx.security_tags.add("confirmed_release")

    if not skip_confirmation and _needs_confirmation(ctx):
        resp_reason = ctx.disposition_reasons[0] if ctx.disposition_reasons else "response_high_risk"
        debug_log_original("response_confirmation_original", final_resp.output_text, reason=resp_reason)

        if not _confirmation_approval_enabled():
            _maybe_log_dangerous_response_sample(
                ctx,
                final_resp.output_text,
                route=req.route,
                model=req.model,
                source="chat_auto_sanitize",
                log_key="chat_auto_sanitize",
            )
            final_resp.output_text = _build_sanitized_full_response(ctx, source_text=final_resp.output_text)
            ctx.response_disposition = "sanitize"
            ctx.enforcement_actions.append("auto_sanitize:hit_fragments_obfuscated")
            logger.info("chat completion auto-sanitized (no confirmation) request_id=%s", ctx.request_id)
            info_log_sanitized("chat_completion_sanitized", final_resp.output_text, request_id=ctx.request_id, reason=resp_reason)
            _attach_security_metadata(final_resp, ctx, boundary=boundary)
            _write_audit_event(ctx, boundary=boundary)
            return _render_non_confirmation_chat_response(upstream_body, final_resp, ctx)

        reason, summary = _confirmation_reason_and_summary(ctx, source_text=final_resp.output_text)
        cached_output = passthrough_chat_response(
            upstream_body,
            request_id=req.request_id,
            session_id=req.session_id,
            model=req.model,
        )
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
    req = await _run_payload_transform(to_internal_responses, payload)
    ctx = RequestContext(request_id=req.request_id, session_id=req.session_id, route=req.route, tenant_id=tenant_id)
    ctx.redaction_whitelist_keys = _extract_redaction_whitelist_keys(request_headers)
    policy_engine.resolve(ctx, policy_name=payload.get("policy", settings.default_policy))
    filter_mode = _apply_filter_mode(ctx, request_headers)
    passthrough_payload = _build_responses_passthrough_payload(payload) if filter_mode == "passthrough" else payload

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

    forward_headers = _with_trace_forward_headers(_build_forward_headers(request_headers), ctx.request_id)

    if filter_mode == "passthrough":
        return await _forward_json_passthrough(
            ctx=ctx,
            payload=passthrough_payload,
            upstream_url=upstream_url,
            forward_headers=forward_headers,
            boundary=boundary,
            on_success=lambda upstream_body: passthrough_responses_output(
                upstream_body,
                request_id=req.request_id,
                session_id=req.session_id,
                model=req.model,
            ),
            log_label="responses endpoint",
        )

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
        return passthrough_responses_output(
            upstream_body,
            request_id=req.request_id,
            session_id=req.session_id,
            model=req.model,
        )

    # 用户已确认放行（yes）：不再走请求侧过滤，直接转发
    pipeline = _get_pipeline()
    if forced_upstream_base and skip_confirmation:
        upstream_payload = await _run_payload_transform(
            _build_responses_upstream_payload,
            payload,
            req.messages,
            request_id=ctx.request_id,
            session_id=ctx.session_id,
            route=ctx.route,
            whitelist_keys=ctx.redaction_whitelist_keys,
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

            if not _confirmation_approval_enabled():
                block_text = f"[AegisGate] {reason}: {summary}"
                block_resp = InternalResponse(
                    request_id=req.request_id, session_id=req.session_id,
                    model=req.model, output_text=block_text,
                )
                ctx.enforcement_actions.append("auto_block:no_confirmation")
                _attach_security_metadata(block_resp, ctx, boundary=boundary)
                _write_audit_event(ctx, boundary=boundary)
                logger.info("responses endpoint request blocked (no confirmation) request_id=%s", ctx.request_id)
                return to_responses_output(block_resp)

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

        upstream_payload = await _run_payload_transform(
            _build_responses_upstream_payload,
            payload,
            sanitized_req.messages,
            request_id=ctx.request_id,
            session_id=ctx.session_id,
            route=ctx.route,
            whitelist_keys=ctx.redaction_whitelist_keys,
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
    logger.debug(
        "response_before_filters (responses) input_len=%s request_id=%s",
        len(internal_resp.output_text),
        req.request_id,
    )
    debug_log_original("response_before_filters", internal_resp.output_text)

    final_resp = await _run_response_pipeline(pipeline, internal_resp, ctx)
    if not skip_confirmation:
        await _apply_semantic_review(ctx, final_resp.output_text, phase="response")
    if skip_confirmation and ctx.response_disposition in {"block", "sanitize"}:
        _maybe_log_dangerous_response_sample(
            ctx,
            final_resp.output_text,
            route=req.route,
            model=req.model,
            source="responses_confirmed_release",
            log_key="responses_confirmed_release",
        )
        final_resp.output_text = _build_sanitized_full_response(ctx, source_text=final_resp.output_text)
        ctx.response_disposition = "allow"
        ctx.disposition_reasons.append("confirmed_release_override")
        ctx.enforcement_actions.append("confirmation:confirmed_release")
        ctx.enforcement_actions.append("confirmed_sanitize:hit_fragments_obfuscated")
        ctx.security_tags.add("confirmed_release")

    if not skip_confirmation and _needs_confirmation(ctx):
        resp_reason = ctx.disposition_reasons[0] if ctx.disposition_reasons else "response_high_risk"
        debug_log_original("response_confirmation_original", final_resp.output_text, reason=resp_reason)

        if not _confirmation_approval_enabled():
            _maybe_log_dangerous_response_sample(
                ctx,
                final_resp.output_text,
                route=req.route,
                model=req.model,
                source="responses_auto_sanitize",
                log_key="responses_auto_sanitize",
            )
            final_resp.output_text = _build_sanitized_full_response(ctx, source_text=final_resp.output_text)
            ctx.response_disposition = "sanitize"
            ctx.enforcement_actions.append("auto_sanitize:hit_fragments_obfuscated")
            logger.info("responses endpoint auto-sanitized (no confirmation) request_id=%s", ctx.request_id)
            info_log_sanitized("responses_endpoint_sanitized", final_resp.output_text, request_id=ctx.request_id, reason=resp_reason)
            _attach_security_metadata(final_resp, ctx, boundary=boundary)
            _write_audit_event(ctx, boundary=boundary)
            return _render_non_confirmation_responses_output(upstream_body, final_resp, ctx)

        reason, summary = _confirmation_reason_and_summary(ctx, source_text=final_resp.output_text)
        cached_output = passthrough_responses_output(
            upstream_body,
            request_id=req.request_id,
            session_id=req.session_id,
            model=req.model,
        )
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
    ctx.redaction_whitelist_keys = _extract_redaction_whitelist_keys(request_headers)
    policy_engine.resolve(ctx, policy_name=payload.get("policy", settings.default_policy))
    filter_mode = _apply_filter_mode(ctx, request_headers)
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

    forward_headers = _with_trace_forward_headers(_build_forward_headers(request_headers), ctx.request_id)

    if filter_mode == "passthrough":
        return _build_passthrough_stream_response(
            ctx=ctx,
            payload=payload,
            upstream_url=upstream_url,
            forward_headers=forward_headers,
            boundary=boundary,
            log_label="generic stream",
        )

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
            async for line in _iter_sse_frames(_forward_stream_lines(upstream_url, payload, forward_headers)):
                payload_text = _extract_sse_data_payload_from_chunk(line)
                if payload_text is not None and payload_text != "[DONE]":
                    chunk_text = _extract_stream_text_from_event(payload_text)
                    if chunk_text:
                        stream_window = _trim_stream_window(stream_window, chunk_text)
                        chunk_count += 1

                        if chunk_count <= _STREAM_FILTER_CHECK_INTERVAL or chunk_count % _STREAM_FILTER_CHECK_INTERVAL == 0:
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
                            if not _confirmation_approval_enabled():
                                ctx.enforcement_actions.append("stream:auto_sanitize")
                                _maybe_log_dangerous_response_sample(
                                    ctx,
                                    stream_window,
                                    route=request_path,
                                    model=model,
                                    source="generic_stream_auto_sanitize",
                                    log_key="generic_stream_auto_sanitize",
                                )
                                sanitized_response = _build_sanitized_full_response(ctx, source_text=stream_window)
                                logger.info("generic stream auto-sanitized request_id=%s reason=%s", ctx.request_id, block_reason)
                                info_log_sanitized("generic_stream_sanitized", sanitized_response, request_id=ctx.request_id, reason=block_reason)
                                yield _stream_confirmation_sse_chunk(ctx, model, request_path, sanitized_response, None)
                                yield _stream_done_sse_chunk()
                                return
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
    ctx.redaction_whitelist_keys = _extract_redaction_whitelist_keys(request_headers)
    policy_engine.resolve(ctx, policy_name=payload.get("policy", settings.default_policy))
    filter_mode = _apply_filter_mode(ctx, request_headers)
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

    forward_headers = _with_trace_forward_headers(_build_forward_headers(request_headers), ctx.request_id)
    if filter_mode == "passthrough":
        return await _forward_json_passthrough(
            ctx=ctx,
            payload=payload,
            upstream_url=upstream_url,
            forward_headers=forward_headers,
            boundary=boundary,
            on_success=_passthrough_any_response,
            log_label="generic proxy",
        )

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
    if ctx.response_disposition == "sanitize":
        sanitized_text = internal_resp.output_text
        _write_audit_event(ctx, boundary=boundary)
        logger.info("generic proxy sanitized request_id=%s route=%s", ctx.request_id, request_path)
        return _passthrough_any_response(
            {"sanitized_text": sanitized_text} if isinstance(upstream_body, dict) else sanitized_text
        )

    if _needs_confirmation(ctx):
        if not _confirmation_approval_enabled():
            _maybe_log_dangerous_response_sample(
                ctx,
                capped_upstream_text,
                route=request_path,
                model=model,
                source="generic_auto_sanitize",
                log_key="generic_auto_sanitize",
            )
            sanitized_text = _build_sanitized_full_response(ctx, source_text=capped_upstream_text)
            ctx.response_disposition = "sanitize"
            ctx.enforcement_actions.append("auto_sanitize:hit_fragments_obfuscated")
            logger.info("generic proxy auto-sanitized (no confirmation) request_id=%s", ctx.request_id)
            info_log_sanitized("generic_proxy_sanitized", sanitized_text, request_id=ctx.request_id)
            _write_audit_event(ctx, boundary=boundary)
            return _passthrough_any_response(
                {"sanitized_text": sanitized_text} if isinstance(upstream_body, dict) else sanitized_text
            )

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
    # --- 格式兼容：Responses API 格式误发到 chat 端点时，内部转发 ---
    if _looks_like_responses_payload(payload):
        request.scope["aegis_upstream_route_path"] = "/v1/responses"
        logger.info(
            "chat_completions format_redirect: payload has 'input' without 'messages', "
            "redirecting to responses handler"
        )
        redirected = await responses(payload, request)
        req_preview = await _run_payload_transform(to_internal_responses, payload)
        if isinstance(redirected, StreamingResponse):
            return coerce_responses_stream_to_chat_stream(
                redirected,
                request_id=req_preview.request_id,
                model=req_preview.model,
                response_text_extractor=_extract_responses_output_text,
            )
        return coerce_responses_output_to_chat_output(
            redirected,
            fallback_request_id=req_preview.request_id,
            fallback_session_id=req_preview.session_id,
            fallback_model=req_preview.model,
            text_extractor=_extract_responses_output_text,
        )

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
    body_size_bytes = boundary.get("request_body_size")
    if not isinstance(body_size_bytes, int):
        body_size_bytes = None

    ok_payload, status_code, reason, detail = _validate_payload_limits(
        payload,
        route=ctx_preview.route,
        body_size_bytes=body_size_bytes,
    )
    if not ok_payload:
        return _error_response(
            status_code=status_code,
            reason=reason,
            detail=detail,
            ctx=ctx_preview,
            boundary=boundary,
        )

    req_preview = await _run_payload_transform(to_internal_chat, payload)
    ctx_preview.request_id = req_preview.request_id
    ctx_preview.session_id = req_preview.session_id

    now_ts = int(time.time())
    user_text = _extract_chat_user_text(payload)
    decision_value, confirm_id_hint = _parse_explicit_confirmation_command(user_text)
    pending = await run_store_io(
        _resolve_pending_confirmation,
        payload,
        user_text,
        now_ts,
        expected_route=req_preview.route,
        tenant_id=tenant_id,
    )
    # Only log confirmation details when there's an actual pending or explicit command.
    if pending or decision_value not in {"unknown", ""}:
        logger.debug(
            "confirmation incoming request_id=%s route=%s decision=%s pending_found=%s",
            req_preview.request_id,
            req_preview.route,
            decision_value,
            bool(pending),
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
            # Approval flow disabled — always reject with informational message.
            logger.info(
                "confirmation approve rejected (disabled) request_id=%s session_id=%s tenant_id=%s confirm_id=%s",
                req_preview.request_id,
                req_preview.session_id,
                tenant_id,
                confirm_id,
            )
            return to_chat_response(InternalResponse(
                request_id=req_preview.request_id,
                session_id=req_preview.session_id,
                model=req_preview.model,
                output_text=(
                    f"⚠️ [AegisGate] 放行功能已禁用\n---\n"
                    f"确认编号：{confirm_id}\n"
                    f"所有危险内容已自动遮挡/分割处理，不支持手动放行。\n"
                    f"如需查看完整原文，请联系安全管理员。\n\n"
                    f"⚠️ [AegisGate] Approval Disabled\n---\n"
                    f"Event ID: {confirm_id}\n"
                    f"All dangerous content has been auto-redacted/split. Manual approval is not available."
                ),
            ))

    elif decision_value in {"yes", "no"}:
        if confirm_id_hint:
            confirmation_bypass_reason = "confirmation_command_no_matching_pending"
        else:
            confirmation_bypass_reason = "confirmation_command_without_unique_pending"

    # Skip logging the common no-op passthrough to reduce noise.
    if confirmation_bypass_reason != "no_explicit_confirmation_command":
        logger.debug(
            "confirmation bypass request_id=%s route=%s reason=%s pending_found=%s",
            req_preview.request_id,
            req_preview.route,
            confirmation_bypass_reason,
            bool(pending),
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
    if _looks_like_chat_payload(payload):
        request.scope["aegis_upstream_route_path"] = "/v1/chat/completions"
        logger.info(
            "responses format_redirect: payload has 'messages' without 'input', "
            "redirecting to chat handler"
        )
        redirected = await chat_completions(payload, request)
        req_preview = await _run_payload_transform(to_internal_chat, payload)
        if isinstance(redirected, StreamingResponse):
            return coerce_chat_stream_to_responses_stream(
                redirected,
                request_id=req_preview.request_id,
                model=req_preview.model,
            )
        return coerce_chat_output_to_responses_output(
            redirected,
            fallback_request_id=req_preview.request_id,
            fallback_session_id=req_preview.session_id,
            fallback_model=req_preview.model,
            text_extractor=_extract_chat_output_text,
        )

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
    body_size_bytes = boundary.get("request_body_size")
    if not isinstance(body_size_bytes, int):
        body_size_bytes = None

    ok_payload, status_code, reason, detail = _validate_payload_limits(
        payload,
        route=ctx_preview.route,
        body_size_bytes=body_size_bytes,
    )
    if not ok_payload:
        return _error_response(
            status_code=status_code,
            reason=reason,
            detail=detail,
            ctx=ctx_preview,
            boundary=boundary,
        )

    req_preview = await _run_payload_transform(to_internal_responses, payload)
    ctx_preview.request_id = req_preview.request_id
    ctx_preview.session_id = req_preview.session_id

    now_ts = int(time.time())
    user_text = _extract_responses_user_text(payload)
    decision_value, confirm_id_hint = _parse_explicit_confirmation_command(user_text)
    pending = await run_store_io(
        _resolve_pending_confirmation,
        payload,
        user_text,
        now_ts,
        expected_route=req_preview.route,
        tenant_id=tenant_id,
    )
    # Only log confirmation details when there's an actual pending or explicit command.
    if pending or decision_value not in {"unknown", ""}:
        logger.debug(
            "confirmation incoming request_id=%s route=%s decision=%s pending_found=%s",
            req_preview.request_id,
            req_preview.route,
            decision_value,
            bool(pending),
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
            # Approval flow disabled — always reject with informational message.
            logger.info(
                "confirmation approve rejected (disabled) request_id=%s session_id=%s tenant_id=%s confirm_id=%s",
                req_preview.request_id,
                req_preview.session_id,
                tenant_id,
                confirm_id,
            )
            return to_responses_output(InternalResponse(
                request_id=req_preview.request_id,
                session_id=req_preview.session_id,
                model=req_preview.model,
                output_text=(
                    f"⚠️ [AegisGate] 放行功能已禁用\n---\n"
                    f"确认编号：{confirm_id}\n"
                    f"所有危险内容已自动遮挡/分割处理，不支持手动放行。\n"
                    f"如需查看完整原文，请联系安全管理员。\n\n"
                    f"⚠️ [AegisGate] Approval Disabled\n---\n"
                    f"Event ID: {confirm_id}\n"
                    f"All dangerous content has been auto-redacted/split. Manual approval is not available."
                ),
            ))

    elif decision_value in {"yes", "no"}:
        if confirm_id_hint:
            confirmation_bypass_reason = "confirmation_command_no_matching_pending"
        else:
            confirmation_bypass_reason = "confirmation_command_without_unique_pending"

    # Skip logging the common no-op passthrough to reduce noise.
    if confirmation_bypass_reason != "no_explicit_confirmation_command":
        logger.debug(
            "confirmation bypass request_id=%s route=%s reason=%s pending_found=%s",
            req_preview.request_id,
            req_preview.route,
            confirmation_bypass_reason,
            bool(pending),
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


@router.post("/messages")
async def messages(payload: dict, request: Request):
    """Anthropic /v1/messages endpoint.

    - 无 compat 标记：原样透传到 Anthropic 兼容上游（安全管道照常生效）。
    - compat=openai_chat（通过 token 配置注入）：
      Messages → Chat Completions 转换 → 转发上游 → 响应转回 Messages 格式。
    """
    _log_request_if_debug(request, payload, "/v1/messages")
    boundary = getattr(request.state, "security_boundary", {})
    gateway_headers = _effective_gateway_headers(request)
    tenant_id = _resolve_tenant_id(payload=payload, headers=gateway_headers, boundary=boundary)
    request_id = str(payload.get("request_id") or "preview-messages")
    session_id = str(payload.get("session_id") or request_id)
    ctx_preview = RequestContext(
        request_id=request_id,
        session_id=session_id,
        route="/v1/messages",
        tenant_id=tenant_id,
    )
    body_size_bytes = boundary.get("request_body_size")
    if not isinstance(body_size_bytes, int):
        body_size_bytes = None

    ok_payload, status_code, reason, detail = _validate_payload_limits(
        payload,
        route=ctx_preview.route,
        body_size_bytes=body_size_bytes,
    )
    if not ok_payload:
        return _error_response(
            status_code=status_code,
            reason=reason,
            detail=detail,
            ctx=ctx_preview,
            boundary=boundary,
        )

    req_preview = await _run_payload_transform(to_internal_messages, payload)
    ctx_preview.request_id = req_preview.request_id
    ctx_preview.session_id = req_preview.session_id

    # --- compat 检测：是否需要 Messages → Chat Completions 转换 ---
    compat = request.scope.get("aegis_compat")
    if compat == "openai_chat":
        return await _messages_compat_openai_chat(
            payload=payload,
            request=request,
            gateway_headers=gateway_headers,
            boundary=boundary,
            tenant_id=tenant_id,
        )

    # --- 原样透传：上游是 Anthropic 兼容 API ---
    request_path = _request_target_path(request, fallback_path="/v1/messages")

    if _should_stream(payload):
        return await _execute_generic_stream_once(
            payload=payload,
            request_headers=gateway_headers,
            request_path=request_path,
            boundary=boundary,
            tenant_id=tenant_id,
        )

    return await _execute_generic_once(
        payload=payload,
        request_headers=gateway_headers,
        request_path=request_path,
        boundary=boundary,
        tenant_id=tenant_id,
    )


async def _messages_compat_openai_chat(
    *,
    payload: dict,
    request: Request,
    gateway_headers: dict[str, str],
    boundary: dict | None,
    tenant_id: str,
) -> JSONResponse | StreamingResponse:
    """Messages → Chat Completions 转换链路。

    1. 将 Anthropic Messages payload 转为 OpenAI Chat payload
    2. 通过现有 chat 执行链路转发到上游
    3. 将响应转回 Anthropic Messages 格式
    """
    original_model = payload.get("model", "unknown-model")
    model_map = request.scope.get("aegis_model_map") or {}
    default_model = request.scope.get("aegis_default_model")

    # 转换请求: Messages → Chat
    try:
        chat_payload = messages_payload_to_chat_payload(
            payload, model_map=model_map, default_model=default_model,
        )
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})
    logger.info(
        "messages_compat converting model=%s->%s stream=%s",
        original_model,
        chat_payload.get("model"),
        chat_payload.get("stream"),
    )

    # 用 /v1/chat/completions 路径转发
    chat_request_path = "/v1/chat/completions"

    if _should_stream(chat_payload):
        # 流式：Chat stream → Messages stream
        chat_stream_resp = await _execute_chat_stream_once(
            payload=chat_payload,
            request_headers=gateway_headers,
            request_path=chat_request_path,
            boundary=boundary,
            tenant_id=tenant_id,
            forced_upstream_base=None,
        )
        if isinstance(chat_stream_resp, StreamingResponse):
            return coerce_chat_stream_to_messages_stream(
                chat_stream_resp,
                original_model=original_model,
            )
        # 非 StreamingResponse（错误等），直接返回
        return chat_stream_resp

    # 非流式：Chat response → Messages response
    chat_resp = await _execute_chat_once(
        payload=chat_payload,
        request_headers=gateway_headers,
        request_path=chat_request_path,
        boundary=boundary,
        tenant_id=tenant_id,
        skip_confirmation=False,
        forced_upstream_base=None,
    )
    if isinstance(chat_resp, (JSONResponse, PlainTextResponse)):
        return chat_resp
    if isinstance(chat_resp, dict):
        return JSONResponse(
            content=chat_response_to_messages_response(chat_resp, original_model=original_model)
        )
    return chat_resp


@router.post("/{subpath:path}")
async def generic_provider_proxy(subpath: str, payload: dict, request: Request):
    normalized = subpath.strip("/")
    route_base_path = f"/v1/{normalized}" if normalized else "/v1"
    route_path = _request_target_path(request, fallback_path=route_base_path)
    _log_request_if_debug(request, payload, route_path)
    logger.info("generic proxy route hit subpath=%s", normalized)
    if normalized in {"chat/completions", "responses", "messages"}:
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
