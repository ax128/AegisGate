"""OpenAI-compatible routes."""

from __future__ import annotations

import copy
import json
import logging
import asyncio
import re
import threading
import time
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
    _resolve_gateway_key,
    _resolve_upstream_base,
    _safe_error_detail,
    _validate_gateway_headers,
    close_upstream_async_client,
)
from aegisgate.config.settings import settings
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
_GENERIC_EXTRACT_MAX_CHARS = 16000
_GENERIC_BINARY_RE = re.compile(r"[A-Za-z0-9+/]{512,}={0,2}")
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
    try:
        body_str = json.dumps(payload, ensure_ascii=False, indent=2)
    except (TypeError, ValueError):
        body_str = str(payload)
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


def _build_responses_upstream_payload(payload: dict[str, Any], sanitized_req_messages: list) -> dict[str, Any]:
    upstream_payload = dict(payload)
    if sanitized_req_messages:
        original_input = payload.get("input")
        if _is_structured_content(original_input):
            upstream_payload["input"] = original_input
        else:
            upstream_payload["input"] = sanitized_req_messages[0].content
    return upstream_payload


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
        return to_chat_response(
            InternalResponse(
                request_id=request_id,
                session_id=session_id,
                model=model,
                output_text=content,
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
        return to_responses_output(
            InternalResponse(
                request_id=request_id,
                session_id=session_id,
                model=model,
                output_text=content,
            )
        )
    return None


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
        return raw_input.strip()
    if isinstance(raw_input, list):
        for item in reversed(raw_input):
            if not isinstance(item, dict):
                continue
            if str(item.get("role", "")).strip().lower() != "user":
                continue
            if "content" in item:
                return _flatten_text(item.get("content")).strip()
            return _flatten_text(item).strip()
        return _flatten_text(raw_input).strip()
    if isinstance(raw_input, dict):
        role = str(raw_input.get("role", "")).strip().lower()
        if role == "user":
            if "content" in raw_input:
                return _flatten_text(raw_input.get("content")).strip()
            return _flatten_text(raw_input).strip()
        if "input" in raw_input:
            return _extract_latest_user_text_from_responses_input(raw_input.get("input"))
        if "content" in raw_input:
            return _flatten_text(raw_input.get("content")).strip()
        return _flatten_text(raw_input).strip()
    return str(raw_input or "").strip()


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


def _confirmation_reason_and_summary(ctx: RequestContext, phase: str = PHASE_RESPONSE) -> tuple[str, str]:
    return _flow_reason_and_summary(phase, ctx.disposition_reasons, ctx.security_tags)


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


def _extract_action_token(text: str) -> str:
    matches = re.findall(r"\bact-[a-f0-9]{8,16}\b", str(text or "").lower())
    if not matches:
        return ""
    return str(matches[-1])


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
    template_markers = ("copy this line", "复制这一行")
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
    decision = parse_confirmation_decision(prefix_in_line).value
    if decision in {"yes", "no"}:
        return decision
    window_start = max(0, idx - 120)
    decision = parse_confirmation_decision(source[window_start:idx]).value
    if decision in {"yes", "no"}:
        return decision
    return "unknown"


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
    if explicit_decision not in {"yes", "no"}:
        return None
    confirm_id = explicit_confirm_id
    if not confirm_id:
        # 兼容简化确认：当用户明确 yes/no 且池中仅有 1 条 pending 时，可不带 confirm_id。
        return _load_single_pending_for_session(
            payload,
            now_ts,
            expected_route=expected_route,
            tenant_id=tenant_id,
        )
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
    return record


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
    return (
        "确认消息缺少动作摘要码，无法校验放行目标。\n"
        f"确认编号：{confirm_id}\n"
        f"动作摘要码：{action_token}\n\n"
        "请单独发送以下任一可复制消息：\n"
        f"yes {confirm_id} {action_token}\n"
        f"no {confirm_id} {action_token}\n\n"
        "Missing action bind token in confirmation message.\n"
        f"Confirmation ID: {confirm_id}\n"
        f"Action Bind Token: {action_token}\n"
        "Send one standalone line:\n"
        f"yes {confirm_id} {action_token}\n"
        f"no {confirm_id} {action_token}"
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
        token_suffix = f" {action_token}" if action_token else ""
        yes_line = f"yes {confirm_id}{token_suffix}"
        no_line = f"no {confirm_id}{token_suffix}"
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
        reason, summary = _flow_reason_and_summary(PHASE_REQUEST, ctx.disposition_reasons, ctx.security_tags)
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
        try:
            async for line in _forward_stream_lines(upstream_url, upstream_payload, forward_headers):
                payload_text = _extract_sse_data_payload(line)
                if payload_text is None:
                    yield line
                    continue

                if payload_text == "[DONE]":
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
                        reason, summary = _confirmation_reason_and_summary(ctx)
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
                        break

                yield line
        except RuntimeError as exc:
            detail = str(exc)
            reason = _stream_runtime_reason(detail)
            ctx.response_disposition = "block"
            ctx.disposition_reasons.append(reason)
            ctx.enforcement_actions.append(f"upstream:{reason}")
            logger.error("chat stream upstream failure request_id=%s error=%s", ctx.request_id, detail)
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
        reason, summary = _flow_reason_and_summary(PHASE_REQUEST, ctx.disposition_reasons, ctx.security_tags)
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

    upstream_payload = _build_responses_upstream_payload(payload, sanitized_req.messages)

    async def guarded_generator() -> AsyncGenerator[bytes, None]:
        stream_window = ""
        stream_cached_parts: list[str] = []
        chunk_count = 0
        try:
            async for line in _forward_stream_lines(upstream_url, upstream_payload, forward_headers):
                payload_text = _extract_sse_data_payload(line)
                if payload_text is None:
                    yield line
                    continue

                if payload_text == "[DONE]":
                    yield line
                    break

                chunk_text = _extract_stream_text_from_event(payload_text)
                if chunk_text:
                    stream_window = _trim_stream_window(stream_window, chunk_text)
                    stream_cached_parts.append(chunk_text)
                    chunk_count += 1

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
                            "responses stream block decision request_id=%s reason=%s risk_score=%.4f threshold=%.4f response_disposition=%s requires_human_review=%s security_tags=%s disposition_reasons=%s chunk_count=%s cached_chars=%s",
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
                        reason, summary = _confirmation_reason_and_summary(ctx)
                        confirm_id = make_confirm_id()
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
                            "responses stream requires confirmation request_id=%s confirm_id=%s reason=%s",
                            ctx.request_id,
                            confirm_id,
                            block_reason,
                        )
                        logger.info(
                            "confirmation response cached request_id=%s confirm_id=%s route=%s format=%s bytes=%s",
                            ctx.request_id,
                            confirm_id,
                            req.route,
                            _PENDING_FORMAT_RESPONSES_STREAM_TEXT,
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
                        break

                yield line
        except RuntimeError as exc:
            detail = str(exc)
            reason = _stream_runtime_reason(detail)
            ctx.response_disposition = "block"
            ctx.disposition_reasons.append(reason)
            ctx.enforcement_actions.append(f"upstream:{reason}")
            logger.error("responses stream upstream failure request_id=%s error=%s", ctx.request_id, detail)
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
            reason, summary = _flow_reason_and_summary(PHASE_REQUEST, ctx.disposition_reasons, ctx.security_tags)
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
        reason, summary = _confirmation_reason_and_summary(ctx)
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
        upstream_payload = _build_responses_upstream_payload(payload, req.messages)
        ctx.enforcement_actions.append("confirmation:request_filters_skipped")
    else:
        request_user_text = _request_user_text_for_excerpt(payload, req.route)
        debug_log_original("request_before_filters", request_user_text, max_len=180)

        sanitized_req = await _run_request_pipeline(pipeline, req, ctx)
        if ctx.request_disposition == "block":
            block_reason = ctx.disposition_reasons[-1] if ctx.disposition_reasons else "request_blocked"
            debug_log_original("request_blocked", request_user_text, reason=block_reason)
            reason, summary = _flow_reason_and_summary(PHASE_REQUEST, ctx.disposition_reasons, ctx.security_tags)
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

        upstream_payload = _build_responses_upstream_payload(payload, sanitized_req.messages)

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
        reason, summary = _confirmation_reason_and_summary(ctx)
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

    ok, reason, detail = _validate_gateway_headers(gateway_headers)
    if not ok:
        return _error_response(
            status_code=_to_status_code(reason),
            reason=reason,
            detail=detail,
            ctx=ctx_preview,
            boundary=boundary,
        )

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
        decision_value, decision_source = _resolve_pending_decision(user_text, confirm_id, decision_value)
        reason_text = str(pending.get("reason", "高风险响应"))
        summary_text = str(pending.get("summary", "检测到高风险信号"))
        expected_action_token = _pending_action_bind_token(pending)
        provided_action_token = _extract_action_token(user_text)
        explicit_confirm_id = bool(confirm_id_hint)
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
        if explicit_confirm_id and not provided_action_token:
            invalid_reason = "missing_action_token"
        elif explicit_confirm_id and provided_action_token != expected_action_token:
            invalid_reason = "action_token_mismatch"
        elif pending_route != req_preview.route:
            invalid_reason = "route_mismatch"
        elif decision_value not in {"yes", "no"}:
            invalid_reason = f"unsupported_decision_{decision_value}"
        if invalid_reason:
            confirmation_bypass_reason = f"pending_retained_{invalid_reason}"
            logger.info(
                "confirmation command not executable request_id=%s session_id=%s tenant_id=%s route=%s confirm_id=%s decision=%s source=%s invalid_reason=%s action_token_provided=%s action_token_match=%s forward_as_new_request=true pending_retained=true",
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

    ok, reason, detail = _validate_gateway_headers(gateway_headers)
    if not ok:
        return _error_response(
            status_code=_to_status_code(reason),
            reason=reason,
            detail=detail,
            ctx=ctx_preview,
            boundary=boundary,
        )

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
        decision_value, decision_source = _resolve_pending_decision(user_text, confirm_id, decision_value)
        reason_text = str(pending.get("reason", "高风险响应"))
        summary_text = str(pending.get("summary", "检测到高风险信号"))
        expected_action_token = _pending_action_bind_token(pending)
        provided_action_token = _extract_action_token(user_text)
        explicit_confirm_id = bool(confirm_id_hint)
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
        if explicit_confirm_id and not provided_action_token:
            invalid_reason = "missing_action_token"
        elif explicit_confirm_id and provided_action_token != expected_action_token:
            invalid_reason = "action_token_mismatch"
        elif pending_route != req_preview.route:
            invalid_reason = "route_mismatch"
        elif decision_value not in {"yes", "no"}:
            invalid_reason = f"unsupported_decision_{decision_value}"
        if invalid_reason:
            confirmation_bypass_reason = f"pending_retained_{invalid_reason}"
            logger.info(
                "confirmation command not executable request_id=%s session_id=%s tenant_id=%s route=%s confirm_id=%s decision=%s source=%s invalid_reason=%s action_token_provided=%s action_token_match=%s forward_as_new_request=true pending_retained=true",
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
    ok, reason, detail = _validate_gateway_headers(gateway_headers)
    if not ok:
        preview_ctx = RequestContext(
            request_id=str(payload.get("request_id") or "preview-generic"),
            session_id=str(payload.get("session_id") or payload.get("request_id") or "preview-generic"),
            route=route_path,
            tenant_id=tenant_id,
        )
        return _error_response(
            status_code=_to_status_code(reason),
            reason=reason,
            detail=detail,
            ctx=preview_ctx,
            boundary=boundary,
        )

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
