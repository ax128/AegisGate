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
_GENERIC_EXTRACT_MAX_CHARS = 16000
_GENERIC_BINARY_RE = re.compile(r"[A-Za-z0-9+/]{512,}={0,2}")
_pipeline_local = threading.local()


def _build_pipeline() -> Pipeline:
    request_filters = [
        RedactionFilter(store),
        RequestSanitizer(),
    ]
    response_filters = [
        AnomalyDetector(),
        PromptInjectionDetector(),
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


def _extract_responses_user_text(payload: dict[str, Any]) -> str:
    return str(payload.get("input", "")).strip()


def _request_user_text_for_excerpt(payload: dict[str, Any], route: str) -> str:
    """取请求侧用户输入文本，用于 debug 原文摘要（截断展示）。"""
    if route == "/v1/responses":
        return _extract_responses_user_text(payload)
    return _extract_chat_user_text(payload)


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

    match = re.search(r"\bcfm-[a-f0-9]{12}\b", text.lower())
    return match.group(0) if match else ""


def _resolve_pending_confirmation(payload: dict[str, Any], user_text: str, now_ts: int) -> dict[str, Any] | None:
    confirm_id = _extract_confirm_id(user_text)
    if confirm_id:
        record = store.get_pending_confirmation(confirm_id)
        if not record:
            return None
        if str(record.get("status")) != "pending":
            return None
        if int(record.get("expires_at", 0)) <= int(now_ts):
            store.update_pending_confirmation_status(confirm_id=confirm_id, status="expired", now_ts=now_ts)
            return None
        return record

    session_id = str(payload.get("session_id") or payload.get("request_id") or "").strip()
    if not session_id:
        return None
    return store.get_latest_pending_confirmation(session_id=session_id, now_ts=now_ts)


def _attach_confirmation_metadata(
    resp: InternalResponse,
    *,
    confirm_id: str,
    status: str,
    reason: str,
    summary: str,
    phase: str = PHASE_RESPONSE,
    payload_omitted: bool = False,
) -> None:
    metadata = resp.metadata.setdefault("aegisgate", {})
    metadata["confirmation"] = _flow_confirmation_metadata(
        confirm_id=confirm_id,
        status=status,
        reason=reason,
        summary=summary,
        phase=phase,
        payload_omitted=payload_omitted,
    )


def _build_confirmation_message(
    confirm_id: str, reason: str, summary: str, phase: str = PHASE_RESPONSE, note: str = ""
) -> str:
    return _flow_confirmation_message(confirm_id=confirm_id, reason=reason, summary=summary, phase=phase, note=note)


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
        "risk_score": round(ctx.risk_score, 4),
        "risk_threshold": ctx.risk_threshold,
        "requires_human_review": ctx.requires_human_review,
        "request_disposition": ctx.request_disposition,
        "response_disposition": ctx.response_disposition,
        "reasons": sorted(set(ctx.disposition_reasons)),
        "security_tags": sorted(ctx.security_tags),
        "enforcement_actions": ctx.enforcement_actions,
        "security_boundary": boundary or {},
    }


def _write_audit_event(ctx: RequestContext, boundary: dict | None = None) -> None:
    write_audit(
        {
            "request_id": ctx.request_id,
            "session_id": ctx.session_id,
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
            "report": ctx.report_items,
        }
    )


def _error_response(status_code: int, reason: str, detail: str, ctx: RequestContext, boundary: dict | None = None) -> JSONResponse:
    ctx.response_disposition = "block"
    ctx.disposition_reasons.append(reason)
    ctx.enforcement_actions.append(f"upstream:{reason}")
    _write_audit_event(ctx, boundary=boundary)
    # 保证 agent 端能拿到非空原因（error + detail）
    detail_str = (detail or "").strip() or reason
    return JSONResponse(
        status_code=status_code,
        content={
            "error": reason,
            "detail": detail_str,
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
    forced_upstream_base: str | None = None,
) -> StreamingResponse | JSONResponse:
    req = to_internal_chat(payload)
    ctx = RequestContext(request_id=req.request_id, session_id=req.session_id, route=req.route)
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
            created_at=now_ts,
            expires_at=now_ts + max(30, int(settings.confirmation_ttl_seconds)),
            retained_until=now_ts + max(60, int(settings.pending_data_ttl_seconds)),
        )
        if pending_payload_omitted:
            summary = f"{summary}（请求体过大，未缓存原文：{pending_payload_size} bytes）"
        ctx.disposition_reasons.append("awaiting_user_confirmation")
        ctx.security_tags.add("confirmation_required")
        confirmation_meta = _flow_confirmation_metadata(
            confirm_id=confirm_id, status="pending", reason=reason, summary=summary,
            phase=PHASE_REQUEST, payload_omitted=pending_payload_omitted,
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
                        debug_log_original("response_stream_blocked", stream_window, reason=block_reason)
                        ctx.response_disposition = "block"
                        if block_reason not in ctx.disposition_reasons:
                            ctx.disposition_reasons.append(block_reason)
                        ctx.enforcement_actions.append("stream:block")
                        logger.info("chat stream blocked request_id=%s reason=%s", ctx.request_id, block_reason)
                        yield _stream_block_sse_chunk(ctx, req.model, block_reason, req.route)
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
        finally:
            _write_audit_event(ctx, boundary=boundary)

    return _build_streaming_response(guarded_generator())


async def _execute_responses_stream_once(
    *,
    payload: dict[str, Any],
    request_headers: Mapping[str, str],
    request_path: str,
    boundary: dict | None,
    forced_upstream_base: str | None = None,
) -> StreamingResponse | JSONResponse:
    req = to_internal_responses(payload)
    ctx = RequestContext(request_id=req.request_id, session_id=req.session_id, route=req.route)
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
            created_at=now_ts,
            expires_at=now_ts + max(30, int(settings.confirmation_ttl_seconds)),
            retained_until=now_ts + max(60, int(settings.pending_data_ttl_seconds)),
        )
        if pending_payload_omitted:
            summary = f"{summary}（请求体过大，未缓存原文：{pending_payload_size} bytes）"
        ctx.disposition_reasons.append("awaiting_user_confirmation")
        ctx.security_tags.add("confirmation_required")
        confirmation_meta = _flow_confirmation_metadata(
            confirm_id=confirm_id, status="pending", reason=reason, summary=summary,
            phase=PHASE_REQUEST, payload_omitted=pending_payload_omitted,
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
                        debug_log_original("response_stream_blocked", stream_window, reason=block_reason)
                        ctx.response_disposition = "block"
                        if block_reason not in ctx.disposition_reasons:
                            ctx.disposition_reasons.append(block_reason)
                        ctx.enforcement_actions.append("stream:block")
                        logger.info("responses stream blocked request_id=%s reason=%s", ctx.request_id, block_reason)
                        yield _stream_block_sse_chunk(ctx, req.model, block_reason, req.route)
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
        finally:
            _write_audit_event(ctx, boundary=boundary)

    return _build_streaming_response(guarded_generator())


async def _execute_chat_once(
    *,
    payload: dict[str, Any],
    request_headers: Mapping[str, str],
    request_path: str,
    boundary: dict | None,
    skip_confirmation: bool = False,
    forced_upstream_base: str | None = None,
) -> dict | JSONResponse:
    req = to_internal_chat(payload)
    ctx = RequestContext(request_id=req.request_id, session_id=req.session_id, route=req.route)
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

    # 用户已确认放行（yes）：不再走请求侧过滤，直接转发，避免同一内容再次被拦截
    if forced_upstream_base and skip_confirmation:
        upstream_payload = _build_chat_upstream_payload(payload, req.messages)
        ctx.enforcement_actions.append("confirmation:request_filters_skipped")
    else:
        request_user_text = _request_user_text_for_excerpt(payload, req.route)
        debug_log_original("request_before_filters", request_user_text, max_len=180)

        pipeline = _get_pipeline()
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
                created_at=now_ts,
                expires_at=now_ts + max(30, int(settings.confirmation_ttl_seconds)),
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
        pending_payload, pending_payload_hash, pending_payload_omitted, pending_payload_size = _prepare_pending_payload(upstream_payload)
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
            created_at=now_ts,
            expires_at=now_ts + max(30, int(settings.confirmation_ttl_seconds)),
            retained_until=now_ts + max(60, int(settings.pending_data_ttl_seconds)),
        )
        if pending_payload_omitted:
            ctx.security_tags.add("pending_payload_omitted")
            ctx.enforcement_actions.append("pending:payload_omitted")
            summary = f"{summary}（请求体过大，未缓存原文：{pending_payload_size} bytes）"
        ctx.response_disposition = "block"
        ctx.disposition_reasons.append("awaiting_user_confirmation")
        ctx.security_tags.add("confirmation_required")
        ctx.enforcement_actions.append("confirmation:pending")

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
            payload_omitted=pending_payload_omitted,
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
    skip_confirmation: bool = False,
    forced_upstream_base: str | None = None,
) -> dict | JSONResponse:
    req = to_internal_responses(payload)
    ctx = RequestContext(request_id=req.request_id, session_id=req.session_id, route=req.route)
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

    # 用户已确认放行（yes）：不再走请求侧过滤，直接转发
    if forced_upstream_base and skip_confirmation:
        upstream_payload = _build_responses_upstream_payload(payload, req.messages)
        ctx.enforcement_actions.append("confirmation:request_filters_skipped")
    else:
        request_user_text = _request_user_text_for_excerpt(payload, req.route)
        debug_log_original("request_before_filters", request_user_text, max_len=180)

        pipeline = _get_pipeline()
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
                created_at=now_ts,
                expires_at=now_ts + max(30, int(settings.confirmation_ttl_seconds)),
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
        pending_payload, pending_payload_hash, pending_payload_omitted, pending_payload_size = _prepare_pending_payload(upstream_payload)
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
            created_at=now_ts,
            expires_at=now_ts + max(30, int(settings.confirmation_ttl_seconds)),
            retained_until=now_ts + max(60, int(settings.pending_data_ttl_seconds)),
        )
        if pending_payload_omitted:
            ctx.security_tags.add("pending_payload_omitted")
            ctx.enforcement_actions.append("pending:payload_omitted")
            summary = f"{summary}（请求体过大，未缓存原文：{pending_payload_size} bytes）"
        ctx.response_disposition = "block"
        ctx.disposition_reasons.append("awaiting_user_confirmation")
        ctx.security_tags.add("confirmation_required")
        ctx.enforcement_actions.append("confirmation:pending")

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
            payload_omitted=pending_payload_omitted,
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


async def _execute_generic_once(
    *,
    payload: dict[str, Any],
    request_headers: Mapping[str, str],
    request_path: str,
    boundary: dict | None,
) -> JSONResponse | PlainTextResponse:
    request_id = str(payload.get("request_id") or f"generic-{int(time.time() * 1000)}")
    session_id = str(payload.get("session_id") or request_id)
    model = str(payload.get("model") or payload.get("target_model") or "generic-model")
    ctx = RequestContext(request_id=request_id, session_id=session_id, route=request_path)
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
        blocked_resp = InternalResponse(
            request_id=req.request_id,
            session_id=req.session_id,
            model=req.model,
            output_text="[AegisGate] request blocked by security policy.",
        )
        _attach_security_metadata(blocked_resp, ctx, boundary=boundary)
        _write_audit_event(ctx, boundary=boundary)
        return JSONResponse(
            status_code=403,
            content={
                "error": "request_blocked",
                "detail": "generic provider request blocked by security policy",
                "aegisgate": blocked_resp.metadata.get("aegisgate", {}),
            },
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
    request_id = str(payload.get("request_id") or "preview-chat")
    session_id = str(payload.get("session_id") or request_id)
    ctx_preview = RequestContext(request_id=request_id, session_id=session_id, route="/v1/chat/completions")

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

    ok, reason, detail = _validate_gateway_headers(_effective_gateway_headers(request))
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
    decision = parse_confirmation_decision(user_text)
    pending = await _maybe_offload(_resolve_pending_confirmation, payload, user_text, now_ts)
    confirm_id_hint = _extract_confirm_id(user_text)

    if pending:
        pending_route = str(pending.get("route", ""))
        confirm_id = str(pending["confirm_id"])
        reason_text = str(pending.get("reason", "高风险响应"))
        summary_text = str(pending.get("summary", "检测到高风险信号"))
        if pending_route != req_preview.route:
            return _error_response(
                status_code=409,
                reason="confirmation_route_mismatch",
                detail=f"pending confirmation belongs to {pending_route}",
                ctx=ctx_preview,
                boundary=boundary,
            )

        if decision.value == "no":
            await _store_call("update_pending_confirmation_status", confirm_id=confirm_id, status="canceled", now_ts=now_ts)
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
            return to_chat_response(canceled_resp)

        if decision.value == "yes":
            pending_payload = pending.get("pending_request_payload", {})
            if not isinstance(pending_payload, dict):
                return _error_response(
                    status_code=409,
                    reason="pending_payload_invalid",
                    detail="pending payload is invalid",
                    ctx=ctx_preview,
                    boundary=boundary,
                )
            if _is_pending_payload_omitted(pending_payload):
                await _store_call("update_pending_confirmation_status", confirm_id=confirm_id, status="expired", now_ts=now_ts)
                return _error_response(
                    status_code=409,
                    reason="pending_payload_omitted",
                    detail="pending payload was omitted due to size limit, please resend the original request",
                    ctx=ctx_preview,
                    boundary=boundary,
                )
            if payload_hash(pending_payload) != str(pending.get("pending_request_hash", "")):
                return _error_response(
                    status_code=409,
                    reason="pending_hash_mismatch",
                    detail="pending request hash mismatch",
                    ctx=ctx_preview,
                    boundary=boundary,
                )

            executed = await _execute_chat_once(
                payload=pending_payload,
                request_headers=_effective_gateway_headers(request),
                request_path=request.url.path,
                boundary=boundary,
                skip_confirmation=True,
                forced_upstream_base=str(pending.get("upstream_base", "")),
            )
            if isinstance(executed, JSONResponse):
                return executed
            await _store_call("update_pending_confirmation_status", confirm_id=confirm_id, status="executed", now_ts=int(time.time()))
            aegis = executed.setdefault("aegisgate", {})
            aegis["confirmation"] = {
                "required": False,
                "confirm_id": confirm_id,
                "status": "executed",
                "reason": reason_text,
                "summary": summary_text,
                "payload_omitted": False,
            }
            return executed

        note = "输入不明确，请仅回复 yes 或 no。" if decision.value == "ambiguous" else "请仅回复 yes 或 no。"
        pending_resp = InternalResponse(
            request_id=req_preview.request_id,
            session_id=req_preview.session_id,
            model=req_preview.model,
            output_text=_build_confirmation_message(confirm_id=confirm_id, reason=reason_text, summary=summary_text, note=note),
        )
        ctx_preview.response_disposition = "block"
        ctx_preview.disposition_reasons.append("awaiting_user_confirmation")
        _attach_security_metadata(pending_resp, ctx_preview, boundary=boundary)
        _attach_confirmation_metadata(
            pending_resp,
            confirm_id=confirm_id,
            status="pending",
            reason=reason_text,
            summary=summary_text,
        )
        _write_audit_event(ctx_preview, boundary=boundary)
        return to_chat_response(pending_resp)

    if confirm_id_hint:
        expired_resp = InternalResponse(
            request_id=req_preview.request_id,
            session_id=req_preview.session_id,
            model=req_preview.model,
            output_text=f"确认已过期，请重新发起请求。确认编号：{confirm_id_hint}\nConfirmation expired. Please send the request again.",
        )
        ctx_preview.response_disposition = "block"
        ctx_preview.disposition_reasons.append("confirmation_expired")
        _attach_security_metadata(expired_resp, ctx_preview, boundary=boundary)
        _attach_confirmation_metadata(
            expired_resp,
            confirm_id=confirm_id_hint,
            status="expired",
            reason="确认已过期",
            summary="未找到可执行的 pending 记录",
        )
        _write_audit_event(ctx_preview, boundary=boundary)
        return to_chat_response(expired_resp)

    # 用户回复了 yes 但未匹配到任何 pending：不再对当前 body 跑请求管道，避免再次被 request_sanitizer 拦截
    if decision.value == "yes" and not pending:
        no_pending_resp = InternalResponse(
            request_id=req_preview.request_id,
            session_id=req_preview.session_id,
            model=req_preview.model,
            output_text="未找到待确认记录。请使用与触发确认时相同的 session_id，或在消息中包含确认编号（如 yes cfm-xxx）。\nNo pending confirmation found. Use the same session_id as the blocked request or include the confirm_id in your message (e.g. yes cfm-xxx).",
        )
        ctx_preview.response_disposition = "block"
        ctx_preview.disposition_reasons.append("no_pending_for_yes")
        _attach_security_metadata(no_pending_resp, ctx_preview, boundary=boundary)
        _write_audit_event(ctx_preview, boundary=boundary)
        return to_chat_response(no_pending_resp)

    if _should_stream(payload):
        return await _execute_chat_stream_once(
            payload=payload,
            request_headers=_effective_gateway_headers(request),
            request_path=request.url.path,
            boundary=boundary,
            forced_upstream_base=None,
        )

    return await _execute_chat_once(
        payload=payload,
        request_headers=_effective_gateway_headers(request),
        request_path=request.url.path,
        boundary=boundary,
        skip_confirmation=False,
        forced_upstream_base=None,
    )


@router.post("/responses")
async def responses(payload: dict, request: Request):
    _log_request_if_debug(request, payload, "/v1/responses")
    boundary = getattr(request.state, "security_boundary", {})
    request_id = str(payload.get("request_id") or "preview-responses")
    session_id = str(payload.get("session_id") or request_id)
    ctx_preview = RequestContext(request_id=request_id, session_id=session_id, route="/v1/responses")

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

    ok, reason, detail = _validate_gateway_headers(_effective_gateway_headers(request))
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
    decision = parse_confirmation_decision(user_text)
    pending = await _maybe_offload(_resolve_pending_confirmation, payload, user_text, now_ts)
    confirm_id_hint = _extract_confirm_id(user_text)

    if pending:
        pending_route = str(pending.get("route", ""))
        confirm_id = str(pending["confirm_id"])
        reason_text = str(pending.get("reason", "高风险响应"))
        summary_text = str(pending.get("summary", "检测到高风险信号"))
        if pending_route != req_preview.route:
            return _error_response(
                status_code=409,
                reason="confirmation_route_mismatch",
                detail=f"pending confirmation belongs to {pending_route}",
                ctx=ctx_preview,
                boundary=boundary,
            )

        if decision.value == "no":
            await _store_call("update_pending_confirmation_status", confirm_id=confirm_id, status="canceled", now_ts=now_ts)
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
            return to_responses_output(canceled_resp)

        if decision.value == "yes":
            pending_payload = pending.get("pending_request_payload", {})
            if not isinstance(pending_payload, dict):
                return _error_response(
                    status_code=409,
                    reason="pending_payload_invalid",
                    detail="pending payload is invalid",
                    ctx=ctx_preview,
                    boundary=boundary,
                )
            if _is_pending_payload_omitted(pending_payload):
                await _store_call("update_pending_confirmation_status", confirm_id=confirm_id, status="expired", now_ts=now_ts)
                return _error_response(
                    status_code=409,
                    reason="pending_payload_omitted",
                    detail="pending payload was omitted due to size limit, please resend the original request",
                    ctx=ctx_preview,
                    boundary=boundary,
                )
            if payload_hash(pending_payload) != str(pending.get("pending_request_hash", "")):
                return _error_response(
                    status_code=409,
                    reason="pending_hash_mismatch",
                    detail="pending request hash mismatch",
                    ctx=ctx_preview,
                    boundary=boundary,
                )

            executed = await _execute_responses_once(
                payload=pending_payload,
                request_headers=_effective_gateway_headers(request),
                request_path=request.url.path,
                boundary=boundary,
                skip_confirmation=True,
                forced_upstream_base=str(pending.get("upstream_base", "")),
            )
            if isinstance(executed, JSONResponse):
                return executed
            await _store_call("update_pending_confirmation_status", confirm_id=confirm_id, status="executed", now_ts=int(time.time()))
            aegis = executed.setdefault("aegisgate", {})
            aegis["confirmation"] = {
                "required": False,
                "confirm_id": confirm_id,
                "status": "executed",
                "reason": reason_text,
                "summary": summary_text,
                "payload_omitted": False,
            }
            return executed

        note = "输入不明确，请仅回复 yes 或 no。" if decision.value == "ambiguous" else "请仅回复 yes 或 no。"
        pending_resp = InternalResponse(
            request_id=req_preview.request_id,
            session_id=req_preview.session_id,
            model=req_preview.model,
            output_text=_build_confirmation_message(confirm_id=confirm_id, reason=reason_text, summary=summary_text, note=note),
        )
        ctx_preview.response_disposition = "block"
        ctx_preview.disposition_reasons.append("awaiting_user_confirmation")
        _attach_security_metadata(pending_resp, ctx_preview, boundary=boundary)
        _attach_confirmation_metadata(
            pending_resp,
            confirm_id=confirm_id,
            status="pending",
            reason=reason_text,
            summary=summary_text,
        )
        _write_audit_event(ctx_preview, boundary=boundary)
        return to_responses_output(pending_resp)

    if confirm_id_hint:
        expired_resp = InternalResponse(
            request_id=req_preview.request_id,
            session_id=req_preview.session_id,
            model=req_preview.model,
            output_text=f"确认已过期，请重新发起请求。确认编号：{confirm_id_hint}\nConfirmation expired. Please send the request again.",
        )
        ctx_preview.response_disposition = "block"
        ctx_preview.disposition_reasons.append("confirmation_expired")
        _attach_security_metadata(expired_resp, ctx_preview, boundary=boundary)
        _attach_confirmation_metadata(
            expired_resp,
            confirm_id=confirm_id_hint,
            status="expired",
            reason="确认已过期",
            summary="未找到可执行的 pending 记录",
        )
        _write_audit_event(ctx_preview, boundary=boundary)
        return to_responses_output(expired_resp)

    # 用户回复了 yes 但未匹配到任何 pending：不再对当前 body 跑请求管道
    if decision.value == "yes" and not pending:
        no_pending_resp = InternalResponse(
            request_id=req_preview.request_id,
            session_id=req_preview.session_id,
            model=req_preview.model,
            output_text="未找到待确认记录。请使用与触发确认时相同的 session_id，或在消息中包含确认编号（如 yes cfm-xxx）。\nNo pending confirmation found. Use the same session_id as the blocked request or include the confirm_id in your message (e.g. yes cfm-xxx).",
        )
        ctx_preview.response_disposition = "block"
        ctx_preview.disposition_reasons.append("no_pending_for_yes")
        _attach_security_metadata(no_pending_resp, ctx_preview, boundary=boundary)
        _write_audit_event(ctx_preview, boundary=boundary)
        return to_responses_output(no_pending_resp)

    if _should_stream(payload):
        return await _execute_responses_stream_once(
            payload=payload,
            request_headers=_effective_gateway_headers(request),
            request_path=request.url.path,
            boundary=boundary,
            forced_upstream_base=None,
        )

    return await _execute_responses_once(
        payload=payload,
        request_headers=_effective_gateway_headers(request),
        request_path=request.url.path,
        boundary=boundary,
        skip_confirmation=False,
        forced_upstream_base=None,
    )


@router.post("/{subpath:path}")
async def generic_provider_proxy(subpath: str, payload: dict, request: Request):
    normalized = subpath.strip("/")
    route_path = f"/v1/{normalized}" if normalized else "/v1"
    _log_request_if_debug(request, payload, route_path)
    logger.info("generic proxy route hit subpath=%s", normalized)
    if normalized in {"chat/completions", "responses"}:
        return JSONResponse(status_code=404, content={"error": "not_found"})

    boundary = getattr(request.state, "security_boundary", {})
    ok, reason, detail = _validate_gateway_headers(_effective_gateway_headers(request))
    if not ok:
        preview_ctx = RequestContext(
            request_id=str(payload.get("request_id") or "preview-generic"),
            session_id=str(payload.get("session_id") or payload.get("request_id") or "preview-generic"),
            route=route_path,
        )
        return _error_response(
            status_code=_to_status_code(reason),
            reason=reason,
            detail=detail,
            ctx=preview_ctx,
            boundary=boundary,
        )

    return await _execute_generic_once(
        payload=payload,
        request_headers=_effective_gateway_headers(request),
        request_path=route_path,
        boundary=boundary,
    )
