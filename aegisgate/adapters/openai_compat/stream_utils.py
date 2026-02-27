"""
流式 SSE 与 chunk 构建。从 router 拆出，便于维护与单测。
"""

from __future__ import annotations

import json
from typing import Any, AsyncIterable, Iterable

from fastapi.responses import StreamingResponse

from aegisgate.core.context import RequestContext


def _flatten_stream_content(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "".join(_flatten_stream_content(item) for item in value)
    if isinstance(value, dict):
        if isinstance(value.get("text"), str):
            return value["text"]
        for key in ("content", "delta", "output_text", "text"):
            if key in value:
                text = _flatten_stream_content(value[key])
                if text:
                    return text
    return ""


def _extract_stream_text_from_event(data_payload: str) -> str:
    try:
        event = json.loads(data_payload)
    except json.JSONDecodeError:
        return ""

    if not isinstance(event, dict):
        return ""

    # Responses typed events may include both delta and full-text done/completed payloads.
    # Only count incremental delta text to avoid duplicate cache/replay content.
    event_type = str(event.get("type") or "").strip().lower()
    if event_type:
        if event_type in {
            "response.output_text.done",
            "response.content_part.done",
            "response.output_item.done",
            "response.completed",
            "response.created",
            "response.output_item.added",
            "response.content_part.added",
        }:
            return ""
        if event_type == "response.output_text.delta":
            text = _flatten_stream_content(event.get("delta"))
            return text if text else ""

    choices = event.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            delta = first.get("delta")
            text = _flatten_stream_content(delta)
            if text:
                return text
            message = first.get("message")
            text2 = _flatten_stream_content(message)
            if text2:
                return text2

    for key in ("delta", "output_text", "text", "output"):
        if key in event:
            text = _flatten_stream_content(event[key])
            if text:
                return text
    return ""


def _stream_block_reason(ctx: RequestContext) -> str | None:
    # Command-like high risk output should always require confirmation in stream mode.
    if "response_anomaly_high_risk_command" in ctx.security_tags:
        return "response_high_risk_command"

    if ctx.response_disposition == "block":
        if ctx.disposition_reasons:
            return ctx.disposition_reasons[-1]
        return "response_blocked"
    if ctx.response_disposition == "sanitize":
        return "response_sanitized"
    if ctx.requires_human_review and any(tag.startswith("response_") for tag in ctx.security_tags):
        return "response_human_review_required"

    high_risk_tags = {
        "response_privilege_abuse",
        "response_injection_system_exfil",
        "response_injection_unicode_bidi",
        "response_semantic_leak",
        "response_semantic_privilege",
    }
    for tag in high_risk_tags:
        if tag in ctx.security_tags:
            return tag
    if ctx.risk_score >= max(ctx.risk_threshold, 0.9):
        return "response_high_risk"
    return None


def _stream_block_message(reason: str) -> str:
    return f"[AegisGate] stream blocked by security policy: {reason}"


def _stream_block_sse_chunk(ctx: RequestContext, model: str, reason: str, route: str) -> bytes:
    if route == "/v1/responses":
        payload = {
            "id": ctx.request_id,
            "object": "response.chunk",
            "model": model,
            "type": "response.output_text.delta",
            "delta": _stream_block_message(reason),
            "aegisgate": {
                "action": "block",
                "risk_score": round(ctx.risk_score, 4),
                "reason": reason,
                "security_tags": sorted(ctx.security_tags),
            },
        }
        return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8")

    payload = {
        "id": ctx.request_id,
        "object": "chat.completion.chunk",
        "model": model,
        "choices": [
            {
                "index": 0,
                "delta": {"role": "assistant", "content": _stream_block_message(reason)},
                "finish_reason": "stop",
            }
        ],
        "aegisgate": {
            "action": "block",
            "risk_score": round(ctx.risk_score, 4),
            "reason": reason,
            "security_tags": sorted(ctx.security_tags),
        },
    }
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8")


def _stream_error_sse_chunk(message: str, code: str | None = None) -> bytes:
    """SSE chunk 携带上游失败原因，兼容 error.message / error.code 解析。"""
    detail = (message or "upstream_error").strip() or "upstream_error"
    error_code = (code or "upstream_error").strip() or "upstream_error"
    payload: dict[str, Any] = {
        "type": "error",
        "error": {
            "message": detail,
            "type": "aegisgate_error",
            "code": error_code,
        },
        "aegisgate": {
            "action": "block",
            "reason": error_code,
        },
    }
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8")


def _stream_done_sse_chunk() -> bytes:
    return b"data: [DONE]\n\n"


def _stream_confirmation_sse_chunk(
    ctx: RequestContext,
    model: str,
    route: str,
    content: str,
    confirmation_meta: dict[str, Any],
) -> bytes:
    """流式返回一条「确认放行」内容，带 aegisgate.confirmation 元数据（非 block）。"""
    if route == "/v1/responses":
        payload = {
            "id": ctx.request_id,
            "object": "response.chunk",
            "model": model,
            "type": "response.output_text.delta",
            "delta": content,
            "aegisgate": {"confirmation": confirmation_meta, "action": "awaiting_confirmation"},
        }
    else:
        payload = {
            "id": ctx.request_id,
            "object": "chat.completion.chunk",
            "model": model,
            "choices": [
                {"index": 0, "delta": {"role": "assistant", "content": content}, "finish_reason": "stop"}
            ],
            "aegisgate": {"confirmation": confirmation_meta, "action": "awaiting_confirmation"},
        }
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8")


def _extract_sse_data_payload(line: bytes) -> str | None:
    if not line:
        return None
    stripped = line.strip()
    if not stripped.startswith(b"data:"):
        return None
    return stripped[5:].strip().decode("utf-8", errors="replace")


def _build_streaming_response(generator: Iterable[bytes] | AsyncIterable[bytes]) -> StreamingResponse:
    return StreamingResponse(
        generator,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
