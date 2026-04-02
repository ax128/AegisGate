"""
流式 SSE 与 chunk 构建。从 router 拆出，便于维护与单测。
"""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator
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

    # For Responses typed streams, only incremental assistant text deltas should
    # contribute to stream cache. Any other typed event (summary/tool/completed/etc.)
    # would cause duplicate or noisy replay text when upstream closes early.
    event_type = str(event.get("type") or "").strip().lower()
    if event_type:
        if event_type == "response.output_text.delta":
            text = _flatten_stream_content(event.get("delta"))
            return text if text else ""
        if event_type == "content_block_delta":
            text = _flatten_stream_content(event.get("delta"))
            return text if text else ""
        if event_type == "content_block_start":
            text = _flatten_stream_content(event.get("content_block"))
            return text if text else ""
        if event_type == "message_start":
            text = _flatten_stream_content(event.get("message"))
            return text if text else ""
        return ""

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

    for key in ("delta", "content_block", "message", "output_text", "text", "output"):
        if key in event:
            text = _flatten_stream_content(event[key])
            if text:
                return text
    return ""


def _extract_stream_event_type(data_payload: str) -> str:
    """Return normalized stream event type, or empty string if unavailable."""
    try:
        event = json.loads(data_payload)
    except json.JSONDecodeError:
        return ""
    if not isinstance(event, dict):
        return ""
    event_type = event.get("type")
    if not isinstance(event_type, str):
        return ""
    return event_type.strip().lower()


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
    # tool_call_violation 仅在实际 block 动作时才阻断流；review 动作不阻断
    if "tool_call_violation" in ctx.security_tags:
        has_block_action = any(
            a.endswith(":block") and a.startswith("tool_call_guard:")
            for a in ctx.enforcement_actions
        )
        if has_block_action:
            return "response_tool_call_violation"
    if ctx.requires_human_review and any(
        tag.startswith("response_") for tag in ctx.security_tags
    ):
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


def _stream_block_sse_chunk(
    ctx: RequestContext, model: str, reason: str, route: str
) -> bytes:
    if route == "/v1/responses":
        payload: dict[str, Any] = {
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
                "delta": {
                    "role": "assistant",
                    "content": _stream_block_message(reason),
                },
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


def _stream_messages_error_sse_chunk(
    message: str,
    *,
    code: str | None = None,
    error_type: str = "api_error",
) -> bytes:
    detail = (message or "upstream_error").strip() or "upstream_error"
    reason = (code or error_type).strip() or error_type
    payload: dict[str, Any] = {
        "type": "error",
        "error": {
            "type": error_type,
            "message": detail,
        },
        "aegisgate": {
            "action": "block",
            "reason": reason,
        },
    }
    return _stream_messages_sse_chunk("error", payload)


def _stream_done_sse_chunk() -> bytes:
    return b"data: [DONE]\n\n"


def _stream_confirmation_sse_chunk(
    ctx: RequestContext,
    model: str,
    route: str,
    content: str,
    confirmation_meta: dict[str, Any] | None,
) -> bytes:
    """流式返回一条「确认放行」或「直接拦截」内容。confirmation_meta 为 None 时不附带确认元数据。"""
    aegis_meta: dict[str, Any] = {}
    if confirmation_meta is not None:
        aegis_meta["confirmation"] = confirmation_meta
        aegis_meta["action"] = "awaiting_confirmation"
    else:
        aegis_meta["action"] = "blocked"
    if route == "/v1/responses":
        payload: dict[str, Any] = {
            "id": ctx.request_id,
            "object": "response.chunk",
            "model": model,
            "type": "response.output_text.delta",
            "delta": content,
            "aegisgate": aegis_meta,
        }
    else:
        payload = {
            "id": ctx.request_id,
            "object": "chat.completion.chunk",
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "delta": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
            "aegisgate": aegis_meta,
        }
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8")


def _stream_messages_sse_chunk(event: str, payload: dict[str, Any]) -> bytes:
    return (
        f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
    ).encode("utf-8")


def _stream_messages_message_start_sse_chunk(
    request_id: str,
    model: str,
    *,
    message_id: str | None = None,
    aegisgate_meta: dict[str, Any] | None = None,
) -> bytes:
    payload: dict[str, Any] = {
        "type": "message_start",
        "message": {
            "id": message_id or request_id,
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [],
        },
    }
    if aegisgate_meta:
        payload["aegisgate"] = aegisgate_meta
    return _stream_messages_sse_chunk("message_start", payload)


def _stream_messages_content_block_start_sse_chunk(
    *,
    index: int = 0,
    text: str = "",
) -> bytes:
    return _stream_messages_sse_chunk(
        "content_block_start",
        {
            "type": "content_block_start",
            "index": index,
            "content_block": {"type": "text", "text": text},
        },
    )


def _stream_messages_content_block_delta_sse_chunk(
    text: str,
    *,
    index: int = 0,
) -> bytes:
    return _stream_messages_sse_chunk(
        "content_block_delta",
        {
            "type": "content_block_delta",
            "index": index,
            "delta": {"type": "text_delta", "text": text},
        },
    )


def _stream_messages_content_block_stop_sse_chunk(*, index: int = 0) -> bytes:
    return _stream_messages_sse_chunk(
        "content_block_stop",
        {"type": "content_block_stop", "index": index},
    )


def _stream_messages_message_delta_sse_chunk(
    *,
    stop_reason: str = "end_turn",
    stop_sequence: str | None = None,
    usage: dict[str, Any] | None = None,
    aegisgate_meta: dict[str, Any] | None = None,
) -> bytes:
    payload: dict[str, Any] = {
        "type": "message_delta",
        "delta": {
            "stop_reason": stop_reason,
            "stop_sequence": stop_sequence,
        },
        "usage": usage or {"input_tokens": 0, "output_tokens": 0},
    }
    if aegisgate_meta:
        payload["aegisgate"] = aegisgate_meta
    return _stream_messages_sse_chunk("message_delta", payload)


def _stream_messages_message_stop_sse_chunk(
    *,
    aegisgate_meta: dict[str, Any] | None = None,
) -> bytes:
    payload: dict[str, Any] = {"type": "message_stop"}
    if aegisgate_meta:
        payload["aegisgate"] = aegisgate_meta
    return _stream_messages_sse_chunk("message_stop", payload)


def _extract_sse_data_payload(line: bytes) -> str | None:
    if not line:
        return None
    stripped = line.strip()
    if not stripped.startswith(b"data:"):
        return None
    return stripped[5:].strip().decode("utf-8", errors="replace")


def _extract_sse_data_payload_from_chunk(chunk: bytes) -> str | None:
    normalized = chunk.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    payload_lines: list[str] = []
    for raw_line in normalized.split(b"\n"):
        payload = _extract_sse_data_payload(raw_line)
        if payload is not None:
            payload_lines.append(payload)
    if not payload_lines:
        return None
    return "\n".join(payload_lines)


def _build_sse_frame(lines: list[bytes]) -> bytes:
    frame = b"".join(lines)
    if not frame.endswith(b"\n"):
        frame += b"\n"
    if not frame.endswith(b"\n\n"):
        frame += b"\n"
    return frame


_SSE_MAX_BUFFER_BYTES = 10 * 1024 * 1024  # 10 MB — safety limit per stream.


async def _iter_sse_frames(chunks: AsyncIterable[bytes]) -> AsyncGenerator[bytes, None]:
    buffer = b""
    async for chunk in chunks:
        if not chunk:
            continue
        buffer += chunk.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        if len(buffer) > _SSE_MAX_BUFFER_BYTES:
            raise RuntimeError(
                f"SSE buffer exceeded {_SSE_MAX_BUFFER_BYTES} bytes without frame delimiter"
            )
        while True:
            split_at = buffer.find(b"\n\n")
            if split_at < 0:
                break
            frame_body = buffer[:split_at]
            buffer = buffer[split_at + 2 :]
            if not frame_body:
                continue
            frame_lines = [line + b"\n" for line in frame_body.split(b"\n") if line]
            if frame_lines:
                yield _build_sse_frame(frame_lines)
    if buffer.strip():
        frame_lines = [line + b"\n" for line in buffer.split(b"\n") if line]
        if frame_lines:
            yield _build_sse_frame(frame_lines)


def _build_streaming_response(
    generator: Iterable[bytes] | AsyncIterable[bytes],
) -> StreamingResponse:
    return StreamingResponse(
        generator,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
