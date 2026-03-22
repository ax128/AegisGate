"""OpenAI chat/responses protocol bridge helpers.

This module keeps endpoint-shape conversion out of the router so the routing
layer only decides where to send traffic.
"""

from __future__ import annotations

import copy
import json
from collections.abc import AsyncGenerator, Callable
from typing import Any

from fastapi.responses import JSONResponse, StreamingResponse

from aegisgate.adapters.openai_compat.mapper import to_chat_response, to_responses_output
from aegisgate.adapters.openai_compat.stream_utils import (
    _build_streaming_response,
    _extract_sse_data_payload_from_chunk,
    _extract_stream_text_from_event,
    _iter_sse_frames,
    _stream_done_sse_chunk,
)
from aegisgate.core.models import InternalResponse


BodyTextExtractor = Callable[[dict[str, Any] | str], str]


def passthrough_chat_response(
    upstream_body: dict[str, Any] | str,
    *,
    request_id: str,
    session_id: str,
    model: str,
) -> dict[str, Any]:
    if isinstance(upstream_body, dict):
        return upstream_body
    return to_chat_response(
        InternalResponse(
            request_id=request_id,
            session_id=session_id,
            model=model,
            output_text=str(upstream_body),
        )
    )


def passthrough_responses_output(
    upstream_body: dict[str, Any] | str,
    *,
    request_id: str,
    session_id: str,
    model: str,
) -> dict[str, Any]:
    if isinstance(upstream_body, dict):
        return upstream_body
    return to_responses_output(
        InternalResponse(
            request_id=request_id,
            session_id=session_id,
            model=model,
            output_text=str(upstream_body),
        )
    )


def _copy_aegis_meta(payload: dict[str, Any]) -> dict[str, Any] | None:
    aegis_meta = payload.get("aegisgate")
    if isinstance(aegis_meta, dict):
        return copy.deepcopy(aegis_meta)
    return None


def _attach_aegis_meta(payload: dict[str, Any], aegis_meta: dict[str, Any] | None) -> dict[str, Any]:
    if aegis_meta:
        payload["aegisgate"] = copy.deepcopy(aegis_meta)
    return payload


def coerce_responses_output_to_chat_output(
    result: dict[str, Any] | JSONResponse,
    *,
    fallback_request_id: str,
    fallback_session_id: str,
    fallback_model: str,
    text_extractor: BodyTextExtractor,
) -> dict[str, Any] | JSONResponse:
    if isinstance(result, JSONResponse):
        return result
    text = text_extractor(result)
    resp = InternalResponse(
        request_id=str(result.get("id") or fallback_request_id),
        session_id=fallback_session_id,
        model=str(result.get("model") or fallback_model),
        output_text=text,
    )
    aegis_meta = result.get("aegisgate")
    if isinstance(aegis_meta, dict):
        resp.metadata["aegisgate"] = aegis_meta
    return to_chat_response(resp)


def coerce_chat_output_to_responses_output(
    result: dict[str, Any] | JSONResponse,
    *,
    fallback_request_id: str,
    fallback_session_id: str,
    fallback_model: str,
    text_extractor: BodyTextExtractor,
) -> dict[str, Any] | JSONResponse:
    if isinstance(result, JSONResponse):
        return result
    text = text_extractor(result)
    resp = InternalResponse(
        request_id=str(result.get("id") or fallback_request_id),
        session_id=fallback_session_id,
        model=str(result.get("model") or fallback_model),
        output_text=text,
    )
    aegis_meta = result.get("aegisgate")
    if isinstance(aegis_meta, dict):
        resp.metadata["aegisgate"] = aegis_meta
    return to_responses_output(resp)


async def _iter_stream_body_chunks(response: StreamingResponse) -> AsyncGenerator[bytes, None]:
    async for chunk in response.body_iterator:
        yield chunk if isinstance(chunk, bytes) else str(chunk).encode("utf-8")


def _serialize_sse_payload(payload: dict[str, Any]) -> bytes:
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode("utf-8")


def _convert_responses_stream_payload_to_chat_chunk(
    payload_text: str,
    *,
    request_id: str,
    model: str,
    role_sent: bool,
    emitted_text: bool,
    response_text_extractor: BodyTextExtractor,
) -> tuple[list[bytes], bool, bool]:
    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError:
        return [], role_sent, emitted_text
    if not isinstance(payload, dict):
        return [], role_sent, emitted_text

    event_type = str(payload.get("type") or "").strip().lower()
    if event_type == "error":
        return [_serialize_sse_payload(payload)], role_sent, emitted_text

    chunks: list[bytes] = []
    aegis_meta = _copy_aegis_meta(payload)
    text = ""
    if event_type == "response.output_text.delta":
        text = _extract_stream_text_from_event(payload_text)
    elif event_type == "response.completed" and not emitted_text:
        response = payload.get("response")
        if isinstance(response, dict):
            extracted = response_text_extractor(response)
            if extracted and not extracted.startswith("[status="):
                text = extracted

    if not text:
        return [], role_sent, emitted_text

    delta: dict[str, Any] = {"content": text}
    if not role_sent:
        delta["role"] = "assistant"
        role_sent = True
    chunk_payload = {
        "id": request_id,
        "object": "chat.completion.chunk",
        "model": model,
        "choices": [
            {
                "index": 0,
                "delta": delta,
                "finish_reason": None,
            }
        ],
    }
    chunks.append(_serialize_sse_payload(_attach_aegis_meta(chunk_payload, aegis_meta)))
    emitted_text = True
    return chunks, role_sent, emitted_text


def coerce_responses_stream_to_chat_stream(
    response: StreamingResponse,
    *,
    request_id: str,
    model: str,
    response_text_extractor: BodyTextExtractor,
) -> StreamingResponse:
    async def generator() -> AsyncGenerator[bytes, None]:
        role_sent = False
        emitted_text = False
        async for frame in _iter_sse_frames(_iter_stream_body_chunks(response)):
            payload_text = _extract_sse_data_payload_from_chunk(frame)
            if payload_text is None:
                continue
            if payload_text == "[DONE]":
                yield _stream_done_sse_chunk()
                continue
            chunks, role_sent, emitted_text = _convert_responses_stream_payload_to_chat_chunk(
                payload_text,
                request_id=request_id,
                model=model,
                role_sent=role_sent,
                emitted_text=emitted_text,
                response_text_extractor=response_text_extractor,
            )
            for chunk in chunks:
                yield chunk

    return _build_streaming_response(generator())


def _responses_stream_start_events(
    *,
    request_id: str,
    model: str,
    item_id: str,
    aegis_meta: dict[str, Any] | None,
) -> list[bytes]:
    events = [
        {
            "type": "response.created",
            "response": {
                "id": request_id,
                "object": "response",
                "model": model,
                "status": "in_progress",
                "output": [],
            },
        },
        {
            "type": "response.output_item.added",
            "response_id": request_id,
            "output_index": 0,
            "item": {
                "type": "message",
                "id": item_id,
                "role": "assistant",
                "status": "in_progress",
                "content": [],
            },
        },
        {
            "type": "response.content_part.added",
            "response_id": request_id,
            "item_id": item_id,
            "output_index": 0,
            "content_index": 0,
            "part": {"type": "output_text", "text": ""},
        },
    ]
    return [_serialize_sse_payload(_attach_aegis_meta(payload, aegis_meta)) for payload in events]


def _responses_stream_finish_events(
    *,
    request_id: str,
    model: str,
    item_id: str,
    text: str,
    aegis_meta: dict[str, Any] | None,
) -> list[bytes]:
    output_item = {
        "type": "message",
        "id": item_id,
        "role": "assistant",
        "status": "completed",
        "content": [{"type": "output_text", "text": text, "annotations": []}],
    }
    events = [
        {
            "type": "response.output_text.done",
            "response_id": request_id,
            "item_id": item_id,
            "output_index": 0,
            "content_index": 0,
            "text": text,
        },
        {
            "type": "response.content_part.done",
            "response_id": request_id,
            "item_id": item_id,
            "output_index": 0,
            "content_index": 0,
            "part": {"type": "output_text", "text": text},
        },
        {
            "type": "response.output_item.done",
            "response_id": request_id,
            "output_index": 0,
            "item": output_item,
        },
        {
            "type": "response.completed",
            "response": {
                "id": request_id,
                "object": "response",
                "model": model,
                "status": "completed",
                "output": [output_item],
            },
        },
    ]
    return [_serialize_sse_payload(_attach_aegis_meta(payload, aegis_meta)) for payload in events]


def _responses_stream_empty_complete(
    *,
    request_id: str,
    model: str,
    aegis_meta: dict[str, Any] | None,
) -> bytes:
    payload = {
        "type": "response.completed",
        "response": {
            "id": request_id,
            "object": "response",
            "model": model,
            "status": "completed",
            "output": [],
        },
    }
    return _serialize_sse_payload(_attach_aegis_meta(payload, aegis_meta))


def coerce_chat_stream_to_responses_stream(
    response: StreamingResponse,
    *,
    request_id: str,
    model: str,
) -> StreamingResponse:
    async def generator() -> AsyncGenerator[bytes, None]:
        item_id = f"msg_{(request_id or 'resp')[:12]}"
        emitted_text = False
        started = False
        pending_meta: dict[str, Any] | None = None
        replay_parts: list[str] = []

        async for frame in _iter_sse_frames(_iter_stream_body_chunks(response)):
            payload_text = _extract_sse_data_payload_from_chunk(frame)
            if payload_text is None:
                continue
            if payload_text == "[DONE]":
                final_meta = pending_meta
                if started:
                    for chunk in _responses_stream_finish_events(
                        request_id=request_id,
                        model=model,
                        item_id=item_id,
                        text="".join(replay_parts),
                        aegis_meta=final_meta,
                    ):
                        yield chunk
                else:
                    yield _responses_stream_empty_complete(
                        request_id=request_id,
                        model=model,
                        aegis_meta=final_meta,
                    )
                yield _stream_done_sse_chunk()
                continue

            try:
                payload = json.loads(payload_text)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue

            event_type = str(payload.get("type") or "").strip().lower()
            if event_type == "error":
                yield _serialize_sse_payload(payload)
                continue

            pending_meta = _copy_aegis_meta(payload) or pending_meta
            text = _extract_stream_text_from_event(payload_text)
            if not text:
                continue

            if not started:
                for chunk in _responses_stream_start_events(
                    request_id=request_id,
                    model=model,
                    item_id=item_id,
                    aegis_meta=pending_meta,
                ):
                    yield chunk
                started = True

            replay_parts.append(text)
            emitted_text = True
            delta_payload = {
                "type": "response.output_text.delta",
                "response_id": request_id,
                "item_id": item_id,
                "output_index": 0,
                "content_index": 0,
                "delta": text,
            }
            yield _serialize_sse_payload(_attach_aegis_meta(delta_payload, pending_meta))

        if not emitted_text and not started:
            return

    return _build_streaming_response(generator())
