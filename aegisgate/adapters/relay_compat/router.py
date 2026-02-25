"""Relay-compatible routes."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from aegisgate.adapters.openai_compat.router import (
    _execute_chat_once,
    _execute_chat_stream_once,
)
from aegisgate.adapters.openai_compat.upstream import (
    _effective_gateway_headers,
    _header_value,
    _resolve_gateway_key,
)
from aegisgate.config.settings import settings
from aegisgate.util.logger import logger


router = APIRouter()


def _relay_to_chat_payload(payload: dict) -> dict:
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        messages = [{"role": "user", "content": str(payload.get("prompt", ""))}]

    request_id = str(payload.get("request_id") or "relay-unknown")
    session_id = str(payload.get("session_id") or request_id)
    model = str(payload.get("model") or "relay-model")

    mapped: dict = {
        "request_id": request_id,
        "session_id": session_id,
        "model": model,
        "messages": messages,
    }
    if "stream" in payload:
        mapped["stream"] = bool(payload.get("stream"))
    if "policy" in payload:
        mapped["policy"] = payload.get("policy")
    logger.debug(
        "relay payload mapped request_id=%s messages=%d stream=%s",
        mapped["request_id"],
        len(mapped.get("messages", [])),
        bool(mapped.get("stream")),
    )
    return mapped


@router.post("/generate")
async def relay_generate(payload: dict, request: Request):
    headers = _effective_gateway_headers(request)
    upstream_base = (_header_value(headers, settings.upstream_base_header) or "").strip()
    gateway_key = _resolve_gateway_key(headers).strip()
    if not upstream_base:
        return JSONResponse(status_code=400, content={"error": "invalid_parameters", "detail": "missing upstream base header"})
    if not settings.gateway_key:
        return JSONResponse(status_code=500, content={"error": "gateway_misconfigured"})
    if gateway_key != settings.gateway_key:
        return JSONResponse(status_code=401, content={"error": "gateway_auth_failed"})

    mapped_payload = _relay_to_chat_payload(payload)
    boundary = getattr(request.state, "security_boundary", {})
    logger.info("relay generate request_id=%s routed_to=/v1/chat/completions", mapped_payload.get("request_id"))

    if bool(mapped_payload.get("stream")):
        return await _execute_chat_stream_once(
            payload=mapped_payload,
            request_headers=headers,
            request_path="/v1/chat/completions",
            boundary=boundary,
            forced_upstream_base=None,
        )

    return await _execute_chat_once(
        payload=mapped_payload,
        request_headers=headers,
        request_path="/v1/chat/completions",
        boundary=boundary,
        skip_confirmation=False,
        forced_upstream_base=None,
    )
