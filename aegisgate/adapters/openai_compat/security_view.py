"""Shared preview/security-view helpers for core OpenAI-compatible routes."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from aegisgate.adapters.openai_compat.mapper import (
    to_internal_chat,
    to_internal_messages,
    to_internal_responses,
)
from aegisgate.adapters.openai_compat.offload import run_payload_transform_offloop
from aegisgate.config.settings import settings
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalRequest


@dataclass(slots=True)
class SecurityPreview:
    ctx: RequestContext
    request: InternalRequest


@dataclass(slots=True)
class SecurityPreviewError:
    ctx: RequestContext
    status_code: int
    reason: str
    detail: str


def _serialized_payload_size(payload: dict[str, Any]) -> int:
    try:
        return len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    except Exception:
        return 0


def _header_lookup(headers: Mapping[str, str], target: str) -> str:
    needle = target.strip().lower()
    if not needle:
        return ""
    for key, value in headers.items():
        if key.lower() == needle:
            return str(value).strip()
    return ""


def _derive_session_id(
    payload: Mapping[str, Any],
    request_id: str,
    request_headers: Mapping[str, str] | None = None,
) -> str:
    """Derive a session_id scoped to the authenticated token."""
    client_session = str(payload.get("session_id") or request_id)
    if request_headers:
        token_hint = _header_lookup(request_headers, "x-aegis-token-hint").strip()
        if token_hint:
            return f"{token_hint}:{client_session}"
    return client_session


def _resolve_tenant_id(
    *,
    payload: Mapping[str, Any] | None = None,
    headers: Mapping[str, str] | None = None,
    boundary: Mapping[str, Any] | None = None,
) -> str:
    if boundary:
        value = str(boundary.get("tenant_id") or "").strip()
        if value:
            return value
    if headers:
        token_hint = _header_lookup(headers, "x-aegis-token-hint")
        if token_hint:
            return f"token:{token_hint}"
    return "default"


def _validate_payload_limits(
    payload: dict[str, Any],
    route: str,
    *,
    body_size_bytes: int | None = None,
) -> tuple[bool, int, str, str]:
    max_body = int(settings.max_request_body_bytes)
    if max_body > 0:
        body_size = (
            body_size_bytes
            if body_size_bytes is not None
            else _serialized_payload_size(payload)
        )
        if body_size > max_body:
            return (
                False,
                413,
                "request_body_too_large",
                f"payload bytes={body_size} exceeds max={max_body}",
            )

    max_messages = int(settings.max_messages_count)
    if route == "/v1/chat/completions":
        messages = payload.get("messages", [])
        if not isinstance(messages, list):
            return False, 400, "invalid_messages_format", "messages must be a list"
        if max_messages > 0 and len(messages) > max_messages:
            return (
                False,
                400,
                "messages_too_many",
                f"messages count={len(messages)} exceeds max={max_messages}",
            )

    return True, 200, "", ""


async def _prepare_security_view(
    payload: dict[str, Any],
    *,
    route: str,
    preview_request_id: str,
    request_headers: Mapping[str, str] | None,
    boundary: Mapping[str, Any] | None,
    transform: Callable[[dict[str, Any]], InternalRequest],
) -> SecurityPreview | SecurityPreviewError:
    tenant_id = _resolve_tenant_id(payload=payload, headers=request_headers, boundary=boundary)
    ctx = RequestContext(
        request_id=str(payload.get("request_id") or preview_request_id),
        session_id=_derive_session_id(
            payload,
            str(payload.get("request_id") or preview_request_id),
            request_headers,
        ),
        route=route,
        tenant_id=tenant_id,
    )
    body_size_bytes = boundary.get("request_body_size") if boundary else None
    if not isinstance(body_size_bytes, int):
        body_size_bytes = None

    ok_payload, status_code, reason, detail = _validate_payload_limits(
        payload,
        route=ctx.route,
        body_size_bytes=body_size_bytes,
    )
    if not ok_payload:
        return SecurityPreviewError(
            ctx=ctx,
            status_code=status_code,
            reason=reason,
            detail=detail,
        )

    req_preview = await run_payload_transform_offloop(transform, payload)
    req_preview.session_id = _derive_session_id(payload, req_preview.request_id, request_headers)
    ctx.request_id = req_preview.request_id
    ctx.session_id = req_preview.session_id
    return SecurityPreview(ctx=ctx, request=req_preview)


async def prepare_chat_security_view(
    *,
    payload: dict[str, Any],
    request_headers: Mapping[str, str] | None,
    boundary: Mapping[str, Any] | None,
) -> SecurityPreview | SecurityPreviewError:
    return await _prepare_security_view(
        payload,
        route="/v1/chat/completions",
        preview_request_id="preview-chat",
        request_headers=request_headers,
        boundary=boundary,
        transform=to_internal_chat,
    )


async def prepare_responses_security_view(
    *,
    payload: dict[str, Any],
    request_headers: Mapping[str, str] | None,
    boundary: Mapping[str, Any] | None,
) -> SecurityPreview | SecurityPreviewError:
    return await _prepare_security_view(
        payload,
        route="/v1/responses",
        preview_request_id="preview-responses",
        request_headers=request_headers,
        boundary=boundary,
        transform=to_internal_responses,
    )


async def prepare_messages_security_view(
    *,
    payload: dict[str, Any],
    request_headers: Mapping[str, str] | None,
    boundary: Mapping[str, Any] | None,
) -> SecurityPreview | SecurityPreviewError:
    return await _prepare_security_view(
        payload,
        route="/v1/messages",
        preview_request_id="preview-messages",
        request_headers=request_headers,
        boundary=boundary,
        transform=to_internal_messages,
    )
