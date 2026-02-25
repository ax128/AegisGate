"""Relay protocol mapper placeholder."""

from __future__ import annotations

from aegisgate.core.models import InternalMessage, InternalRequest


def relay_to_internal(payload: dict) -> InternalRequest:
    return InternalRequest(
        request_id=payload.get("request_id", "relay-unknown"),
        session_id=payload.get("session_id", "relay-session"),
        route="/relay/generate",
        model=payload.get("model", "relay-model"),
        messages=[InternalMessage(role="user", content=payload.get("prompt", ""))],
        metadata={"raw": payload},
    )
