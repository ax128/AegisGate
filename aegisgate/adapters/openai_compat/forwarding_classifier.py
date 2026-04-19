from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ForwardingRouteIntent:
    entry_route: str
    detected_contract: str
    target_path: str
    compat_mode: str
    stream: bool


def _looks_like_responses_payload(payload: dict[str, Any]) -> bool:
    return "input" in payload and "messages" not in payload


def _looks_like_chat_payload(payload: dict[str, Any]) -> bool:
    return "messages" in payload and "input" not in payload and "max_tokens" not in payload


def _looks_like_messages_payload(payload: dict[str, Any]) -> bool:
    return "messages" in payload and "max_tokens" in payload and "input" not in payload


def classify_forwarding_intent(
    *, entry_path: str, payload: dict[str, Any], compat_mode: str | None = None
) -> ForwardingRouteIntent:
    stream = bool(payload.get("stream") is True)
    compat = str(compat_mode or "").strip()

    if entry_path == "/v1/chat/completions" and _looks_like_responses_payload(payload):
        return ForwardingRouteIntent(
            entry_route=entry_path,
            detected_contract="responses",
            target_path="/v1/responses",
            compat_mode=compat,
            stream=stream,
        )

    if entry_path == "/v1/responses" and _looks_like_chat_payload(payload):
        return ForwardingRouteIntent(
            entry_route=entry_path,
            detected_contract="chat",
            target_path="/v1/chat/completions",
            compat_mode=compat,
            stream=stream,
        )

    if entry_path == "/v1/messages" and _looks_like_messages_payload(payload):
        return ForwardingRouteIntent(
            entry_route=entry_path,
            detected_contract="messages",
            target_path="/v1/responses" if compat == "openai_chat" else "/v1/messages",
            compat_mode=compat,
            stream=stream,
        )

    detected_contract = "responses"
    if entry_path == "/v1/chat/completions":
        detected_contract = "chat"
    elif entry_path == "/v1/messages":
        detected_contract = "messages"

    return ForwardingRouteIntent(
        entry_route=entry_path,
        detected_contract=detected_contract,
        target_path=entry_path,
        compat_mode=compat,
        stream=stream,
    )
