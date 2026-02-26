"""OpenAI <-> internal model mapping."""

from __future__ import annotations

import re
import uuid

from aegisgate.config.settings import settings
from aegisgate.core.models import InternalMessage, InternalRequest, InternalResponse


_BINARY_PLACEHOLDER = "[BINARY_CONTENT]"
_IMAGE_PLACEHOLDER = "[IMAGE_CONTENT]"
_NON_TEXT_PLACEHOLDER = "[NON_TEXT_PART]"
_TRUNCATED_SUFFIX = " [TRUNCATED]"
_BASE64_LIKE_RE = re.compile(r"[A-Za-z0-9+/]{256,}={0,2}")


def _cap_text(text: str, limit: int) -> str:
    if limit <= 0:
        return text
    if len(text) <= limit:
        return text
    return f"{text[:limit]}{_TRUNCATED_SUFFIX}"


def _looks_like_data_url(value: str) -> bool:
    lowered = value.strip().lower()
    return lowered.startswith("data:image/") or lowered.startswith("data:audio/") or lowered.startswith("data:video/")


def _is_binary_dict_part(part: dict) -> bool:
    ptype = str(part.get("type", "")).lower()
    if any(token in ptype for token in ("image", "audio", "video", "file")):
        return True
    return any(key in part for key in ("image_url", "image", "file", "audio", "video", "input_image", "input_audio"))


def _flatten_part(part: object) -> str:
    if isinstance(part, dict):
        if _is_binary_dict_part(part):
            return _IMAGE_PLACEHOLDER if "image" in str(part.get("type", "")).lower() or "image_url" in part else _BINARY_PLACEHOLDER

        text = part.get("text")
        if isinstance(text, str):
            return text

        content = part.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            merged = " ".join(_flatten_part(item) for item in content).strip()
            return merged or _NON_TEXT_PLACEHOLDER
        return _NON_TEXT_PLACEHOLDER

    if isinstance(part, str):
        if _looks_like_data_url(part):
            return _IMAGE_PLACEHOLDER
        if len(part) > 1024 and _BASE64_LIKE_RE.search(part):
            return _BINARY_PLACEHOLDER
        return part

    return str(part)


def _flatten_content(content: object) -> str:
    if isinstance(content, list):
        merged = " ".join(_flatten_part(part) for part in content)
        return " ".join(merged.split())
    if isinstance(content, dict):
        return _flatten_part(content)
    return str(content)


def _extract_latest_user_text_from_responses_input(raw_input: object) -> str:
    if isinstance(raw_input, str):
        return raw_input.strip()

    if isinstance(raw_input, list):
        for item in reversed(raw_input):
            if not isinstance(item, dict):
                continue
            if str(item.get("role", "")).strip().lower() != "user":
                continue
            if "content" in item:
                return _flatten_content(item.get("content", "")).strip()
            return _flatten_content(item).strip()
        return _flatten_content(raw_input).strip()

    if isinstance(raw_input, dict):
        role = str(raw_input.get("role", "")).strip().lower()
        if role == "user":
            if "content" in raw_input:
                return _flatten_content(raw_input.get("content", "")).strip()
            return _flatten_content(raw_input).strip()
        if "input" in raw_input:
            return _extract_latest_user_text_from_responses_input(raw_input.get("input"))
        if "content" in raw_input:
            return _flatten_content(raw_input.get("content", "")).strip()
        return _flatten_content(raw_input).strip()

    return str(raw_input or "").strip()


def to_internal_chat(payload: dict) -> InternalRequest:
    request_id = payload.get("request_id") or str(uuid.uuid4())
    session_id = payload.get("session_id") or request_id
    route = "/v1/chat/completions"
    model = payload.get("model", "unknown-model")

    messages = []
    for item in payload.get("messages", []):
        role = item.get("role", "user")
        source = item.get("source") or ("system" if role == "system" else "user")
        content = _flatten_content(item.get("content", ""))
        content = _cap_text(content, settings.max_content_length_per_message)
        messages.append(
            InternalMessage(
                role=role,
                content=str(content),
                source=source,
                metadata=item.get("metadata", {}),
            )
        )

    return InternalRequest(
        request_id=request_id,
        session_id=session_id,
        route=route,
        model=model,
        messages=messages,
        metadata={"raw": payload},
    )


def to_chat_response(resp: InternalResponse) -> dict:
    output = {
        "id": resp.request_id,
        "object": "chat.completion",
        "model": resp.model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": resp.output_text}, "finish_reason": "stop"}],
    }
    if resp.metadata.get("aegisgate"):
        output["aegisgate"] = resp.metadata["aegisgate"]
    return output


def to_internal_responses(payload: dict) -> InternalRequest:
    request_id = payload.get("request_id") or str(uuid.uuid4())
    session_id = payload.get("session_id") or request_id
    route = "/v1/responses"
    model = payload.get("model", "unknown-model")

    content = _extract_latest_user_text_from_responses_input(payload.get("input", ""))
    content = _cap_text(content, settings.max_content_length_per_message)
    messages = [InternalMessage(role="user", content=content, source="user")]

    return InternalRequest(
        request_id=request_id,
        session_id=session_id,
        route=route,
        model=model,
        messages=messages,
        metadata={"raw": payload},
    )


def to_responses_output(resp: InternalResponse) -> dict:
    output = {
        "id": resp.request_id,
        "object": "response",
        "model": resp.model,
        "output_text": resp.output_text,
    }
    if resp.metadata.get("aegisgate"):
        output["aegisgate"] = resp.metadata["aegisgate"]
    return output
