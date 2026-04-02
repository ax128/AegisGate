"""OpenAI <-> internal model mapping."""

from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path

from aegisgate.config.settings import settings
from aegisgate.core.models import InternalMessage, InternalRequest, InternalResponse
from aegisgate.util.logger import logger


_BINARY_PLACEHOLDER = "[BINARY_CONTENT]"
_IMAGE_PLACEHOLDER = "[IMAGE_CONTENT]"
_NON_TEXT_PLACEHOLDER = "[NON_TEXT_PART]"
_TRUNCATED_SUFFIX = " [TRUNCATED]"
_BASE64_LIKE_RE = re.compile(r"[A-Za-z0-9+/]{256,}={0,2}")
_SYSTEM_EXEC_RUNTIME_LINE_RE = re.compile(
    r"^\s*System:\s*\[[^\]]+\]\s*Exec\s+(?:completed|failed)\b",
    re.IGNORECASE,
)


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


def _strip_system_exec_runtime_lines(text: str) -> str:
    body = str(text or "")
    if not body:
        return ""
    lines = body.splitlines()
    kept = [line for line in lines if not _SYSTEM_EXEC_RUNTIME_LINE_RE.match(line)]
    return "\n".join(kept).strip()


def _extract_latest_user_text_from_responses_input(raw_input: object) -> str:
    if isinstance(raw_input, str):
        return _strip_system_exec_runtime_lines(raw_input)

    if isinstance(raw_input, list):
        for item in reversed(raw_input):
            if not isinstance(item, dict):
                continue
            if str(item.get("role", "")).strip().lower() != "user":
                continue
            if "content" in item:
                return _strip_system_exec_runtime_lines(_flatten_content(item.get("content", "")))
            return _strip_system_exec_runtime_lines(_flatten_content(item))
        return _strip_system_exec_runtime_lines(_flatten_content(raw_input))

    if isinstance(raw_input, dict):
        role = str(raw_input.get("role", "")).strip().lower()
        if role == "user":
            if "content" in raw_input:
                return _strip_system_exec_runtime_lines(_flatten_content(raw_input.get("content", "")))
            return _strip_system_exec_runtime_lines(_flatten_content(raw_input))
        if "input" in raw_input:
            return _extract_latest_user_text_from_responses_input(raw_input.get("input"))
        if "content" in raw_input:
            return _strip_system_exec_runtime_lines(_flatten_content(raw_input.get("content", "")))
        return _strip_system_exec_runtime_lines(_flatten_content(raw_input))

    return _strip_system_exec_runtime_lines(str(raw_input or ""))


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


def to_internal_messages(payload: dict) -> InternalRequest:
    """Anthropic /v1/messages payload → InternalRequest for security scanning."""
    request_id = payload.get("request_id") or str(uuid.uuid4())
    session_id = payload.get("session_id") or request_id
    route = "/v1/messages"
    model = payload.get("model", "unknown-model")

    messages: list[InternalMessage] = []

    # Anthropic puts system prompt at top level (str or list of content blocks)
    system = payload.get("system")
    if system:
        if isinstance(system, str):
            sys_text = system
        elif isinstance(system, list):
            sys_text = " ".join(
                _flatten_part(block) for block in system
            ).strip()
        else:
            sys_text = str(system)
        sys_text = _cap_text(sys_text, settings.max_content_length_per_message)
        if sys_text:
            messages.append(
                InternalMessage(role="system", content=sys_text, source="system")
            )

    for item in payload.get("messages", []):
        role = item.get("role", "user")
        content = _flatten_content(item.get("content", ""))
        content = _cap_text(content, settings.max_content_length_per_message)
        messages.append(
            InternalMessage(
                role=role,
                content=str(content),
                source="system" if role == "system" else "user",
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


def to_messages_response(resp: InternalResponse) -> dict:
    """InternalResponse → Anthropic /v1/messages response envelope."""
    output: dict = {
        "id": resp.request_id,
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": resp.output_text}],
        "model": resp.model,
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 0, "output_tokens": 0},
    }
    if resp.metadata.get("aegisgate"):
        output["aegisgate"] = resp.metadata["aegisgate"]
    return output


def to_internal_responses(payload: dict) -> InternalRequest:
    """Convert a ``/v1/responses`` payload into an :class:`InternalRequest`.

    Unlike the previous implementation that only extracted the *last* user
    message, this version converts **all** input items so that earlier
    messages are not silently skipped by the redaction pipeline.
    """
    request_id = payload.get("request_id") or str(uuid.uuid4())
    session_id = payload.get("session_id") or request_id
    route = "/v1/responses"
    model = payload.get("model", "unknown-model")

    raw_input = payload.get("input", "")
    messages: list[InternalMessage] = []

    if isinstance(raw_input, str):
        content = _strip_system_exec_runtime_lines(raw_input)
        content = _cap_text(content, settings.max_content_length_per_message)
        messages.append(InternalMessage(role="user", content=content, source="user"))
    elif isinstance(raw_input, list):
        for item in raw_input:
            if isinstance(item, str):
                text = _strip_system_exec_runtime_lines(item)
                text = _cap_text(text, settings.max_content_length_per_message)
                messages.append(InternalMessage(role="user", content=text, source="user"))
            elif isinstance(item, dict):
                role = str(item.get("role", "user")).strip().lower()
                source = "system" if role == "system" else "user"
                content = _flatten_content(item.get("content", ""))
                content = _strip_system_exec_runtime_lines(content)
                content = _cap_text(content, settings.max_content_length_per_message)
                messages.append(
                    InternalMessage(
                        role=role,
                        content=content,
                        source=source,
                        metadata=item.get("metadata", {}),
                    )
                )
    elif isinstance(raw_input, dict):
        role = str(raw_input.get("role", "user")).strip().lower()
        source = "system" if role == "system" else "user"
        content = _flatten_content(raw_input.get("content", ""))
        content = _strip_system_exec_runtime_lines(content)
        content = _cap_text(content, settings.max_content_length_per_message)
        messages.append(
            InternalMessage(role=role, content=content, source=source, metadata=raw_input.get("metadata", {}))
        )
    else:
        content = _strip_system_exec_runtime_lines(str(raw_input or ""))
        content = _cap_text(content, settings.max_content_length_per_message)
        messages.append(InternalMessage(role="user", content=content, source="user"))

    if not messages:
        messages.append(InternalMessage(role="user", content="", source="user"))

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


# ---------------------------------------------------------------------------
# Anthropic Messages <-> OpenAI Chat payload-level conversion
# ---------------------------------------------------------------------------

_ANTHROPIC_STOP_REASON_MAP = {
    "stop": "end_turn",
    "length": "max_tokens",
    "content_filter": "end_turn",
}

# compat=openai_chat 时允许的目标模型白名单
COMPAT_ALLOWED_MODELS = frozenset({
    "gpt-5",
    "gpt-5.2",
    "gpt-5.4",
    "gpt-5.4-mini",
    "gpt-5.2-codex",
    "gpt-5.3-codex",
})
COMPAT_DEFAULT_MODEL = "gpt-5.4"

# 全局模型映射（从 config/model_map.json 加载）
_global_model_map: dict[str, str] = {}


def load_global_model_map() -> None:
    """从 config/model_map.json 加载全局模型映射。启动和热重载时调用。"""
    global _global_model_map
    p = settings.compat_model_map_path
    path = Path(p) if os.path.isabs(p) else Path.cwd() / p
    if not path.is_file():
        logger.debug("global model_map not found path=%s, skip", path)
        _global_model_map = {}
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        raw_map = data.get("map") if isinstance(data, dict) else None
        if isinstance(raw_map, dict):
            _global_model_map = {str(k): str(v) for k, v in raw_map.items()}
            logger.info("global model_map loaded path=%s count=%d", path, len(_global_model_map))
        else:
            _global_model_map = {}
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("global model_map load failed path=%s error=%s", path, exc)
        _global_model_map = {}


def get_global_model_map() -> dict[str, str]:
    """返回当前全局模型映射（只读引用）。"""
    return _global_model_map


def _anthropic_tool_to_responses_tool(tool: object) -> dict | None:
    if not isinstance(tool, dict):
        return None
    if str(tool.get("type") or "").strip().lower() == "function" and "name" in tool:
        copied = dict(tool)
        if "input_schema" in copied and "parameters" not in copied:
            copied["parameters"] = copied.pop("input_schema")
        return copied

    name = tool.get("name")
    if not isinstance(name, str) or not name.strip():
        return None

    converted: dict[str, object] = {
        "type": "function",
        "name": name,
    }
    if isinstance(tool.get("description"), str):
        converted["description"] = tool["description"]
    if "input_schema" in tool:
        converted["parameters"] = tool["input_schema"]
    if "strict" in tool:
        converted["strict"] = tool["strict"]
    return converted


def _anthropic_content_block_to_responses_part(block: object) -> dict | None:
    if isinstance(block, str):
        text = block.strip()
        return {"type": "input_text", "text": text} if text else None
    if not isinstance(block, dict):
        text = str(block).strip()
        return {"type": "input_text", "text": text} if text else None

    block_type = str(block.get("type", "")).strip().lower()
    if block_type == "text":
        text = str(block.get("text") or "").strip()
        return {"type": "input_text", "text": text} if text else None
    if block_type == "image":
        source = block.get("source")
        if isinstance(source, dict):
            url = source.get("url")
            if isinstance(url, str) and url.strip():
                return {"type": "input_image", "image_url": url}
        placeholder = _flatten_part(block).strip()
        return {"type": "input_text", "text": placeholder} if placeholder else None
    if block_type == "tool_use":
        name = str(block.get("name") or "").strip()
        raw_input = block.get("input")
        if isinstance(raw_input, str):
            arguments = raw_input
        else:
            arguments = json.dumps(raw_input or {}, ensure_ascii=False)
        part = {
            "type": "function_call",
            "call_id": str(block.get("id") or f"call_{uuid.uuid4().hex[:12]}"),
            "name": name or "tool_use",
            "arguments": arguments,
        }
        return part
    if block_type == "tool_result":
        content = block.get("content", "")
        output = _flatten_content(content).strip() if isinstance(content, (list, dict)) else str(content).strip()
        part = {
            "type": "function_call_output",
            "call_id": str(block.get("tool_use_id") or block.get("id") or f"call_{uuid.uuid4().hex[:12]}"),
            "output": output,
        }
        if isinstance(block.get("name"), str) and block.get("name"):
            part["name"] = str(block["name"])
        return part

    flattened = _flatten_part(block).strip()
    return {"type": "input_text", "text": flattened} if flattened else None


def _responses_arguments_to_anthropic_input(arguments: object) -> dict:
    if isinstance(arguments, dict):
        return arguments
    if not isinstance(arguments, str):
        return {"value": arguments}
    text = arguments.strip()
    if not text:
        return {}
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {"raw": text}
    if isinstance(parsed, dict):
        return parsed
    return {"value": parsed}


def messages_payload_to_chat_payload(
    payload: dict,
    model_map: dict[str, str] | None = None,
    default_model: str | None = None,
) -> dict:
    """Convert Anthropic /v1/messages request → OpenAI /v1/chat/completions request.

    Handles: system (str/list), messages, model mapping, max_tokens,
    temperature, top_p, top_k, stream, stop_sequences, tools.
    """
    messages: list[dict] = []

    # Anthropic: system is top-level, not in messages array
    system = payload.get("system")
    if system:
        if isinstance(system, str):
            sys_text = system
        elif isinstance(system, list):
            sys_text = " ".join(
                block.get("text", "") if isinstance(block, dict) else str(block)
                for block in system
            ).strip()
        else:
            sys_text = str(system)
        if sys_text:
            messages.append({"role": "system", "content": sys_text})

    # Convert messages — Anthropic content can be str or list of content blocks
    for msg in payload.get("messages", []):
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if isinstance(content, str):
            messages.append({"role": role, "content": content})
        elif isinstance(content, list):
            # Flatten text blocks; pass tool_use/tool_result as-is for now
            text_parts = []
            for block in content:
                if isinstance(block, str):
                    text_parts.append(block)
                elif isinstance(block, dict):
                    if block.get("type") == "text":
                        text_parts.append(block.get("text", ""))
                    elif block.get("type") == "tool_use":
                        # Will be handled in tool_calls conversion later
                        text_parts.append(f"[tool_use: {block.get('name', '')}]")
                    elif block.get("type") == "tool_result":
                        text_parts.append(str(block.get("content", "")))
                    else:
                        text_parts.append(_flatten_part(block))
            messages.append({"role": role, "content": " ".join(text_parts).strip()})
        else:
            messages.append({"role": role, "content": str(content)})

    # Model mapping 优先级: token 级 model_map > 全局 model_map > default_model > COMPAT_DEFAULT_MODEL
    original_model = payload.get("model", "unknown-model")
    if model_map and original_model in model_map:
        model = model_map[original_model]
    elif original_model in _global_model_map:
        model = _global_model_map[original_model]
    elif default_model:
        model = default_model
    else:
        model = COMPAT_DEFAULT_MODEL
    # 白名单校验
    if model not in COMPAT_ALLOWED_MODELS:
        raise ValueError(
            f"compat target model '{model}' not allowed, "
            f"valid: {sorted(COMPAT_ALLOWED_MODELS)}"
        )

    result: dict = {
        "model": model,
        "messages": messages,
        "stream": payload.get("stream", False),
    }

    # Optional params
    if "max_tokens" in payload:
        result["max_tokens"] = payload["max_tokens"]
    if "temperature" in payload:
        result["temperature"] = payload["temperature"]
    if "top_p" in payload:
        result["top_p"] = payload["top_p"]
    if "stop_sequences" in payload:
        result["stop"] = payload["stop_sequences"]

    return result


def chat_response_to_messages_response(
    chat_resp: dict,
    *,
    original_model: str,
) -> dict:
    """Convert OpenAI /v1/chat/completions response → Anthropic /v1/messages response."""
    choice = (chat_resp.get("choices") or [{}])[0]
    message = choice.get("message") or {}
    content_text = message.get("content") or ""
    finish_reason = choice.get("finish_reason", "stop")

    usage = chat_resp.get("usage") or {}
    anthropic_usage = {
        "input_tokens": usage.get("prompt_tokens", 0),
        "output_tokens": usage.get("completion_tokens", 0),
    }

    result: dict = {
        "id": f"msg_{chat_resp.get('id', str(uuid.uuid4()))}",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": content_text}],
        "model": original_model,
        "stop_reason": _ANTHROPIC_STOP_REASON_MAP.get(finish_reason, "end_turn"),
        "stop_sequence": None,
        "usage": anthropic_usage,
    }

    # Preserve aegisgate metadata if present
    if chat_resp.get("aegisgate"):
        result["aegisgate"] = chat_resp["aegisgate"]

    return result


def messages_payload_to_responses_payload(
    payload: dict,
    model_map: dict[str, str] | None = None,
    default_model: str | None = None,
) -> dict:
    """Convert Anthropic /v1/messages request → OpenAI /v1/responses request.

    Responses API uses 'input' (str or list of messages) instead of 'messages'.
    System prompt goes into 'instructions' (top-level).
    """
    input_messages: list[dict] = []

    for msg in payload.get("messages", []):
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if isinstance(content, list):
            content_parts = [
                part
                for block in content
                for part in [_anthropic_content_block_to_responses_part(block)]
                if part is not None
            ]
            input_messages.append(
                {"role": role, "content": content_parts or [{"type": "input_text", "text": ""}]}
            )
            continue
        input_messages.append({"role": role, "content": str(content)})

    # Model mapping
    original_model = payload.get("model", "unknown-model")
    if model_map and original_model in model_map:
        model = model_map[original_model]
    elif original_model in _global_model_map:
        model = _global_model_map[original_model]
    elif default_model:
        model = default_model
    else:
        model = COMPAT_DEFAULT_MODEL
    if model not in COMPAT_ALLOWED_MODELS:
        raise ValueError(
            f"compat target model '{model}' not allowed, "
            f"valid: {sorted(COMPAT_ALLOWED_MODELS)}"
        )

    result: dict = {
        "model": model,
        "input": input_messages,
        "stream": payload.get("stream", False),
    }

    # system → instructions
    system = payload.get("system")
    if system:
        if isinstance(system, str):
            result["instructions"] = system
        elif isinstance(system, list):
            result["instructions"] = " ".join(
                block.get("text", "") if isinstance(block, dict) else str(block)
                for block in system
            ).strip()

    if "max_tokens" in payload:
        result["max_output_tokens"] = payload["max_tokens"]
    if "temperature" in payload:
        result["temperature"] = payload["temperature"]
    if "top_p" in payload:
        result["top_p"] = payload["top_p"]
    if isinstance(payload.get("tools"), list):
        converted_tools = [
            converted
            for tool in payload["tools"]
            for converted in [_anthropic_tool_to_responses_tool(tool)]
            if converted is not None
        ]
        if converted_tools:
            result["tools"] = converted_tools
    if "tool_choice" in payload:
        result["tool_choice"] = payload["tool_choice"]
    for key in ("request_id", "session_id", "policy", "metadata"):
        if key in payload:
            result[key] = payload[key]

    return result


def responses_response_to_messages_response(
    resp: dict,
    *,
    original_model: str,
) -> dict:
    """Convert OpenAI /v1/responses response → Anthropic /v1/messages response."""
    output_text = resp.get("output_text") or ""
    content_blocks: list[dict] = []
    for item in resp.get("output") or []:
        if not isinstance(item, dict):
            continue
        item_type = str(item.get("type", "")).strip().lower()
        if item_type == "message":
            for block in item.get("content") or []:
                if not isinstance(block, dict):
                    continue
                if block.get("type") != "output_text":
                    continue
                text = str(block.get("text") or "")
                content_blocks.append({"type": "text", "text": text})
                if not output_text and text:
                    output_text = text
            continue
        if item_type == "function_call":
            content_blocks.append(
                {
                    "type": "tool_use",
                    "id": str(item.get("call_id") or item.get("id") or f"toolu_{uuid.uuid4().hex[:24]}"),
                    "name": str(item.get("name") or "function_call"),
                    "input": _responses_arguments_to_anthropic_input(item.get("arguments")),
                }
            )

    if not content_blocks:
        content_blocks = [{"type": "text", "text": output_text}]

    usage = resp.get("usage") or {}

    result: dict = {
        "id": f"msg_{resp.get('id', str(uuid.uuid4()))}",
        "type": "message",
        "role": "assistant",
        "content": content_blocks,
        "model": original_model,
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {
            "input_tokens": usage.get("input_tokens", 0),
            "output_tokens": usage.get("output_tokens", 0),
        },
    }

    if resp.get("aegisgate"):
        result["aegisgate"] = resp["aegisgate"]

    return result
