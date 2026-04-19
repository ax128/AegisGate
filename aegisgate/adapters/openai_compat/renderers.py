"""Route-native non-stream response renderers and patch helpers."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any, Callable

from aegisgate.adapters.openai_compat.mapper import (
    to_chat_response,
    to_messages_response,
    to_responses_output,
)
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalResponse


@dataclass(frozen=True)
class NonStreamRenderOps:
    sanitize_text: Callable[[str, RequestContext], str]
    build_sanitized_full_response: Callable[..., str]
    looks_executable_payload_dangerous: Callable[[str], bool]
    placeholderize_value: Callable[[Any], Any]
    critical_danger_placeholder: str


def render_chat_response(
    upstream_body: dict[str, Any] | str, final_resp: InternalResponse
) -> dict[str, Any]:
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


def render_responses_output(
    upstream_body: dict[str, Any] | str, final_resp: InternalResponse
) -> dict[str, Any]:
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


def sanitize_nested_text_value(
    value: Any,
    ctx: RequestContext,
    *,
    ops: NonStreamRenderOps,
) -> Any:
    if isinstance(value, str):
        return ops.sanitize_text(value, ctx)
    if isinstance(value, list):
        return [sanitize_nested_text_value(item, ctx, ops=ops) for item in value]
    if isinstance(value, dict):
        patched = copy.deepcopy(value)
        for key, item in list(patched.items()):
            if isinstance(item, (str, list, dict)):
                patched[key] = sanitize_nested_text_value(item, ctx, ops=ops)
        return patched
    return value


def patch_chat_tool_call(
    tool_call: dict[str, Any],
    ctx: RequestContext,
    *,
    ops: NonStreamRenderOps,
) -> dict[str, Any]:
    patched = copy.deepcopy(tool_call)
    function = patched.get("function")
    name = ""
    arguments = ""
    if isinstance(function, dict):
        name = str(function.get("name", ""))
        arguments = str(function.get("arguments", ""))
    combined = f"{name} {arguments}".strip()
    if ops.looks_executable_payload_dangerous(combined):
        patched["function"] = {
            "name": ops.critical_danger_placeholder,
            "arguments": json.dumps(
                {"_blocked": ops.critical_danger_placeholder}, ensure_ascii=False
            ),
        }
        return patched
    if isinstance(function, dict):
        if isinstance(function.get("name"), str):
            function["name"] = ops.sanitize_text(str(function["name"]), ctx)
        if isinstance(function.get("arguments"), str):
            function["arguments"] = ops.sanitize_text(str(function["arguments"]), ctx)
        patched["function"] = function
    return patched


def patch_chat_message(
    message: dict[str, Any],
    ctx: RequestContext,
    *,
    ops: NonStreamRenderOps,
) -> dict[str, Any]:
    patched = copy.deepcopy(message)
    content = patched.get("content")
    if isinstance(content, (str, list, dict)):
        patched["content"] = sanitize_nested_text_value(content, ctx, ops=ops)
    tool_calls = patched.get("tool_calls")
    if isinstance(tool_calls, list):
        patched["tool_calls"] = [
            patch_chat_tool_call(item, ctx, ops=ops) if isinstance(item, dict) else item
            for item in tool_calls
        ]
    return patched


def patch_responses_output_item(
    item: dict[str, Any],
    ctx: RequestContext,
    *,
    ops: NonStreamRenderOps,
) -> dict[str, Any]:
    patched = copy.deepcopy(item)
    item_type = str(patched.get("type", "")).strip().lower()

    if item_type == "message":
        content = patched.get("content")
        if isinstance(content, list):
            updated: list[Any] = []
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    part = copy.deepcopy(part)
                    part["text"] = ops.sanitize_text(str(part["text"]), ctx)
                elif isinstance(part, (str, list, dict)):
                    part = sanitize_nested_text_value(part, ctx, ops=ops)
                updated.append(part)
            patched["content"] = updated
        return patched

    if item_type == "function_call":
        combined = f"{patched.get('name', '')} {patched.get('arguments', '')}".strip()
        if ops.looks_executable_payload_dangerous(combined):
            patched["name"] = ops.critical_danger_placeholder
            patched["arguments"] = json.dumps(
                {"_blocked": ops.critical_danger_placeholder}, ensure_ascii=False
            )
            return patched
        if isinstance(patched.get("name"), str):
            patched["name"] = ops.sanitize_text(str(patched["name"]), ctx)
        if isinstance(patched.get("arguments"), str):
            patched["arguments"] = ops.sanitize_text(str(patched["arguments"]), ctx)
        return patched

    if item_type in {"bash", "computer_call"}:
        action = patched.get("action")
        action_text = (
            json.dumps(action, ensure_ascii=False)
            if isinstance(action, (dict, list))
            else str(action or "")
        )
        if ops.looks_executable_payload_dangerous(action_text):
            patched["action"] = ops.placeholderize_value(action)
            return patched
        if isinstance(action, (str, list, dict)):
            patched["action"] = sanitize_nested_text_value(action, ctx, ops=ops)
        return patched

    if item_type:
        return patched

    for key in ("text", "summary", "output_text"):
        if isinstance(patched.get(key), str):
            patched[key] = ops.sanitize_text(str(patched[key]), ctx)
    return patched


def patch_chat_response_body(
    upstream_body: dict[str, Any],
    ctx: RequestContext,
    *,
    ops: NonStreamRenderOps,
) -> dict[str, Any]:
    out = copy.deepcopy(upstream_body)
    choices = out.get("choices")
    if isinstance(choices, list):
        updated_choices: list[Any] = []
        for choice in choices:
            if not isinstance(choice, dict):
                updated_choices.append(choice)
                continue
            updated = copy.deepcopy(choice)
            message = updated.get("message")
            if isinstance(message, dict):
                updated["message"] = patch_chat_message(message, ctx, ops=ops)
            updated_choices.append(updated)
        out["choices"] = updated_choices
    return out


def patch_responses_body(
    upstream_body: dict[str, Any],
    ctx: RequestContext,
    *,
    ops: NonStreamRenderOps,
) -> dict[str, Any]:
    out = copy.deepcopy(upstream_body)
    if isinstance(out.get("output_text"), str):
        out["output_text"] = ops.sanitize_text(str(out["output_text"]), ctx)
    output = out.get("output")
    if isinstance(output, list):
        out["output"] = [
            patch_responses_output_item(item, ctx, ops=ops)
            if isinstance(item, dict)
            else item
            for item in output
        ]
    return out


def patch_messages_content_block(
    block: dict[str, Any],
    ctx: RequestContext,
    *,
    ops: NonStreamRenderOps,
) -> dict[str, Any]:
    patched = copy.deepcopy(block)
    if isinstance(patched.get("text"), str):
        patched["text"] = ops.sanitize_text(str(patched["text"]), ctx)
    return patched


def patch_messages_response_body(
    upstream_body: dict[str, Any],
    ctx: RequestContext,
    *,
    ops: NonStreamRenderOps,
) -> dict[str, Any]:
    out = copy.deepcopy(upstream_body)
    content = out.get("content")
    if isinstance(content, list):
        out["content"] = [
            patch_messages_content_block(block, ctx, ops=ops)
            if isinstance(block, dict)
            else ops.sanitize_text(block, ctx)
            if isinstance(block, str)
            else block
            for block in content
        ]
    elif isinstance(content, str):
        out["content"] = ops.sanitize_text(content, ctx)
    return out


def render_non_confirmation_chat_response(
    upstream_body: dict[str, Any] | str,
    final_resp: InternalResponse,
    ctx: RequestContext,
    *,
    ops: NonStreamRenderOps,
) -> dict[str, Any]:
    if isinstance(upstream_body, dict):
        out = patch_chat_response_body(upstream_body, ctx, ops=ops)
        out.setdefault("id", final_resp.request_id)
        out.setdefault("object", "chat.completion")
        out.setdefault("model", final_resp.model)
        if final_resp.metadata.get("aegisgate"):
            out["aegisgate"] = final_resp.metadata["aegisgate"]
        return out

    final_resp.output_text = ops.build_sanitized_full_response(
        ctx, source_text=final_resp.output_text
    )
    return to_chat_response(final_resp)


def render_non_confirmation_responses_output(
    upstream_body: dict[str, Any] | str,
    final_resp: InternalResponse,
    ctx: RequestContext,
    *,
    ops: NonStreamRenderOps,
) -> dict[str, Any]:
    if isinstance(upstream_body, dict):
        out = patch_responses_body(upstream_body, ctx, ops=ops)
        out.setdefault("id", final_resp.request_id)
        out.setdefault("object", "response")
        out.setdefault("model", final_resp.model)
        if final_resp.metadata.get("aegisgate"):
            out["aegisgate"] = final_resp.metadata["aegisgate"]
        return out

    final_resp.output_text = ops.build_sanitized_full_response(
        ctx, source_text=final_resp.output_text
    )
    return to_responses_output(final_resp)


def render_non_confirmation_messages_output(
    upstream_body: dict[str, Any] | str,
    final_resp: InternalResponse,
    ctx: RequestContext,
    *,
    ops: NonStreamRenderOps,
) -> dict[str, Any]:
    if isinstance(upstream_body, dict):
        out = patch_messages_response_body(upstream_body, ctx, ops=ops)
        out.setdefault("id", final_resp.request_id)
        out.setdefault("type", "message")
        out.setdefault("role", "assistant")
        out.setdefault("model", final_resp.model)
        out.setdefault("stop_reason", "end_turn")
        out.setdefault("stop_sequence", None)
        out.setdefault("usage", {"input_tokens": 0, "output_tokens": 0})
        if final_resp.metadata.get("aegisgate"):
            out["aegisgate"] = final_resp.metadata["aegisgate"]
        return out

    final_resp.output_text = ops.build_sanitized_full_response(
        ctx, source_text=final_resp.output_text
    )
    return to_messages_response(final_resp)
