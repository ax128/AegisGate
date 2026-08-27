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
from aegisgate.config.redact_values import replace_exact_values
from aegisgate.config.settings import settings
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalResponse

ROUTE_CHAT = "/v1/chat/completions"
ROUTE_RESPONSES = "/v1/responses"
ROUTE_MESSAGES = "/v1/messages"


@dataclass(frozen=True)
class NonStreamRenderOps:
    sanitize_text: Callable[[str, RequestContext], str]
    build_sanitized_full_response: Callable[..., str]
    looks_executable_payload_dangerous: Callable[[str], bool]
    placeholderize_value: Callable[[Any], Any]
    critical_danger_placeholder: str


def render_chat_response(
    upstream_body: dict[str, Any] | str,
    final_resp: InternalResponse,
    ctx: RequestContext,
) -> dict[str, Any]:
    if isinstance(upstream_body, dict):
        choices = upstream_body.get("choices")
        if isinstance(choices, list) and choices:
            out = apply_pipeline_text_to_body(
                ROUTE_CHAT, upstream_body, final_resp, ctx
            )
            if isinstance(out, dict):
                out.setdefault("id", final_resp.request_id)
                out.setdefault("object", "chat.completion")
                out.setdefault("model", final_resp.model)
                if final_resp.metadata.get("aegisgate"):
                    out["aegisgate"] = final_resp.metadata["aegisgate"]
                return out
    return to_chat_response(final_resp)


def render_responses_output(
    upstream_body: dict[str, Any] | str,
    final_resp: InternalResponse,
    ctx: RequestContext,
) -> dict[str, Any]:
    if isinstance(upstream_body, dict):
        out = apply_pipeline_text_to_body(
            ROUTE_RESPONSES, upstream_body, final_resp, ctx
        )
        if isinstance(out, dict):
            out.setdefault("id", final_resp.request_id)
            out.setdefault("object", "response")
            out.setdefault("model", final_resp.model)
            if final_resp.metadata.get("aegisgate"):
                out["aegisgate"] = final_resp.metadata["aegisgate"]
            return out
    return to_responses_output(final_resp)


# ---------------------------------------------------------------------------
# allow disposition: write the pipeline's own text back into the protocol body
# ---------------------------------------------------------------------------


def approved_placeholder_mapping(ctx: RequestContext) -> dict[str, str]:
    """The placeholder→plaintext pairs a renderer is allowed to substitute.

    Restoration is not "whatever is still in ``ctx.redaction_mapping``". A token
    may only be restored in a nested field when RestorationFilter restored that
    same token in this round's ``output_text`` — that is the only text the
    volume / partial / exfiltration guards and PostRestoreGuard ever scanned.

    Two cases collapse the set to empty even though the mapping survives:

    * ``restoration_applied`` missing — this round had no placeholder in
      ``output_text``, or a guard refused, so nothing is approved.
    * ``confirmed_release`` present — the skip-confirmation path already
      replaced the body text with an obfuscated summary. Restoring the nested
      tool calls there would hand back the plaintext the summary hides.
    """
    if "restoration_applied" not in ctx.security_tags:
        return {}
    if "confirmed_release" in ctx.security_tags:
        return {}
    mapping = ctx.redaction_mapping
    return {
        token: mapping[token] for token in ctx.restored_placeholders if token in mapping
    }


@dataclass(frozen=True)
class _LeafOps:
    """What one string leaf goes through, in response-pipeline order."""

    exact_values: bool
    placeholders: dict[str, str]

    def apply(self, value: str) -> str:
        if not value:
            return value
        out = value
        if self.exact_values:
            replaced, count = replace_exact_values(out)
            if count > 0:
                out = replaced
        for token, raw in self.placeholders.items():
            if token in out:
                out = out.replace(token, raw)
        return out

    def apply_nested(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.apply(value)
        if isinstance(value, list):
            return [self.apply_nested(item) for item in value]
        if isinstance(value, dict):
            return {key: self.apply_nested(item) for key, item in value.items()}
        return value


def _leaf_ops(ctx: RequestContext) -> _LeafOps:
    return _LeafOps(
        exact_values=bool(settings.enable_exact_value_redaction),
        placeholders=approved_placeholder_mapping(ctx),
    )


def _apply_chat_body(
    out: dict[str, Any], final_resp: InternalResponse, ops: _LeafOps
) -> dict[str, Any]:
    choices = out.get("choices")
    if not isinstance(choices, list) or not choices:
        return out
    first = choices[0]
    if not isinstance(first, dict):
        first = {}
    message = first.get("message")
    if not isinstance(message, dict):
        message = {"role": "assistant"}
    # Unchanged behaviour: the body text is the pipeline's output_text, length
    # cap included. Only the tool calls are new, and they are transformed leaf
    # by leaf — writing output_text into them would duplicate the answer.
    message["content"] = final_resp.output_text
    tool_calls = message.get("tool_calls")
    if isinstance(tool_calls, list):
        message["tool_calls"] = [
            _apply_chat_tool_call(item, ops) if isinstance(item, dict) else item
            for item in tool_calls
        ]
    first["message"] = message
    choices[0] = first
    out["choices"] = choices
    return out


def _apply_chat_tool_call(tool_call: dict[str, Any], ops: _LeafOps) -> dict[str, Any]:
    patched = dict(tool_call)
    function = patched.get("function")
    if isinstance(function, dict):
        function = dict(function)
        for key in ("name", "arguments"):
            if isinstance(function.get(key), str):
                function[key] = ops.apply(str(function[key]))
        patched["function"] = function
    return patched


def _apply_responses_body(
    out: dict[str, Any], final_resp: InternalResponse, ops: _LeafOps
) -> dict[str, Any]:
    out["output_text"] = final_resp.output_text
    output = out.get("output")
    if isinstance(output, list):
        out["output"] = [
            _apply_responses_output_item(item, ops) if isinstance(item, dict) else item
            for item in output
        ]
    return out


def _apply_responses_output_item(item: dict[str, Any], ops: _LeafOps) -> dict[str, Any]:
    patched = dict(item)
    item_type = str(patched.get("type", "")).strip().lower()
    if item_type == "message":
        content = patched.get("content")
        if isinstance(content, list):
            updated: list[Any] = []
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    part = dict(part)
                    part["text"] = ops.apply(str(part["text"]))
                updated.append(part)
            patched["content"] = updated
        return patched
    if item_type == "function_call":
        for key in ("name", "arguments"):
            if isinstance(patched.get(key), str):
                patched[key] = ops.apply(str(patched[key]))
    return patched


def _apply_messages_body(out: dict[str, Any], ops: _LeafOps) -> dict[str, Any]:
    content = out.get("content")
    if isinstance(content, list):
        out["content"] = [_apply_messages_block(block, ops) for block in content]
    elif isinstance(content, str):
        out["content"] = ops.apply(content)
    return out


def _apply_messages_block(block: Any, ops: _LeafOps) -> Any:
    if isinstance(block, str):
        return ops.apply(block)
    if not isinstance(block, dict):
        return block
    patched = dict(block)
    if patched.get("type") == "tool_use":
        if "input" in patched:
            patched["input"] = ops.apply_nested(patched["input"])
        return patched
    if isinstance(patched.get("text"), str):
        patched["text"] = ops.apply(str(patched["text"]))
    return patched


def apply_pipeline_text_to_body(
    route: str,
    upstream_body: dict[str, Any] | str,
    final_resp: InternalResponse,
    ctx: RequestContext,
) -> dict[str, Any] | str:
    """Write what the response pipeline produced into the protocol-native body.

    The allow disposition used to hand the client either the raw upstream body
    (messages / generic) or a body whose convenience field alone had been
    patched (responses), so exact-value redaction and placeholder restoration
    were invisible wherever an SDK actually reads. This is the shared write-back.

    It is deliberately *not* "assign ``output_text`` to every text leaf": on a
    multi-part body that duplicates the whole answer into each part. Each string
    leaf goes through the same two steps the pipeline ran, in the same order —
    exact values first (``ExactValueRedactionFilter``), then the approved
    placeholders (``RestorationFilter``).

    With no exact values configured and nothing approved for restoration, every
    leaf comes back unchanged, so a benign response is byte-identical to what
    the gateway returned before.
    """
    ops = _leaf_ops(ctx)
    if not isinstance(upstream_body, dict):
        return ops.apply(str(upstream_body))

    out = copy.deepcopy(upstream_body)
    normalized_route = str(route or "").strip().lower()
    if normalized_route == ROUTE_CHAT:
        return _apply_chat_body(out, final_resp, ops)
    if normalized_route == ROUTE_RESPONSES:
        return _apply_responses_body(out, final_resp, ops)
    if normalized_route == ROUTE_MESSAGES:
        return _apply_messages_body(out, ops)
    # Generic provider bodies have no known schema, so there is no defined place
    # to write output_text — only the leaves are transformed, shape intact.
    return ops.apply_nested(out)


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


def _sanitize_tool_call_arguments(
    arguments: str, ctx: RequestContext, *, ops: NonStreamRenderOps
) -> str:
    """Sanitize a tool-call ``arguments`` JSON string without breaking JSON validity.

    Fragment obfuscation runs on the serialized string and can split JSON
    structure or escape sequences. When the original was valid JSON but the
    obfuscated form is not, fall back to sanitizing the decoded string values and
    re-serializing (``json.dumps`` re-escapes safely) so the client can still
    parse the tool call.
    """
    sanitized = ops.sanitize_text(arguments, ctx)
    if sanitized == arguments:
        return arguments
    try:
        decoded = json.loads(arguments)
    except (ValueError, TypeError):
        return sanitized  # not JSON to begin with — nothing to protect
    try:
        json.loads(sanitized)
    except (ValueError, TypeError):
        cleaned = sanitize_nested_text_value(decoded, ctx, ops=ops)
        return json.dumps(cleaned, ensure_ascii=False)
    return sanitized


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
            function["arguments"] = _sanitize_tool_call_arguments(
                str(function["arguments"]), ctx, ops=ops
            )
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
            patched["arguments"] = _sanitize_tool_call_arguments(
                str(patched["arguments"]), ctx, ops=ops
            )
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
    if patched.get("type") == "tool_use":
        name = str(patched.get("name") or "")
        inp = patched.get("input")
        combined = f"{name} {inp}".strip()
        if ops.looks_executable_payload_dangerous(combined):
            patched["name"] = ops.critical_danger_placeholder
            patched["input"] = {"_blocked": ops.critical_danger_placeholder}
            return patched
        if isinstance(patched.get("name"), str):
            patched["name"] = ops.sanitize_text(str(patched["name"]), ctx)
        patched["input"] = sanitize_nested_text_value(inp, ctx, ops=ops)
        return patched
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
