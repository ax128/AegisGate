"""Chat Completions <-> Responses API payload compatibility layer.

Centralises the parameter differences between the two API formats: before the upstream payload is
built, it strips fields the target API does not accept, renames parameters, and converts content
types.

Reference: https://github.com/teabranch/open-responses-server
Reference: https://github.com/openai/completions-responses-migration-pack
"""

from __future__ import annotations

from typing import Any

# ─── Chat Completions-only fields (rejected by the Responses API) ──────────────
_CHAT_ONLY_KEYS: frozenset[str] = frozenset({
    # streaming control
    "stream_options",
    # token probabilities
    "logprobs",
    "top_logprobs",
    "logit_bias",
    # message model
    "messages",
    # legacy function calling
    "functions",
    "function_call",
    # response format (top-level string/object in Chat, text.format in Responses)
    "response_format",
    # Chat-specific naming
    "max_tokens",
    "max_completion_tokens",
    # other Chat-only fields
    "n",
    "seed",
    "service_tier",
    "suffix",
})

# ─── Responses API-only fields (rejected by Chat Completions) ─────────────
_RESPONSES_ONLY_KEYS: frozenset[str] = frozenset({
    # input model
    "input",
    "instructions",
    # Responses-specific naming
    "max_output_tokens",
    # context management
    "previous_response_id",
    "truncation",
    # storage and metadata
    "store",
    "include",
    # content format
    "text",
    # reasoning control
    "reasoning",
    # parallel tool calls
    "parallel_tool_calls",
})

# ─── Parameter rename map ────────────────────────────────────────────────
# (source_key, target_key) — the calling function decides the direction
_CHAT_TO_RESPONSES_RENAMES: dict[str, str] = {
    "max_tokens": "max_output_tokens",
}

_RESPONSES_TO_CHAT_RENAMES: dict[str, str] = {
    "max_output_tokens": "max_tokens",
}


def sanitize_for_responses(payload: dict[str, Any]) -> dict[str, Any]:
    """Strip Chat Completions-only fields so the payload can be safely forwarded to the Responses API.

    Only incompatible parameters are removed; no deep content conversion (such as messages -> input)
    is performed.
    """
    result = {k: v for k, v in payload.items() if k not in _CHAT_ONLY_KEYS}

    # Rename parameters: Chat-specific names in the original payload become their Responses equivalents
    for src, dst in _CHAT_TO_RESPONSES_RENAMES.items():
        if src in payload and dst not in result:
            result[dst] = payload[src]

    return result


def sanitize_for_chat(payload: dict[str, Any]) -> dict[str, Any]:
    """Strip Responses API-only fields so the payload can be safely forwarded to Chat Completions.

    Only incompatible parameters are removed; no deep content conversion (such as input -> messages)
    is performed.
    """
    result = {k: v for k, v in payload.items() if k not in _RESPONSES_ONLY_KEYS}

    # Rename parameters
    for src, dst in _RESPONSES_TO_CHAT_RENAMES.items():
        if src in payload and dst not in result:
            result[dst] = payload[src]

    # The Chat API does not support the reasoning parameter, but some upstreams (Azure, for example)
    # may accept it; drop it only when every value is None, so upstreams do not reject an empty one.
    reasoning = result.get("reasoning")
    if isinstance(reasoning, dict) and all(v is None for v in reasoning.values()):
        del result["reasoning"]

    return result


def sanitize_tools_for_chat(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert the flat Responses API tool format into the nested Chat Completions function format.

    Responses: {"type": "function", "name": "foo", "description": "...", "parameters": {...}}
    Chat:      {"type": "function", "function": {"name": "foo", "description": "...", "parameters": {...}}}
    """
    converted: list[dict[str, Any]] = []
    for tool in tools:
        if tool.get("type") != "function":
            converted.append(tool)
            continue
        # already nested, skip
        if "function" in tool:
            converted.append(tool)
            continue
        func_def: dict[str, Any] = {}
        if "name" in tool:
            func_def["name"] = tool["name"]
        if "description" in tool:
            func_def["description"] = tool["description"]
        if "parameters" in tool:
            func_def["parameters"] = tool["parameters"]
        if "strict" in tool:
            func_def["strict"] = tool["strict"]
        converted.append({"type": "function", "function": func_def})
    return converted


def sanitize_tools_for_responses(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert the nested Chat Completions function format into the flat Responses API format.

    Chat:      {"type": "function", "function": {"name": "foo", ...}}
    Responses: {"type": "function", "name": "foo", ...}
    """
    converted: list[dict[str, Any]] = []
    for tool in tools:
        if tool.get("type") != "function":
            converted.append(tool)
            continue
        func = tool.get("function")
        if not isinstance(func, dict):
            converted.append(tool)
            continue
        flat: dict[str, Any] = {"type": "function"}
        for key in ("name", "description", "parameters", "strict"):
            if key in func:
                flat[key] = func[key]
        converted.append(flat)
    return converted
