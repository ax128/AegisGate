"""Chat Completions <-> Responses API payload 兼容层。

集中管理两种 API 格式之间的参数差异，在构建上游 payload 前
剥离目标 API 不支持的字段、重命名参数、转换内容类型。

参考: https://github.com/teabranch/open-responses-server
参考: https://github.com/openai/completions-responses-migration-pack
"""

from __future__ import annotations

from typing import Any

# ─── Chat Completions 专有字段（Responses API 不接受） ──────────────
_CHAT_ONLY_KEYS: frozenset[str] = frozenset({
    # 流式控制
    "stream_options",
    # token 概率
    "logprobs",
    "top_logprobs",
    "logit_bias",
    # 消息体系
    "messages",
    # 旧版 function calling
    "functions",
    "function_call",
    # 响应格式（Chat 为顶层 string/object，Responses 为 text.format）
    "response_format",
    # Chat 专有命名
    "max_tokens",
    "max_completion_tokens",
    # 其他 Chat 专有
    "n",
    "seed",
    "service_tier",
    "suffix",
})

# ─── Responses API 专有字段（Chat Completions 不接受） ─────────────
_RESPONSES_ONLY_KEYS: frozenset[str] = frozenset({
    # 输入体系
    "input",
    "instructions",
    # Responses 专有命名
    "max_output_tokens",
    # 上下文管理
    "previous_response_id",
    "truncation",
    # 存储与元数据
    "store",
    "include",
    # 内容格式
    "text",
    # 推理控制
    "reasoning",
    # 并行工具调用
    "parallel_tool_calls",
})

# ─── 参数重命名映射 ──────────────────────────────────────────────
# (source_key, target_key) — 转换方向由调用函数决定
_CHAT_TO_RESPONSES_RENAMES: dict[str, str] = {
    "max_tokens": "max_output_tokens",
}

_RESPONSES_TO_CHAT_RENAMES: dict[str, str] = {
    "max_output_tokens": "max_tokens",
}


def sanitize_for_responses(payload: dict[str, Any]) -> dict[str, Any]:
    """剥离 Chat Completions 专有字段，使 payload 可安全转发至 Responses API。

    仅移除不兼容的参数，不做深度内容转换（如 messages -> input）。
    """
    result = {k: v for k, v in payload.items() if k not in _CHAT_ONLY_KEYS}

    # 参数重命名：若原 payload 含 Chat 专有命名，转为 Responses 对应名称
    for src, dst in _CHAT_TO_RESPONSES_RENAMES.items():
        if src in payload and dst not in result:
            result[dst] = payload[src]

    return result


def sanitize_for_chat(payload: dict[str, Any]) -> dict[str, Any]:
    """剥离 Responses API 专有字段，使 payload 可安全转发至 Chat Completions。

    仅移除不兼容的参数，不做深度内容转换（如 input -> messages）。
    """
    result = {k: v for k, v in payload.items() if k not in _RESPONSES_ONLY_KEYS}

    # 参数重命名
    for src, dst in _RESPONSES_TO_CHAT_RENAMES.items():
        if src in payload and dst not in result:
            result[dst] = payload[src]

    # reasoning 参数 Chat API 不支持，但部分上游（如 Azure）可能接受；
    # 仅当所有值均为 None 时移除，避免上游拒绝空 reasoning
    reasoning = result.get("reasoning")
    if isinstance(reasoning, dict) and all(v is None for v in reasoning.values()):
        del result["reasoning"]

    return result


def sanitize_tools_for_chat(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """将 Responses API 扁平 tool 格式转换为 Chat Completions 嵌套 function 格式。

    Responses: {"type": "function", "name": "foo", "description": "...", "parameters": {...}}
    Chat:      {"type": "function", "function": {"name": "foo", "description": "...", "parameters": {...}}}
    """
    converted: list[dict[str, Any]] = []
    for tool in tools:
        if tool.get("type") != "function":
            converted.append(tool)
            continue
        # 已经是嵌套格式，跳过
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
    """将 Chat Completions 嵌套 function 格式转换为 Responses API 扁平格式。

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
