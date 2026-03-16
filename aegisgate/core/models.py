"""Internal transport models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class InternalMessage(BaseModel):
    role: str
    content: str
    source: str = "user"
    metadata: dict = Field(default_factory=dict)


class InternalRequest(BaseModel):
    request_id: str
    session_id: str
    route: str
    model: str
    messages: list[InternalMessage] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


class InternalResponse(BaseModel):
    request_id: str
    session_id: str
    model: str
    output_text: str
    raw: dict = Field(default_factory=dict)
    metadata: dict = Field(default_factory=dict)

    @property
    def tool_call_content(self) -> str:
        """Extract text from structured tool call arguments for security scanning.

        Supports OpenAI (tool_calls[].function.arguments), Anthropic Claude
        (content[].input when type=tool_use), and generic fallback.
        """
        parts: list[str] = []

        # OpenAI format: choices[].message.tool_calls[].function.arguments
        for choice in self.raw.get("choices") or []:
            if not isinstance(choice, dict):
                continue
            msg = choice.get("message") or choice.get("delta") or {}
            if not isinstance(msg, dict):
                continue
            for tc in msg.get("tool_calls") or []:
                if not isinstance(tc, dict):
                    continue
                func = tc.get("function") or {}
                if not isinstance(func, dict):
                    continue
                name = func.get("name", "")
                args = func.get("arguments", "")
                if name:
                    parts.append(str(name))
                if args:
                    parts.append(str(args))

        # Anthropic Claude format: content[].input when type=tool_use
        for block in self.raw.get("content") or []:
            if not isinstance(block, dict) or block.get("type") != "tool_use":
                continue
            name = block.get("name", "")
            inp = block.get("input", {})
            if name:
                parts.append(str(name))
            if inp:
                parts.append(str(inp))

        return " ".join(parts)
