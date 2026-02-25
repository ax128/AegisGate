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
