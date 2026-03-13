"""Shared test fixtures for AegisGate test suite."""

from __future__ import annotations

import json

import pytest
from starlette.requests import Request

from aegisgate.core.context import RequestContext


@pytest.fixture
def make_request():
    """Factory fixture for building mock Starlette Request objects."""

    def _build(
        path: str,
        *,
        method: str = "POST",
        body: dict | None = None,
        headers: dict[str, str] | None = None,
        client_host: str = "127.0.0.1",
    ) -> Request:
        payload = json.dumps(body).encode("utf-8") if body else b""
        raw_headers: list[tuple[bytes, bytes]] = [
            (b"content-type", b"application/json"),
        ]
        for k, v in (headers or {}).items():
            raw_headers.append((k.lower().encode("latin-1"), v.encode("latin-1")))
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("latin-1"),
            "query_string": b"",
            "headers": raw_headers,
            "client": (client_host, 50000),
            "server": ("127.0.0.1", 18080),
        }
        sent = False

        async def receive():
            nonlocal sent
            if sent:
                return {"type": "http.request", "body": b"", "more_body": False}
            sent = True
            return {"type": "http.request", "body": payload, "more_body": False}

        return Request(scope, receive)

    return _build


@pytest.fixture
def make_ctx():
    """Factory fixture for RequestContext with sensible defaults."""

    def _build(**overrides) -> RequestContext:
        defaults = {
            "request_id": "test-1",
            "session_id": "test-1",
            "route": "/v1/chat/completions",
        }
        defaults.update(overrides)
        return RequestContext(**defaults)

    return _build
