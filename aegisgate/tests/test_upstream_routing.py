from __future__ import annotations

from fastapi import Request

from aegisgate.adapters.openai_compat.upstream import (
    _build_forward_headers,
    _build_upstream_url,
    _effective_gateway_headers,
    _is_upstream_whitelisted,
    _normalize_upstream_base,
    _resolve_gateway_key,
    _resolve_upstream_base,
)
from aegisgate.config.settings import settings


def test_build_upstream_url_replaces_gateway_base_segment() -> None:
    base = "https://upstream.example.com/v1"

    assert _build_upstream_url("/v1/chat/completions", base) == "https://upstream.example.com/v1/chat/completions"


def test_build_upstream_url_keeps_query_string() -> None:
    base = "https://upstream.example.com/v1"

    assert (
        _build_upstream_url("/v1/messages?anthropic-version=2023-06-01", base)
        == "https://upstream.example.com/v1/messages?anthropic-version=2023-06-01"
    )


def test_build_forward_headers_strips_internal_headers() -> None:
    headers = {
        "Host": "127.0.0.1:18080",
        "Content-Length": "123",
        "X-Upstream-Base": "https://upstream.example.com/v1",
        "x-aegis-signature": "abc",
        "Authorization": "Bearer token",
        "Content-Type": "application/json",
    }

    forwarded = _build_forward_headers(headers)

    assert "Host" not in forwarded
    assert "Content-Length" not in forwarded
    assert "X-Upstream-Base" not in forwarded
    assert "x-aegis-signature" not in forwarded
    assert forwarded["Authorization"] == "Bearer token"


def test_resolve_upstream_base_prefers_request_header() -> None:
    headers = {"X-Upstream-Base": "https://upstream.example.com/v1"}

    assert _resolve_upstream_base(headers) == "https://upstream.example.com/v1"


def test_resolve_upstream_base_requires_header() -> None:
    try:
        _resolve_upstream_base({})
    except ValueError as exc:
        assert str(exc) == "missing_upstream_base"
    else:
        raise AssertionError("expected ValueError for missing upstream header")


def test_resolve_upstream_base_falls_back_to_default(monkeypatch) -> None:
    monkeypatch.setattr(settings, "upstream_base_url", "http://cli-proxy-api:8317")

    assert _resolve_upstream_base({}) == "http://cli-proxy-api:8317"


def test_resolve_gateway_key_accepts_underscore_header() -> None:
    assert _resolve_gateway_key({"gateway_key": "abc123"}) == "abc123"


def test_effective_gateway_headers_uses_scope_injected_upstream_and_key() -> None:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/v1/responses",
        "raw_path": b"/v1/responses",
        "query_string": b"",
        "headers": [(b"authorization", b"Bearer demo"), (b"x-upstream-base", b"https://evil.example.com/v1")],
        "aegis_upstream_base": "https://upstream.example.com/v1",
    }

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    request = Request(scope, receive)
    headers = _effective_gateway_headers(request)

    assert headers["x-upstream-base"] == "https://upstream.example.com/v1"
    assert headers["authorization"] == "Bearer demo"


def test_effective_gateway_headers_includes_redaction_whitelist_from_scope() -> None:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/v1/responses",
        "raw_path": b"/v1/responses",
        "query_string": b"",
        "headers": [(b"authorization", b"Bearer demo")],
        "aegis_redaction_whitelist_keys": ["bn_key", "okx_key"],
    }

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    request = Request(scope, receive)
    headers = _effective_gateway_headers(request)

    assert headers["x-aegis-redaction-whitelist"] == "bn_key,okx_key"


def test_upstream_whitelist_matching() -> None:
    original = settings.upstream_whitelist_url_list
    settings.upstream_whitelist_url_list = "https://upstream.example.com/v1, https://another-upstream.example.com/v1"
    try:
        assert _is_upstream_whitelisted("https://upstream.example.com/v1") is True
        assert _is_upstream_whitelisted("https://other.example.com/v1") is False
    finally:
        settings.upstream_whitelist_url_list = original


def test_normalize_upstream_base_rejects_invalid_scheme() -> None:
    try:
        _normalize_upstream_base("ftp://example.com/v1")
    except ValueError as exc:
        assert str(exc) == "invalid_upstream_scheme"
    else:
        raise AssertionError("expected ValueError for invalid scheme")
