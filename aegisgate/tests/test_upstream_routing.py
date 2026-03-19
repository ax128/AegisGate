import httpx
import pytest

from aegisgate.adapters.openai_compat.upstream import (
    _build_forward_headers,
    _build_upstream_url,
    _decode_json_or_text,
    _effective_gateway_headers,
    _forward_json,
    _forward_stream_lines,
    _is_upstream_whitelisted,
    _normalize_upstream_base,
    _resolve_gateway_key,
    _resolve_upstream_base,
    _safe_error_detail,
)
from aegisgate.config.settings import settings
from starlette.requests import Request


def test_build_upstream_url_replaces_gateway_base_segment():
    base = "https://upstream.example.com/v1"
    url = _build_upstream_url("/v1/chat/completions", base)
    assert url == "https://upstream.example.com/v1/chat/completions"


def test_build_upstream_url_keeps_query_string():
    base = "https://upstream.example.com/v1"
    url = _build_upstream_url("/v1/messages?anthropic-version=2023-06-01", base)
    assert url == "https://upstream.example.com/v1/messages?anthropic-version=2023-06-01"


def test_build_forward_headers_strips_internal_headers():
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


def test_build_forward_headers_adds_default_content_type_and_strips_hop_by_hop():
    headers = {
        "Authorization": "Bearer token",
        "Connection": "keep-alive",
        "Transfer-Encoding": "chunked",
        settings.gateway_key_header: "secret",
    }

    forwarded = _build_forward_headers(headers)

    assert forwarded == {
        "Authorization": "Bearer token",
        "Content-Type": "application/json",
    }


def test_resolve_upstream_base_prefers_request_header():
    headers = {"X-Upstream-Base": "https://upstream.example.com/v1"}
    resolved = _resolve_upstream_base(headers)
    assert resolved == "https://upstream.example.com/v1"


def test_resolve_upstream_base_requires_header():
    headers = {}
    try:
        _resolve_upstream_base(headers)
    except ValueError as exc:
        assert str(exc) == "missing_upstream_base"
    else:
        raise AssertionError("expected ValueError for missing upstream header")


def test_resolve_upstream_base_falls_back_to_default(monkeypatch):
    monkeypatch.setattr(settings, "upstream_base_url", "http://cli-proxy-api:8317")
    headers = {}
    resolved = _resolve_upstream_base(headers)
    assert resolved == "http://cli-proxy-api:8317"


def test_resolve_gateway_key_accepts_underscore_header():
    headers = {"gateway_key": "abc123"}
    assert _resolve_gateway_key(headers) == "abc123"


def test_effective_gateway_headers_uses_scope_injected_upstream_and_key():
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

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    request = Request(scope, receive)
    headers = _effective_gateway_headers(request)
    assert headers["x-upstream-base"] == "https://upstream.example.com/v1"
    assert headers["authorization"] == "Bearer demo"


def test_effective_gateway_headers_includes_redaction_whitelist_from_scope():
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

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    request = Request(scope, receive)
    headers = _effective_gateway_headers(request)
    assert headers["x-aegis-redaction-whitelist"] == "bn_key,okx_key"


def test_upstream_whitelist_matching():
    original = settings.upstream_whitelist_url_list
    settings.upstream_whitelist_url_list = "https://upstream.example.com/v1, https://another-upstream.example.com/v1"
    try:
        assert _is_upstream_whitelisted("https://upstream.example.com/v1") is True
        assert _is_upstream_whitelisted("https://other.example.com/v1") is False
    finally:
        settings.upstream_whitelist_url_list = original


def test_normalize_upstream_base_rejects_invalid_scheme():
    try:
        _normalize_upstream_base("ftp://example.com/v1")
    except ValueError as exc:
        assert str(exc) == "invalid_upstream_scheme"
    else:
        raise AssertionError("expected ValueError for invalid scheme")


@pytest.mark.parametrize(
    ("raw_base", "error"),
    [
        ("https:///v1", "invalid_upstream_host"),
        ("https://example.com/v1?x=1", "invalid_upstream_query_fragment"),
        ("https://example.com/v1#frag", "invalid_upstream_query_fragment"),
    ],
)
def test_normalize_upstream_base_rejects_invalid_host_and_query_fragment(raw_base, error):
    with pytest.raises(ValueError, match=error):
        _normalize_upstream_base(raw_base)


def test_decode_json_or_text_returns_text_for_non_object_and_invalid_json():
    assert _decode_json_or_text(b'["a", "b"]') == '["a", "b"]'
    assert _decode_json_or_text(b"plain text") == "plain text"
    assert _decode_json_or_text(b"") == ""


def test_safe_error_detail_prefers_error_field_and_truncates():
    assert _safe_error_detail({"error": "x" * 700}) == "x" * 600
    assert _safe_error_detail("y" * 700) == "y" * 600


@pytest.mark.asyncio
async def test_forward_json_wraps_http_error(monkeypatch):
    class FakeClient:
        async def post(self, **kwargs):
            raise httpx.ConnectError("dns failure")

    async def fake_get_client():
        return FakeClient()

    monkeypatch.setattr("aegisgate.adapters.openai_compat.upstream._get_upstream_async_client", fake_get_client)

    with pytest.raises(RuntimeError, match="upstream_unreachable: dns failure"):
        await _forward_json(
            url="https://upstream.example.com/v1/chat/completions",
            payload={"model": "test"},
            headers={"Authorization": "Bearer token"},
        )


@pytest.mark.asyncio
async def test_forward_stream_lines_yields_lines_and_wraps_http_status(monkeypatch):
    class FakeResponse:
        def __init__(self, status_code, lines=None, body=b""):
            self.status_code = status_code
            self._lines = list(lines or [])
            self._body = body

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def aread(self):
            return self._body

        async def aiter_lines(self):
            for line in self._lines:
                yield line

    class FakeClient:
        def __init__(self, response):
            self._response = response

        def stream(self, *args, **kwargs):
            return self._response

    async def fake_ok_client():
        return FakeClient(FakeResponse(200, lines=["data: hello", "data: [DONE]"]))

    monkeypatch.setattr("aegisgate.adapters.openai_compat.upstream._get_upstream_async_client", fake_ok_client)
    chunks = [
        chunk
        async for chunk in _forward_stream_lines(
            url="https://upstream.example.com/v1/responses",
            payload={"model": "test", "stream": True},
            headers={"Authorization": "Bearer token"},
        )
    ]
    assert chunks == [b"data: hello\n", b"data: [DONE]\n"]

    async def fake_error_client():
        return FakeClient(FakeResponse(502, body=b'{"error":"bad gateway"}'))

    monkeypatch.setattr("aegisgate.adapters.openai_compat.upstream._get_upstream_async_client", fake_error_client)
    with pytest.raises(RuntimeError, match=r"upstream_http_error:502:bad gateway"):
        chunks = [
            chunk
            async for chunk in _forward_stream_lines(
                url="https://upstream.example.com/v1/responses",
                payload={"model": "test", "stream": True},
                headers={"Authorization": "Bearer token"},
            )
        ]
