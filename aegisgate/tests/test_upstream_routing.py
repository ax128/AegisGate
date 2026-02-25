from aegisgate.adapters.openai_compat.upstream import (
    _build_forward_headers,
    _build_upstream_url,
    _is_upstream_whitelisted,
    _normalize_upstream_base,
    _resolve_gateway_key,
    _resolve_upstream_base,
    _validate_gateway_headers,
)
from aegisgate.config.settings import settings


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


def test_resolve_gateway_key_accepts_underscore_header():
    headers = {"gateway_key": "abc123"}
    assert _resolve_gateway_key(headers) == "abc123"


def test_validate_gateway_headers_missing_parameters():
    ok, reason, detail = _validate_gateway_headers({})
    assert ok is False
    assert reason == "invalid_parameters"
    assert "missing" in detail.lower()


def test_validate_gateway_headers_auth_checks():
    original = settings.gateway_key
    settings.gateway_key = "gw-secret"
    try:
        ok, reason, _ = _validate_gateway_headers(
            {
                "X-Upstream-Base": "https://upstream.example.com/v1",
                "gateway-key": "gw-secret",
            }
        )
        assert ok is True
        assert reason == ""

        ok2, reason2, _ = _validate_gateway_headers(
            {
                "X-Upstream-Base": "https://upstream.example.com/v1",
                "gateway-key": "wrong",
            }
        )
        assert ok2 is False
        assert reason2 == "gateway_auth_failed"
    finally:
        settings.gateway_key = original


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
