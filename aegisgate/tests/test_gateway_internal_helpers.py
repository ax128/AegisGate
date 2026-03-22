from __future__ import annotations

from fastapi import Request

from aegisgate.core.gateway_auth import _gateway_token_base_url
from aegisgate.core.gateway_keys import (
    _is_forbidden_upstream_base_example,
    _normalize_input_upstream_base,
)


def _build_request(*, host: str = "gateway.test", scheme: str = "https") -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"host", host.encode("latin-1"))],
            "query_string": b"",
            "scheme": scheme,
            "server": ("testserver", 443 if scheme == "https" else 80),
            "client": ("127.0.0.1", 12345),
        }
    )


def test_normalize_input_upstream_base_trims_and_drops_trailing_slash() -> None:
    assert _normalize_input_upstream_base("  https://upstream.example.com/v1/  ") == "https://upstream.example.com/v1"
    assert _normalize_input_upstream_base(None) == ""


def test_forbidden_upstream_example_matches_normalized_input() -> None:
    assert _is_forbidden_upstream_base_example(" https://your-upstream.example.com/v1/ ") is True
    assert _is_forbidden_upstream_base_example("https://real-upstream.example.com/v1") is False


def test_gateway_token_base_url_reuses_public_base_url() -> None:
    request = _build_request(host="api.example.com")

    assert _gateway_token_base_url(request, "token123") == "https://api.example.com/v1/__gw__/t/token123"
