from __future__ import annotations

from fastapi import Request

from aegisgate.adapters.openai_compat.upstream import _build_forward_headers as build_openai_forward_headers
from aegisgate.adapters.v2_proxy.router import _build_forward_headers as build_v2_forward_headers


def _build_request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v2",
            "headers": [
                (b"host", b"gateway.test"),
                (b"content-length", b"12"),
                (b"x-target-url", b"https://upstream.example.com/v2"),
                (b"x-upstream-base", b"https://upstream.example.com/v1"),
                (b"x_upstream_base", b"https://upstream.example.com/v1"),
                (b"gateway-key", b"secret"),
                (b"gateway_key", b"secret"),
                (b"x-aegis-filter-mode", b"passthrough"),
                (b"x_aegis_filter_mode", b"passthrough"),
                (b"x-aegis-redaction-whitelist", b"tenant"),
                (b"x_aegis_redaction_whitelist", b"tenant"),
                (b"x-extra", b"keep-me"),
            ],
            "query_string": b"",
            "scheme": "https",
            "server": ("gateway.test", 443),
            "client": ("127.0.0.1", 12345),
        }
    )


def test_openai_forward_headers_strip_internal_header_aliases() -> None:
    headers = build_openai_forward_headers(
        {
            "Host": "gateway.test",
            "Content-Length": "12",
            "x-upstream-base": "https://upstream.example.com/v1",
            "x_upstream_base": "https://upstream.example.com/v1",
            "gateway-key": "secret",
            "gateway_key": "secret",
            "x-aegis-filter-mode": "passthrough",
            "x_aegis_filter_mode": "passthrough",
            "x-aegis-redaction-whitelist": "tenant",
            "x_aegis_redaction_whitelist": "tenant",
            "X-Extra": "keep-me",
        }
    )

    assert headers == {"X-Extra": "keep-me", "Content-Type": "application/json"}


def test_v2_forward_headers_strip_internal_header_aliases() -> None:
    headers = build_v2_forward_headers(_build_request())

    assert headers == {"x-extra": "keep-me"}
