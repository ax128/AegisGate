from __future__ import annotations

import asyncio

from fastapi import Request

import aegisgate.adapters.openai_compat.router as openai_router
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


def test_store_call_uses_dedicated_store_executor(monkeypatch) -> None:
    calls: dict[str, object] = {}

    class DummyStore:
        def ping(self, *, confirm_id: str) -> str:
            calls["confirm_id"] = confirm_id
            return f"pong:{confirm_id}"

    async def fake_run_store_io(func, *args, **kwargs):
        calls["func_name"] = getattr(func, "__name__", "")
        calls["kwargs"] = dict(kwargs)
        return func(*args, **kwargs)

    monkeypatch.setattr(openai_router, "run_store_io", fake_run_store_io)
    monkeypatch.setattr(openai_router, "store", DummyStore())

    result = asyncio.run(openai_router._store_call("ping", confirm_id="cfm-test"))

    assert result == "pong:cfm-test"
    assert calls["func_name"] == "ping"
    assert calls["kwargs"] == {"confirm_id": "cfm-test"}
    assert calls["confirm_id"] == "cfm-test"


def test_run_payload_transform_uses_dedicated_executor(monkeypatch) -> None:
    calls: dict[str, object] = {}

    async def fake_run_payload_transform_offloop(func, *args, **kwargs):
        calls["func_name"] = getattr(func, "__name__", "")
        calls["args"] = list(args)
        calls["kwargs"] = dict(kwargs)
        return func(*args, **kwargs)

    monkeypatch.setattr(openai_router, "run_payload_transform_offloop", fake_run_payload_transform_offloop)

    result = asyncio.run(openai_router._run_payload_transform(str.upper, "chat"))

    assert result == "CHAT"
    assert calls["func_name"] == "upper"
    assert calls["args"] == ["chat"]
    assert calls["kwargs"] == {}


def test_validate_payload_limits_uses_precomputed_body_size(monkeypatch) -> None:
    monkeypatch.setattr(openai_router, "_serialized_payload_size", lambda payload: (_ for _ in ()).throw(AssertionError("should not serialize")))

    ok, status_code, reason, detail = openai_router._validate_payload_limits(
        {"messages": [{"role": "user", "content": "hello"}]},
        route="/v1/chat/completions",
        body_size_bytes=32,
    )

    assert ok is True
    assert status_code == 200
    assert reason == ""
    assert detail == ""
