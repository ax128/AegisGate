"""Request-side redaction must run on the filter-pipeline pool, not the event loop.

A blocking redactor on the loop thread stalls every other request in the
process. Mapping transforms stay inline on purpose (see test_offload_contract):
this file only covers the redaction builders.
"""

from __future__ import annotations

import asyncio
import json
import threading
from typing import Any, Callable

import pytest
from starlette.requests import Request

from aegisgate.adapters.openai_compat import router as openai_router
from aegisgate.config import redact_values
from aegisgate.config.settings import settings
from aegisgate.core.models import InternalMessage

_POOL_PREFIX = "aegisgate-filter-pipeline"
_EXACT_VALUE = "exact-value-token-0000"


def _chat_payload(text: str = "hello") -> dict[str, Any]:
    return {
        "model": "gpt-5.4",
        "messages": [{"role": "user", "content": text}],
    }


def _messages() -> list[InternalMessage]:
    return [InternalMessage(role="user", content="hello")]


def _record_thread(real: Callable[..., Any], seen: list[str]) -> Callable[..., Any]:
    def _wrapped(*args: Any, **kwargs: Any) -> Any:
        seen.append(threading.current_thread().name)
        return real(*args, **kwargs)

    return _wrapped


def _assert_pool_thread(names: list[str]) -> None:
    assert names, "redaction callable was not invoked"
    assert all(name.startswith(_POOL_PREFIX) for name in names), names
    assert all(name != threading.current_thread().name for name in names), names


async def _run_builder(func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    return await openai_router._run_payload_transform(func, *args, **kwargs)


def test_blocking_request_redaction_does_not_stall_the_event_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A redactor that blocks must leave the loop free to run other callbacks."""
    real = openai_router._sanitize_chat_messages_for_upstream_with_hits
    seen: dict[str, Any] = {}

    def _blocking(messages: Any, **kwargs: Any) -> Any:
        loop = seen["loop"]
        assert isinstance(loop, asyncio.AbstractEventLoop)
        seen["name"] = threading.current_thread().name
        seen["ident"] = threading.get_ident()
        loop.call_soon_threadsafe(seen["progress"].set)
        # On the loop thread this wait cannot be satisfied: the callback is
        # queued behind the very call that is blocked. On a pool thread the
        # loop runs the callback while this wait is parked.
        seen["progress_during_block"] = seen["progress"].wait(1.0)
        return real(messages, **kwargs)

    monkeypatch.setattr(
        openai_router,
        "_sanitize_chat_messages_for_upstream_with_hits",
        _blocking,
    )

    async def _drive() -> dict[str, Any]:
        seen["loop"] = asyncio.get_running_loop()
        seen["progress"] = threading.Event()
        seen["loop_ident"] = threading.get_ident()
        built = await _run_builder(
            openai_router._build_chat_upstream_payload,
            _chat_payload(),
            _messages(),
            route="/v1/chat/completions",
        )
        assert isinstance(built, dict)
        return built

    asyncio.run(_drive())

    assert seen["progress_during_block"] is True, (
        f"request redaction blocked the event loop on thread {seen.get('name')!r}"
    )
    assert str(seen["name"]).startswith(_POOL_PREFIX)
    assert seen["ident"] != seen["loop_ident"]


def test_request_redaction_builders_run_on_the_filter_pipeline_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every forward-path redaction builder is submitted to the shared pool."""
    cases: list[tuple[str, Callable[..., Any], tuple[Any, ...], dict[str, Any]]] = [
        (
            "_sanitize_chat_messages_for_upstream_with_hits",
            openai_router._build_chat_upstream_payload,
            (_chat_payload(), _messages()),
            {"route": "/v1/chat/completions"},
        ),
        (
            "_sanitize_responses_input_for_upstream_with_hits",
            openai_router._build_responses_upstream_payload,
            (
                {
                    "model": "gpt-5.4",
                    "input": [{"role": "user", "content": "hello"}],
                },
                _messages(),
            ),
            {"route": "/v1/responses"},
        ),
        (
            "_sanitize_chat_messages_for_upstream_with_hits",
            openai_router._build_messages_upstream_payload,
            (
                {
                    "model": "claude-sonnet-4.5",
                    "max_tokens": 8,
                    "messages": [{"role": "user", "content": "hello"}],
                },
                _messages(),
            ),
            {"route": "/v1/messages"},
        ),
        (
            "_sanitize_generic_payload_for_upstream_with_hits",
            openai_router._build_generic_upstream_payload,
            ({"input": "hello"},),
            {"route": "/v1/embeddings"},
        ),
    ]

    async def _drive() -> None:
        for target, builder, args, kwargs in cases:
            seen: list[str] = []
            real = getattr(openai_router, target)
            monkeypatch.setattr(openai_router, target, _record_thread(real, seen))
            await _run_builder(builder, *args, **kwargs)
            _assert_pool_thread(seen)

    asyncio.run(_drive())


def test_request_redaction_offload_propagates_builder_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A shape error raised on the pool thread must still reach the caller."""

    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise ValueError("chat_input_shape_violation")

    monkeypatch.setattr(
        openai_router,
        "_sanitize_chat_messages_for_upstream_with_hits",
        _boom,
    )

    async def _drive() -> None:
        with pytest.raises(ValueError, match="chat_input_shape_violation"):
            await _run_builder(
                openai_router._build_chat_upstream_payload,
                _chat_payload(),
                _messages(),
                route="/v1/chat/completions",
            )

    asyncio.run(_drive())


def test_request_mapping_stays_on_the_caller_thread() -> None:
    """Lightweight mapping is not redaction and must not hop threads."""

    async def _drive() -> int:
        return await openai_router._run_payload_transform(threading.get_ident)

    assert asyncio.run(_drive()) == threading.get_ident()


def test_exact_value_override_reaches_offloaded_request_redaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A forward rule's exact-value pin is a ContextVar on the request task.

    The worker must see that pin. Losing it would redact a value the rule
    turned off, or keep one the rule turned on.
    """
    monkeypatch.setattr(redact_values, "load_redact_values", lambda: [_EXACT_VALUE])
    monkeypatch.setattr(settings, "enable_exact_value_redaction", False)

    text = f"note {_EXACT_VALUE} end"

    async def _build(*, override: bool) -> str:
        token = redact_values._exact_value_override.set(override)
        try:
            # Structured content is what the builder forwards after redaction.
            # A plain string is replaced by the pipeline message, which this
            # test does not run, so it would hide whether the worker saw the pin.
            built = await _run_builder(
                openai_router._build_chat_upstream_payload,
                {
                    "model": "gpt-5.4",
                    "messages": [
                        {"role": "user", "content": [{"type": "text", "text": text}]}
                    ],
                },
                [InternalMessage(role="user", content=text)],
                route="/v1/chat/completions",
            )
        finally:
            redact_values._exact_value_override.reset(token)
        return json.dumps(built, ensure_ascii=False)

    kept = asyncio.run(_build(override=False))
    redacted = asyncio.run(_build(override=True))
    assert _EXACT_VALUE in kept
    assert _EXACT_VALUE not in redacted


def _multipart_request(text: str) -> Request:
    body = (
        b"--abc\r\n"
        b'Content-Disposition: form-data; name="prompt"\r\n'
        b"\r\n" + text.encode("utf-8") + b"\r\n"
        b"--abc--\r\n"
    )
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/v1/images/edits",
        "raw_path": b"/v1/images/edits",
        "query_string": b"",
        "headers": [(b"content-type", b"multipart/form-data; boundary=abc")],
        "client": ("127.0.0.1", 1234),
        "server": ("127.0.0.1", 80),
    }
    sent = False

    async def _receive() -> dict[str, Any]:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, _receive)


def test_multipart_field_redaction_runs_on_the_filter_pipeline_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Multipart form fields are request redaction too, and they bypass the builder."""
    seen: list[str] = []
    real = openai_router._sanitize_text_for_upstream_with_hits
    monkeypatch.setattr(
        openai_router,
        "_sanitize_text_for_upstream_with_hits",
        _record_thread(real, seen),
    )

    async def _resolve(_headers: Any) -> tuple[str, tuple[str, ...], str]:
        return ("http://upstream.test", (), "")

    async def _forward(**_kwargs: Any) -> tuple[int, dict[str, str]]:
        return (200, {"ok": "yes"})

    async def _pipeline(_pipeline: Any, req: Any, _ctx: Any) -> Any:
        return req

    monkeypatch.setattr(openai_router, "_resolve_upstream_base", _resolve)
    monkeypatch.setattr(openai_router, "_forward_multipart_with_pinning", _forward)
    monkeypatch.setattr(openai_router, "_run_request_pipeline", _pipeline)
    monkeypatch.setattr(openai_router, "_write_audit_event", lambda *_a, **_k: None)

    async def _drive() -> None:
        response = await openai_router._execute_multipart_once(
            request=_multipart_request("hello"),
            request_headers={},
            request_path="/v1/images/edits",
            boundary={},
        )
        assert response.status_code == 200

    asyncio.run(_drive())
    _assert_pool_thread(seen)
