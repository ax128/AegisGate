from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import Request

from aegisgate.adapters.openai_compat import router as openai_router


def test_chat_endpoint_input_payload_redirects_to_responses_intent() -> None:
    from aegisgate.adapters.openai_compat.forwarding_classifier import (
        classify_forwarding_intent,
    )

    intent = classify_forwarding_intent(
        entry_path="/v1/chat/completions",
        payload={"model": "gpt-5.4", "input": "hello"},
    )

    assert intent.entry_route == "/v1/chat/completions"
    assert intent.detected_contract == "responses"
    assert intent.target_path == "/v1/responses"
    assert intent.compat_mode == ""
    assert intent.stream is False


def test_responses_endpoint_messages_payload_redirects_to_chat_intent() -> None:
    from aegisgate.adapters.openai_compat.forwarding_classifier import (
        classify_forwarding_intent,
    )

    intent = classify_forwarding_intent(
        entry_path="/v1/responses",
        payload={
            "model": "gpt-5.4",
            "messages": [{"role": "user", "content": "hello"}],
        },
    )

    assert intent.entry_route == "/v1/responses"
    assert intent.detected_contract == "chat"
    assert intent.target_path == "/v1/chat/completions"
    assert intent.compat_mode == ""
    assert intent.stream is False


def test_messages_endpoint_openai_chat_compat_redirects_to_responses_intent() -> None:
    from aegisgate.adapters.openai_compat.forwarding_classifier import (
        classify_forwarding_intent,
    )

    intent = classify_forwarding_intent(
        entry_path="/v1/messages",
        payload={
            "model": "claude-sonnet-4.5",
            "messages": [{"role": "user", "content": "hello"}],
            "max_tokens": 128,
        },
        compat_mode="openai_chat",
    )

    assert intent.entry_route == "/v1/messages"
    assert intent.detected_contract == "messages"
    assert intent.target_path == "/v1/responses"
    assert intent.compat_mode == "openai_chat"
    assert intent.stream is False


def test_payload_with_messages_and_input_does_not_redirect_implicitly() -> None:
    from aegisgate.adapters.openai_compat.forwarding_classifier import (
        classify_forwarding_intent,
    )

    intent = classify_forwarding_intent(
        entry_path="/v1/responses",
        payload={
            "model": "gpt-5.4",
            "messages": [{"role": "user", "content": "hello"}],
            "input": "hello",
        },
    )

    assert intent.entry_route == "/v1/responses"
    assert intent.detected_contract == "responses"
    assert intent.target_path == "/v1/responses"
    assert intent.compat_mode == ""
    assert intent.stream is False


def test_native_messages_shape_stays_native_when_only_messages_present() -> None:
    from aegisgate.adapters.openai_compat.forwarding_classifier import (
        classify_forwarding_intent,
    )

    intent = classify_forwarding_intent(
        entry_path="/v1/messages",
        payload={
            "model": "claude-sonnet-4.5",
            "messages": [{"role": "user", "content": "hello"}],
            "max_tokens": 128,
            "stream": True,
        },
    )

    assert intent.entry_route == "/v1/messages"
    assert intent.detected_contract == "messages"
    assert intent.target_path == "/v1/messages"
    assert intent.compat_mode == ""
    assert intent.stream is True


@pytest.mark.parametrize(
    ("raw_setting", "route_key", "expected"),
    [
        ("", "responses.once", False),
        ("responses.once", "responses.once", True),
        ("responses.once, chat.stream", "chat.stream", True),
        ("responses.once, chat.stream", "messages.compat", False),
        ("responses.once,unknown-token", "unknown-token", False),
    ],
)
def test_internal_rollout_gate_is_private_and_fail_closed(
    raw_setting: str, route_key: str, expected: bool
) -> None:
    from aegisgate.adapters.openai_compat.forwarding_gate import (
        is_forwarding_kernel_rollout_enabled,
    )

    assert is_forwarding_kernel_rollout_enabled(raw_setting, route_key) is expected


def _build_request(path: str, scope_updates: dict | None = None) -> Request:
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 12345),
    }
    if scope_updates:
        scope.update(scope_updates)
    return Request(scope)


def _preview_request(*, payload: dict, route: str) -> SimpleNamespace:
    return SimpleNamespace(
        request_id=str(payload.get("request_id") or "preview-request"),
        session_id=str(payload.get("session_id") or payload.get("request_id") or "preview-session"),
        route=route,
        model=str(payload.get("model") or "gpt-5.4"),
    )


@pytest.mark.asyncio
async def test_chat_endpoint_uses_forwarding_classifier_for_redirect_decision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aegisgate.adapters.openai_compat.forwarding_classifier import (
        ForwardingRouteIntent,
    )

    payload = {
        "model": "gpt-5.4",
        "input": "route this responses payload",
        "request_id": "chat-redirect-on",
    }
    log_messages: list[str] = []

    def fake_classifier(*, entry_path: str, payload: dict, compat_mode: str | None = None):
        assert entry_path == "/v1/chat/completions"
        assert compat_mode in {None, ""}
        return ForwardingRouteIntent(
            entry_route=entry_path,
            detected_contract="responses",
            target_path="/v1/responses",
            compat_mode="",
            stream=False,
        )

    async def fake_redirect(payload_arg: dict, request_arg: Request):
        assert payload_arg is payload
        assert request_arg.url.path == "/v1/chat/completions"
        return {"redirected": "responses"}

    monkeypatch.setattr(
        openai_router.settings, "internal_forwarding_kernel_rollout", "chat.once"
    )
    monkeypatch.setattr(
        openai_router.logger,
        "info",
        lambda msg, *args: log_messages.append(msg % args if args else msg),
    )
    monkeypatch.setattr(openai_router, "classify_forwarding_intent", fake_classifier)
    monkeypatch.setattr(
        openai_router, "_handle_responses_payload_on_chat_endpoint", fake_redirect
    )

    result = await openai_router.chat_completions(payload, _build_request("/v1/chat/completions"))

    assert result == {"redirected": "responses"}
    assert any("path_version=forwarding_kernel" in message for message in log_messages)
    assert any("fallback_reason=none" in message for message in log_messages)


@pytest.mark.asyncio
async def test_responses_endpoint_uses_forwarding_classifier_for_redirect_decision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aegisgate.adapters.openai_compat.forwarding_classifier import (
        ForwardingRouteIntent,
    )

    payload = {
        "model": "gpt-5.4",
        "messages": [{"role": "user", "content": "hello"}],
        "request_id": "responses-redirect-on",
    }
    log_messages: list[str] = []

    def fake_classifier(*, entry_path: str, payload: dict, compat_mode: str | None = None):
        assert entry_path == "/v1/responses"
        assert compat_mode in {None, ""}
        return ForwardingRouteIntent(
            entry_route=entry_path,
            detected_contract="chat",
            target_path="/v1/chat/completions",
            compat_mode="",
            stream=False,
        )

    async def fake_chat(payload_arg: dict, request_arg: Request):
        assert payload_arg is payload
        assert request_arg.url.path == "/v1/responses"
        return {
            "id": "chat-1",
            "object": "chat.completion",
            "model": "gpt-5.4",
            "choices": [{"message": {"role": "assistant", "content": "收到。"}}],
        }

    async def fake_run_payload_transform(func, *args, **kwargs):
        return func(*args, **kwargs)

    monkeypatch.setattr(
        openai_router.settings,
        "internal_forwarding_kernel_rollout",
        "responses.once",
    )
    monkeypatch.setattr(
        openai_router.logger,
        "info",
        lambda msg, *args: log_messages.append(msg % args if args else msg),
    )
    monkeypatch.setattr(openai_router, "classify_forwarding_intent", fake_classifier)
    monkeypatch.setattr(openai_router, "chat_completions", fake_chat)
    monkeypatch.setattr(openai_router, "_run_payload_transform", fake_run_payload_transform)

    result = await openai_router.responses(payload, _build_request("/v1/responses"))

    assert isinstance(result, dict)
    assert result["object"] == "response"
    assert result["output_text"] == "收到。"
    assert any("path_version=forwarding_kernel" in message for message in log_messages)
    assert any("fallback_reason=none" in message for message in log_messages)


@pytest.mark.asyncio
async def test_chat_endpoint_mixed_payload_fail_closes_to_native_path_when_rollout_is_live(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aegisgate.adapters.openai_compat.forwarding_classifier import (
        ForwardingRouteIntent,
    )

    payload = {
        "model": "gpt-5.4",
        "messages": [{"role": "user", "content": "hello"}],
        "input": "shadow this mixed payload",
        "request_id": "chat-mixed-fail-closed",
        "session_id": "chat-mixed-fail-closed",
    }
    log_messages: list[str] = []

    async def fake_run_store_io(*args, **kwargs):
        return None

    async def fake_execute_chat_once(**kwargs):
        return {"native": "chat"}

    async def fake_redirect(*args, **kwargs):
        raise AssertionError("mixed /v1/chat/completions payload must fail closed to native path")

    monkeypatch.setattr(
        openai_router.settings, "internal_forwarding_kernel_rollout", "chat.once"
    )
    monkeypatch.setattr(
        openai_router.logger,
        "info",
        lambda msg, *args: log_messages.append(msg % args if args else msg),
    )
    monkeypatch.setattr(
        openai_router,
        "classify_forwarding_intent",
        lambda **kwargs: ForwardingRouteIntent(
            entry_route="/v1/chat/completions",
            detected_contract="responses",
            target_path="/v1/responses",
            compat_mode="",
            stream=False,
        ),
    )
    monkeypatch.setattr(openai_router, "run_store_io", fake_run_store_io)
    monkeypatch.setattr(openai_router, "_execute_chat_once", fake_execute_chat_once)
    monkeypatch.setattr(
        openai_router, "_handle_responses_payload_on_chat_endpoint", fake_redirect
    )

    result = await openai_router.chat_completions(payload, _build_request("/v1/chat/completions"))

    assert result == {"native": "chat"}
    assert any(
        "fallback_reason=mixed_payload_fail_closed" in message for message in log_messages
    )


@pytest.mark.asyncio
async def test_responses_endpoint_mixed_payload_fail_closes_to_native_path_when_rollout_is_live(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aegisgate.adapters.openai_compat.forwarding_classifier import (
        ForwardingRouteIntent,
    )

    payload = {
        "model": "gpt-5.4",
        "messages": [{"role": "user", "content": "hello"}],
        "input": "shadow this mixed payload",
        "request_id": "responses-mixed-fail-closed",
        "session_id": "responses-mixed-fail-closed",
    }
    log_messages: list[str] = []

    async def fake_run_store_io(*args, **kwargs):
        return None

    async def fake_execute_responses_once(**kwargs):
        return {"native": "responses"}

    async def fake_chat(*args, **kwargs):
        raise AssertionError("mixed /v1/responses payload must fail closed to native path")

    monkeypatch.setattr(
        openai_router.settings,
        "internal_forwarding_kernel_rollout",
        "responses.once",
    )
    monkeypatch.setattr(
        openai_router.logger,
        "info",
        lambda msg, *args: log_messages.append(msg % args if args else msg),
    )
    monkeypatch.setattr(
        openai_router,
        "classify_forwarding_intent",
        lambda **kwargs: ForwardingRouteIntent(
            entry_route="/v1/responses",
            detected_contract="chat",
            target_path="/v1/chat/completions",
            compat_mode="",
            stream=False,
        ),
    )
    monkeypatch.setattr(openai_router, "run_store_io", fake_run_store_io)
    monkeypatch.setattr(
        openai_router, "_execute_responses_once", fake_execute_responses_once
    )
    monkeypatch.setattr(openai_router, "chat_completions", fake_chat)

    result = await openai_router.responses(payload, _build_request("/v1/responses"))

    assert result == {"native": "responses"}
    assert any(
        "fallback_reason=mixed_payload_fail_closed" in message for message in log_messages
    )


@pytest.mark.asyncio
async def test_chat_endpoint_keeps_legacy_safe_path_when_private_rollout_gate_is_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aegisgate.adapters.openai_compat.forwarding_classifier import (
        ForwardingRouteIntent,
    )

    payload = {
        "model": "gpt-5.4",
        "messages": [{"role": "user", "content": "hello"}],
        "request_id": "chat-gate-off",
        "session_id": "chat-gate-off",
    }

    async def fake_run_payload_transform(func, payload_arg, *args, **kwargs):
        assert payload_arg is payload
        return _preview_request(payload=payload_arg, route="/v1/chat/completions")

    async def fake_run_store_io(*args, **kwargs):
        return None

    async def fake_execute_chat_once(**kwargs):
        return {"native": "chat"}

    async def fake_redirect(*args, **kwargs):
        return {"redirected": "responses"}

    monkeypatch.setattr(openai_router.settings, "internal_forwarding_kernel_rollout", "")
    monkeypatch.setattr(
        openai_router,
        "classify_forwarding_intent",
        lambda **kwargs: ForwardingRouteIntent(
            entry_route="/v1/chat/completions",
            detected_contract="responses",
            target_path="/v1/responses",
            compat_mode="",
            stream=False,
        ),
    )
    monkeypatch.setattr(openai_router, "_run_payload_transform", fake_run_payload_transform)
    monkeypatch.setattr(openai_router, "run_store_io", fake_run_store_io)
    monkeypatch.setattr(openai_router, "_execute_chat_once", fake_execute_chat_once)
    monkeypatch.setattr(
        openai_router, "_handle_responses_payload_on_chat_endpoint", fake_redirect
    )

    result = await openai_router.chat_completions(payload, _build_request("/v1/chat/completions"))

    assert result == {"native": "chat"}


@pytest.mark.asyncio
async def test_responses_endpoint_keeps_legacy_safe_path_when_private_rollout_gate_is_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aegisgate.adapters.openai_compat.forwarding_classifier import (
        ForwardingRouteIntent,
    )

    payload = {
        "model": "gpt-5.4",
        "input": "hello",
        "request_id": "responses-gate-off",
        "session_id": "responses-gate-off",
    }

    async def fake_run_payload_transform(func, payload_arg, *args, **kwargs):
        assert payload_arg is payload
        return _preview_request(payload=payload_arg, route="/v1/responses")

    async def fake_run_store_io(*args, **kwargs):
        return None

    async def fake_execute_responses_once(**kwargs):
        return {"native": "responses"}

    async def fake_chat(*args, **kwargs):
        return {"redirected": "chat"}

    monkeypatch.setattr(openai_router.settings, "internal_forwarding_kernel_rollout", "")
    monkeypatch.setattr(
        openai_router,
        "classify_forwarding_intent",
        lambda **kwargs: ForwardingRouteIntent(
            entry_route="/v1/responses",
            detected_contract="chat",
            target_path="/v1/chat/completions",
            compat_mode="",
            stream=False,
        ),
    )
    monkeypatch.setattr(openai_router, "_run_payload_transform", fake_run_payload_transform)
    monkeypatch.setattr(openai_router, "run_store_io", fake_run_store_io)
    monkeypatch.setattr(
        openai_router, "_execute_responses_once", fake_execute_responses_once
    )
    monkeypatch.setattr(openai_router, "chat_completions", fake_chat)

    result = await openai_router.responses(payload, _build_request("/v1/responses"))

    assert result == {"native": "responses"}


@pytest.mark.asyncio
async def test_messages_endpoint_uses_forwarding_classifier_for_compat_decision_when_rollout_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aegisgate.adapters.openai_compat.forwarding_classifier import (
        ForwardingRouteIntent,
    )

    payload = {
        "model": "claude-sonnet-4.5",
        "messages": [{"role": "user", "content": "hello"}],
        "max_tokens": 128,
        "request_id": "messages-gate-on",
        "session_id": "messages-gate-on",
    }

    async def fake_run_payload_transform(func, payload_arg, *args, **kwargs):
        assert payload_arg is payload
        return _preview_request(payload=payload_arg, route="/v1/messages")

    async def fake_compat(**kwargs):
        return {"redirected": "messages-compat"}

    monkeypatch.setattr(
        openai_router.settings,
        "internal_forwarding_kernel_rollout",
        "messages.compat",
    )
    monkeypatch.setattr(openai_router, "_effective_gateway_headers", lambda request: {})
    monkeypatch.setattr(openai_router, "_run_payload_transform", fake_run_payload_transform)
    monkeypatch.setattr(
        openai_router,
        "classify_forwarding_intent",
        lambda **kwargs: ForwardingRouteIntent(
            entry_route="/v1/messages",
            detected_contract="messages",
            target_path="/v1/responses",
            compat_mode="openai_chat",
            stream=False,
        ),
    )
    monkeypatch.setattr(openai_router, "_messages_compat_openai_chat", fake_compat)

    result = await openai_router.messages(
        payload,
        _build_request(
            "/v1/messages",
            scope_updates={"aegis_compat": "openai_chat"},
        ),
    )

    assert result == {"redirected": "messages-compat"}


@pytest.mark.asyncio
async def test_messages_endpoint_keeps_legacy_safe_path_when_private_rollout_gate_is_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aegisgate.adapters.openai_compat.forwarding_classifier import (
        ForwardingRouteIntent,
    )

    payload = {
        "model": "claude-sonnet-4.5",
        "messages": [{"role": "user", "content": "hello"}],
        "input": "shadow this mixed payload",
        "max_tokens": 128,
        "request_id": "messages-gate-off",
        "session_id": "messages-gate-off",
    }

    async def fake_run_payload_transform(func, payload_arg, *args, **kwargs):
        assert payload_arg is payload
        return _preview_request(payload=payload_arg, route="/v1/messages")

    async def fake_execute_messages_once(**kwargs):
        return {"native": "messages"}

    async def fake_compat(**kwargs):
        return {"redirected": "messages-compat"}

    monkeypatch.setattr(openai_router.settings, "internal_forwarding_kernel_rollout", "")
    monkeypatch.setattr(openai_router, "_effective_gateway_headers", lambda request: {})
    monkeypatch.setattr(openai_router, "_run_payload_transform", fake_run_payload_transform)
    monkeypatch.setattr(
        openai_router,
        "classify_forwarding_intent",
        lambda **kwargs: ForwardingRouteIntent(
            entry_route="/v1/messages",
            detected_contract="messages",
            target_path="/v1/responses",
            compat_mode="openai_chat",
            stream=False,
        ),
    )
    monkeypatch.setattr(
        openai_router, "_execute_messages_once", fake_execute_messages_once
    )
    monkeypatch.setattr(openai_router, "_messages_compat_openai_chat", fake_compat)

    result = await openai_router.messages(
        payload,
        _build_request(
            "/v1/messages",
            scope_updates={"aegis_compat": "openai_chat"},
        ),
    )

    assert result == {"native": "messages"}


@pytest.mark.asyncio
async def test_messages_endpoint_mixed_payload_fail_closes_to_native_path_when_compat_rollout_is_live(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aegisgate.adapters.openai_compat.forwarding_classifier import (
        ForwardingRouteIntent,
    )

    payload = {
        "model": "claude-sonnet-4.5",
        "messages": [{"role": "user", "content": "hello"}],
        "input": "shadow this mixed payload",
        "max_tokens": 128,
        "request_id": "messages-mixed-fail-closed",
        "session_id": "messages-mixed-fail-closed",
    }
    log_messages: list[str] = []

    async def fake_run_payload_transform(func, payload_arg, *args, **kwargs):
        assert payload_arg is payload
        return _preview_request(payload=payload_arg, route="/v1/messages")

    async def fake_execute_messages_once(**kwargs):
        return {"native": "messages"}

    async def fake_compat(**kwargs):
        raise AssertionError("mixed /v1/messages payload must fail closed to native path")

    monkeypatch.setattr(
        openai_router.settings,
        "internal_forwarding_kernel_rollout",
        "messages.compat",
    )
    monkeypatch.setattr(
        openai_router.logger,
        "info",
        lambda msg, *args: log_messages.append(msg % args if args else msg),
    )
    monkeypatch.setattr(openai_router, "_effective_gateway_headers", lambda request: {})
    monkeypatch.setattr(openai_router, "_run_payload_transform", fake_run_payload_transform)
    monkeypatch.setattr(
        openai_router,
        "classify_forwarding_intent",
        lambda **kwargs: ForwardingRouteIntent(
            entry_route="/v1/messages",
            detected_contract="messages",
            target_path="/v1/responses",
            compat_mode="openai_chat",
            stream=False,
        ),
    )
    monkeypatch.setattr(
        openai_router, "_execute_messages_once", fake_execute_messages_once
    )
    monkeypatch.setattr(openai_router, "_messages_compat_openai_chat", fake_compat)

    result = await openai_router.messages(
        payload,
        _build_request(
            "/v1/messages",
            scope_updates={"aegis_compat": "openai_chat"},
        ),
    )

    assert result == {"native": "messages"}
    assert any(
        "fallback_reason=mixed_payload_fail_closed" in message for message in log_messages
    )


def test_settings_exposes_private_forwarding_rollout_field(monkeypatch: pytest.MonkeyPatch) -> None:
    from aegisgate.config.settings import Settings

    monkeypatch.delenv("AEGIS_INTERNAL_FORWARDING_KERNEL_ROLLOUT", raising=False)
    assert Settings().internal_forwarding_kernel_rollout == ""

    monkeypatch.setenv("AEGIS_INTERNAL_FORWARDING_KERNEL_ROLLOUT", "responses.once")
    assert Settings().internal_forwarding_kernel_rollout == "responses.once"
