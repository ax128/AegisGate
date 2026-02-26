import pytest
from starlette.requests import Request

from aegisgate.adapters.openai_compat import router as openai_router
from aegisgate.config.settings import settings
from aegisgate.core.confirmation import payload_hash


def _build_request(
    headers: dict[str, str] | None = None,
    path: str = "/v1/chat/completions",
) -> Request:
    raw_headers = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in (headers or {}).items()]
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("latin-1"),
        "query_string": b"",
        "headers": raw_headers,
        "client": ("127.0.0.1", 54321),
        "server": ("testserver", 80),
    }

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    request = Request(scope, receive)
    request.state.security_boundary = {}
    return request


def test_resolve_pending_confirmation_requires_confirm_id(monkeypatch):
    def _should_not_call(*args, **kwargs):
        raise AssertionError("get_pending_confirmation should not be called without confirm_id")

    monkeypatch.setattr(openai_router.store, "get_pending_confirmation", _should_not_call)
    result = openai_router._resolve_pending_confirmation(
        {"session_id": "s1"},
        "普通消息",
        1,
        expected_route="/v1/chat/completions",
        tenant_id="default",
    )
    assert result is None


def test_resolve_pending_confirmation_yes_without_id_uses_single_pending(monkeypatch):
    record = {
        "confirm_id": "cfm-abc123def456",
        "status": "pending",
        "expires_at": 9999999999,
        "route": "/v1/chat/completions",
        "pending_request_payload": {"model": "gpt-test", "messages": [{"role": "user", "content": "hello"}]},
        "pending_request_hash": "hash",
    }
    monkeypatch.setattr(
        openai_router.store,
        "get_single_pending_confirmation",
        lambda *, session_id, route, now_ts, tenant_id, recover_executing_before: record
        if session_id == "s1" and route == "/v1/chat/completions" and tenant_id == "default"
        else None,
    )
    result = openai_router._resolve_pending_confirmation(
        {"session_id": "s1"},
        "yes",
        1,
        expected_route="/v1/chat/completions",
        tenant_id="default",
    )
    assert result == record


@pytest.mark.asyncio
async def test_chat_yes_without_confirm_id_is_not_forced_into_pending(monkeypatch):
    async def fake_execute_chat_once(**kwargs):
        return {"ok": True}

    monkeypatch.setattr(openai_router, "_execute_chat_once", fake_execute_chat_once)
    request = _build_request(
        headers={
            "X-Upstream-Base": "https://upstream.example.com/v1",
            "gateway-key": settings.gateway_key,
        }
    )
    result = await openai_router.chat_completions(
        {
            "request_id": "chat-confirm-1",
            "session_id": "s-confirm-1",
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "yes"}],
        },
        request,
    )
    assert result == {"ok": True}


@pytest.mark.asyncio
async def test_chat_pending_payload_omitted_returns_visible_confirmation_message(monkeypatch):
    confirm_id = "cfm-f43e7cbb7ca0"

    def fake_resolve_pending_confirmation(_payload, _user_text, _now_ts, *, expected_route, tenant_id):
        return {
            "confirm_id": confirm_id,
            "route": expected_route,
            "reason": "高风险响应",
            "summary": "触发信号：request_shape_sanitized",
            "status": "pending",
            "expires_at": 9999999999,
            "pending_request_hash": "ignored",
            "pending_request_payload": {
                "_aegisgate_pending_payload_omitted": True,
                "payload_size_bytes": 181801,
            },
        }

    async def fake_store_call(method_name, *args, **kwargs):
        assert method_name == "update_pending_confirmation_status"
        return None

    async def fake_transition(**kwargs):
        return True

    monkeypatch.setattr(openai_router, "_resolve_pending_confirmation", fake_resolve_pending_confirmation)
    monkeypatch.setattr(openai_router, "_store_call", fake_store_call)
    monkeypatch.setattr(openai_router, "_try_transition_pending_status", fake_transition)

    request = _build_request(
        headers={
            "X-Upstream-Base": "https://upstream.example.com/v1",
            "gateway-key": settings.gateway_key,
        }
    )
    result = await openai_router.chat_completions(
        {
            "request_id": "chat-confirm-2",
            "session_id": "s-confirm-2",
            "model": "gpt-test",
            "messages": [{"role": "user", "content": f"yes {confirm_id}"}],
        },
        request,
    )

    assert isinstance(result, dict)
    content = result["choices"][0]["message"]["content"]
    assert "无法直接放行执行" in content
    assert confirm_id in content
    assert result["aegisgate"]["confirmation"]["status"] == "payload_omitted"
    assert result["aegisgate"]["confirmation"]["payload_omitted"] is True


@pytest.mark.asyncio
async def test_chat_confirmation_route_mismatch_returns_visible_message(monkeypatch):
    confirm_id = "cfm-route000000"

    def fake_resolve_pending_confirmation(_payload, _user_text, _now_ts, *, expected_route, tenant_id):
        return {
            "confirm_id": confirm_id,
            "route": "/v1/responses",
            "reason": "高风险响应",
            "summary": "route mismatch",
            "status": "pending",
            "expires_at": 9999999999,
            "pending_request_hash": "hash",
            "pending_request_payload": {},
        }

    monkeypatch.setattr(openai_router, "_resolve_pending_confirmation", fake_resolve_pending_confirmation)

    request = _build_request(
        headers={
            "X-Upstream-Base": "https://upstream.example.com/v1",
            "gateway-key": settings.gateway_key,
        }
    )
    result = await openai_router.chat_completions(
        {
            "request_id": "chat-confirm-3",
            "session_id": "s-confirm-3",
            "model": "gpt-test",
            "messages": [{"role": "user", "content": f"yes {confirm_id}"}],
        },
        request,
    )

    assert isinstance(result, dict)
    content = result["choices"][0]["message"]["content"]
    assert "当前接口不匹配" in content
    assert result["aegisgate"]["confirmation"]["status"] == "route_mismatch"


@pytest.mark.asyncio
async def test_chat_confirmation_already_processed_returns_visible_message(monkeypatch):
    confirm_id = "cfm-processed0"

    def fake_resolve_pending_confirmation(_payload, _user_text, _now_ts, *, expected_route, tenant_id):
        return {
            "confirm_id": confirm_id,
            "route": expected_route,
            "reason": "高风险响应",
            "summary": "already processed",
            "status": "pending",
            "expires_at": 9999999999,
            "pending_request_hash": "hash",
            "pending_request_payload": {"model": "gpt-test", "messages": [{"role": "user", "content": "x"}]},
        }

    async def fake_transition(**kwargs):
        return False

    monkeypatch.setattr(openai_router, "_resolve_pending_confirmation", fake_resolve_pending_confirmation)
    monkeypatch.setattr(openai_router, "_try_transition_pending_status", fake_transition)

    request = _build_request(
        headers={
            "X-Upstream-Base": "https://upstream.example.com/v1",
            "gateway-key": settings.gateway_key,
        }
    )
    result = await openai_router.chat_completions(
        {
            "request_id": "chat-confirm-4",
            "session_id": "s-confirm-4",
            "model": "gpt-test",
            "messages": [{"role": "user", "content": f"yes {confirm_id}"}],
        },
        request,
    )

    assert isinstance(result, dict)
    content = result["choices"][0]["message"]["content"]
    assert "已被处理" in content
    assert result["aegisgate"]["confirmation"]["status"] == "already_processed"


def test_resolve_pending_confirmation_rejects_cross_tenant_confirm_id(monkeypatch):
    monkeypatch.setattr(
        openai_router.store,
        "get_pending_confirmation",
        lambda confirm_id: {
            "confirm_id": confirm_id,
            "tenant_id": "tenant-b",
            "status": "pending",
            "expires_at": 9999999999,
            "updated_at": 1,
        },
    )
    result = openai_router._resolve_pending_confirmation(
        {"session_id": "s1"},
        "yes cfm-abc123def456",
        10,
        expected_route="/v1/chat/completions",
        tenant_id="tenant-a",
    )
    assert result is None


def test_resolve_pending_confirmation_recovers_stale_executing(monkeypatch):
    state = {"status": "executing"}

    def fake_get_pending_confirmation(_confirm_id):
        return {
            "confirm_id": "cfm-abc123def456",
            "tenant_id": "default",
            "status": state["status"],
            "expires_at": 9999999999,
            "updated_at": 1,
            "pending_request_payload": {"model": "gpt-test", "messages": [{"role": "user", "content": "hello"}]},
            "pending_request_hash": "hash",
        }

    def fake_compare_and_update_pending_confirmation_status(*, confirm_id, expected_status, new_status, now_ts):
        if state["status"] != expected_status:
            return False
        state["status"] = new_status
        return True

    monkeypatch.setattr(openai_router.store, "get_pending_confirmation", fake_get_pending_confirmation)
    monkeypatch.setattr(
        openai_router.store,
        "compare_and_update_pending_confirmation_status",
        fake_compare_and_update_pending_confirmation_status,
    )
    result = openai_router._resolve_pending_confirmation(
        {"session_id": "s1"},
        "yes cfm-abc123def456",
        1000,
        expected_route="/v1/chat/completions",
        tenant_id="default",
    )
    assert result is not None
    assert result["status"] == "pending"


@pytest.mark.asyncio
async def test_chat_wrong_confirm_id_returns_correction_hint(monkeypatch):
    provided_id = "cfm-aaaaaaaaaaaa"
    expected_id = "cfm-bbbbbbbbbbbb"

    monkeypatch.setattr(openai_router, "_resolve_pending_confirmation", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        openai_router,
        "_load_single_pending_for_session",
        lambda *_args, **_kwargs: {
            "confirm_id": expected_id,
            "status": "pending",
            "expires_at": 9999999999,
            "route": "/v1/chat/completions",
        },
    )

    request = _build_request(
        headers={
            "X-Upstream-Base": "https://upstream.example.com/v1",
            "gateway-key": settings.gateway_key,
        }
    )
    result = await openai_router.chat_completions(
        {
            "request_id": "chat-confirm-5",
            "session_id": "s-confirm-5",
            "model": "gpt-test",
            "messages": [{"role": "user", "content": f"yes {provided_id}"}],
        },
        request,
    )

    assert isinstance(result, dict)
    content = result["choices"][0]["message"]["content"]
    assert expected_id in content
    assert result["aegisgate"]["confirmation"]["status"] == "id_mismatch"


@pytest.mark.asyncio
async def test_chat_confirmation_tail_yes_overrides_template_ambiguity(monkeypatch):
    confirm_id = "cfm-1234abcdefff"

    def fake_resolve_pending_confirmation(_payload, _user_text, _now_ts, *, expected_route, tenant_id):
        pending_payload = {"model": "gpt-test", "messages": [{"role": "user", "content": "hello"}]}
        return {
            "confirm_id": confirm_id,
            "tenant_id": tenant_id,
            "route": expected_route,
            "reason": "高风险响应",
            "summary": "tail yes",
            "status": "pending",
            "expires_at": 9999999999,
            "pending_request_hash": payload_hash(pending_payload),
            "pending_request_payload": pending_payload,
            "upstream_base": "https://upstream.example.com/v1",
        }

    async def fake_transition(**kwargs):
        return True

    async def fake_execute_chat_once(**kwargs):
        return {"ok": True}

    monkeypatch.setattr(openai_router, "_resolve_pending_confirmation", fake_resolve_pending_confirmation)
    monkeypatch.setattr(openai_router, "_try_transition_pending_status", fake_transition)
    monkeypatch.setattr(openai_router, "_execute_chat_once", fake_execute_chat_once)

    request = _build_request(
        headers={
            "X-Upstream-Base": "https://upstream.example.com/v1",
            "gateway-key": settings.gateway_key,
        }
    )
    noisy_input = (
        "请单独发送以下可复制消息之一（不要附加其它内容）：\n"
        f"放行（复制这一行）：yes {confirm_id}\n"
        f"取消（复制这一行）：no {confirm_id}\n"
        f"yes {confirm_id} -- 我确认执行\n"
    )
    result = await openai_router.chat_completions(
        {
            "request_id": "chat-confirm-6",
            "session_id": "s-confirm-6",
            "model": "gpt-test",
            "messages": [{"role": "user", "content": noisy_input}],
        },
        request,
    )

    assert isinstance(result, dict)
    assert result.get("ok") is True
    assert result.get("aegisgate", {}).get("confirmation", {}).get("status") == "executed"


def test_extract_decision_before_confirm_id_prefers_prefix_command():
    confirm_id = "cfm-40ca0cacd5d5"
    text = f"放行（复制这一行）：yes {confirm_id}\n取消（复制这一行）：no {confirm_id}\n"
    assert openai_router._extract_decision_before_confirm_id(text, confirm_id) == "no"


def test_resolve_pending_decision_uses_id_context_when_base_ambiguous():
    confirm_id = "cfm-40ca0cacd5d5"
    noisy = (
        "请单独发送以下可复制消息之一：\n"
        f"yes {confirm_id}\n"
        f"no {confirm_id}\n"
        f"yes {confirm_id} 我确认\n"
    )
    value, source = openai_router._resolve_pending_decision(noisy, confirm_id, "ambiguous")
    assert value == "yes"
    assert source == "id_context"
