"""The allow disposition must hand the client the pipeline's own bytes.

Three separate holes used to sit behind the same word "allow":

* ``/v1/messages`` and the generic proxy returned ``upstream_body`` verbatim, so
  every response-side rewrite was thrown away;
* ``/v1/responses`` patched only the convenience ``output_text`` field, while
  the SDKs read ``output[]``;
* ``/v1/chat/completions`` patched ``message.content`` and left ``tool_calls``
  as the model wrote them.

The other half of this file is the *limit* on the fix. Placeholder restoration
in a nested field is allowed only for tokens RestorationFilter already restored
in ``output_text`` — the only text the volume / partial / exfiltration guards
and PostRestoreGuard ever scanned. A placeholder that appears solely in a tool
call was never scanned by anything, so it must come back as a placeholder.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from fastapi.responses import PlainTextResponse

from aegisgate.adapters.openai_compat import renderers
from aegisgate.adapters.openai_compat import router as openai_router
from aegisgate.core.models import InternalResponse
from aegisgate.filters.restoration import RestorationFilter
from aegisgate.storage.kv import KVStore
from aegisgate.tests.test_response_sanitization_routes import (
    _install_response_route_mocks,
    _json_body,
    _run_route_once,
)

_TOKEN = "{{AG_REQ_TOKEN_1}}"
_RESTORED = "restored-value"


def _approved_pipeline(*, sink: list[str] | None = None, **ctx_updates: Any):
    """Identity pipeline that fakes an approved restoration.

    An identity pipeline never runs RestorationFilter, so a test that wants the
    nested restore has to set both ``restoration_applied`` and
    ``restored_placeholders`` itself — without them the write-back must be a
    no-op, which is exactly what the gating cases below rely on.

    ``sink`` collects the pipeline's own ``output_text`` so a consistency guard
    can compare against it rather than against a hand-written literal.
    """

    async def fake_run_response_pipeline(pipeline, resp: InternalResponse, ctx):
        ctx.redaction_mapping = {_TOKEN: _RESTORED}
        ctx.restored_placeholders = {_TOKEN}
        ctx.security_tags.add("restoration_applied")
        for key, value in ctx_updates.items():
            if key == "security_tags":
                ctx.security_tags.update(value)
            else:
                setattr(ctx, key, value)
        resp.output_text = resp.output_text.replace(_TOKEN, _RESTORED)
        if sink is not None:
            sink.append(resp.output_text)
        return resp

    return fake_run_response_pipeline


async def _identity_pipeline(pipeline, resp: InternalResponse, ctx):
    return resp


def _flatten_output_items(body: dict[str, Any]) -> str:
    """The Responses guard must ignore the convenience field.

    ``_extract_responses_output_text`` reads ``output_text`` first, so calling it
    after the write-back is a tautology: it would stay green with ``output[]``
    left completely untouched.
    """
    return openai_router._flatten_text(body.get("output"))


# ── allow write-back reaches the nested protocol fields ────────────────────


@pytest.mark.asyncio
async def test_chat_allow_restores_content_and_tool_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, _ = await _run_route_once(
        monkeypatch,
        route_name="chat",
        upstream_body={
            "id": "chat-wb",
            "object": "chat.completion",
            "model": "gpt-5.4",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": f"the host is {_TOKEN}",
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {
                                    "name": "lookup",
                                    "arguments": json.dumps({"host": _TOKEN}),
                                },
                            }
                        ],
                    },
                }
            ],
        },
        response_pipeline=_approved_pipeline(),
    )

    message = result["choices"][0]["message"]
    assert _TOKEN not in message["content"]
    arguments = message["tool_calls"][0]["function"]["arguments"]
    assert _TOKEN not in arguments
    assert json.loads(arguments)["host"] == _RESTORED

    # Consistency guard: what the extractor sees equals what the pipeline made.
    assert openai_router._extract_chat_output_text(result) == f"the host is {_RESTORED}"


@pytest.mark.asyncio
async def test_responses_allow_restores_nested_output_items(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, _ = await _run_route_once(
        monkeypatch,
        route_name="responses",
        upstream_body={
            "id": "resp-wb",
            "object": "response",
            "model": "gpt-5.4",
            "output_text": f"the host is {_TOKEN}",
            "output": [
                {
                    "type": "message",
                    "id": "msg-1",
                    "role": "assistant",
                    "content": [
                        {"type": "output_text", "text": f"the host is {_TOKEN}"}
                    ],
                },
                {
                    "type": "function_call",
                    "name": "lookup",
                    "arguments": json.dumps({"host": _TOKEN}),
                },
            ],
        },
        response_pipeline=_approved_pipeline(),
    )

    assert _TOKEN not in result["output"][0]["content"][0]["text"]
    assert _TOKEN not in result["output"][1]["arguments"]
    assert json.loads(result["output"][1]["arguments"])["host"] == _RESTORED


@pytest.mark.asyncio
async def test_messages_allow_no_longer_returns_the_raw_upstream_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, _ = await _run_route_once(
        monkeypatch,
        route_name="messages",
        upstream_body={
            "id": "msg-wb",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-4.5",
            "content": [
                {"type": "text", "text": f"the host is {_TOKEN}"},
                {
                    "type": "tool_use",
                    "id": "toolu_1",
                    "name": "lookup",
                    "input": {"host": _TOKEN},
                },
            ],
        },
        response_pipeline=_approved_pipeline(),
    )

    assert _TOKEN not in result["content"][0]["text"]
    assert result["content"][1]["input"]["host"] == _RESTORED


@pytest.mark.asyncio
async def test_responses_multi_block_bodies_are_transformed_per_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Assigning ``output_text`` to every part would duplicate the answer."""
    first = f"alpha block mentions {_TOKEN}"
    second = "omega block says something else entirely"
    pipeline_text: list[str] = []
    result, _ = await _run_route_once(
        monkeypatch,
        route_name="responses",
        upstream_body={
            "id": "resp-multi",
            "object": "response",
            "model": "gpt-5.4",
            "output_text": f"{first}{second}",
            "output": [
                {
                    "type": "message",
                    "id": "msg-1",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": first}],
                },
                {
                    "type": "message",
                    "id": "msg-2",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": second}],
                },
            ],
        },
        response_pipeline=_approved_pipeline(sink=pipeline_text),
    )

    block_one = result["output"][0]["content"][0]["text"]
    block_two = result["output"][1]["content"][0]["text"]
    assert block_one == f"alpha block mentions {_RESTORED}"
    assert block_two == second
    assert second not in block_one
    assert block_one not in block_two

    # Consistency guard, convenience field deliberately excluded.
    assert _flatten_output_items(result) == pipeline_text[0]


@pytest.mark.asyncio
async def test_messages_multi_block_bodies_are_transformed_per_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = f"alpha block mentions {_TOKEN}"
    second = "omega block says something else entirely"
    pipeline_text: list[str] = []
    result, _ = await _run_route_once(
        monkeypatch,
        route_name="messages",
        upstream_body={
            "id": "msg-multi",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-4.5",
            "content": [
                {"type": "text", "text": first},
                {"type": "text", "text": second},
            ],
        },
        response_pipeline=_approved_pipeline(sink=pipeline_text),
    )

    assert result["content"][0]["text"] == f"alpha block mentions {_RESTORED}"
    assert result["content"][1]["text"] == second
    assert second not in result["content"][0]["text"]
    # Consistency guard: this route's own extractor, run over the written-back
    # body, has to come out as the text the pipeline produced.
    assert openai_router._extract_generic_analysis_text(result) == pipeline_text[0]


# ── the restore surface stops at what the guards scanned ───────────────────


@pytest.mark.asyncio
async def test_tool_call_placeholders_stay_redacted_without_an_approval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The body never carried the token, so nothing ever scanned it.

    Restoring it here would hand back a credential that skipped the volume,
    partial-restore and exfiltration guards as well as PostRestoreGuard.
    """

    async def mapping_without_approval(pipeline, resp: InternalResponse, ctx):
        ctx.redaction_mapping = {_TOKEN: _RESTORED}
        return resp

    result, _ = await _run_route_once(
        monkeypatch,
        route_name="chat",
        upstream_body={
            "id": "chat-gate",
            "object": "chat.completion",
            "model": "gpt-5.4",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "no placeholder in the body at all",
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {
                                    "name": "lookup",
                                    "arguments": json.dumps({"host": _TOKEN}),
                                },
                            }
                        ],
                    }
                }
            ],
        },
        response_pipeline=mapping_without_approval,
    )

    arguments = result["choices"][0]["message"]["tool_calls"][0]["function"][
        "arguments"
    ]
    assert _TOKEN in arguments
    assert _RESTORED not in arguments


@pytest.mark.asyncio
async def test_confirmed_release_does_not_restore_tool_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The body is already an obfuscated summary; the tool calls must not undo it."""
    result, _ = await _run_route_once(
        monkeypatch,
        route_name="chat",
        upstream_body={
            "id": "chat-confirmed",
            "object": "chat.completion",
            "model": "gpt-5.4",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": f"the host is {_TOKEN}",
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {
                                    "name": "lookup",
                                    "arguments": json.dumps({"host": _TOKEN}),
                                },
                            }
                        ],
                    }
                }
            ],
        },
        response_pipeline=_approved_pipeline(
            security_tags={"confirmed_release"},
        ),
    )

    arguments = result["choices"][0]["message"]["tool_calls"][0]["function"][
        "arguments"
    ]
    assert _TOKEN in arguments
    assert _RESTORED not in arguments


# ── end to end, through the real RestorationFilter ─────────────────────────


class _NullStore(KVStore):
    def set_mapping(self, session_id: str, request_id: str, mapping: dict) -> None:
        return None

    def get_mapping(self, session_id: str, request_id: str) -> dict:
        return {}

    def consume_mapping(self, session_id: str, request_id: str) -> dict:
        return {}


@pytest.mark.asyncio
async def test_messages_end_to_end_restore_reaches_the_client_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pins the clear timing: the map must still exist when the renderer runs.

    Clearing right after ``audit_once()`` would still be *before* the render, so
    this case — not a hand-set ``output_text`` — is what catches it.
    """
    placeholder = "{{AG_REQ_HOSTNAME_1}}"
    restorer = RestorationFilter(_NullStore())

    async def real_restoration_pipeline(pipeline, resp: InternalResponse, ctx):
        ctx.redaction_mapping = {placeholder: "db-prod-01"}
        ctx.restoration_store_consumed = True
        return restorer.process_response(resp, ctx)

    result, _ = await _run_route_once(
        monkeypatch,
        route_name="messages",
        upstream_body={
            "id": "msg-e2e",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-4.5",
            "content": [{"type": "text", "text": f"connect to {placeholder} on 5432"}],
        },
        response_pipeline=real_restoration_pipeline,
    )

    assert result["content"][0]["text"] == "connect to db-prod-01 on 5432"


# ── benign bodies come back untouched ──────────────────────────────────────


@pytest.mark.asyncio
async def test_allow_write_back_is_byte_identical_for_a_benign_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    upstream_body = {
        "id": "msg-benign",
        "type": "message",
        "role": "assistant",
        "model": "claude-sonnet-4.5",
        "content": [{"type": "text", "text": "plain benign answer"}],
        "usage": {"input_tokens": 3, "output_tokens": 4},
    }
    expected = copy.deepcopy(upstream_body)

    result, _ = await _run_route_once(
        monkeypatch,
        route_name="messages",
        upstream_body=upstream_body,
        response_pipeline=_identity_pipeline,
    )

    assert result == expected


def test_generic_allow_keeps_the_provider_schema() -> None:
    """No ``sanitized_text`` collapse on the allow path, and no key set change."""
    from aegisgate.core.context import RequestContext

    ctx = RequestContext(request_id="g", session_id="g", route="/v1/embeddings")
    ctx.redaction_mapping = {_TOKEN: _RESTORED}
    ctx.restored_placeholders = {_TOKEN}
    ctx.security_tags.add("restoration_applied")
    body = {
        "object": "list",
        "data": [{"object": "embedding", "index": 0, "note": f"from {_TOKEN}"}],
        "model": "text-embedding-3-small",
    }
    resp = InternalResponse(
        request_id="g", session_id="g", model="m", output_text="ignored"
    )

    out = renderers.apply_pipeline_text_to_body("generic", body, resp, ctx)

    assert isinstance(out, dict)
    assert set(out) == set(body)
    assert "sanitized_text" not in out
    assert out["data"][0]["note"] == f"from {_RESTORED}"
    assert out["object"] == "list"


# ── the generic proxy has three exits, not two ─────────────────────────────


async def _run_generic_once(
    monkeypatch: pytest.MonkeyPatch,
    *,
    upstream_body: dict[str, Any] | str,
    response_pipeline,
) -> dict[str, Any] | str:
    _install_response_route_mocks(monkeypatch)
    monkeypatch.setattr(openai_router, "_run_response_pipeline", response_pipeline)

    async def fake_forward_json(url: str, payload: dict[str, Any], headers: dict[str, str]):
        return 200, copy.deepcopy(upstream_body)

    monkeypatch.setattr(openai_router, "_forward_json", fake_forward_json)

    result = await openai_router._execute_generic_once(
        payload={
            "model": "text-embedding-3-small",
            "input": "hello",
            "request_id": "generic-writeback",
            "session_id": "generic-writeback",
        },
        request_headers={},
        request_path="/v1/embeddings",
        boundary={},
    )
    if isinstance(result, PlainTextResponse):
        raw = result.body
        return (raw.tobytes() if isinstance(raw, memoryview) else raw).decode("utf-8")
    return _json_body(result)


def _generic_pipeline(*, disposition: str, tags: set[str] | None = None, review: bool = False):
    async def fake_run_response_pipeline(pipeline, resp: InternalResponse, ctx):
        ctx.response_disposition = disposition
        ctx.requires_human_review = review
        for tag in tags or set():
            ctx.security_tags.add(tag)
        return resp

    return fake_run_response_pipeline


@pytest.mark.asyncio
async def test_generic_surgical_sanitize_preserves_the_response_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Collapsing to a single ``sanitized_text`` key destroyed embeddings bodies."""
    dangerous_fragment = "rm -rf /tmp/generic"
    body = {
        "object": "list",
        "model": "text-embedding-3-small",
        "data": [
            {"object": "embedding", "index": 0, "note": f"see {dangerous_fragment} here"}
        ],
    }

    result = await _run_generic_once(
        monkeypatch,
        upstream_body=body,
        response_pipeline=_generic_pipeline(disposition="sanitize"),
    )

    assert isinstance(result, dict)
    assert set(result) == set(body)
    assert "sanitized_text" not in result
    assert result["object"] == "list"
    note = result["data"][0]["note"]
    assert dangerous_fragment not in note
    assert openai_router._DANGER_FRAGMENT_NOTICE in note


@pytest.mark.asyncio
async def test_generic_block_still_returns_a_whole_replacement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A blocked answer must not come back wearing the provider's own schema."""
    body = {
        "object": "list",
        "model": "text-embedding-3-small",
        "data": [{"object": "embedding", "index": 0, "note": "cat /etc/shadow"}],
    }

    result = await _run_generic_once(
        monkeypatch,
        upstream_body=body,
        response_pipeline=_generic_pipeline(disposition="block"),
    )

    assert isinstance(result, dict)
    assert set(result) == {"sanitized_text"}


@pytest.mark.asyncio
async def test_generic_allow_returns_the_written_back_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = {
        "object": "list",
        "model": "text-embedding-3-small",
        "data": [{"object": "embedding", "index": 0, "note": f"host {_TOKEN}"}],
    }

    result = await _run_generic_once(
        monkeypatch,
        upstream_body=body,
        response_pipeline=_approved_pipeline(),
    )

    assert isinstance(result, dict)
    assert set(result) == set(body)
    assert result["data"][0]["note"] == f"host {_RESTORED}"


@pytest.mark.asyncio
async def test_generic_benign_body_is_returned_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = {
        "object": "list",
        "model": "text-embedding-3-small",
        "data": [{"object": "embedding", "index": 0, "embedding": [0.1, 0.2]}],
    }
    expected = copy.deepcopy(body)

    result = await _run_generic_once(
        monkeypatch,
        upstream_body=body,
        response_pipeline=_identity_pipeline,
    )

    assert result == expected
