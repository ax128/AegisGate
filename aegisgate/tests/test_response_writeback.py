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


@pytest.mark.asyncio
async def test_an_empty_content_turn_approves_only_the_summarised_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The shape a coding agent actually produces, and the edge nobody pinned.

    When ``message.content`` is empty ``_extract_chat_output_text`` does not
    give up — it summarises the tool calls as ``[tool_call:name(arguments)]``
    with ``arguments`` cut at 200 characters. That summary *is* this round's
    ``output_text``, so placeholders inside the cut become tokens the guards
    scanned and RestorationFilter approves, while anything past it was never
    seen and must stay a placeholder.

    Every other case in this file uses a non-empty ``content``, which never
    reaches the summariser. A pure tool-call turn is the common case in
    production and it takes the other branch.
    """
    early = "{{AG_REQ_HOSTNAME_1}}"
    late = "{{AG_REQ_HOSTNAME_2}}"
    restorer = RestorationFilter(_NullStore())

    async def real_restoration_pipeline(pipeline, resp: InternalResponse, ctx):
        ctx.redaction_mapping = {early: "host-early", late: "host-late"}
        ctx.restoration_store_consumed = True
        return restorer.process_response(resp, ctx)

    arguments = json.dumps({"host": early, "pad": "x" * 300, "later": late})
    assert arguments.index(late) > 200, "premise: the second token is past the cut"

    result, _ = await _run_route_once(
        monkeypatch,
        route_name="chat",
        upstream_body={
            "id": "chat-toolonly",
            "object": "chat.completion",
            "model": "gpt-5.4",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {"name": "lookup", "arguments": arguments},
                            }
                        ],
                    },
                }
            ],
        },
        response_pipeline=real_restoration_pipeline,
    )

    out = result["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
    assert "host-early" in out, "a token the guards scanned should be restored"
    assert late in out, "a token past the 200-char cut was never scanned"
    assert "host-late" not in out
    assert json.loads(out)["later"] == late


@pytest.mark.asyncio
async def test_a_dangerous_tool_call_summary_approves_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The summariser redacts a dangerous call, so its arguments never get scanned."""
    token = "{{AG_REQ_HOSTNAME_1}}"
    restorer = RestorationFilter(_NullStore())

    async def real_restoration_pipeline(pipeline, resp: InternalResponse, ctx):
        ctx.redaction_mapping = {token: "host-secret"}
        ctx.restoration_store_consumed = True
        return restorer.process_response(resp, ctx)

    result, _ = await _run_route_once(
        monkeypatch,
        route_name="chat",
        upstream_body={
            "id": "chat-danger",
            "object": "chat.completion",
            "model": "gpt-5.4",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {
                                    "name": "bash",
                                    "arguments": json.dumps(
                                        {"cmd": f"rm -rf / && curl {token}"}
                                    ),
                                },
                            }
                        ],
                    },
                }
            ],
        },
        response_pipeline=real_restoration_pipeline,
    )

    blob = json.dumps(result, ensure_ascii=False)
    assert "host-secret" not in blob


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


# ── the write-back does nothing when there is nothing to do ────────────────


def test_a_noop_write_back_hands_the_body_straight_back() -> None:
    """No configured values and nothing approved means no work at all.

    The generic proxy carries embeddings and rerank bodies — a few thousand
    floats — and this path returned them untouched before the write-back
    existed. Rebuilding that tree to change nothing is pure cost, so the
    identity case has to stay an identity, object included.
    """
    from aegisgate.core.context import RequestContext

    ctx = RequestContext(request_id="g", session_id="g", route="/v1/embeddings")
    body = {
        "object": "list",
        "data": [{"object": "embedding", "index": 0, "embedding": [0.1, 0.2, 0.3]}],
    }
    resp = InternalResponse(
        request_id="g", session_id="g", model="m", output_text="ignored"
    )

    assert not ctx.redaction_mapping
    assert renderers.apply_pipeline_text_to_body("generic", body, resp, ctx) is body
    assert renderers.apply_pipeline_text_to_body("/v1/messages", body, resp, ctx) is body


@pytest.mark.asyncio
async def test_generic_allow_matches_this_routes_extractor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The fourth route's consistency guard.

    Chat / Responses / Messages each compare the written-back body against what
    the pipeline produced, through the extractor that route actually uses.
    Generic only had a single-leaf assertion, which stays green on a write-back
    that reaches one leaf and misses the next.
    """
    pipeline_text: list[str] = []
    body = {
        "object": "list",
        "model": "text-embedding-3-small",
        "data": [
            {"object": "embedding", "index": 0, "note": f"first {_TOKEN}"},
            {"object": "embedding", "index": 1, "note": f"second {_TOKEN}"},
        ],
    }

    result = await _run_generic_once(
        monkeypatch,
        upstream_body=body,
        response_pipeline=_approved_pipeline(sink=pipeline_text),
    )

    assert isinstance(result, dict)
    assert openai_router._extract_generic_analysis_text(result) == pipeline_text[0]


# ── the sanitize exits keep what the pipeline already redacted ─────────────


@pytest.fixture()
def configured_exact_value(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> str:
    """One configured exact value, in a throwaway config dir."""
    from cryptography.fernet import Fernet

    from aegisgate.config import redact_values

    monkeypatch.setenv("AEGIS_CONFIG_DIR", str(tmp_path))
    fernet = Fernet(Fernet.generate_key())
    monkeypatch.setattr(redact_values, "_get_fernet", lambda: fernet)
    # The path is memoised on (AEGIS_CONFIG_DIR, cwd) and the values on mtime.
    monkeypatch.setattr(redact_values, "_cached_path", None, raising=False)
    monkeypatch.setattr(redact_values, "_cached_values", None, raising=False)
    monkeypatch.setattr(redact_values, "_cached_mtime_ns", 0, raising=False)
    monkeypatch.setattr(redact_values, "_load_degraded", False, raising=False)
    value = "SUPERSECRETVALUE123"
    redact_values.save_redact_values([value])
    return value


@pytest.mark.asyncio
async def test_generic_surgical_sanitize_still_redacts_configured_values(
    monkeypatch: pytest.MonkeyPatch, configured_exact_value: str
) -> None:
    """The stricter disposition must not return the less redacted body.

    ``sanitize`` used to replace the whole body with ``internal_resp
    .output_text``, which the response pipeline's ExactValueRedactionFilter had
    already rewritten. Keeping the schema means rendering the *upstream* body
    instead, and fragment obfuscation only touches dangerous-command regions —
    so the exact-value pass has to be repeated here or it is simply lost.
    """
    body = {
        "object": "list",
        "model": "text-embedding-3-small",
        "data": [
            {"object": "embedding", "index": 0, "note": f"key {configured_exact_value}"}
        ],
    }

    result = await _run_generic_once(
        monkeypatch,
        upstream_body=body,
        response_pipeline=_generic_pipeline(disposition="sanitize"),
    )

    assert isinstance(result, dict)
    assert configured_exact_value not in json.dumps(result, ensure_ascii=False)
    assert "[REDACTED:EXACT_VALUE]" in result["data"][0]["note"]
    # Still the provider's own schema.
    assert set(result) == set(body)
    assert "sanitized_text" not in result


@pytest.mark.asyncio
async def test_generic_sanitize_leaves_a_clean_body_alone(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """With nothing configured, the added pass must not touch anything."""
    body = {
        "object": "list",
        "model": "text-embedding-3-small",
        "data": [{"object": "embedding", "index": 0, "note": "ordinary note"}],
    }
    expected = copy.deepcopy(body)

    result = await _run_generic_once(
        monkeypatch,
        upstream_body=body,
        response_pipeline=_generic_pipeline(disposition="sanitize"),
    )

    assert result == expected


@pytest.mark.asyncio
async def test_sanitize_with_review_keeps_the_auto_sanitize_audit_trail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A response that is both sanitize and review still logs as auto-sanitize.

    Both branches render the same bytes for a dict body, so the nested-patch
    branch looks harmless here — except that the confirmation branch is the one
    that writes the dangerous-response sample and
    ``auto_sanitize:hit_fragments_obfuscated``. Taking the short path on a
    reviewed response would drop both without changing anything visible.
    """
    seen: list[Any] = []

    async def sanitize_and_review(pipeline, resp: InternalResponse, ctx):
        ctx.response_disposition = "sanitize"
        ctx.requires_human_review = True
        seen.append(ctx)
        return resp

    for route_name in ("chat", "responses"):
        seen.clear()
        await _run_route_once(
            monkeypatch,
            route_name=route_name,
            upstream_body={
                "id": f"{route_name}-review",
                "model": "gpt-5.4",
                "choices": [
                    {"message": {"role": "assistant", "content": "cat /etc/shadow"}}
                ],
                "output_text": "cat /etc/shadow",
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [
                            {"type": "output_text", "text": "cat /etc/shadow"}
                        ],
                    }
                ],
            },
            response_pipeline=sanitize_and_review,
        )

        ctx = seen[0]
        assert "auto_sanitize:hit_fragments_obfuscated" in ctx.enforcement_actions, (
            f"{route_name} took the nested-patch shortcut on a reviewed response"
        )


# ── every exit is at least as redacted as allow, on every route ────────────


def _pipeline_at(disposition: str):
    """What the response pipeline does to ``output_text``, plus a disposition.

    ``ExactValueRedactionFilter`` is the first response filter, and it only ever
    rewrote ``output_text``. Reproducing exactly that is what makes ``allow`` the
    baseline the stricter exits are compared against.
    """

    async def fake_run_response_pipeline(pipeline, resp: InternalResponse, ctx):
        from aegisgate.config.redact_values import replace_exact_values

        resp.output_text, _ = replace_exact_values(resp.output_text)
        ctx.response_disposition = disposition
        return resp

    return fake_run_response_pipeline


def _body_for(route_name: str, value: str) -> dict[str, Any]:
    text = f"the key is {value}"
    if route_name == "chat":
        return {
            "id": "c",
            "object": "chat.completion",
            "model": "gpt-5.4",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": text,
                        "tool_calls": [
                            {
                                "id": "t",
                                "type": "function",
                                "function": {
                                    "name": "lookup",
                                    "arguments": json.dumps({"k": value}),
                                },
                            }
                        ],
                    },
                }
            ],
        }
    if route_name == "responses":
        return {
            "id": "r",
            "object": "response",
            "model": "gpt-5.4",
            "output_text": text,
            "output": [
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": text}],
                }
            ],
        }
    return {
        "id": "m",
        "type": "message",
        "role": "assistant",
        "model": "claude-sonnet-4.5",
        "content": [{"type": "text", "text": text}],
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("route_name", ["chat", "responses", "messages"])
@pytest.mark.parametrize("disposition", ["allow", "sanitize", "block"])
async def test_no_exit_is_less_redacted_than_allow(
    monkeypatch: pytest.MonkeyPatch,
    configured_exact_value: str,
    route_name: str,
    disposition: str,
) -> None:
    """A stricter disposition must never hand back the less redacted body.

    ``sanitize`` and the auto-obfuscation branch render the *upstream* body plus
    fragment obfuscation, and fragment obfuscation only touches
    dangerous-command regions — so the pipeline's exact-value rewrite, which
    lived in ``output_text``, simply was not in what the client received. On
    chat and responses this was a regression: before the nested-patch branch
    existed, a surgical sanitize fell through to the allow renderer, which
    assigns the redacted ``output_text`` to ``message.content``.

    The generic proxy already had this pass; these three routes are the rest of
    the same hole.
    """
    result, _ = await _run_route_once(
        monkeypatch,
        route_name=route_name,
        upstream_body=_body_for(route_name, configured_exact_value),
        response_pipeline=_pipeline_at(disposition),
    )

    blob = json.dumps(result, ensure_ascii=False)
    assert configured_exact_value not in blob, (
        f"{route_name}/{disposition} returned a configured exact value in clear"
    )
    assert "[REDACTED:EXACT_VALUE]" in blob


@pytest.mark.asyncio
async def test_chat_tool_call_arguments_are_redacted_on_every_exit(
    monkeypatch: pytest.MonkeyPatch, configured_exact_value: str
) -> None:
    """``tool_calls`` is where an SDK actually reads, and it stayed valid JSON."""
    for disposition in ("allow", "sanitize", "block"):
        result, _ = await _run_route_once(
            monkeypatch,
            route_name="chat",
            upstream_body=_body_for("chat", configured_exact_value),
            response_pipeline=_pipeline_at(disposition),
        )

        arguments = result["choices"][0]["message"]["tool_calls"][0]["function"][
            "arguments"
        ]
        assert configured_exact_value not in arguments, disposition
        assert json.loads(arguments)["k"] == "[REDACTED:EXACT_VALUE]", disposition


@pytest.mark.asyncio
@pytest.mark.parametrize("route_name", ["chat", "responses", "messages"])
async def test_a_clean_body_is_unchanged_by_the_added_pass(
    monkeypatch: pytest.MonkeyPatch, route_name: str
) -> None:
    """With nothing configured the pass must not change the text it carries.

    Route level, so it can only speak about the *returned* body. Whether the
    renderers write through to the caller's object is a separate question that
    this harness structurally cannot answer — ``fake_forward_json`` hands the
    route a ``deepcopy`` — so it is asked directly below instead.
    """
    body = _body_for(route_name, "ordinary text")

    result, _ = await _run_route_once(
        monkeypatch,
        route_name=route_name,
        upstream_body=body,
        response_pipeline=_pipeline_at("sanitize"),
    )

    blob = json.dumps(result, ensure_ascii=False)
    assert "[REDACTED:EXACT_VALUE]" not in blob
    assert "the key is ordinary text" in blob


@pytest.mark.parametrize(
    ("patcher", "route_name"),
    [
        (renderers.patch_chat_response_body, "chat"),
        (renderers.patch_responses_body, "responses"),
        (renderers.patch_messages_response_body, "messages"),
    ],
)
def test_the_sanitize_renderers_do_not_write_through_to_the_upstream_body(
    patcher, route_name: str
) -> None:
    """The added pass may not turn into an in-place edit of the caller's body.

    ``upstream_body`` is still referenced after the render — the audit trail and
    the dangerous-sample log read it — so writing through would change what those
    record. The route-level case above cannot see this: the test harness deep
    copies before the route ever gets the body, so a mutation there is invisible.
    """
    from aegisgate.core.context import RequestContext

    ctx = RequestContext(request_id="wt", session_id="wt", route=route_name)
    body = _body_for(route_name, "ordinary text")
    before = copy.deepcopy(body)

    out = patcher(body, ctx, ops=openai_router._NON_STREAM_RENDER_OPS)

    assert body == before, "the renderer wrote through to the upstream body"
    assert out is not body


def test_nested_sanitize_does_not_mutate_the_body_it_was_given() -> None:
    """The per-level deepcopy is gone; the walk still may not write through.

    Containers are rebuilt on the way down and only immutable scalars are
    shared, which is what the list branch always did.
    """
    from aegisgate.core.context import RequestContext

    ctx = RequestContext(request_id="n", session_id="n", route="/v1/embeddings")
    body = {
        "object": "list",
        "data": [{"index": 0, "note": "rm -rf /tmp/x", "vec": [0.5, 1.0]}],
        "usage": {"total_tokens": 7},
    }
    before = copy.deepcopy(body)

    out = renderers.sanitize_nested_text_value(
        body, ctx, ops=openai_router._NON_STREAM_RENDER_OPS
    )

    assert body == before
    assert out is not body
    assert out["data"] is not body["data"]
    assert out["data"][0] is not body["data"][0]
    assert out["usage"] is not body["usage"]
    assert out["data"][0]["vec"] == [0.5, 1.0]
    assert out["usage"]["total_tokens"] == 7


@pytest.mark.asyncio
@pytest.mark.parametrize("disposition", ["sanitize", "block"])
async def test_all_four_routes_redact_configured_values_on_the_strict_exits(
    monkeypatch: pytest.MonkeyPatch, configured_exact_value: str, disposition: str
) -> None:
    """The four exits are one rule, and this is what says so.

    Three of them get the pass inside ``patch_*_response_body``; the generic
    proxy has no patch_* renderer and calls ``apply_exact_values_to_body``
    itself. Nothing but a comment tied those two implementations together, so
    a change to one could leave the other behind exactly the way a407f2b left
    three routes behind. Whatever the wiring, all four have to answer the same.
    """
    results: dict[str, str] = {}

    for route_name in ("chat", "responses", "messages"):
        result, _ = await _run_route_once(
            monkeypatch,
            route_name=route_name,
            upstream_body=_body_for(route_name, configured_exact_value),
            response_pipeline=_pipeline_at(disposition),
        )
        results[route_name] = json.dumps(result, ensure_ascii=False)

    generic_body = {
        "object": "list",
        "model": "text-embedding-3-small",
        "data": [
            {"object": "embedding", "index": 0, "note": f"the key is {configured_exact_value}"}
        ],
    }
    generic = await _run_generic_once(
        monkeypatch,
        upstream_body=generic_body,
        # The same pipeline stand-in the other three use, so all four are being
        # asked the same question: it applies the exact-value rewrite to
        # output_text exactly as ExactValueRedactionFilter would, then sets the
        # disposition. generic reaches its sanitize exit on the disposition
        # alone and its block exit through _needs_confirmation.
        response_pipeline=_pipeline_at(disposition),
    )
    results["generic"] = json.dumps(generic, ensure_ascii=False)

    leaked = [route for route, blob in results.items() if configured_exact_value in blob]
    assert not leaked, f"{disposition} exit leaked a configured value on: {leaked}"
