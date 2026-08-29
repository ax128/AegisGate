"""The metric names and label sets become a dashboard contract on first scrape."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

import httpx
import pytest

from aegisgate.observability import metrics

_LIVE = ("FILTER_MATCHES", "FILTER_ERRORS", "DISPOSITION", "STREAM_PROBES", "SEMANTIC_CALLS")


# ---------------------------------------------------------------------------
# Contract: names, labels, and the counting semantics readers get wrong
# ---------------------------------------------------------------------------
_needs_prometheus = pytest.mark.skipif(
    not metrics._HAS_PROMETHEUS,
    reason="prometheus_client is an optional extra; the helpers are no-ops without it",
)


@_needs_prometheus
def test_metric_names_and_labels_are_stable() -> None:
    """These names become a dashboard contract the moment anyone graphs them."""
    assert metrics.FILTER_MATCHES._name == "aegisgate_filter_matches"
    assert metrics.FILTER_MATCHES._labelnames == ("filter", "phase")
    assert metrics.FILTER_ERRORS._name == "aegisgate_filter_errors"
    assert metrics.FILTER_ERRORS._labelnames == ("filter", "phase")
    assert metrics.DISPOSITION._name == "aegisgate_disposition"
    assert metrics.DISPOSITION._labelnames == ("phase", "disposition")
    assert metrics.STREAM_PROBES._name == "aegisgate_stream_probes"
    assert metrics.STREAM_PROBES._labelnames == ("route",)
    assert metrics.SEMANTIC_CALLS._name == "aegisgate_semantic_calls"
    assert metrics.SEMANTIC_CALLS._labelnames == ("outcome",)


@_needs_prometheus
def test_retired_metric_names_are_not_reused() -> None:
    """2d4ce8e removed these; a same-name different-label revival breaks dashboards.

    Compare against the *emitted* names, not the constructor arguments: Counter
    strips the _total suffix into _name while Histogram keeps its full name, so a
    hand-written literal list is the wrong shape on one of the two.
    """
    live = {getattr(metrics, name)._name for name in _LIVE}
    assert live.isdisjoint(
        {
            "aegisgate_filter_hits",
            "aegisgate_confirmations",
            "aegisgate_upstream_errors",
            "aegisgate_pipeline_duration_seconds",
        }
    )


@_needs_prometheus
def test_filter_matches_documents_its_per_run_counting() -> None:
    """The one thing a reader will get wrong: this is not a per-request counter.

    The streaming path re-runs the response pipeline every N chunks, so one long
    answer contributes hundreds of increments on the response side. If someone
    later "tidies" the HELP text away, the metric silently starts looking like an
    answer to "how much did we block", which is disposition_total's job.
    """
    assert "per pipeline run" in metrics.FILTER_MATCHES._documentation


@_needs_prometheus
def test_no_per_filter_duration_histogram() -> None:
    """Deliberately absent: it would run thousands of times per streamed answer,
    inside the very thing it would be measuring. cProfile answers that question
    with no observer effect and nothing left in production."""
    assert not hasattr(metrics, "FILTER_DURATION")
    assert not hasattr(metrics, "observe_filter_duration")


def test_probe_route_labels_are_bounded() -> None:
    from aegisgate.adapters.openai_compat.router import _probe_route_label

    assert _probe_route_label("/v1/chat/completions") == "chat"
    assert _probe_route_label("/v1/responses") == "responses"
    assert _probe_route_label("/v1/messages") == "messages"
    # The generic proxy passes the raw request path through, so anything else
    # has to collapse or the label set is unbounded.
    assert _probe_route_label("/anything/else") == "other"
    assert _probe_route_label("/v1/../../etc/passwd") == "other"


def test_helpers_are_noop_without_prometheus(monkeypatch) -> None:
    """No skipif: this is the branch that runs without the observability extra."""
    for name in _LIVE:
        monkeypatch.setattr(metrics, name, None)
    metrics.inc_filter_match("redaction", "request")
    metrics.inc_filter_error("redaction", "request")
    metrics.inc_disposition("request", "allow")
    metrics.inc_stream_probe("chat")
    metrics.inc_semantic_call("miss")


# ---------------------------------------------------------------------------
# End to end: one request, through the real app, with a mocked upstream
# ---------------------------------------------------------------------------
def _counter_value(counter: Any, **labels: str) -> float:
    if counter is None:
        return 0.0
    return counter.labels(**labels)._value.get()


@pytest.fixture
def gateway_client(monkeypatch):
    """The real app over an ASGI transport, with every upstream call mocked."""
    from aegisgate.adapters.openai_compat import upstream as upstream_mod
    from aegisgate.core.gateway import app

    tmp = tempfile.mkdtemp(prefix="aegisgate-metrics-")
    monkeypatch.setattr(
        "aegisgate.config.settings.settings.sqlite_db_path", str(Path(tmp) / "t.db")
    )

    state: dict[str, Any] = {
        "status": 200,
        "stream": False,
        "stream_text": "a calm and entirely ordinary streamed answer. " * 8,
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        if state["status"] >= 400:
            return httpx.Response(state["status"], json={"error": {"message": "boom"}})
        if state.get("stream"):
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=state["frames_cls"](state["sse"](state["stream_text"])),
            )
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl-t",
                "object": "chat.completion",
                "created": 0,
                "model": "gpt-4o-mini",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "all fine here"},
                        "finish_reason": "stop",
                    }
                ],
            },
        )

    def _sse(text: str, chunk: int = 8) -> list[bytes]:
        frames = []
        for start in range(0, len(text), chunk):
            frames.append(
                b"data: "
                + json.dumps(
                    {
                        "id": "chatcmpl-t",
                        "object": "chat.completion.chunk",
                        "created": 0,
                        "model": "gpt-4o-mini",
                        "choices": [
                            {
                                "index": 0,
                                "delta": {"content": text[start : start + chunk]},
                                "finish_reason": None,
                            }
                        ],
                    }
                ).encode("utf-8")
                + b"\n\n"
            )
        frames.append(b"data: [DONE]\n\n")
        return frames

    class _Frames(httpx.AsyncByteStream):
        def __init__(self, frames: list[bytes]) -> None:
            self._frames = frames

        async def __aiter__(self):  # type: ignore[override]
            for frame in self._frames:
                yield frame

    state["sse"] = _sse
    state["frames_cls"] = _Frames

    mock = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=10.0)
    monkeypatch.setattr(upstream_mod, "_upstream_async_client", mock)
    monkeypatch.setattr(
        "aegisgate.config.settings.settings.upstream_base_url",
        "https://upstream.invalid/v1",
    )

    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://metrics.test",
        timeout=30.0,
    )
    yield client, state


async def _stream(client: httpx.AsyncClient, content: str) -> bytes:
    chunks: list[bytes] = []
    async with client.stream(
        "POST",
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "stream": True,
            "messages": [{"role": "user", "content": content}],
        },
    ) as resp:
        async for chunk in resp.aiter_bytes():
            chunks.append(chunk)
    return b"".join(chunks)


async def _post(client: httpx.AsyncClient, content: str) -> httpx.Response:
    return await client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": content}],
        },
    )


@_needs_prometheus
async def test_a_request_phase_match_counts_once_per_request(gateway_client) -> None:
    """Request phase, not response: the request pipeline runs exactly once per
    request, while the response side re-runs per streaming probe. An assertion
    written against the response phase would be green non-streamed and red
    streamed."""
    client, _ = gateway_client
    labels = {"filter": "redaction", "phase": "request"}
    async with client:
        await _post(client, "warm up")
        before = _counter_value(metrics.FILTER_MATCHES, **labels)
        # A token-shaped value the repo already uses in fixtures.
        await _post(client, "my key is sk-abcdefghijklmnopqrstuvwxyz012345")
        after_hit = _counter_value(metrics.FILTER_MATCHES, **labels)
        await _post(client, "nothing sensitive in this sentence")
        after_clean = _counter_value(metrics.FILTER_MATCHES, **labels)

    assert after_hit - before == 1, "one redacting request must count exactly one match"
    assert after_clean == after_hit, "a clean request must not count a match"


async def test_one_request_writes_exactly_one_audit_line(gateway_client, monkeypatch) -> None:
    """inc_disposition lives inside _write_audit_event, so a path that writes two
    audit lines would silently double the metric. Pin the premise, not the hope.

    Patch router.write_audit, not core.audit.write_audit: router.py binds the
    callable into its own namespace at import time, so patching the source module
    would not intercept it and this test would pass while the premise was false.
    """
    from aegisgate.adapters.openai_compat import router

    client, state = gateway_client
    calls: list[str] = []
    monkeypatch.setattr(
        router, "write_audit", lambda record: calls.append(str(record.get("request_id")))
    )

    async with client:
        for label, content, status in (
            ("allow", "an ordinary question", 200),
            ("sanitize", "my key is sk-abcdefghijklmnopqrstuvwxyz012345", 200),
        ):
            state["status"] = status
            calls.clear()
            await _post(client, content)
            assert len(calls) == 1, f"{label} wrote {len(calls)} audit lines: {calls}"
            assert len(set(calls)) == len(calls)

        # Upstream failure: this path reaches _write_audit_event through
        # _error_response, which does not go through audit_once.
        state["status"] = 500
        calls.clear()
        await _post(client, "an ordinary question")
        assert len(calls) == 1, f"upstream error wrote {len(calls)} audit lines: {calls}"

        # Streaming: audit_once fires from inside the generator, and the
        # passthrough variant audits from a finally. Both must still be one line.
        state["status"] = 200
        state["stream"] = True
        calls.clear()
        await _stream(client, "an ordinary question")
        assert len(calls) == 1, f"stream wrote {len(calls)} audit lines: {calls}"


@_needs_prometheus
async def test_disposition_counts_once_per_request_on_every_path(gateway_client) -> None:
    """The metric this Task uses to answer "how much did we block yesterday"."""
    client, state = gateway_client
    async with client:
        await _post(client, "warm up")
        for status in (200, 500):
            state["status"] = status
            before = sum(
                _counter_value(metrics.DISPOSITION, phase="request", disposition=value)
                for value in ("allow", "block", "sanitize")
            )
            await _post(client, "an ordinary question")
            after = sum(
                _counter_value(metrics.DISPOSITION, phase="request", disposition=value)
                for value in ("allow", "block", "sanitize")
            )
            assert after - before == 1, f"status={status} counted {after - before} dispositions"


@_needs_prometheus
def test_disposition_values_stay_a_three_value_enum() -> None:
    """Assignments to ctx.*_disposition anywhere in the runtime are allow /
    block / sanitize. "review" is not one: human review is a separate boolean,
    and pinning a fourth value here would document a state that cannot occur."""
    import re

    root = Path(__file__).resolve().parent.parent
    seen: set[str] = set()
    for path in root.rglob("*.py"):
        if "tests" in path.parts:
            continue
        for match in re.finditer(
            r"""_disposition\s*=\s*["']([a-z_]+)["']""",
            path.read_text(encoding="utf-8"),
        ):
            seen.add(match.group(1))
    assert seen == {"allow", "block", "sanitize"}, sorted(seen)


def test_semantic_outcomes_stay_a_bounded_enum() -> None:
    """Every analyze() return path reports, and the value set stays closed.

    The plan listed six outcomes; there are seven, because the empty-text early
    return sits ahead of the service_url check and is reachable. Pinning the set
    is what makes that a decision rather than an oversight — a new return path
    that forgets to report makes semantic_calls_total quietly smaller than the
    number of calls, which is the exact silence this counter exists to remove.
    """
    import ast

    from aegisgate.core import semantic

    tree = ast.parse(Path(semantic.__file__).read_text(encoding="utf-8"))
    analyze = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "analyze"
    )
    reports = [
        node.args[0].value
        for node in ast.walk(analyze)
        if isinstance(node, ast.Call)
        and getattr(node.func, "id", None) == "inc_semantic_call"
    ]
    assert set(reports) == {
        "empty",
        "unconfigured",
        "hit",
        "miss",
        "timeout",
        "circuit_open",
        "error",
    }, sorted(set(reports))
    # One report per outcome, and one per return: a return that grew a second
    # report would double-count, and one that grew none would make the counter
    # quietly smaller than the number of calls.
    assert len(reports) == len(set(reports)), sorted(reports)
    returns = [node for node in ast.walk(analyze) if isinstance(node, ast.Return)]
    assert len(returns) == len(reports), f"{len(returns)} returns, {len(reports)} reports"


@_needs_prometheus
async def test_streaming_increments_the_probe_counter(gateway_client) -> None:
    """The probe count is the number Task 8's investigation is about, and the
    route label has to land on the bounded value rather than the raw path."""
    client, state = gateway_client
    state["stream"] = True
    async with client:
        before = _counter_value(metrics.STREAM_PROBES, route="chat")
        await _stream(client, "an ordinary question")
        after = _counter_value(metrics.STREAM_PROBES, route="chat")
    assert after > before, "a streamed response ran no response-pipeline probe"
