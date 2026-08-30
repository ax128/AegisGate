#!/usr/bin/env python3
"""In-memory end-to-end benchmark for the AegisGate request path.

The repo has per-regex timing budgets (``tests/test_redos_guard.py`` caps a
single pattern at 0.1 s, ``tests/test_exfil_chain_rules.py`` caps the chain
rules at 8 KB / 100 ms) but nothing end to end, so a change to the SQLite
connection lifecycle or to the streaming scan cadence had no baseline to be
verified against. This is that baseline.

Everything runs over ``httpx.ASGITransport`` against the real ``app`` with a
mocked upstream: no sockets, no listener, and no persisted files (the audit log
is disabled and the SQLite database is a throwaway under a temp directory).

    python scripts/bench_gateway.py --json
    python scripts/bench_gateway.py --scenario nonstream_redact
    python scripts/bench_gateway.py --scenario stream_long
    python scripts/bench_gateway.py --scenario stream_long --json

The script reports numbers; it never asserts on them. Thresholds would turn a
slower machine into a failure, and the judgement belongs to whoever reads the
two runs side by side.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Settings are read from the environment at import time, so every knob has to be
# in place before the first aegisgate import below.
_TMP_DIR = tempfile.mkdtemp(prefix="aegisgate-bench-")
os.environ.setdefault("AEGIS_SECURITY_LEVEL", "medium")
os.environ.setdefault("AEGIS_UPSTREAM_BASE_URL", "https://upstream.invalid/v1")
os.environ["AEGIS_AUDIT_LOG_PATH"] = ""
os.environ["AEGIS_SQLITE_DB_PATH"] = str(Path(_TMP_DIR) / "bench.db")
os.environ["AEGIS_ENABLE_DANGEROUS_RESPONSE_LOG"] = "false"
os.environ["AEGIS_ENABLE_MAPPING_PRUNE_TASK"] = "false"
os.environ["AEGIS_ENABLE_HOT_RELOAD"] = "false"
os.environ["AEGIS_LOG_LEVEL"] = "error"

import httpx  # noqa: E402

from aegisgate.adapters.openai_compat import router as _router  # noqa: E402
from aegisgate.adapters.openai_compat import upstream as _upstream  # noqa: E402
from aegisgate.config.security_rules import load_security_rules  # noqa: E402
from aegisgate.config.settings import settings  # noqa: E402
from aegisgate.core.gateway import app  # noqa: E402

WARMUP_ITERATIONS = 10
"""The first request builds the filter pipeline and compiles every rule; timing
it would measure start-up, not the request path."""

STREAM_LONG_WARMUP = 2
STREAM_LONG_ITERATIONS = 3
"""stream_long is the expensive scenario: 3200 frames through ~800 full
response-pipeline probes, so one request costs seconds rather than milliseconds.
Ten of each would put a single run past five minutes, and the point of this
script is that someone re-runs it either side of a change. Three measured
requests separate the size of difference a hot-path change makes; they are not
enough for a p99, which is why the percentile reporting stays on
nonstream_small and this scenario reports p50 and mean."""

SCENARIOS = ("nonstream_small", "nonstream_redact", "stream_ttfb", "stream_long")

_PROMPT = "please summarise the following operational note. " * 4
_PROMPT = _PROMPT[:200]
_ANSWER = "the quick brown fox jumps over the lazy dog. " * 12
_ANSWER = _ANSWER[:500]
# A token-shaped value in the same harmless form the repo's own fixtures use.
# It matters that this is credential-class: /v1/chat/completions is in
# LOW_FALSE_POSITIVE_V1_ROUTES, so only the relaxed id set runs there and a
# card- or id-shaped value would not be redacted at all. TOKEN is in that set,
# so this prompt really does drive a set_mapping on the way in and a
# consume_mapping on the way back — which is the work the mapping store's
# connection lifecycle is about, and which nonstream_small never performs.
_REDACT_PROMPT = (
    "please summarise this deployment note. the service key is "
    "sk-abcdefghijklmnopqrstuvwxyz012345 and it rotates weekly."
)
_LONG_ANSWER_CHARS = 32000
_LONG_ANSWER_CHUNK_CHARS = 10


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    # Nearest-rank: with N=200 the interpolation of a quantile estimator would
    # invent a latency no request actually had. ceil, not round — round() is
    # banker's rounding, so p95 of 50 samples would land on rank 48 instead of
    # the 48th-or-later value the definition asks for.
    rank = max(1, min(len(ordered), math.ceil(pct / 100.0 * len(ordered))))
    return ordered[rank - 1]


def _chat_body(stream: bool, prompt: str = _PROMPT) -> dict[str, Any]:
    return {
        "model": "gpt-4o-mini",
        "stream": stream,
        "messages": [{"role": "user", "content": prompt}],
    }


def _nonstream_upstream_payload() -> dict[str, Any]:
    return {
        "id": "chatcmpl-bench",
        "object": "chat.completion",
        "created": 0,
        "model": "gpt-4o-mini",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": _ANSWER},
                "finish_reason": "stop",
            }
        ],
    }


def _sse_frames(text: str, chunk_chars: int) -> list[bytes]:
    frames: list[bytes] = []
    for start in range(0, len(text), chunk_chars):
        piece = text[start : start + chunk_chars]
        payload = {
            "id": "chatcmpl-bench",
            "object": "chat.completion.chunk",
            "created": 0,
            "model": "gpt-4o-mini",
            "choices": [{"index": 0, "delta": {"content": piece}, "finish_reason": None}],
        }
        frames.append(
            b"data: " + json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n\n"
        )
    frames.append(b"data: [DONE]\n\n")
    return frames


class _AsyncFrames(httpx.AsyncByteStream):
    """Replays a fixed frame list, so every iteration sees the same upstream."""

    def __init__(self, frames: list[bytes]) -> None:
        self._frames = frames

    async def __aiter__(self):  # type: ignore[override]
        for frame in self._frames:
            yield frame


def _install_mock_upstream(frames: list[bytes] | None) -> httpx.AsyncClient:
    """Point every upstream call at an in-process transport.

    All upstream traffic — JSON and SSE alike — goes through
    ``upstream._get_upstream_async_client()``, so replacing that one module
    global covers both shapes without patching each call site.
    """

    async def handler(request: httpx.Request) -> httpx.Response:
        if frames is None:
            return httpx.Response(200, json=_nonstream_upstream_payload())
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=_AsyncFrames(frames),
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=30.0)
    _upstream._upstream_async_client = client
    return client


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://bench.local",
        timeout=60.0,
    )


async def _post_nonstream(client: httpx.AsyncClient) -> int:
    resp = await client.post("/v1/chat/completions", json=_chat_body(stream=False))
    return resp.status_code


async def _post_nonstream_redact(client: httpx.AsyncClient) -> int:
    resp = await client.post(
        "/v1/chat/completions", json=_chat_body(stream=False, prompt=_REDACT_PROMPT)
    )
    return resp.status_code


async def _post_stream_collect(client: httpx.AsyncClient) -> tuple[int, float, int]:
    """Returns (status, seconds to first content delta, byte count)."""
    first_content_at = 0.0
    total = 0
    started = time.perf_counter()
    async with client.stream(
        "POST", "/v1/chat/completions", json=_chat_body(stream=True)
    ) as resp:
        async for chunk in resp.aiter_bytes():
            total += len(chunk)
            if not first_content_at and b'"content"' in chunk:
                first_content_at = time.perf_counter() - started
    return resp.status_code, first_content_at, total


class _ProbeCounter:
    """Counts _run_stream_response_probe calls without changing what it does."""

    def __init__(self) -> None:
        self.count = 0
        self._original = _router._run_stream_response_probe

    def install(self) -> None:
        original = self._original

        async def counting(*args: Any, **kwargs: Any):
            self.count += 1
            return await original(*args, **kwargs)

        _router._run_stream_response_probe = counting  # type: ignore[assignment]

    def restore(self) -> None:
        _router._run_stream_response_probe = self._original  # type: ignore[assignment]


async def _run_repeated(
    call: Callable[[httpx.AsyncClient], Any],
    iterations: int,
    warmup: int = WARMUP_ITERATIONS,
) -> tuple[list[float], list[Any]]:
    samples: list[float] = []
    results: list[Any] = []
    async with _client() as client:
        for _ in range(warmup):
            await call(client)
        for _ in range(iterations):
            started = time.perf_counter()
            result = await call(client)
            samples.append(time.perf_counter() - started)
            results.append(result)
    return samples, results


async def scenario_nonstream_small() -> dict[str, Any]:
    """200-char prompt, 500-char upstream answer, end-to-end percentiles."""
    client = _install_mock_upstream(None)
    try:
        samples, results = await _run_repeated(_post_nonstream, 200)
    finally:
        await client.aclose()
        _upstream._upstream_async_client = None
    return {
        "iterations": len(samples),
        "status_codes": sorted(set(results)),
        "p50_ms": round(_percentile(samples, 50) * 1000, 3),
        "p95_ms": round(_percentile(samples, 95) * 1000, 3),
        "p99_ms": round(_percentile(samples, 99) * 1000, 3),
        "mean_ms": round(statistics.fmean(samples) * 1000, 3),
    }


async def scenario_nonstream_redact() -> dict[str, Any]:
    """The same shape as nonstream_small, but with a value that gets redacted.

    Kept as its own scenario rather than folded into nonstream_small: the two
    answer different questions, and the clean one is the right baseline for
    anything that is not about the mapping store. This one is the baseline for
    everything that is — a redacting request stores a mapping on the request
    side and consumes it on the response side, so it is the scenario a change to
    the store's connection lifecycle has to be read against.
    """
    client = _install_mock_upstream(None)
    try:
        samples, results = await _run_repeated(_post_nonstream_redact, 200)
    finally:
        await client.aclose()
        _upstream._upstream_async_client = None
    return {
        "iterations": len(samples),
        "status_codes": sorted(set(results)),
        "p50_ms": round(_percentile(samples, 50) * 1000, 3),
        "p95_ms": round(_percentile(samples, 95) * 1000, 3),
        "p99_ms": round(_percentile(samples, 99) * 1000, 3),
        "mean_ms": round(statistics.fmean(samples) * 1000, 3),
    }


async def scenario_stream_ttfb() -> dict[str, Any]:
    """Time from request start to the first content delta reaching the client."""
    frames = _sse_frames(_ANSWER, 20)
    client = _install_mock_upstream(frames)
    try:
        _, results = await _run_repeated(_post_stream_collect, 50)
    finally:
        await client.aclose()
        _upstream._upstream_async_client = None
    ttfbs = [ttfb for _, ttfb, _ in results]
    return {
        "iterations": len(ttfbs),
        "status_codes": sorted({status for status, _, _ in results}),
        "ttfb_p50_ms": round(_percentile(ttfbs, 50) * 1000, 3),
        "ttfb_p95_ms": round(_percentile(ttfbs, 95) * 1000, 3),
        "ttfb_p99_ms": round(_percentile(ttfbs, 99) * 1000, 3),
    }


async def scenario_stream_long() -> dict[str, Any]:
    """32k answer in 10-char chunks: total cost plus the response-probe count.

    The probe count is the number Task 8 is about — the streaming path hands the
    whole window back to the response pipeline every
    settings.stream_scan_interval_chunks chunks, so it grows with the answer.
    """
    text = (_ANSWER * ((_LONG_ANSWER_CHARS // len(_ANSWER)) + 1))[:_LONG_ANSWER_CHARS]
    frames = _sse_frames(text, _LONG_ANSWER_CHUNK_CHARS)
    client = _install_mock_upstream(frames)
    counter = _ProbeCounter()
    try:
        counter.install()
        samples, results = await _run_repeated(
            _post_stream_collect,
            STREAM_LONG_ITERATIONS,
            warmup=STREAM_LONG_WARMUP,
        )
        probes = counter.count
    finally:
        counter.restore()
        await client.aclose()
        _upstream._upstream_async_client = None
    measured = len(samples) + STREAM_LONG_WARMUP
    return {
        "iterations": len(samples),
        "answer_chars": _LONG_ANSWER_CHARS,
        "chunk_chars": _LONG_ANSWER_CHUNK_CHARS,
        "status_codes": sorted({status for status, _, _ in results}),
        "total_p50_ms": round(_percentile(samples, 50) * 1000, 3),
        "total_mean_ms": round(statistics.fmean(samples) * 1000, 3),
        "probes_per_request": round(probes / measured, 1) if measured else 0.0,
        "bytes_to_client_mean": round(
            statistics.fmean([total for _, _, total in results])
        ),
    }


_RUNNERS: dict[str, Callable[[], Any]] = {
    "nonstream_small": scenario_nonstream_small,
    "nonstream_redact": scenario_nonstream_redact,
    "stream_ttfb": scenario_stream_ttfb,
    "stream_long": scenario_stream_long,
}


def _rule_count() -> int:
    rules = load_security_rules()
    total = 0
    for section in rules.values():
        if isinstance(section, dict):
            for group in section.values():
                if isinstance(group, list):
                    total += sum(1 for item in group if isinstance(item, dict))
    return total


def _environment() -> dict[str, Any]:
    """Without these, two runs from two machines are not comparable."""
    return {
        "python_version": sys.version.split()[0],
        "cpu_count": os.cpu_count(),
        "security_level": settings.security_level,
        "rule_count": _rule_count(),
        # A plain attribute read, with no getattr default behind it. The
        # interval is a setting now and the module constant it replaced is
        # gone, so a fallback could no longer be reached — it could only report
        # a confident 4 if the setting were ever renamed, which is the same
        # quietly-wrong number this script exists to avoid producing.
        "stream_scan_interval_chunks": settings.stream_scan_interval_chunks,
    }


async def _main_async(names: list[str]) -> dict[str, Any]:
    results: dict[str, Any] = {}
    for name in names:
        results[name] = await _RUNNERS[name]()
    return {"environment": _environment(), "scenarios": results}


def _print_human(report: dict[str, Any]) -> None:
    env = report["environment"]
    print(
        f"python={env['python_version']} cpu={env['cpu_count']} "
        f"security_level={env['security_level']} rules={env['rule_count']} "
        f"interval={env['stream_scan_interval_chunks']}"
    )
    for name, data in report["scenarios"].items():
        print(f"\n[{name}]")
        for key, value in data.items():
            print(f"  {key}: {value}")


def _shutdown_runtime() -> None:
    """Stop the background workers so the interpreter can actually exit.

    The audit, stats and dangerous-response workers run on non-daemon threads
    parked on a queue.get(), so without this the script prints its report and
    then hangs at interpreter shutdown. tests/conftest.py does the same thing at
    session teardown for the same reason.

    There is no payload-transform executor to shut down. That pool was never
    created (run_payload_transform_offloop runs inline) and its shutdown helper
    has since been deleted outright, which is exactly why this list never named
    it.
    """
    from aegisgate.adapters.openai_compat.offload import (
        shutdown_filter_pipeline_executor,
    )
    from aegisgate.adapters.openai_compat.router import (
        close_runtime_dependencies,
        close_semantic_async_client,
    )
    from aegisgate.adapters.openai_compat.upstream import close_upstream_async_client
    from aegisgate.adapters.v2_proxy.router import close_v2_async_client
    from aegisgate.core.audit import shutdown_audit_worker
    from aegisgate.core.dangerous_response_log import (
        shutdown_dangerous_response_log_worker,
    )
    from aegisgate.core.stats import shutdown_stats_worker
    from aegisgate.storage.offload import shutdown_store_io_executor

    close_runtime_dependencies()
    shutdown_store_io_executor()
    shutdown_filter_pipeline_executor()
    shutdown_audit_worker()
    shutdown_dangerous_response_log_worker()
    shutdown_stats_worker()
    for closer in (
        close_upstream_async_client,
        close_v2_async_client,
        close_semantic_async_client,
    ):
        asyncio.run(closer())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="In-memory gateway benchmark (mocked upstream, no network)."
    )
    parser.add_argument(
        "--scenario",
        choices=SCENARIOS,
        help="run a single scenario instead of all three (useful under cProfile)",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit the report as JSON on stdout"
    )
    args = parser.parse_args(argv)

    names = [args.scenario] if args.scenario else list(SCENARIOS)
    try:
        report = asyncio.run(_main_async(names))
        if args.json:
            print(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            _print_human(report)
    finally:
        _shutdown_runtime()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
