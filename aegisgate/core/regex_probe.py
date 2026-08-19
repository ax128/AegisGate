"""Sandboxed regex probe backing the console's rule tester.

A pattern typed into the console is untrusted *from a runtime standpoint*: it is
easy to write catastrophic backtracking by accident, and CPython's ``re`` has no
timeout, so a bad pattern in-process would burn a core until the gateway is
restarted. Matching therefore runs in a child process that can actually be
killed, and a timeout is reported as a normal result — "no match within Ns" is
precisely the answer the admin needs before saving the rule.

Inputs are capped hard as a second line of defence; the caps are generous enough
for the "paste a log line and see what it hits" workflow the tester exists for.
"""

from __future__ import annotations

import multiprocessing
import re
from typing import Any

from aegisgate.util.logger import logger

MAX_REGEX_LEN = 500
MAX_SAMPLES = 5
MAX_SAMPLE_LEN = 2_000
MAX_MATCHES_PER_SAMPLE = 20
MAX_MATCH_PREVIEW_LEN = 120
PROBE_TIMEOUT_SECONDS = 2.0


class ProbeInputError(ValueError):
    """Raised when the submitted regex or samples exceed the accepted limits."""


def normalize_probe_input(raw_regex: object, raw_samples: object) -> tuple[str, list[str]]:
    """Validate and clamp probe input, raising ``ProbeInputError`` on violations."""
    regex = str(raw_regex or "")
    if not regex.strip():
        raise ProbeInputError("regex 不能为空")
    if len(regex) > MAX_REGEX_LEN:
        raise ProbeInputError(f"regex 长度超过 {MAX_REGEX_LEN} 字符")
    try:
        re.compile(regex)
    except re.error as exc:
        raise ProbeInputError(f"正则无法编译: {exc}") from exc

    if isinstance(raw_samples, str):
        raw_list: list[object] = [raw_samples]
    elif isinstance(raw_samples, list):
        raw_list = list(raw_samples)
    else:
        raise ProbeInputError("samples 必须是字符串或字符串数组")
    if not raw_list:
        raise ProbeInputError("至少需要一条测试文本")
    if len(raw_list) > MAX_SAMPLES:
        raise ProbeInputError(f"最多 {MAX_SAMPLES} 条测试文本")

    samples: list[str] = []
    for entry in raw_list:
        text = str(entry if entry is not None else "")
        if len(text) > MAX_SAMPLE_LEN:
            raise ProbeInputError(f"单条测试文本超过 {MAX_SAMPLE_LEN} 字符")
        samples.append(text)
    return regex, samples


# POSIX gets ``fork``: it is the only start method that does not re-run the
# parent's __main__ in the child, which both ``spawn`` and ``forkserver`` do and
# which breaks under several ways of launching the gateway. Forking a
# multi-threaded process is only hazardous if the child takes a lock a dead
# thread held — so the child below takes none: the pattern is compiled in the
# parent and handed over already built, and results travel over a raw Pipe
# rather than a Queue with its feeder thread.
_START_METHOD_PREFERENCE = ("fork", "spawn")
_context: Any = None


def _probe_context() -> Any:
    global _context
    if _context is not None:
        return _context
    available = multiprocessing.get_all_start_methods()
    for method in _START_METHOD_PREFERENCE:
        if method in available:
            _context = multiprocessing.get_context(method)
            logger.debug("regex probe using multiprocessing start method=%s", method)
            return _context
    _context = multiprocessing.get_context()  # pragma: no cover - no POSIX/Windows method
    return _context


def _probe_worker(pattern: "re.Pattern[str]", samples: list[str], conn: Any) -> None:
    """Child-process entry point. Must stay importable at module level.

    Deliberately lock-free: *pattern* arrives already compiled, ``finditer`` is
    pure C, and ``conn.send`` pickles plain builtins.
    """
    results = []
    for index, sample in enumerate(samples):
        spans: list[list[int]] = []
        previews: list[str] = []
        for match in pattern.finditer(sample):
            if len(spans) >= MAX_MATCHES_PER_SAMPLE:
                break
            start, end = match.span()
            spans.append([start, end])
            fragment = sample[start:end]
            if len(fragment) > MAX_MATCH_PREVIEW_LEN:
                fragment = fragment[:MAX_MATCH_PREVIEW_LEN] + "\u2026"
            previews.append(fragment)
        results.append({
            "index": index,
            "matched": bool(spans),
            "match_count": len(spans),
            "truncated": len(spans) >= MAX_MATCHES_PER_SAMPLE,
            "spans": spans,
            "matches": previews,
        })
    conn.send({"results": results})
    conn.close()


def probe(regex: str, samples: list[str], timeout: float = PROBE_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Run *regex* against *samples* in a killable child process.

    Blocking; call it off the event loop. Returns ``timed_out=True`` instead of
    raising when the pattern does not finish inside *timeout*.
    """
    try:
        pattern = re.compile(regex)
    except re.error as exc:
        return {"timed_out": False, "results": [], "error": str(exc)}

    ctx = _probe_context()
    receiver, sender = ctx.Pipe(duplex=False)
    process = ctx.Process(target=_probe_worker, args=(pattern, samples, sender), daemon=True)
    process.start()
    sender.close()  # only the child keeps the write end, so poll() sees EOF on exit
    try:
        payload: dict[str, Any] | None = None
        if receiver.poll(timeout):
            try:
                payload = receiver.recv()
            except EOFError:  # pragma: no cover - child died before sending
                payload = None
        if payload is None:
            # Still running means the pattern blew the budget; already exited
            # means the child died without publishing, which is a real failure.
            still_running = process.is_alive()
            _terminate(process)
            if still_running:
                return {"timed_out": True, "timeout_seconds": timeout, "results": []}
            return {"timed_out": False, "results": [], "error": "probe_no_result"}
        process.join(1.0)
        return {"timed_out": False, "results": payload["results"]}
    finally:
        receiver.close()
        _terminate(process)


def _terminate(process: Any) -> None:
    """Stop *process* if it is still running, escalating to SIGKILL."""
    if not process.is_alive():
        return
    process.terminate()
    process.join(1.0)
    if process.is_alive():  # pragma: no cover - terminate is reliable on POSIX
        process.kill()
        process.join(1.0)
