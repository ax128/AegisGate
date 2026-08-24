"""Process identity and the multi-process warning.

Request statistics, the admin/UI rate-limit windows, the in-memory HMAC nonce
replay cache, the compiled-rule LRU caches and the background prune worker are
all per-process singletons. Running more than one worker against one config
directory does not fail — it silently splits that state, so counters undercount
and the rate limiter and replay cache admit N times what they should.

That is exactly the failure the docs warn about and nothing in the runtime ever
said. This module adds the two cheap signals ROADMAP R4 asks for: the pid and a
per-process instance id on ``/health`` and ``/ready``, so two replicas are
distinguishable in a probe response, and a startup ERROR when the environment
looks like it asked for more than one worker.

It deliberately does **not** refuse to start. A worker child usually cannot see
the parent's argv, so a hard check would produce both failure directions at
once: missed detections that break silently, and false positives that stop a
correctly configured deployment from booting. The reliable layer is the warning
plus the documentation.
"""

from __future__ import annotations

import os
import sys
import uuid

from aegisgate.util.logger import logger

# Regenerated per process, including per forked worker: that is the point — two
# replicas answering the same probe URL return different ids.
_INSTANCE_ID = uuid.uuid4().hex[:12]


def instance_id() -> str:
    """Stable-for-this-process identifier, short enough to eyeball in a probe."""
    return _INSTANCE_ID


def _worker_count_from_argv() -> int | None:
    argv = sys.argv[1:]
    for index, token in enumerate(argv):
        if token in {"--workers", "-w"} and index + 1 < len(argv):
            candidate = argv[index + 1]
        elif token.startswith("--workers="):
            candidate = token.split("=", 1)[1]
        else:
            continue
        try:
            return int(candidate)
        except ValueError:
            return None
    return None


def multiprocess_signal() -> str | None:
    """Describe why this looks like a multi-worker deployment, or ``None``.

    Env vars are checked first because they survive into worker children, which
    is where argv no longer helps.
    """
    for name in ("WEB_CONCURRENCY", "UVICORN_WORKERS", "GUNICORN_WORKERS"):
        raw = os.environ.get(name, "").strip()
        if not raw:
            continue
        try:
            if int(raw) > 1:
                return f"{name}={raw}"
        except ValueError:
            continue

    gunicorn_args = os.environ.get("GUNICORN_CMD_ARGS", "")
    if "--workers" in gunicorn_args or " -w " in f" {gunicorn_args} ":
        return "GUNICORN_CMD_ARGS contains a worker count"

    count = _worker_count_from_argv()
    if count is not None and count > 1:
        return f"--workers {count}"
    return None


def log_process_identity() -> None:
    """Emit the startup identity line, plus an ERROR when multi-worker is implied."""
    logger.info(
        "process identity pid=%s instance=%s",
        os.getpid(),
        _INSTANCE_ID,
    )
    signal = multiprocess_signal()
    if signal is None:
        return
    logger.error(
        "AegisGate is single-process only, but the environment implies multiple "
        "workers (%s). Request statistics, admin/UI rate limiting, the in-memory "
        "HMAC nonce replay cache and the background prune worker are per-process "
        "singletons and will split silently across workers. Run one worker, or "
        "move to a Redis storage/nonce backend with separate config directories. "
        "See README 'Deployment Model'.",
        signal,
    )


def process_identity_payload() -> dict[str, object]:
    """The identity block shared by ``/health`` and ``/ready``."""
    payload: dict[str, object] = {"pid": os.getpid(), "instance": _INSTANCE_ID}
    signal = multiprocess_signal()
    if signal is not None:
        # Surfaced in the body as well as the log: whoever is debugging a
        # counter that undercounts is usually reading a probe, not the log.
        payload["multiprocess_warning"] = signal
    return payload
