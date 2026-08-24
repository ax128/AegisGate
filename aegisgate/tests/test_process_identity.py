"""Guards for the single-process signal (ROADMAP R4, layer 1).

The failure this exists to make visible is silent: with more than one worker the
per-process singletons split, counters undercount and the rate limiter and nonce
replay cache admit N times what they should — and nothing anywhere said so.
"""

from __future__ import annotations

import os

import pytest

from aegisgate.core.process_identity import (
    instance_id,
    log_process_identity,
    multiprocess_signal,
    process_identity_payload,
)

_WORKER_ENV_VARS = (
    "WEB_CONCURRENCY",
    "UVICORN_WORKERS",
    "GUNICORN_WORKERS",
    "GUNICORN_CMD_ARGS",
)


@pytest.fixture(autouse=True)
def _clean_worker_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """A CI runner that sets WEB_CONCURRENCY must not flip these assertions."""
    for name in _WORKER_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("sys.argv", ["pytest"])


def test_instance_id_is_stable_within_a_process() -> None:
    assert instance_id() == instance_id()
    assert len(instance_id()) == 12


def test_payload_carries_pid_and_instance() -> None:
    payload = process_identity_payload()
    assert payload["pid"] == os.getpid()
    assert payload["instance"] == instance_id()


def test_single_worker_environment_is_quiet() -> None:
    assert multiprocess_signal() is None
    assert "multiprocess_warning" not in process_identity_payload()


@pytest.mark.parametrize(
    ("env_name", "value"),
    [
        ("WEB_CONCURRENCY", "4"),
        ("UVICORN_WORKERS", "2"),
        ("GUNICORN_WORKERS", "8"),
    ],
)
def test_worker_env_vars_are_detected(
    monkeypatch: pytest.MonkeyPatch, env_name: str, value: str
) -> None:
    monkeypatch.setenv(env_name, value)
    signal = multiprocess_signal()
    assert signal == f"{env_name}={value}"
    assert process_identity_payload()["multiprocess_warning"] == signal


@pytest.mark.parametrize("value", ["1", "0", "", "  ", "not-a-number"])
def test_one_worker_or_junk_does_not_warn(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """``WEB_CONCURRENCY=1`` is the correct configuration, not a problem."""
    monkeypatch.setenv("WEB_CONCURRENCY", value)
    assert multiprocess_signal() is None


@pytest.mark.parametrize(
    "argv",
    [
        ["uvicorn", "aegisgate.core.gateway:app", "--workers", "4"],
        ["uvicorn", "aegisgate.core.gateway:app", "--workers=3"],
        ["uvicorn", "aegisgate.core.gateway:app", "-w", "2"],
    ],
)
def test_worker_argv_is_detected(
    monkeypatch: pytest.MonkeyPatch, argv: list[str]
) -> None:
    monkeypatch.setattr("sys.argv", argv)
    assert multiprocess_signal() is not None


def test_single_worker_argv_is_quiet(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "sys.argv", ["uvicorn", "aegisgate.core.gateway:app", "--workers", "1"]
    )
    assert multiprocess_signal() is None


def test_gunicorn_cmd_args_is_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUNICORN_CMD_ARGS", "--workers 4 --timeout 600")
    assert multiprocess_signal() == "GUNICORN_CMD_ARGS contains a worker count"


def test_detection_never_raises_on_malformed_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Detection runs on every /health call — it must never be the thing that 500s."""
    monkeypatch.setenv("WEB_CONCURRENCY", "four")
    monkeypatch.setenv("UVICORN_WORKERS", "-∞")
    monkeypatch.setattr("sys.argv", ["uvicorn", "--workers"])  # value missing
    assert multiprocess_signal() is None

    monkeypatch.setattr("sys.argv", ["uvicorn", "--workers", "many"])
    assert multiprocess_signal() is None


def _captured_errors(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Collect ERROR calls on the package logger.

    ``aegisgate.util.logger`` sets ``propagate = False``, so ``caplog`` (which
    attaches to the root logger) never sees these records.
    """
    import aegisgate.core.process_identity as module

    recorded: list[str] = []

    class _Recorder:
        def info(self, *args: object, **kwargs: object) -> None:
            pass

        def error(self, message: str, *args: object, **kwargs: object) -> None:
            recorded.append(str(message) % args if args else str(message))

    monkeypatch.setattr(module, "logger", _Recorder())
    return recorded


def test_log_process_identity_reports_multi_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    errors = _captured_errors(monkeypatch)
    log_process_identity()
    assert len(errors) == 1
    assert "single-process only" in errors[0]
    assert "WEB_CONCURRENCY=4" in errors[0]


def test_log_process_identity_is_silent_for_one_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    errors = _captured_errors(monkeypatch)
    log_process_identity()
    assert errors == []
