"""Optional logging of dangerous response samples for offline analysis."""

from __future__ import annotations

import atexit
import hashlib
import json
import queue
import threading
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from aegisgate.config.settings import settings
from aegisgate.core.background_worker import (
    ensure_worker_thread,
    run_queue_worker,
    shutdown_queue_worker,
)
from aegisgate.util.logger import logger

_FALLBACK_LOG_PATH = Path("/tmp") / "aegisgate" / "dangerous_response_samples.jsonl"
_LOG_RETENTION_DAYS = 10
_LOG_PATH: Path | None = None
_LOG_PATH_CONFIG: str | None = None
_LOG_PATH_DATE: str | None = None
_LOG_PATH_LOCK = threading.Lock()

_LOG_QUEUE: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=10000)
_LOG_WORKER: threading.Thread | None = None
_LOG_WORKER_LOCK = threading.Lock()
_LOG_ATEXIT_REGISTERED = False


def _reset_log_path_cache() -> None:
    global _LOG_PATH, _LOG_PATH_CONFIG, _LOG_PATH_DATE
    _LOG_PATH = None
    _LOG_PATH_CONFIG = None
    _LOG_PATH_DATE = None


def merge_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(
        (max(0, start), max(0, end)) for start, end in spans if end > start
    ):
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
            continue
        prev_start, prev_end = merged[-1]
        merged[-1] = (prev_start, max(prev_end, end))
    return merged


def mark_text_with_spans(
    text: str, spans: list[tuple[int, int]], *, delimiter: str = "--"
) -> str:
    source = str(text or "")
    if not source:
        return source

    merged = merge_spans(spans)
    if not merged:
        return source

    parts: list[str] = []
    cursor = 0
    for start, end in merged:
        parts.append(source[cursor:start])
        parts.append(f"{delimiter}{source[start:end]}{delimiter}")
        cursor = end
    parts.append(source[cursor:])
    return "".join(parts)


def _can_append_file(path: Path) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8"):
            pass
        return True
    except OSError:
        return False


def _current_log_date() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")


def _dated_log_path(path: Path, date_str: str) -> Path:
    suffix = path.suffix
    stem = path.name[: -len(suffix)] if suffix else path.name
    filename = f"{stem}-{date_str}{suffix}"
    return path.with_name(filename)


def _parse_log_date(value: str) -> date | None:
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None


def _extract_dated_log_date(path: Path, base_path: Path) -> date | None:
    suffix = base_path.suffix
    base_stem = base_path.name[: -len(suffix)] if suffix else base_path.name
    candidate_name = path.name
    if suffix:
        if not candidate_name.endswith(suffix):
            return None
        candidate_name = candidate_name[: -len(suffix)]

    prefix = f"{base_stem}-"
    if not candidate_name.startswith(prefix):
        return None
    return _parse_log_date(candidate_name[len(prefix) :])


def _prune_old_log_files(base_path: Path, current_date: str) -> None:
    today = _parse_log_date(current_date)
    if today is None:
        return

    cutoff_date = today - timedelta(days=_LOG_RETENTION_DAYS - 1)
    try:
        entries = list(base_path.parent.iterdir())
    except OSError:
        return

    for entry in entries:
        if not entry.is_file():
            continue
        entry_date = _extract_dated_log_date(entry, base_path)
        if entry_date is None or entry_date >= cutoff_date:
            continue
        try:
            entry.unlink()
        except OSError as exc:
            logger.warning(
                "dangerous response log prune failed path=%s error=%s", entry, exc
            )


def _resolve_log_path() -> Path | None:
    global _LOG_PATH, _LOG_PATH_CONFIG, _LOG_PATH_DATE
    configured_path = (settings.dangerous_response_log_path or "").strip()
    current_date = _current_log_date()

    if (
        _LOG_PATH is not None
        and _LOG_PATH_CONFIG == configured_path
        and _LOG_PATH_DATE == current_date
    ):
        return _LOG_PATH

    with _LOG_PATH_LOCK:
        configured_path = (settings.dangerous_response_log_path or "").strip()
        current_date = _current_log_date()
        if (
            _LOG_PATH is not None
            and _LOG_PATH_CONFIG == configured_path
            and _LOG_PATH_DATE == current_date
        ):
            return _LOG_PATH

        if not configured_path:
            logger.warning("dangerous response log path empty, disable sample logging")
            _LOG_PATH = None
            _LOG_PATH_CONFIG = configured_path
            _LOG_PATH_DATE = current_date
            return None

        configured_base = Path(configured_path)
        _prune_old_log_files(configured_base, current_date)
        configured = _dated_log_path(configured_base, current_date)
        if _can_append_file(configured):
            _LOG_PATH = configured
            _LOG_PATH_CONFIG = configured_path
            _LOG_PATH_DATE = current_date
            return _LOG_PATH

        if configured_base != _FALLBACK_LOG_PATH:
            _prune_old_log_files(_FALLBACK_LOG_PATH, current_date)
        fallback = _dated_log_path(_FALLBACK_LOG_PATH, current_date)
        if _can_append_file(fallback):
            _LOG_PATH = fallback
            _LOG_PATH_CONFIG = configured_path
            _LOG_PATH_DATE = current_date
            logger.warning(
                "dangerous response log path not writable, switched to fallback configured=%s fallback=%s",
                configured,
                fallback,
            )
            return _LOG_PATH

        _LOG_PATH = None
        _LOG_PATH_CONFIG = configured_path
        _LOG_PATH_DATE = current_date
        logger.warning(
            "dangerous response log path unavailable, disable sample logging configured=%s fallback=%s",
            configured,
            fallback,
        )
        return None


def _append_payload(payload: dict[str, Any]) -> None:
    path = _resolve_log_path()
    if path is None:
        return
    try:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except OSError as exc:
        logger.warning("dangerous response log write failed: %s", exc)


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _fragment_metadata(fragments: list[str]) -> list[dict[str, Any]]:
    metadata: list[dict[str, Any]] = []
    for fragment in fragments:
        metadata.append(
            {
                "sha256": _digest_text(fragment),
                "length": len(fragment),
            }
        )
    return metadata


def _prepare_event_payload(event: dict[str, Any]) -> dict[str, Any]:
    payload = dict(event)
    include_raw_content = bool(payload.pop("include_raw_content", False))
    include_raw_fragments = bool(payload.pop("include_raw_fragments", False))

    raw_fragments = payload.get("dangerous_fragments")
    fragments = (
        [str(fragment) for fragment in raw_fragments if str(fragment)]
        if isinstance(raw_fragments, list)
        else []
    )
    if fragments and not include_raw_fragments:
        payload.pop("dangerous_fragments", None)
        payload["dangerous_fragments_redacted"] = True
        payload["dangerous_fragments_metadata"] = _fragment_metadata(fragments)

    raw_content = payload.get("content")
    if isinstance(raw_content, str) and raw_content and not include_raw_content:
        payload.pop("content", None)
        payload["content_redacted"] = True
        payload["content_metadata"] = {
            "sha256": _digest_text(raw_content),
            "length": len(raw_content),
        }

    return payload


def _worker_loop() -> None:
    run_queue_worker(
        _LOG_QUEUE,
        _append_payload,
        on_error=lambda exc: logger.warning(
            "dangerous response log worker failed: %s", exc
        ),
    )


def _register_shutdown_handler() -> None:
    global _LOG_ATEXIT_REGISTERED
    if _LOG_ATEXIT_REGISTERED:
        return
    atexit.register(shutdown_dangerous_response_log_worker)
    _LOG_ATEXIT_REGISTERED = True


def _ensure_worker() -> None:
    global _LOG_WORKER
    _register_shutdown_handler()
    _LOG_WORKER = ensure_worker_thread(
        _LOG_WORKER,
        lock=_LOG_WORKER_LOCK,
        build_thread=lambda: threading.Thread(
            target=_worker_loop,
            name="aegisgate-dangerous-response-log",
            daemon=False,
        ),
    )


def write_dangerous_response_sample(event: dict[str, Any]) -> None:
    if not settings.enable_dangerous_response_log:
        return

    payload = {
        "ts": datetime.now(tz=timezone.utc).isoformat(),
        **_prepare_event_payload(event),
    }
    _ensure_worker()
    try:
        _LOG_QUEUE.put_nowait(payload)
    except queue.Full:  # pragma: no cover - overload safeguard
        _append_payload(payload)
        logger.warning(
            "dangerous response log queue full, fallback to sync write request_id=%s",
            event.get("request_id", "unknown"),
        )


def shutdown_dangerous_response_log_worker(timeout_seconds: float = 1.0) -> None:
    global _LOG_WORKER
    if _LOG_WORKER is None:
        _reset_log_path_cache()
        return
    _LOG_WORKER = shutdown_queue_worker(
        _LOG_WORKER,
        work_queue=_LOG_QUEUE,
        timeout_seconds=timeout_seconds,
        on_queue_full=lambda: logger.warning(
            "dangerous response log shutdown queue full, waiting for worker drain"
        ),
        on_timeout=lambda timeout: logger.warning(
            "dangerous response log worker did not stop within %.2fs", timeout
        ),
    )
    if _LOG_WORKER is not None:
        return
    _reset_log_path_cache()
