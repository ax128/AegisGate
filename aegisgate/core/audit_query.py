"""Bounded reverse reader over the JSONL audit and dangerous-sample logs.

The gateway writes one structured record per request to ``logs/audit.jsonl``
(risk score, dispositions, reasons, security tags, enforcement actions) and never
rotates it, so on a long-running instance the file reaches hundreds of megabytes.
Any query path that calls ``read_text()`` or ``readlines()`` would take the
gateway down with it.

So reading works backwards from the end in fixed chunks, newest record first,
stopping at whichever comes first: enough matches, a byte budget, or the start of
the file. Callers page with an opaque byte offset. Nothing here holds more than
one chunk plus one page of results in memory.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from aegisgate.util.logger import logger

DEFAULT_LIMIT = 50
MAX_LIMIT = 200
MAX_EXPORT_LIMIT = 5_000
# Per-request ceiling on how much of the tail we are willing to walk. A filter
# that matches nothing stops here instead of reading the whole file.
DEFAULT_MAX_SCAN_BYTES = 8 * 1024 * 1024
_CHUNK_SIZE = 64 * 1024


@dataclass
class AuditFilter:
    """Filter set for one query. Every field is optional; unset means "any"."""

    since: datetime | None = None
    until: datetime | None = None
    route: str = ""
    disposition: str = ""
    min_risk: float | None = None
    tag: str = ""
    event: str = ""
    request_id: str = ""
    text: str = ""

    def is_empty(self) -> bool:
        return not any(
            (
                self.since,
                self.until,
                self.route,
                self.disposition,
                self.min_risk is not None,
                self.tag,
                self.event,
                self.request_id,
                self.text,
            )
        )


@dataclass
class QueryResult:
    items: list[dict[str, Any]] = field(default_factory=list)
    next_cursor: int | None = None
    scanned_bytes: int = 0
    reached_start: bool = False
    budget_exhausted: bool = False
    file_size: int = 0
    malformed_lines: int = 0


def parse_timestamp(value: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp, tolerating a trailing ``Z``.

    Returns ``None`` for empty or unparseable input; callers treat that as
    "no bound" rather than failing the whole query on one bad parameter.
    """
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _record_time(record: dict[str, Any]) -> datetime | None:
    return parse_timestamp(record.get("ts"))


def _as_float(value: object) -> float | None:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def matches(record: dict[str, Any], criteria: AuditFilter, raw_line: str) -> bool:
    """Return whether *record* satisfies every set field of *criteria*."""
    if criteria.request_id and str(record.get("request_id", "")) != criteria.request_id:
        return False

    if criteria.since or criteria.until:
        stamp = _record_time(record)
        if stamp is None:
            return False
        if criteria.since and stamp < criteria.since:
            return False
        if criteria.until and stamp > criteria.until:
            return False

    if criteria.route and criteria.route not in str(record.get("route", "")):
        return False

    if criteria.disposition:
        dispositions = {
            str(record.get("request_disposition", "")),
            str(record.get("response_disposition", "")),
        }
        if criteria.disposition not in dispositions:
            return False

    if criteria.min_risk is not None:
        risk = _as_float(record.get("risk_score"))
        if risk is None or risk < criteria.min_risk:
            return False

    if criteria.tag:
        tags = record.get("security_tags")
        if not isinstance(tags, list) or criteria.tag not in {str(t) for t in tags}:
            return False

    if criteria.event and not str(record.get("event", "")).startswith(criteria.event):
        return False

    if criteria.text and criteria.text.lower() not in raw_line.lower():
        return False

    return True


def iter_lines_reverse(
    path: Path, end_offset: int, max_scan_bytes: int
) -> Iterator[tuple[str, int, int]]:
    """Yield ``(line, line_start_offset, bytes_scanned_so_far)``, newest first.

    Reads fixed-size chunks backwards from *end_offset*. A line straddling a
    chunk boundary is carried over and emitted once the earlier chunk supplies
    its beginning, so no record is ever split or lost.
    """
    scanned = 0
    carry = b""
    position = end_offset
    with path.open("rb") as handle:
        while position > 0 and scanned < max_scan_bytes:
            read_size = min(_CHUNK_SIZE, position, max_scan_bytes - scanned)
            position -= read_size
            handle.seek(position)
            chunk = handle.read(read_size)
            scanned += len(chunk)

            buffer = chunk + carry
            pieces = buffer.split(b"\n")
            # pieces[0] may be the tail of a line whose start lies further back.
            carry = pieces[0]

            offsets: list[int] = []
            cursor = position
            for piece in pieces:
                offsets.append(cursor)
                cursor += len(piece) + 1

            for index in range(len(pieces) - 1, 0, -1):
                raw = pieces[index]
                if not raw.strip():
                    continue
                yield raw.decode("utf-8", "replace"), offsets[index], scanned

        if position == 0 and carry.strip() and scanned <= max_scan_bytes:
            yield carry.decode("utf-8", "replace"), 0, scanned


def query_log(
    path: Path,
    criteria: AuditFilter | None = None,
    *,
    cursor: int | None = None,
    limit: int = DEFAULT_LIMIT,
    max_scan_bytes: int = DEFAULT_MAX_SCAN_BYTES,
) -> QueryResult:
    """Return up to *limit* matching records from *path*, newest first."""
    criteria = criteria or AuditFilter()
    limit = max(1, min(int(limit), MAX_EXPORT_LIMIT))
    result = QueryResult()

    try:
        file_size = path.stat().st_size
    except OSError:
        result.reached_start = True
        return result
    result.file_size = file_size

    end_offset = file_size if cursor is None else max(0, min(int(cursor), file_size))
    if end_offset == 0:
        result.reached_start = True
        return result

    last_offset = end_offset
    for raw_line, offset, scanned in iter_lines_reverse(path, end_offset, max_scan_bytes):
        last_offset = offset
        result.scanned_bytes = scanned
        try:
            record = json.loads(raw_line)
        except (ValueError, TypeError):
            result.malformed_lines += 1
            continue
        if not isinstance(record, dict):
            result.malformed_lines += 1
            continue
        if matches(record, criteria, raw_line):
            record["_offset"] = offset
            result.items.append(record)
            if len(result.items) >= limit:
                result.next_cursor = offset
                return result

    if result.scanned_bytes >= end_offset:
        # Walked all the way to byte 0; there is nothing older to page into.
        result.reached_start = True
        result.next_cursor = None
    else:
        # Stopped on the byte budget rather than the start of the file: hand back
        # a cursor so the caller can decide whether to keep walking. Always make
        # progress, even on a stretch of the file that yielded no parsable line.
        result.budget_exhausted = True
        result.next_cursor = (
            last_offset
            if last_offset < end_offset
            else max(0, end_offset - result.scanned_bytes)
        )
    return result


def summarize_log(
    path: Path,
    criteria: AuditFilter | None = None,
    *,
    max_scan_bytes: int = DEFAULT_MAX_SCAN_BYTES,
    max_records: int = 20_000,
) -> dict[str, Any]:
    """Aggregate the tail of *path* into counts the overview panel can render."""
    criteria = criteria or AuditFilter()
    try:
        file_size = path.stat().st_size
    except OSError:
        return {
            "available": False,
            "records": 0,
            "file_size": 0,
            "dispositions": {},
            "routes": [],
            "tags": [],
            "risk_buckets": {},
            "complete": True,
        }

    dispositions: dict[str, int] = {}
    routes: dict[str, int] = {}
    tags: dict[str, int] = {}
    risk_buckets = {"0.0-0.3": 0, "0.3-0.7": 0, "0.7-1.0": 0}
    records = 0
    oldest: str | None = None
    newest: str | None = None
    complete = True

    for raw_line, offset, _scanned in iter_lines_reverse(path, file_size, max_scan_bytes):
        if records >= max_records:
            complete = False
            break
        try:
            record = json.loads(raw_line)
        except (ValueError, TypeError):
            continue
        if not isinstance(record, dict) or not matches(record, criteria, raw_line):
            continue
        records += 1

        stamp = str(record.get("ts") or "")
        if stamp:
            if newest is None:
                newest = stamp
            oldest = stamp

        for key in ("request_disposition", "response_disposition"):
            value = str(record.get(key) or "")
            if value:
                dispositions[f"{key}:{value}"] = dispositions.get(f"{key}:{value}", 0) + 1

        route = str(record.get("route") or record.get("event") or "")
        if route:
            routes[route] = routes.get(route, 0) + 1

        raw_tags = record.get("security_tags")
        if isinstance(raw_tags, list):
            for tag in raw_tags:
                key = str(tag)
                tags[key] = tags.get(key, 0) + 1

        risk = _as_float(record.get("risk_score"))
        if risk is not None:
            if risk < 0.3:
                risk_buckets["0.0-0.3"] += 1
            elif risk < 0.7:
                risk_buckets["0.3-0.7"] += 1
            else:
                risk_buckets["0.7-1.0"] += 1
        if offset == 0:
            break
    else:
        complete = file_size <= max_scan_bytes

    def top(counter: dict[str, int], size: int = 10) -> list[dict[str, Any]]:
        ordered = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:size]
        return [{"key": key, "count": count} for key, count in ordered]

    return {
        "available": True,
        "records": records,
        "file_size": file_size,
        "oldest_ts": oldest,
        "newest_ts": newest,
        "dispositions": dispositions,
        "routes": top(routes),
        "tags": top(tags),
        "risk_buckets": risk_buckets,
        "complete": complete,
    }


def resolve_audit_path() -> Path | None:
    """Configured audit log path, or ``None`` when auditing is switched off."""
    from aegisgate.config.settings import settings

    raw = (settings.audit_log_path or "").strip()
    if not raw:
        return None
    path = Path(raw)
    if not path.is_absolute():
        path = Path.cwd() / path
    return path


def list_dangerous_sample_dates() -> list[dict[str, Any]]:
    """Available dangerous-response sample files, newest date first."""
    from aegisgate.config.settings import settings
    from aegisgate.core.dangerous_response_log import _extract_dated_log_date

    raw = (settings.dangerous_response_log_path or "").strip()
    if not raw:
        return []
    base = Path(raw)
    if not base.is_absolute():
        base = Path.cwd() / base
    try:
        entries = list(base.parent.iterdir())
    except OSError:
        return []

    found: list[dict[str, Any]] = []
    for entry in entries:
        if not entry.is_file():
            continue
        entry_date = _extract_dated_log_date(entry, base)
        if entry_date is None:
            continue
        try:
            size = entry.stat().st_size
        except OSError:
            continue
        found.append({"date": entry_date.isoformat(), "size": size})
    found.sort(key=lambda item: item["date"], reverse=True)
    return found


def resolve_dangerous_sample_path(date_str: str) -> Path | None:
    """Path for one dated sample file, or ``None`` if the date is not on disk.

    The date is matched against the enumerated files rather than interpolated
    into a path, so a caller cannot steer this at an arbitrary file.
    """
    from aegisgate.config.settings import settings
    from aegisgate.core.dangerous_response_log import _dated_log_path

    if date_str not in {item["date"] for item in list_dangerous_sample_dates()}:
        return None
    raw = (settings.dangerous_response_log_path or "").strip()
    if not raw:
        return None
    base = Path(raw)
    if not base.is_absolute():
        base = Path.cwd() / base
    candidate = _dated_log_path(base, date_str)
    if not candidate.is_file():  # pragma: no cover - enumerated above
        logger.warning("dangerous sample file vanished path=%s", candidate)
        return None
    return candidate
