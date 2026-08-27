"""Exact-value redaction: load, save, and replace configured sensitive strings.

Values are stored encrypted in ``config/redact_values.enc.json`` using the
same Fernet key as the rest of the system.  The module caches the decrypted
list and refreshes automatically when the file's mtime changes.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from collections.abc import Iterable, Sequence
from pathlib import Path

from cryptography.fernet import InvalidToken

from aegisgate.config.paths import config_dir
from aegisgate.storage.crypto import _get_fernet
from aegisgate.util.logger import logger

_PLACEHOLDER = "[REDACTED:EXACT_VALUE]"
_MIN_VALUE_LENGTH = 10


def _acceptable_value(value: object) -> bool:
    """The contract :func:`save_redact_values` enforces, re-checked on read.

    That validator is the only *writer*, but it is not the only way bytes reach
    the file: a hand-edited copy, a restored backup or one written by an older
    build can hold a short or non-string entry. The empty string is the one that
    matters — ``"" in text`` is always true and ``text.replace("", ...)`` fires
    between every character, so a single empty entry turns each message into a
    wall of placeholders while raising nothing at all.
    """
    return isinstance(value, str) and len(value) >= _MIN_VALUE_LENGTH


_lock = threading.Lock()
_cached_values: list[str] | None = None
_cached_mtime_ns: int = 0
# True when the last load could not read the file's *contents*, as opposed to
# reading it and finding nothing. The two look identical to every caller of
# :func:`load_redact_values` — both are an empty list — and they must not, because
# one of them means the configured values are still on disk and unreadable.
_load_degraded: bool = False


_cached_path: tuple[tuple[str, str], Path] | None = None


def _config_path() -> Path:
    """Resolve the values file, memoised on ``(AEGIS_CONFIG_DIR, cwd)``.

    ``Path.resolve()`` walks the whole realpath chain, and this runs on the
    per-response hot path via :func:`load_redact_values`. Keying the cache on
    the env var and cwd keeps it reactive to both (tests change either one).
    cwd stays in the key even when the env var is set, because a relative
    ``AEGIS_CONFIG_DIR`` resolves against cwd too; ``Path.cwd()`` is ~3 orders
    of magnitude cheaper than the ``resolve()`` this cache exists to avoid.
    Stored as a single tuple so concurrent readers never see a key/path pair
    from two different snapshots.
    """
    global _cached_path

    env = os.environ.get("AEGIS_CONFIG_DIR", "").strip()
    key = (env, str(Path.cwd()))
    cached = _cached_path
    if cached is not None and cached[0] == key:
        return cached[1]
    path = config_dir() / "redact_values.enc.json"
    _cached_path = (key, path)
    return path


def load_redact_values() -> list[str]:
    """Return the list of exact values to redact (mtime-cached, thread-safe)."""
    global _cached_values, _cached_mtime_ns, _load_degraded

    path = _config_path()
    with _lock:
        if not path.is_file():
            # Nothing configured yet is not a degraded read: there is no content
            # being hidden from us, and writing here cannot discard anything.
            _cached_values = []
            _cached_mtime_ns = 0
            _load_degraded = False
            return []

        # Serialize reloads so concurrent callers do not race to refresh the
        # cache from different file snapshots.
        try:
            mtime_ns = path.stat().st_mtime_ns
        except OSError:
            return list(_cached_values) if _cached_values is not None else []
        if _cached_values is not None and _cached_mtime_ns == mtime_ns:
            return list(_cached_values)

        degraded = False
        try:
            encrypted = path.read_text(encoding="utf-8").strip()
            if not encrypted:
                values: list[str] = []
            else:
                fernet = _get_fernet()
                raw = fernet.decrypt(encrypted.encode("utf-8"))
                data = json.loads(raw.decode("utf-8"))
                raw_values = data.get("values") if isinstance(data, dict) else None
                if not isinstance(raw_values, list):
                    # A mapping here used to be accepted by ``list(...)``, which
                    # silently promotes its *keys* into redaction values.
                    raise ValueError(
                        f"'values' must be a list, got {type(raw_values).__name__}"
                    )
                values = [item for item in raw_values if _acceptable_value(item)]
                dropped = len(raw_values) - len(values)
                if dropped:
                    # Counts only: the entries themselves are the secrets this
                    # module exists to keep out of logs.
                    logger.warning(
                        "redact_values: dropped %d invalid entries from %s "
                        "(each value must be a string of at least %d characters)",
                        dropped,
                        path,
                        _MIN_VALUE_LENGTH,
                    )
        except (OSError, ValueError, InvalidToken, json.JSONDecodeError) as exc:
            # InvalidToken is not a ValueError, so ciphertext this key cannot
            # open used to escape into the request pipeline, where it reads as a
            # filter crash and blocks every request until the file is rebuilt.
            # Rotating the Fernet key is enough to trigger it.
            logger.warning(
                "redact_values: failed to load %s error=%s, treating as empty",
                path,
                f"{type(exc).__name__}: {exc}",
            )
            values = []
            degraded = True

        _cached_values = values
        _cached_mtime_ns = mtime_ns
        # Set with the values it describes, under the same lock, so the flag and
        # the list can never be read as belonging to two different loads.
        _load_degraded = degraded
        return list(values)


def redact_values_degraded() -> bool:
    """True when the last load could not read the file's contents.

    Distinct from "nothing is configured": a missing or empty file is an honest
    empty list, but a file this key cannot open — or whose payload is not a list
    — leaves real values on disk that this process cannot see. Anything that
    would rewrite the file has to refuse while that is true, because the
    load-append-save the console does would replace those values with whatever
    is being added, and the originals are not recoverable.

    Reflects the most recent :func:`load_redact_values`, so callers that care
    should load first — the loader is mtime-cached and will re-read a file that
    changed underneath them.
    """
    with _lock:
        return _load_degraded


def save_redact_values(values: Iterable[object]) -> None:
    """Validate, encrypt, and atomically write the values list."""
    clean: list[str] = []
    seen: set[str] = set()
    for v in values:
        if not isinstance(v, str):
            continue
        v = v.strip()
        if len(v) < _MIN_VALUE_LENGTH:
            raise ValueError(
                f"每个值至少 {_MIN_VALUE_LENGTH} 个字符，当前长度 {len(v)}"
            )
        if v in seen:
            continue
        seen.add(v)
        clean.append(v)

    data = json.dumps({"values": clean}, ensure_ascii=False).encode("utf-8")
    fernet = _get_fernet()
    encrypted = fernet.encrypt(data).decode("utf-8")

    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", delete=False, dir=str(path.parent), suffix=".tmp"
    ) as tmp:
        tmp.write(encrypted)
        tmp_path = Path(tmp.name)
    tmp_path.replace(path)

    global _cached_values, _cached_mtime_ns, _load_degraded
    with _lock:
        _cached_values = clean
        _cached_mtime_ns = path.stat().st_mtime_ns
        # Whatever was unreadable before, the bytes now on disk are ours.
        _load_degraded = False

    logger.info("redact_values: saved %d values to %s", len(clean), path)


def replace_exact_values_from(text: str, values: Sequence[str]) -> tuple[str, int]:
    """Replace every entry of *values* in *text*.

    Split out from :func:`replace_exact_values` so a caller walking thousands of
    string leaves can resolve the list **once** instead of re-reading it (and
    re-``stat``-ing the file behind it) per leaf. An empty list returns the text
    unchanged and untouched.
    """
    if not values or not text:
        return text, 0

    # Sort by length descending so longer values match first.
    sorted_values = sorted(values, key=len, reverse=True)
    count = 0
    for val in sorted_values:
        if val in text:
            n = text.count(val)
            text = text.replace(val, _PLACEHOLDER)
            count += n
    return text, count


def replace_exact_values(text: str) -> tuple[str, int]:
    """Replace all configured exact values in *text*.

    Returns ``(replaced_text, replacement_count)``.  Values are matched
    longest-first to avoid partial replacements.
    """
    return replace_exact_values_from(text, load_redact_values())
