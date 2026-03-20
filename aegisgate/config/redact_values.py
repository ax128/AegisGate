"""Exact-value redaction: load, save, and replace configured sensitive strings.

Values are stored encrypted in ``config/redact_values.enc.json`` using the
same Fernet key as the rest of the system.  The module caches the decrypted
list and refreshes automatically when the file's mtime changes.
"""

from __future__ import annotations

import json
import tempfile
import threading
from pathlib import Path

from aegisgate.storage.crypto import _get_fernet
from aegisgate.util.logger import logger

_PLACEHOLDER = "[REDACTED:EXACT_VALUE]"
_MIN_VALUE_LENGTH = 10

_lock = threading.Lock()
_cached_values: list[str] | None = None
_cached_mtime_ns: int = 0


def _config_path() -> Path:
    import os

    env = os.environ.get("AEGIS_CONFIG_DIR", "").strip()
    base = Path(env).resolve() if env else (Path.cwd() / "config").resolve()
    return base / "redact_values.enc.json"


def load_redact_values() -> list[str]:
    """Return the list of exact values to redact (mtime-cached, thread-safe)."""
    global _cached_values, _cached_mtime_ns

    path = _config_path()
    with _lock:
        if not path.is_file():
            _cached_values = []
            _cached_mtime_ns = 0
            return []

        # Serialize reloads so concurrent callers do not race to refresh the
        # cache from different file snapshots.
        try:
            mtime_ns = path.stat().st_mtime_ns
        except OSError:
            return list(_cached_values) if _cached_values is not None else []
        if _cached_values is not None and _cached_mtime_ns == mtime_ns:
            return list(_cached_values)

        try:
            encrypted = path.read_text(encoding="utf-8").strip()
            if not encrypted:
                values: list[str] = []
            else:
                fernet = _get_fernet()
                raw = fernet.decrypt(encrypted.encode("utf-8"))
                data = json.loads(raw.decode("utf-8"))
                values = list(data.get("values", []))
        except Exception:
            logger.warning("redact_values: failed to load %s, treating as empty", path)
            values = []

        _cached_values = values
        _cached_mtime_ns = mtime_ns
        return list(values)


def save_redact_values(values: list[str]) -> None:
    """Validate, encrypt, and atomically write the values list."""
    clean: list[str] = []
    seen: set[str] = set()
    for v in values:
        if not isinstance(v, str):
            continue
        v = v.strip()
        if len(v) < _MIN_VALUE_LENGTH:
            raise ValueError(f"每个值至少 {_MIN_VALUE_LENGTH} 个字符，当前长度 {len(v)}")
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

    global _cached_values, _cached_mtime_ns
    with _lock:
        _cached_values = clean
        _cached_mtime_ns = path.stat().st_mtime_ns

    logger.info("redact_values: saved %d values to %s", len(clean), path)


def replace_exact_values(text: str) -> tuple[str, int]:
    """Replace all configured exact values in *text*.

    Returns ``(replaced_text, replacement_count)``.  Values are matched
    longest-first to avoid partial replacements.
    """
    values = load_redact_values()
    if not values:
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
