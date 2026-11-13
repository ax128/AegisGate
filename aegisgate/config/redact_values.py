"""Exact-value redaction: load, save, and replace configured sensitive strings.

Values are stored encrypted in ``config/redact_values.enc.json`` using the
same Fernet key as the rest of the system.  The module caches the decrypted
list and refreshes automatically when the file's mtime changes.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import unicodedata
from collections.abc import Iterable, Sequence
from contextvars import ContextVar
from pathlib import Path

from cryptography.fernet import InvalidToken

from aegisgate.config.paths import config_dir
from aegisgate.storage.crypto import _get_fernet
from aegisgate.util.logger import logger
from aegisgate.util.text_normalize import (
    DEFAULT_BIDI_CHARS,
    DEFAULT_INVISIBLE_CHARS,
    strip_invisibles,
)

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


# A host-forwarding rule may switch exact-value redaction on or off for its own
# domain. The V1 transport layer (openai_compat.sanitize / renderers) resolves the
# value list without a RequestContext in reach, so the rule's switch reaches it
# through the request task's context instead: ``_apply_filter_mode`` sets it for
# every V1 request (``None`` when no rule overrides), and each request runs in its
# own task, so the value never outlives the request that set it.
_exact_value_override: ContextVar[bool | None] = ContextVar(
    "aegis_exact_value_override", default=None
)


def set_exact_value_override(value: bool | None) -> None:
    """Pin the current request's exact-value switch; ``None`` means the global one."""
    _exact_value_override.set(value)


def exact_value_redaction_active() -> bool:
    """The effective switch: a forward rule's override, else the global setting."""
    override = _exact_value_override.get()
    if override is not None:
        return override
    from aegisgate.config.settings import settings

    return bool(settings.enable_exact_value_redaction)


def active_exact_values() -> tuple[str, ...]:
    """The configured values, snapshotted once for one payload/body walk.

    :func:`load_redact_values` is mtime-cached but still takes the lock and
    ``stat``s the file on every call, and the callers that matter walk every
    string leaf of a request or a response. Resolve once and thread the tuple
    down; an empty tuple turns the per-leaf step into a single truth test.

    Returns an empty tuple when the feature is off, so callers do not have to
    check the flag separately. "Off" follows :func:`exact_value_redaction_active`.
    """
    if not exact_value_redaction_active():
        return ()
    return tuple(load_redact_values())


# One compiled alternation, keyed on the value list it was built from. A single
# slot rather than an lru_cache: the entries hold the operator's secrets, and a
# cache with history would keep every superseded configuration's plaintext alive
# for as long as the process runs. Replacing the slot lets the old one be
# collected, which is the lifetime load_redact_values' own cache already has.
#
# Unlocked on purpose, like _cached_path: rebinding one tuple is atomic, and the
# worst a race can do is compile the same pattern twice.
_pattern_cache: tuple[tuple[str, ...], re.Pattern[str] | None] | None = None


def _exact_value_pattern(values: tuple[str, ...]) -> re.Pattern[str] | None:
    """One alternation matching any configured value, longest first.

    The loop this replaces scanned the whole text once per configured value, and
    it runs on every string leaf of every forwarded payload — including the
    base64 data URIs the blob heuristic used to skip before exact values were
    moved ahead of it. On a 2.6 MB leaf with 50 values configured that was
    ~36 ms; one alternation is ~1.4 ms regardless of how many values there are.

    Longest-first ordering is what preserves the loop's semantics: Python's
    ``|`` takes the first alternative that matches at a position, so a value
    that is a prefix of a longer one must come second. Empty strings are dropped
    — as an alternative one would match at every position, and in the old loop
    ``"" in text`` was likewise always true.
    """
    global _pattern_cache

    cached = _pattern_cache
    if cached is not None and cached[0] == values:
        return cached[1]

    usable = sorted({value for value in values if value}, key=len, reverse=True)
    pattern = (
        re.compile("|".join(re.escape(value) for value in usable)) if usable else None
    )
    _pattern_cache = (values, pattern)
    return pattern


# Same single-slot rule as _pattern_cache. Populated only when some value
# changes under the fold, and dropped once the value list moves on.
_folded_pattern_cache: tuple[tuple[str, ...], re.Pattern[str] | None] | None = None

# The redaction filter's detection copy is NFKC plus these controls. Zero-width
# characters are not removed by NFKC itself, so the strip has to be part of the
# same fold or U+200B still hides a configured value.
_EXACT_INVISIBLE = DEFAULT_INVISIBLE_CHARS | DEFAULT_BIDI_CHARS


def _fold_char(char: str) -> str:
    """One code point the way exact-value detection sees it.

    Per code point, not the whole string: a match span has to map back to the
    original characters, and NFKC of a whole buffer would compose across
    neighbours and lose that correspondence. Fullwidth forms and inserted
    controls fold one character at a time.
    """
    folded = unicodedata.normalize("NFKC", char)
    if not folded or folded in _EXACT_INVISIBLE:
        return ""
    if len(folded) == 1:
        return folded
    return "".join(part for part in folded if part not in _EXACT_INVISIBLE)


def _fold_exact_string(text: str) -> str:
    if not text or text.isascii():
        return text
    return "".join(_fold_char(char) for char in text)


def _text_needs_fold(text: str) -> bool:
    """True when a detection copy would differ from *text*.

    ASCII leaves — including the multi-megabyte data URIs on this path — stay
    on the raw alternation. ``strip_invisibles`` is identity when nothing in
    the set occurs, and NFKC of an already-normalized string compares equal.
    """
    if text.isascii():
        return False
    if strip_invisibles(text) is not text:
        return True
    return unicodedata.normalize("NFKC", text) != text


def _values_need_fold(values: tuple[str, ...]) -> bool:
    for value in values:
        if value and not value.isascii() and _fold_exact_string(value) != value:
            return True
    return False


def _fold_text_map(text: str) -> tuple[str, list[int]] | None:
    """Detection copy, plus the original index of each of its code points.

    ``None`` means the copy would be identical, so the caller keeps raw spans.
    """
    parts: list[str] = []
    origins: list[int] = []
    changed = False
    for index, char in enumerate(text):
        folded = _fold_char(char)
        if folded != char:
            changed = True
        if not folded:
            continue
        parts.append(folded)
        origins.extend([index] * len(folded))
    if not changed:
        return None
    return "".join(parts), origins


def _pattern_spans(
    pattern: re.Pattern[str] | None, text: str
) -> list[tuple[int, int]]:
    if pattern is None or not text:
        return []
    return [(match.start(), match.end()) for match in pattern.finditer(text)]


def _map_span(
    origins: list[int], start: int, end: int
) -> tuple[int, int] | None:
    if end <= start or start >= len(origins):
        return None
    last = min(end, len(origins)) - 1
    origin_start = origins[start]
    origin_end = origins[last] + 1
    if origin_end <= origin_start:
        return None
    return origin_start, origin_end


def _merge_exact_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Overlap collapses; adjacent spans do not.

    The raw scan and the folded scan report the same plaintext hit twice.
    Two secrets sitting next to each other must stay two replacements, so a
    span that merely touches the previous one is not merged into it.
    """
    if not spans:
        return []
    ordered = sorted(spans)
    merged: list[tuple[int, int]] = []
    for start, end in ordered:
        if end <= start:
            continue
        if not merged or start >= merged[-1][1]:
            merged.append((start, end))
            continue
        previous_start, previous_end = merged[-1]
        merged[-1] = (previous_start, max(previous_end, end))
    return merged


def _apply_exact_spans(text: str, spans: list[tuple[int, int]]) -> tuple[str, int]:
    merged = _merge_exact_spans(spans)
    if not merged:
        return text, 0
    pieces: list[str] = []
    cursor = 0
    for start, end in merged:
        pieces.append(text[cursor:start])
        pieces.append(_PLACEHOLDER)
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces), len(merged)


def _drop_stale_folded_pattern(values: tuple[str, ...]) -> None:
    global _folded_pattern_cache

    cached = _folded_pattern_cache
    if cached is not None and cached[0] != values:
        _folded_pattern_cache = None


def _folded_exact_pattern(values: tuple[str, ...]) -> re.Pattern[str] | None:
    """Alternation of values after the same fold applied to the leaf."""
    global _folded_pattern_cache

    cached = _folded_pattern_cache
    if cached is not None and cached[0] == values:
        return cached[1]

    usable: set[str] = set()
    for value in values:
        if not value:
            continue
        folded = value if value.isascii() else _fold_exact_string(value)
        if folded:
            usable.add(folded)
    ordered = sorted(usable, key=len, reverse=True)
    pattern = (
        re.compile("|".join(re.escape(value) for value in ordered)) if ordered else None
    )
    _folded_pattern_cache = (values, pattern)
    return pattern


def _replace_exact_values_folded(
    text: str,
    values: tuple[str, ...],
    raw_pattern: re.Pattern[str],
    *,
    values_fold: bool,
    text_folds: bool,
) -> tuple[str, int]:
    """Raw hits plus hits that exist only after the fold, spliced into *text*.

    The folded string is never returned. Callers include the V2 request body
    as one buffer; writing NFKC back would rewrite every fullwidth punctuation
    mark in that body, and replacing the whole buffer would drop the JSON
    around a single secret.
    """
    spans = _pattern_spans(raw_pattern, text)
    folded_pattern = _folded_exact_pattern(values) if values_fold else raw_pattern
    folded = _fold_text_map(text) if text_folds else None
    if folded is not None:
        folded_text, origins = folded
        for start, end in _pattern_spans(folded_pattern, folded_text):
            span = _map_span(origins, start, end)
            if span is not None:
                spans.append(span)
    elif values_fold:
        spans.extend(_pattern_spans(folded_pattern, text))
    return _apply_exact_spans(text, spans)


def replace_exact_values_from(text: str, values: Sequence[str]) -> tuple[str, int]:
    """Replace every entry of *values* in *text*.

    Split out from :func:`replace_exact_values` so a caller walking thousands of
    string leaves can resolve the list **once** instead of re-reading it (and
    re-``stat``-ing the file behind it) per leaf. An empty list returns the text
    unchanged and untouched.

    Matching also runs on a detection copy: NFKC, then the same zero-width and
    bidi controls the redaction filter strips. A hit there is replaced in the
    original, over the span that folded into the match. Case and whitespace
    stay significant.
    """
    if not values or not text:
        return text, 0

    key = tuple(values)
    pattern = _exact_value_pattern(key)
    if pattern is None:
        return text, 0
    values_fold = _values_need_fold(key)
    text_folds = _text_needs_fold(text)
    if not values_fold:
        _drop_stale_folded_pattern(key)
    if not values_fold and not text_folds:
        return pattern.subn(_PLACEHOLDER, text)
    return _replace_exact_values_folded(
        text,
        key,
        pattern,
        values_fold=values_fold,
        text_folds=text_folds,
    )


def replace_exact_values(text: str) -> tuple[str, int]:
    """Replace all configured exact values in *text*.

    Returns ``(replaced_text, replacement_count)``.  Values are matched
    longest-first to avoid partial replacements. A zero-width character or a
    fullwidth form of a configured value is replaced in the original text.
    """
    return replace_exact_values_from(text, load_redact_values())
