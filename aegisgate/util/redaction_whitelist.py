"""Helpers for per-token redaction whitelist key parsing and matching."""

from __future__ import annotations

import re
from typing import Any, Iterable

_KEY_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")


def normalize_whitelist_keys(raw: Any) -> list[str]:
    """Normalize whitelist key input to a deduplicated lowercase list."""
    candidates: list[str] = []
    if raw is None:
        return []
    if isinstance(raw, str):
        candidates.extend(re.split(r"[\s,]+", raw))
    elif isinstance(raw, dict):
        candidates.extend(str(k) for k, v in raw.items() if bool(v))
    elif isinstance(raw, (list, tuple, set, frozenset)):
        candidates.extend(str(item) for item in raw)
    else:
        candidates.append(str(raw))

    out: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        key = str(item or "").strip().lower()
        if not key:
            continue
        if not _KEY_RE.match(key):
            continue
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def _iter_key_value_patterns(key: str) -> Iterable[re.Pattern[str]]:
    escaped = re.escape(key)
    # Match key:value / key=value / "key":value / 'key'=value
    yield re.compile(
        rf"""(?ix)
        (?:["']?)\b{escaped}\b(?:["']?)\s*[:=]\s*
        (?:
            \{{[^{{}}\n]{{0,2048}}\}} |
            \[[^\]\n]{{0,2048}}\] |
            "(?:\\.|[^"\\]){{0,2048}}" |
            '(?:\\.|[^'\\]){{0,2048}}' |
            [^\s,;)\]}}]{{1,2048}}
        )
        """
    )
    # Match URL/query parameter form ?key=... or &key=...
    yield re.compile(rf"(?i)(?:[?&]){escaped}=(?:[^&#\s]{{0,2048}})")


def protected_spans_for_text(text: str, whitelist_keys: Iterable[str]) -> list[tuple[int, int]]:
    body = str(text or "")
    keys = normalize_whitelist_keys(list(whitelist_keys or []))
    if not body or not keys:
        return []
    spans: list[tuple[int, int]] = []
    for key in keys:
        for pattern in _iter_key_value_patterns(key):
            for match in pattern.finditer(body):
                spans.append((match.start(), match.end()))
    if not spans:
        return []
    spans.sort(key=lambda item: item[0])
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
            continue
        merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return merged


def range_overlaps_protected(spans: list[tuple[int, int]], *, start: int, end: int) -> bool:
    if end <= start:
        return False
    for span_start, span_end in spans:
        if span_end <= start:
            continue
        if span_start >= end:
            return False
        return True
    return False

