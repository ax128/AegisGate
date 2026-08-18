"""Shared text normalization for security-filter matching.

Scoring filters match on the normalized form. Rewrite filters detect on it
but must not write NFKC/lowercased text back into a forwarded payload.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping
from functools import lru_cache

_WHITESPACE_RE = re.compile(r"\s+")

DEFAULT_INVISIBLE_CHARS: frozenset[str] = frozenset(
    {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad"}
)
DEFAULT_BIDI_CHARS: frozenset[str] = frozenset(
    {
        "\u202a",
        "\u202b",
        "\u202d",
        "\u202e",
        "\u202c",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
    }
)


@lru_cache(maxsize=1)
def default_confusable_map() -> dict[str, str]:
    """Lazy-load the YAML confusable map so filters share one translation table."""
    from aegisgate.config.security_rules import load_security_rules

    rules = load_security_rules().get("injection_detector", {})
    return {
        str(src): str(dst)
        for src, dst in (rules.get("unicode_confusable_map") or {}).items()
    }


def normalize_for_match(
    text: str,
    *,
    confusable_map: Mapping[str, str] | None = None,
    strip_chars: Iterable[str] | None = None,
    fold_whitespace: bool = True,
) -> str:
    """NFKC + confusable fold + invisible/bidi strip + lower, optionally whitespace fold.

    Whitespace folding is on by default so ``ignore\\nprevious`` matches
    ``ignore previous``. Callers that must keep newlines (HTTP smuggling
    signatures) should also search the unfolded form.
    """
    if not text:
        return ""
    mapping = (
        dict(confusable_map) if confusable_map is not None else default_confusable_map()
    )
    strip = (
        set(strip_chars)
        if strip_chars is not None
        else set(DEFAULT_INVISIBLE_CHARS | DEFAULT_BIDI_CHARS)
    )
    table = str.maketrans({**mapping, **{ch: None for ch in strip}})
    normalized = unicodedata.normalize("NFKC", text).translate(table).lower()
    if fold_whitespace:
        return _WHITESPACE_RE.sub(" ", normalized).strip()
    return normalized


def match_haystacks(text: str) -> tuple[str, str]:
    """Unfolded (newlines kept) and whitespace-folded forms for pattern search."""
    unfolded = normalize_for_match(text, fold_whitespace=False)
    folded = _WHITESPACE_RE.sub(" ", unfolded).strip()
    return unfolded, folded


def pattern_hits(pattern: re.Pattern[str], text: str) -> bool:
    """True if *pattern* matches the original or either normalized form."""
    if pattern.search(text):
        return True
    unfolded, folded = match_haystacks(text)
    return bool(pattern.search(unfolded) or (folded != unfolded and pattern.search(folded)))


def apply_rewrite_conservatively(
    text: str,
    patterns: Iterable[re.Pattern[str]],
    replacement: str,
) -> str:
    """Rewrite *text* without ever emitting NFKC/lowercased content.

    Plaintext matches keep surgical ``sub`` on the original. Homoglyph /
    whitespace-folded hits that only match after normalization replace the
    whole string with *replacement*.
    """
    pattern_list = list(patterns)
    updated = text
    original_hit = False
    for pattern in pattern_list:
        rewritten = pattern.sub(replacement, updated)
        if rewritten != updated:
            original_hit = True
            updated = rewritten
    if original_hit:
        return updated
    if any(pattern_hits(pattern, text) for pattern in pattern_list):
        return replacement
    return text

