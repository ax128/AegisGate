"""Shared text normalization for security-filter matching.

Scoring filters match on the normalized form. Rewrite filters detect on it
but must not write NFKC/lowercased text back into a forwarded payload.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
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


_INVISIBLE_STRIP_CHARS = DEFAULT_INVISIBLE_CHARS | DEFAULT_BIDI_CHARS
_INVISIBLE_STRIP_TABLE = str.maketrans("", "", "".join(_INVISIBLE_STRIP_CHARS))
# Escaped, and sorted so the class does not depend on set iteration order. None
# of today's code points is a metacharacter, but the two sets above are meant to
# be extended, and one ``-`` or ``^`` would silently turn this into a range.
_INVISIBLE_RE = re.compile(
    f"[{''.join(re.escape(char) for char in sorted(_INVISIBLE_STRIP_CHARS))}]"
)


def strip_invisibles(text: str) -> str:
    """A copy with zero-width / bidi code points removed, or the original.

    For *detection* copies that must not pay for a full NFKC pass — the
    base64-blob heuristic is the case: a zero-width character inserted into a
    credential makes the leaf look base64-ish enough to be waved through, and
    the fix has to be cheap enough to run on every forwarded string leaf. The
    membership scan is one pass and almost always misses, so ordinary text never
    pays for the translate.
    """
    if not text or not _INVISIBLE_RE.search(text):
        return text
    return text.translate(_INVISIBLE_STRIP_TABLE)


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
    casefold: bool = True,
) -> str:
    """NFKC + confusable fold + invisible/bidi strip + lower, optionally whitespace fold.

    Whitespace folding is on by default so ``ignore\\nprevious`` matches
    ``ignore previous``. Callers that must keep newlines (HTTP smuggling
    signatures) should also search the unfolded form.

    ``casefold=False`` keeps the original case. Only pass it when the consumer
    is case-insensitive anyway (an ``re.IGNORECASE`` pattern): it lets plain
    ASCII text normalize back to itself, which :func:`build_haystacks` uses to
    collapse three search forms down to one.
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
    normalized = unicodedata.normalize("NFKC", text).translate(table)
    if casefold:
        normalized = normalized.lower()
    if fold_whitespace:
        return _WHITESPACE_RE.sub(" ", normalized).strip()
    return normalized


def match_haystacks(text: str, *, casefold: bool = True) -> tuple[str, str]:
    """Unfolded (newlines kept) and whitespace-folded forms for pattern search."""
    unfolded = normalize_for_match(text, fold_whitespace=False, casefold=casefold)
    folded = _WHITESPACE_RE.sub(" ", unfolded).strip()
    return unfolded, folded


def build_haystacks(text: str) -> tuple[str, ...]:
    """The distinct forms a pattern should be searched against.

    Normalizing is the expensive part (NFKC + translate over the whole text),
    so callers that test many patterns against one text must build this once
    and reuse it rather than calling :func:`pattern_hits` in a loop.

    Case is deliberately preserved: every caller matches with
    ``re.IGNORECASE``, so lowercasing here would only make the normalized form
    differ from the original and force a third search per pattern. Duplicate
    forms are dropped, so ordinary ASCII text collapses to a single entry.
    """
    if not text:
        return ("",)
    unfolded = normalize_for_match(text, fold_whitespace=False, casefold=False)
    # No ``.strip()``: trailing whitespace cannot hide a match from ``search``,
    # and stripping would make the folded form differ from the unfolded one for
    # every text that merely ends in a newline, costing a second search per
    # pattern for nothing.
    folded = _WHITESPACE_RE.sub(" ", unfolded)
    forms = [text]
    if unfolded != text:
        forms.append(unfolded)
    if folded != unfolded and folded != text:
        forms.append(folded)
    return tuple(forms)


def any_pattern_hits(
    patterns: Iterable[re.Pattern[str]], haystacks: Sequence[str]
) -> bool:
    """True if any pattern matches any prebuilt haystack."""
    return any(pattern.search(hay) for pattern in patterns for hay in haystacks)


def pattern_hits_in(pattern: re.Pattern[str], haystacks: Sequence[str]) -> bool:
    """True if *pattern* matches any prebuilt haystack."""
    return any(pattern.search(hay) for hay in haystacks)


def pattern_hits(pattern: re.Pattern[str], text: str) -> bool:
    """True if *pattern* matches the original or either normalized form.

    Single-shot convenience wrapper. In a loop over patterns, build the
    haystacks once with :func:`build_haystacks` and use
    :func:`pattern_hits_in` instead.
    """
    return pattern_hits_in(pattern, build_haystacks(text))


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
    if any_pattern_hits(pattern_list, build_haystacks(text)):
        return replacement
    return text

