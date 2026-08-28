"""Shared value-masking utilities for audit/security logs."""

from __future__ import annotations

import re

# What a rule that only matched the *normalized* copy of a leaf reports instead
# of a masked fragment. There is no fragment to mask: the match exists only in a
# form the original text does not contain, so there is no span to point at.
#
# Handing the whole leaf to :func:`mask_for_log` is the alternative, and it is
# the wrong one — the leaf is unbounded in length and its first three characters
# would go into the log line in cleartext. Both forward paths use this.
NORMALIZED_MATCH_MASK = "[normalized-form match]"


def mask_for_log(value: str) -> str:
    """Return a partially-masked version of *value* safe for log output.

    Rules:
    - Preserve first 3 chars + last 2 chars for values >= 10 chars.
    - Shorter values get progressively fewer visible chars.
    - Trailing/leading whitespace is collapsed before masking.
    """
    normalized = re.sub(r"\s+", " ", value).strip()
    length = len(normalized)
    if length <= 0:
        return ""
    if length == 1:
        return "*"
    if length <= 4:
        return f"{normalized[:1]}{'*' * (length - 2)}{normalized[-1:]}"

    head = 3 if length >= 10 else 2
    tail = 2
    if head + tail >= length:
        head, tail = 1, 1
    return f"{normalized[:head]}{'*' * (length - head - tail)}{normalized[-tail:]}"
