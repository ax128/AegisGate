"""Shared value-masking utilities for audit/security logs."""

from __future__ import annotations

import re


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
