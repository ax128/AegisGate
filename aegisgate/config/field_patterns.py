"""Shared compiler for ``redaction.field_value_patterns``.

Three call sites used to read the same YAML differently: V1 pipeline replaced
the code fallback with an explicit list, V2 compiled both, the floors were 8
versus 12, and the V1 forward path then filtered the field ids through
``relaxed_pii_ids`` so ``FIELD_SECRET`` / ``AUTH_BEARER`` did not run on the
conversation route. This module is the one reading. PII compilation stays
where it is — including V2's lowercase ids.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from aegisgate.config.security_rules import rule_enabled
from aegisgate.util.logger import logger

FIELD_VALUE_MIN_LEN_FLOOR = 8
DEFAULT_FIELD_VALUE_MIN_LEN = 12
FALLBACK_FIELD_IDS: tuple[str, ...] = ("FIELD_SECRET", "AUTH_BEARER")

# ``{min_len}`` is filled by :func:`resolved_field_value_min_len`. The ``(?i)``
# flag is kept so a dump of the source matches what the three sites used to
# embed; compilation also passes ``re.IGNORECASE``.
FIELD_FALLBACK_TEMPLATES: tuple[tuple[str, str], ...] = (
    (
        "FIELD_SECRET",
        r"(?i)\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token"
        r"|password|passwd|client[_-]?secret|private[_-]?key|secret(?:_key)?)\b\s*[:=]\s*"
        r"(?:bearer\s+)?[A-Za-z0-9._~+/=-]{{{min_len},}}",
    ),
    (
        "AUTH_BEARER",
        r"(?i)\bauthorization\b\s*:\s*bearer\s+[A-Za-z0-9._~+/=-]{{{min_len},}}",
    ),
)


def resolved_field_value_min_len(rules: Mapping[str, Any] | None) -> int:
    """``max(8, configured)``. A non-integer degrades to the YAML default of 12."""
    raw = (rules or {}).get("field_value_min_len", DEFAULT_FIELD_VALUE_MIN_LEN)
    try:
        parsed = int(raw)
    except (TypeError, ValueError):
        parsed = DEFAULT_FIELD_VALUE_MIN_LEN
    return max(FIELD_VALUE_MIN_LEN_FLOOR, parsed)


def field_pattern_entries(
    rules: Mapping[str, Any] | None,
    *,
    honour_enabled: bool = True,
) -> list[tuple[str, str]]:
    """Id/regex pairs the three layers compile.

    An explicit list **replaces** the code fallback. Missing or empty mapping
    ids, and legacy bare strings, become ``FIELD_SECRET_{idx}``.
    """
    rules = rules or {}
    items = rules.get("field_value_patterns")
    if not isinstance(items, list) or not items:
        min_len = resolved_field_value_min_len(rules)
        return [
            (pattern_id, template.format(min_len=min_len))
            for pattern_id, template in FIELD_FALLBACK_TEMPLATES
        ]

    entries: list[tuple[str, str]] = []
    for index, item in enumerate(items, start=1):
        positional = f"FIELD_SECRET_{index}"
        if isinstance(item, dict):
            if honour_enabled and not rule_enabled(item):
                continue
            regex = item.get("regex")
            if not regex:
                continue
            pattern_id = str(item.get("id") or "").strip().upper() or positional
        elif isinstance(item, str):
            if not item:
                continue
            pattern_id = positional
            regex = item
        else:
            continue
        entries.append((pattern_id, str(regex)))
    return entries


def compile_field_value_patterns(
    rules: Mapping[str, Any] | None,
) -> list[tuple[str, re.Pattern[str]]]:
    """Compile :func:`field_pattern_entries` with ``re.IGNORECASE``."""
    compiled: list[tuple[str, re.Pattern[str]]] = []
    for pattern_id, regex in field_pattern_entries(rules):
        try:
            compiled.append((pattern_id, re.compile(str(regex), re.IGNORECASE)))
        except re.error as exc:
            excerpt = str(regex)
            if len(excerpt) > 80:
                excerpt = excerpt[:80] + "…"
            logger.warning(
                "redaction field_pattern skipped (invalid regex) id=%s error=%s regex_excerpt=%s",
                pattern_id,
                exc,
                excerpt,
            )
    return compiled
