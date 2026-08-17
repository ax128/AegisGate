"""redaction.relaxed_pii_ids — the configurable low-false-positive pattern set.

Covers the resolver semantics and the request-filter behaviour on the routes in
_LOW_FALSE_POSITIVE_V1_ROUTES, including the backward-compatible default.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from aegisgate.config import security_rules
from aegisgate.config.security_rules import (
    _DEFAULT_RELAXED_PII_IDS,
    select_relaxed_pii_patterns,
)
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalMessage, InternalRequest
from aegisgate.filters import redaction as redaction_module
from aegisgate.filters.redaction import RedactionFilter
from aegisgate.storage.kv import KVStore


_PII_PATTERNS = [
    {"id": "EMAIL", "regex": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"},
    {"id": "TOKEN", "regex": r"\b(?:sk|rk|pk)-[A-Za-z0-9\-_]{10,}\b"},
    {"id": "IBAN", "regex": r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}\b"},
    {"id": "DE_TAX_ID", "regex": r"\b\d{11}\b"},
]


class _MemoryKVStore(KVStore):
    def __init__(self) -> None:
        self._mappings: dict[tuple[str, str], dict[str, str]] = {}

    def set_mapping(
        self, session_id: str, request_id: str, mapping: dict[str, str]
    ) -> None:
        self._mappings[(session_id, request_id)] = dict(mapping)

    def get_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        return dict(self._mappings.get((session_id, request_id), {}))

    def consume_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        return self._mappings.pop((session_id, request_id), {})

    def prune_pending_confirmations(self, now_ts: int) -> int:  # pragma: no cover
        return 0

    def clear_all_pending_confirmations(self) -> int:  # pragma: no cover
        return 0


def _compiled(ids: list[str]) -> list[tuple[str, re.Pattern[str]]]:
    return [(pattern_id, re.compile(pattern_id.lower())) for pattern_id in ids]


def _selected_ids(patterns: list[tuple[str, re.Pattern[str]]]) -> list[str]:
    return [pattern_id for pattern_id, _ in patterns]


class _WarningRecorder:
    """The aegisgate logger does not propagate, so caplog cannot see it."""

    def __init__(self) -> None:
        self.messages: list[str] = []

    def warning(self, message: str, *args: Any) -> None:
        self.messages.append(message % args if args else message)

    def __getattr__(self, name: str) -> Any:  # pragma: no cover - unused levels
        return lambda *args, **kwargs: None

    @property
    def text(self) -> str:
        return "\n".join(self.messages)


@pytest.fixture(autouse=True)
def warnings_log(monkeypatch: pytest.MonkeyPatch) -> _WarningRecorder:
    security_rules._WARNED_RELAXED_PII_CONFIG.clear()
    recorder = _WarningRecorder()
    monkeypatch.setattr(security_rules, "logger", recorder)
    return recorder


def _rules(relaxed: Any = ..., **extra: Any) -> dict[str, Any]:
    rules: dict[str, Any] = {"pii_patterns": _PII_PATTERNS, **extra}
    if relaxed is not ...:
        rules["relaxed_pii_ids"] = relaxed
    return rules


def test_missing_key_keeps_builtin_default() -> None:
    patterns = _compiled(["EMAIL", "TOKEN", "JWT", "IBAN"])

    selected = select_relaxed_pii_patterns(patterns, redaction_rules=_rules())

    assert _selected_ids(selected) == ["TOKEN", "JWT"]
    assert {"TOKEN", "JWT"} <= _DEFAULT_RELAXED_PII_IDS


def test_configured_list_replaces_default() -> None:
    patterns = _compiled(["EMAIL", "TOKEN", "JWT", "IBAN", "DE_TAX_ID"])

    selected = select_relaxed_pii_patterns(
        patterns,
        redaction_rules=_rules(["EMAIL", "IBAN", "DE_TAX_ID"]),
    )

    assert _selected_ids(selected) == ["EMAIL", "IBAN", "DE_TAX_ID"]


def test_configured_ids_are_case_insensitive_and_trimmed() -> None:
    patterns = _compiled(["EMAIL", "TOKEN"])

    selected = select_relaxed_pii_patterns(
        patterns,
        redaction_rules=_rules([" email ", "Token"]),
    )

    assert _selected_ids(selected) == ["EMAIL", "TOKEN"]


def test_wildcard_keeps_every_pattern() -> None:
    patterns = _compiled(["EMAIL", "TOKEN", "IBAN", "DE_TAX_ID"])

    selected = select_relaxed_pii_patterns(patterns, redaction_rules=_rules(["*"]))

    assert _selected_ids(selected) == ["EMAIL", "TOKEN", "IBAN", "DE_TAX_ID"]


def test_empty_list_disables_relaxed_patterns_with_warning(
    warnings_log: _WarningRecorder,
) -> None:
    patterns = _compiled(["EMAIL", "TOKEN"])

    selected = select_relaxed_pii_patterns(patterns, redaction_rules=_rules([]))

    assert selected == []
    assert "relaxed_pii_ids is empty" in warnings_log.text


def test_non_list_value_falls_back_to_default_with_warning(
    warnings_log: _WarningRecorder,
) -> None:
    patterns = _compiled(["EMAIL", "TOKEN"])

    selected = select_relaxed_pii_patterns(patterns, redaction_rules=_rules(42))

    assert _selected_ids(selected) == ["TOKEN"]
    assert "must be a list of pattern ids" in warnings_log.text


def test_unknown_id_is_reported_once(warnings_log: _WarningRecorder) -> None:
    patterns = _compiled(["EMAIL", "TOKEN"])
    rules = _rules(["EMAIL", "TYPO_ID"])

    first = select_relaxed_pii_patterns(patterns, redaction_rules=rules)
    second = select_relaxed_pii_patterns(patterns, redaction_rules=rules)

    assert _selected_ids(first) == ["EMAIL"]
    assert _selected_ids(second) == ["EMAIL"]
    assert warnings_log.text.count("references unknown pattern id(s)") == 1
    assert "TYPO_ID" in warnings_log.text


def test_field_pattern_ids_are_not_reported_as_unknown(
    warnings_log: _WarningRecorder,
) -> None:
    # The responses-API sanitizer compiles field_value_patterns alongside
    # pii_patterns, so those ids are valid config even though the request
    # filter never sees them.
    patterns = _compiled(["EMAIL", "AUTH_BEARER"])

    selected = select_relaxed_pii_patterns(
        patterns,
        redaction_rules=_rules(["EMAIL", "AUTH_BEARER"]),
    )

    assert _selected_ids(selected) == ["EMAIL", "AUTH_BEARER"]
    assert "references unknown pattern id(s)" not in warnings_log.text


def _run_filter(monkeypatch: pytest.MonkeyPatch, rules: dict[str, Any], text: str) -> str:
    monkeypatch.setattr(
        redaction_module, "load_security_rules", lambda *args, **kwargs: {"redaction": rules}
    )
    redaction_filter = RedactionFilter(_MemoryKVStore())
    req = InternalRequest(
        request_id="relaxed-pii",
        session_id="relaxed-pii",
        route="/v1/chat/completions",
        model="gpt-5.4",
        messages=[InternalMessage(role="user", content=text)],
    )
    ctx = RequestContext(
        request_id="relaxed-pii",
        session_id="relaxed-pii",
        route="/v1/chat/completions",
        enabled_filters={"redaction"},
    )
    return redaction_filter.process_request(req, ctx).messages[0].content


def test_chat_route_default_leaves_email_untouched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = "contact user@example.com about key sk-live-abcdefghijkl"

    result = _run_filter(monkeypatch, _rules(), text)

    assert "user@example.com" in result
    assert "sk-live-abcdefghijkl" not in result


def test_chat_route_redacts_email_once_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = "contact user@example.com about key sk-live-abcdefghijkl"

    result = _run_filter(monkeypatch, _rules(["TOKEN", "EMAIL"]), text)

    assert "user@example.com" not in result
    assert "EMAIL" in result
    assert "sk-live-abcdefghijkl" not in result


def test_chat_route_wildcard_redacts_custom_pattern(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = "german tax id 12345678901 for the invoice"

    result = _run_filter(monkeypatch, _rules(["*"]), text)

    assert "12345678901" not in result
    assert "DE_TAX_ID" in result
