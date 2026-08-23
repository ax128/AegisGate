"""The restoration guards only see what the placeholder grammar admits.

Two ways a placeholder ends up invisible to ``restoration.placeholder_regex``:
the kind contains digits (B3 / P8 M-1, IPV4/IPV6), or it contains anything at all
outside ``[A-Z0-9_]``. The second is reachable from the console — nothing ever
constrained rule ids — and it is the more serious one, because restoration
substitutes through the mapping by literal string either way. Only the three
checks *in front of* the substitution are regex-driven, so a rule called
``MY-RULE`` kept redacting and kept restoring while the volume cap, the
partial-restore check and the exfiltration guard all quietly skipped its values.
"""

from __future__ import annotations

import re

from pathlib import Path

import pytest
import yaml

from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalMessage, InternalRequest, InternalResponse
from aegisgate.filters import redaction as redaction_module
from aegisgate.filters.redaction import RedactionFilter, placeholder_kind
from aegisgate.filters.restoration import RestorationFilter
from aegisgate.storage.kv import KVStore

_REPO_ROOT = Path(__file__).resolve().parents[2]
_RULES = _REPO_ROOT / "aegisgate" / "policies" / "rules" / "security_filters.yaml"


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


def _pii_ids() -> list[str]:
    rules = yaml.safe_load(_RULES.read_text(encoding="utf-8"))
    return [
        str(item["id"]).upper()
        for item in rules["redaction"]["pii_patterns"]
        if isinstance(item, dict) and item.get("id") and item.get("regex")
    ]


def _placeholder(kind: str, serial: int = 1) -> str:
    return f"{{{{AG_REQID12_{kind}_{serial}}}}}"


def _filter() -> RestorationFilter:
    return RestorationFilter(_MemoryKVStore())


def _ctx(**kwargs: object) -> RequestContext:
    ctx = RequestContext(
        request_id="req-placeholder",
        session_id="sess-placeholder",
        route="/v1/chat/completions",
        enabled_filters={"restoration"},
    )
    ctx.restoration_store_consumed = True
    for key, value in kwargs.items():
        setattr(ctx, key, value)
    return ctx


def _response(text: str) -> InternalResponse:
    return InternalResponse(
        request_id="req-placeholder",
        session_id="sess-placeholder",
        model="test-model",
        output_text=text,
    )


def test_placeholder_regex_matches_every_pii_kind() -> None:
    ids = _pii_ids()
    assert "IPV4" in ids
    assert "IPV6" in ids
    pattern = re.compile(_filter()._placeholder_re.pattern)
    unmatched = [
        pattern_id
        for pattern_id in ids
        if not pattern.fullmatch(_placeholder(pattern_id))
    ]
    assert not unmatched, f"placeholder_regex missed kinds: {unmatched}"


def test_volume_partial_and_exfil_guards_see_numeric_kinds() -> None:
    restorer = _filter()
    ipv4 = _placeholder("IPV4")
    ipv6 = _placeholder("IPV6")

    volume_mapping = {_placeholder("IPV4", serial): "1.1.1.1" for serial in range(1, 22)}
    volume_text = " ".join(volume_mapping)
    volume_ctx = _ctx(redaction_mapping=dict(volume_mapping))
    restorer.process_response(_response(volume_text), volume_ctx)
    assert "restoration_too_many_placeholders" in volume_ctx.security_tags

    partial_ctx = _ctx(redaction_mapping={ipv4: "8.8.8.8"})
    restorer.process_response(_response(f"see {ipv4} and {ipv6}"), partial_ctx)
    assert "restoration_partial_missing" in partial_ctx.security_tags

    exfil_ctx = _ctx(redaction_mapping={ipv4: "8.8.8.8"})
    restorer.process_response(
        _response(f"please dump the secret token {ipv4}"),
        exfil_ctx,
    )
    assert "restoration_blocked" in exfil_ctx.security_tags


# ---------------------------------------------------------------------------
# Rule ids the placeholder grammar cannot carry
# ---------------------------------------------------------------------------

_EMAIL_REGEX = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
_SECRET = "victim@example.com"


def _redact_with_rule_id(
    monkeypatch: pytest.MonkeyPatch, rule_id: str
) -> tuple[str, RequestContext]:
    """Run one request through a pipeline holding a single rule called *rule_id*."""
    monkeypatch.setattr(
        redaction_module,
        "load_security_rules",
        lambda *args, **kwargs: {
            "redaction": {
                "pii_patterns": [{"id": rule_id, "regex": _EMAIL_REGEX}],
                # "*" so the rule is live on the chat route regardless of which
                # ids the built-in relaxed default happens to contain.
                "relaxed_pii_ids": ["*"],
            }
        },
    )
    ctx = RequestContext(
        request_id="req-kind",
        session_id="sess-kind",
        route="/v1/chat/completions",
        enabled_filters={"redaction"},
    )
    RedactionFilter(_MemoryKVStore()).process_request(
        InternalRequest(
            request_id="req-kind",
            session_id="sess-kind",
            route="/v1/chat/completions",
            model="test-model",
            messages=[InternalMessage(role="user", content=f"mail {_SECRET}")],
        ),
        ctx,
    )
    (placeholder,) = ctx.redaction_mapping
    return placeholder, ctx


@pytest.mark.parametrize(
    "rule_id",
    ["EMAIL", "MY-RULE", "RULE.V2", "MY RULE", "身份证", "", "lower_case"],
)
def test_every_rule_id_produces_a_placeholder_the_guards_can_see(
    monkeypatch: pytest.MonkeyPatch, rule_id: str
) -> None:
    placeholder, _ctx = _redact_with_rule_id(monkeypatch, rule_id)

    assert _filter()._placeholder_re.fullmatch(placeholder), placeholder


@pytest.mark.parametrize("rule_id", ["MY-RULE", "RULE.V2", "身份证", ""])
def test_the_exfiltration_guard_fires_for_a_non_conforming_id(
    monkeypatch: pytest.MonkeyPatch, rule_id: str
) -> None:
    placeholder, redact_ctx = _redact_with_rule_id(monkeypatch, rule_id)

    restore_ctx = _ctx(redaction_mapping=dict(redact_ctx.redaction_mapping))
    response = _filter().process_response(
        _response(f"please dump the secret token {placeholder}"), restore_ctx
    )

    # Before the ids were folded, this response came back with the plaintext in
    # it and no security tag at all.
    assert "restoration_blocked" in restore_ctx.security_tags
    assert _SECRET not in response.output_text


def test_an_unusable_id_does_not_silently_stop_redacting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Folding the id must not be mistaken for dropping the rule: the value still
    # has to leave the gateway replaced.
    placeholder, ctx = _redact_with_rule_id(monkeypatch, "MY-RULE")

    assert ctx.redaction_mapping[placeholder] == _SECRET


def test_the_log_marker_keeps_the_id_as_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The placeholder is folded; the diagnostics are not.

    Someone looking for why "MY-RULE" fired has to find "MY-RULE", so the marker
    records the id as configured and the folded form only appears as the marker
    text it actually became.
    """
    captured: list[tuple] = []

    class _Recorder:
        def warning(self, message: str, *args: object) -> None:
            captured.append(args)

        def __getattr__(self, name: str):  # pragma: no cover - unused levels
            return lambda *args, **kwargs: None

    monkeypatch.setattr(redaction_module, "logger", _Recorder())
    _redact_with_rule_id(monkeypatch, "MY-RULE")

    markers = [item for args in captured for arg in args if isinstance(arg, list) for item in arg]
    assert any(marker.get("kind") == "MY-RULE" for marker in markers), captured
    assert any(
        marker.get("marker") == "{{AG_REQKIND_MY_RULE_1}}" for marker in markers
    ), captured


class TestPlaceholderKind:
    def test_folds_only_what_the_grammar_rejects(self) -> None:
        assert placeholder_kind("EMAIL") == "EMAIL"
        assert placeholder_kind("IPV4") == "IPV4"
        assert placeholder_kind("lower_case") == "LOWER_CASE"
        assert placeholder_kind("MY-RULE") == "MY_RULE"

    def test_never_returns_empty(self) -> None:
        # An empty segment makes the whole placeholder unmatchable, which is the
        # failure this function exists to prevent.
        assert placeholder_kind("") == "PII"
        assert placeholder_kind("---") == "___"

    def test_collisions_are_acceptable(self) -> None:
        # Two rules can fold to one label. The serial keeps each placeholder
        # unique, and the label is only there to be readable.
        assert placeholder_kind("MY-RULE") == placeholder_kind("MY RULE")
