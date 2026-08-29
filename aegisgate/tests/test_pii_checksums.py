"""Check digits on the PII rules that match on shape alone.

This changes what we *know*, not what we *do*: a value whose checksum fails is
still redacted. The only new output is a per-rule count on the redaction
filter's report, plus a metric.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

from aegisgate.config.security_rules import _DEFAULT_RULES, rule_validator
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalMessage, InternalRequest
from aegisgate.filters.redaction import RedactionFilter
from aegisgate.storage.kv import KVStore
from aegisgate.util.checksums import cn_id_valid, iban_mod97_valid, luhn_valid

_REPO_ROOT = Path(__file__).resolve().parents[2]
_RULES = _REPO_ROOT / "aegisgate" / "policies" / "rules" / "security_filters.yaml"


class _MemoryKVStore(KVStore):
    """Copied from test_placeholder_roundtrip. Deliberately not a store that
    raises: a persist failure puts redaction_mapping_persist_failed into
    ctx.security_tags, which would pollute test_nothing_reaches_the_client_surface."""

    def __init__(self) -> None:
        self._mappings: dict[tuple[str, str], dict[str, str]] = {}

    def set_mapping(self, session_id: str, request_id: str, mapping: dict[str, str]) -> None:
        self._mappings[(session_id, request_id)] = dict(mapping)

    def get_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        return dict(self._mappings.get((session_id, request_id), {}))

    def consume_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        return self._mappings.pop((session_id, request_id), {})


@dataclass
class _Redacted:
    text: str
    ctx: RequestContext
    report: dict


# NOT one of the three protocol routes. /v1/chat/completions, /v1/responses and
# /v1/messages are in LOW_FALSE_POSITIVE_V1_ROUTES, and the relaxed id set they
# use drops CARD, CN_ID and IBAN entirely — so the validators cannot fire there
# at all. See test_the_relaxed_routes_never_reach_a_validator below, which pins
# that fact rather than leaving the next reader to rediscover it.
_FULL_SET_ROUTE = "/v1/embeddings"


def _redact(text: str, route: str = _FULL_SET_ROUTE) -> _Redacted:
    """Run one request through RedactionFilter alone, on an in-memory store.

    Not the whole pipeline: the claim here is about one filter's output and one
    filter's report, and dragging the other five in would let an unrelated
    filter's change turn these red.
    """
    flt = RedactionFilter(_MemoryKVStore())
    ctx = RequestContext(
        request_id="req-chk", session_id="sess-chk", route=route
    )
    req = InternalRequest(
        request_id=ctx.request_id,
        session_id=ctx.session_id,
        route=ctx.route,
        model="m",
        messages=[InternalMessage(role="user", content=text)],
    )
    out = flt.process_request(req, ctx)
    return _Redacted(" ".join(m.content for m in out.messages), ctx, flt.report())


# ---------------------------------------------------------------------------
# The validators themselves
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "value,expected",
    [
        ("4111111111111111", True),  # the public Visa test number
        ("4111111111111112", False),  # last digit changed, Luhn fails
        ("4111 1111 1111 1111", True),  # separators stripped before validating
        ("4111-1111-1111-1111", True),
        ("123456789012345", False),  # 15-digit order-number shape
        ("", False),
        ("abcd", False),
    ],
)
def test_luhn(value: str, expected: bool) -> None:
    assert luhn_valid(value) is expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("11010519491231002X", True),  # the GB11643 worked example
        ("110105194912310021", False),  # wrong check character
        ("11010519491231002", False),  # 17 chars: the pre-1999 form has no check digit
        ("", False),
    ],
)
def test_cn_id(value: str, expected: bool) -> None:
    assert cn_id_valid(value) is expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("GB82WEST12345698765432", True),  # the ISO 13616 worked example
        ("GB82 WEST 1234 5698 7654 32", True),
        ("GB82WEST12345698765433", False),
        ("XX", False),
    ],
)
def test_iban_mod97(value: str, expected: bool) -> None:
    assert iban_mod97_valid(value) is expected


def test_non_ascii_digits_cannot_produce_a_wrong_verdict() -> None:
    """`\\d` matches every Unicode decimal digit, so these really can arrive.

    str.isdigit() says yes to them while ord(char) - 48 computes nonsense, which
    would make the failure count wrong rather than conservative. They are
    rejected before any arithmetic instead. Nothing about redaction changes:
    such a value is redacted either way.
    """
    arabic_indic = "\u0664\u0661\u0661\u0661" * 4  # the digits of 4111... in another script
    assert len(arabic_indic) == 16
    assert arabic_indic.isdigit()  # the trap this guards
    assert luhn_valid(arabic_indic) is False
    assert cn_id_valid("\u0661" * 18) is False
    assert iban_mod97_valid("GB\u0668\u0662WEST12345698765432") is False


# ---------------------------------------------------------------------------
# What the filter does with them
# ---------------------------------------------------------------------------
def test_a_failing_checksum_is_still_redacted() -> None:
    """This change alters what we know, not what we do."""
    out = _redact("order 123456789012345 shipped")
    assert "123456789012345" not in out.text
    assert out.report["validator_failed"] == {"CARD": 1}


def test_a_passing_checksum_is_redacted_without_the_marker() -> None:
    out = _redact("card 4111111111111111")
    assert "4111111111111111" not in out.text
    assert "validator_failed" not in out.report


def test_a_validator_failure_implies_a_redaction() -> None:
    """The report only carries the counts on the `if mapping:` branch, so a path
    that failed a checksum without redacting would drop the count silently."""
    out = _redact("order 123456789012345 shipped")
    assert out.report["hit"] is True and out.report["replacements"] >= 1


def test_the_count_is_distinct_values_not_occurrences() -> None:
    """The validator runs after the dedupe cache, so one value repeated in the
    same request is one entry — which is what makes the number comparable."""
    out = _redact("order 123456789012345 and again 123456789012345 done")
    assert out.report["validator_failed"] == {"CARD": 1}


def test_a_whitelisted_value_produces_no_record() -> None:
    """The whitelist is a higher-priority explicit intent: an exempted value is
    not redacted, so it must not produce a validator record either.

    The whitelist protects `key: value` spans, not bare values, so the text has
    to be in that shape for the exemption to apply at all.
    """
    flt = RedactionFilter(_MemoryKVStore())
    ctx = RequestContext(
        request_id="req-wl", session_id="sess-wl", route=_FULL_SET_ROUTE
    )
    ctx.redaction_whitelist_keys = {"order_no"}
    req = InternalRequest(
        request_id=ctx.request_id,
        session_id=ctx.session_id,
        route=ctx.route,
        model="m",
        messages=[InternalMessage(role="user", content="order_no: 123456789012345")],
    )
    out = flt.process_request(req, ctx)
    text = " ".join(m.content for m in out.messages)
    assert "123456789012345" in text, "the whitelist did not exempt the value"
    assert "validator_failed" not in flt.report()


def test_nothing_reaches_the_client_surface() -> None:
    """The reason this rides on the filter report and not on security_tags.

    ctx.security_tags is echoed to callers by _attach_security_metadata (the
    non-streaming body and the streaming metadata) and by _error_response, not
    only by the SSE block frame — so a tag here would be visible on ordinary
    allowed responses. report_items is not in any of those payloads.
    """
    ctx = _redact("order 123456789012345 shipped").ctx
    assert not any("validator" in tag for tag in ctx.security_tags)

    from aegisgate.adapters.openai_compat.router import _attach_security_metadata
    from aegisgate.core.models import InternalResponse

    resp = InternalResponse(request_id="r", session_id="s", model="m", output_text="")
    _attach_security_metadata(resp, ctx)
    assert "report" not in resp.metadata["aegisgate"]
    assert not any("validator" in str(v) for v in resp.metadata["aegisgate"].values())


# ---------------------------------------------------------------------------
# Guards on the scope of this change
# ---------------------------------------------------------------------------
def test_no_rule_can_opt_out_of_redaction() -> None:
    """The guard against this growing a skip action by accident.

    A validator that could suppress redaction would have to be consistent across
    all three pii_patterns compile sites and the console's editable-field
    whitelist; none of that is in scope here.
    """
    import aegisgate.filters.redaction as mod

    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert "validator_action" not in src


def test_validator_is_not_console_writable() -> None:
    """Until every compile site reads it, the console must not write it —
    gateway_ui_routes' own comment on _ENABLED_AWARE_SECTIONS says why."""
    from aegisgate.core.gateway_ui_routes import (
        RULE_EXTRA_BOOL_FIELDS,
        RULE_EXTRA_STRING_FIELDS,
    )

    assert "validator" not in (RULE_EXTRA_STRING_FIELDS | RULE_EXTRA_BOOL_FIELDS)


def test_validator_metric_labels_by_validator_not_rule_id() -> None:
    """"Let the metric say which rule failed" is a natural follow-up and exactly
    the unbounded label the metric table forbids: the console can add rules."""
    from aegisgate.observability import metrics

    if not metrics._HAS_PROMETHEUS:
        pytest.skip("prometheus_client is an optional extra")
    assert metrics.PII_VALIDATOR_FAILURES._labelnames == ("validator",)


def test_yaml_and_default_rules_declare_the_same_validators() -> None:
    """The copy-consistency guard. Two copies of these rules exist and updating
    one and not the other is this repo's most frequent defect shape."""
    yaml_rules = yaml.safe_load(_RULES.read_text(encoding="utf-8"))
    yaml_map = {
        str(item["id"]): rule_validator(item)
        for item in yaml_rules["redaction"]["pii_patterns"]
        if isinstance(item, dict) and rule_validator(item)
    }
    default_map = {
        str(item["id"]): rule_validator(item)
        for item in _DEFAULT_RULES["redaction"]["pii_patterns"]
        if rule_validator(item)
    }
    assert yaml_map == default_map
    assert yaml_map == {"CARD": "luhn", "CN_ID": "cn_id", "IBAN": "iban_mod97"}


def test_an_unknown_validator_name_degrades_to_no_validator() -> None:
    """A typo must fall back to today's behaviour, not raise on the request path."""
    assert rule_validator({"id": "CARD", "validator": "luhnn"}) is None
    assert rule_validator({"id": "CARD", "validator": 7}) is None
    assert rule_validator({"id": "CARD"}) is None
    assert rule_validator("a bare string rule") is None
    assert rule_validator({"id": "CARD", "validator": " LUHN "}) == "luhn"


def test_the_relaxed_routes_never_reach_a_validator() -> None:
    """The scope of this change, pinned rather than assumed.

    /v1/chat/completions, /v1/responses and /v1/messages use the relaxed
    low-false-positive id set, which does not contain CARD, CN_ID or IBAN. So on
    exactly the three routes that carry most traffic these rules never run, and
    neither do their check digits — the counts come from the other routes, which
    use the full set. Anyone reading validator_failed needs to know that.
    """
    from aegisgate.config.security_rules import LOW_FALSE_POSITIVE_V1_ROUTES

    flt = RedactionFilter(_MemoryKVStore())
    relaxed_ids = {rule_id for rule_id, _ in flt._responses_relaxed_pii_patterns}
    assert relaxed_ids.isdisjoint({"CARD", "CN_ID", "IBAN"})
    assert "/v1/chat/completions" in LOW_FALSE_POSITIVE_V1_ROUTES

    out = _redact("order 123456789012345 shipped", route="/v1/chat/completions")
    assert "123456789012345" in out.text, "the relaxed set unexpectedly redacted this"
    assert "validator_failed" not in out.report


def test_every_validated_rule_runs_on_the_full_set_route() -> None:
    """The three rules that declare a validator must actually be compiled on the
    route the tests above use, or those tests would be green for the wrong reason."""
    flt = RedactionFilter(_MemoryKVStore())
    full_ids = {rule_id for rule_id, _ in flt._pii_patterns}
    assert set(flt._pii_validators) == {"CARD", "CN_ID", "IBAN"}
    assert set(flt._pii_validators).issubset(full_ids)
