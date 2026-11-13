"""Whitelist spans are coordinates, so they must come from the text a rule matches.

Computing them once, on the original message, leaves later rules matching a
string whose length has already changed. A shorter placeholder slides the tail
left into the old interval, and a secret that was past the whitelist is kept.
A longer placeholder slides a whitelisted value right, out of the old interval,
and the value is redacted.
"""

from __future__ import annotations

import re

from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalMessage, InternalRequest
from aegisgate.filters.redaction import RedactionFilter
from aegisgate.storage.kv import KVStore
from aegisgate.util.redaction_whitelist import protected_spans_for_text

# Not a relaxed conversation route, so the full pii_patterns list runs in YAML order.
_FULL_SET_ROUTE = "/v1/embeddings"
_ORDER_NO = "order_no"


class _MemoryKVStore(KVStore):
    """In-memory mapping store. A store that raises would tag the context and
    hide whether the text itself was redacted."""

    def __init__(self) -> None:
        self._mappings: dict[tuple[str, str], dict[str, str]] = {}

    def set_mapping(self, session_id: str, request_id: str, mapping: dict[str, str]) -> None:
        self._mappings[(session_id, request_id)] = dict(mapping)

    def get_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        return dict(self._mappings.get((session_id, request_id), {}))

    def consume_mapping(self, session_id: str, request_id: str) -> dict[str, str]:
        return self._mappings.pop((session_id, request_id), {})


def _patterns() -> list[tuple[str, re.Pattern[str]]]:
    return list(RedactionFilter(_MemoryKVStore())._pii_patterns)


def _redact(text: str, *, request_id: str) -> str:
    flt = RedactionFilter(_MemoryKVStore())
    ctx = RequestContext(
        request_id=request_id, session_id="sess-wl", route=_FULL_SET_ROUTE
    )
    ctx.redaction_whitelist_keys = {_ORDER_NO}
    req = InternalRequest(
        request_id=ctx.request_id,
        session_id=ctx.session_id,
        route=ctx.route,
        model="m",
        messages=[InternalMessage(role="user", content=text)],
    )
    out = flt.process_request(req, ctx)
    return out.messages[0].content


def _fake_jwt(min_len: int = 300) -> str:
    """Stand-in that only has to satisfy the JWT rule. Not a signed token."""
    seg1 = "eyJFAKEHEADER"
    seg2 = "FAKEPAYLOADBB"
    seg3 = "FAKESIGNATURE"
    extra = min_len - (len(seg1) + 1 + len(seg2) + 1 + len(seg3))
    if extra > 0:
        seg1 += "A" * extra
    token = f"{seg1}.{seg2}.{seg3}"
    assert len(token) >= min_len
    assert re.fullmatch(
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        token,
    )
    return token


def _index(patterns: list[tuple[str, re.Pattern[str]]], pattern_id: str) -> int:
    return next(i for i, (pid, _) in enumerate(patterns) if pid == pattern_id)


def test_shorter_placeholder_must_not_keep_a_later_secret() -> None:
    """JWT runs before COOKIE_SESSION. The secret is placed from the measured shift.

    `shift` is the number of characters the JWT replacement removes. The secret
    starts at `len(prefix) + shift + 1`, so once the text slides left it sits
    one character inside the whitelist span that was computed on the original.
    """
    request_id = "req-wl-shrink"
    jwt = _fake_jwt(300)
    placeholder = _redact(jwt, request_id=request_id)
    assert jwt not in placeholder
    assert placeholder.startswith("{{AG_") and placeholder.endswith("}}")
    assert placeholder.count("{{") == 1 and "JWT" in placeholder
    shift = len(jwt) - len(placeholder)

    wl = "order_no: 123456"
    prefix = jwt + " "
    spans = protected_spans_for_text(prefix + wl, {_ORDER_NO})
    assert spans == [(len(prefix), len(prefix) + len(wl))]
    wl_len = spans[0][1] - spans[0][0]
    assert shift > wl_len

    secret = "sid: fakecookie"
    secret_at = len(prefix) + shift + 1
    assert len(prefix) < secret_at - shift < len(prefix) + wl_len
    assert secret_at >= len(prefix) + wl_len

    pad_len = secret_at - (len(prefix) + len(wl))
    assert pad_len >= 1
    text = prefix + wl + (" " * pad_len) + secret
    assert text[secret_at : secret_at + len(secret)] == secret
    # The rule needs a boundary in front of `sid`. The pad is spaces.
    assert text[secret_at - 1] == " "

    patterns = _patterns()
    jwt_at = _index(patterns, "JWT")
    cookie_at = _index(patterns, "COOKIE_SESSION")
    assert jwt_at < cookie_at
    assert patterns[cookie_at][1].fullmatch(secret)
    # An earlier rule matching the secret would redact it while the span was
    # still correct, and this test would pass without exercising the bug.
    for pid, pat in patterns[:jwt_at]:
        assert pat.search(text) is None, pid

    # Recomputed after the shrink, the whitelist ends before the secret.
    assert secret_at - shift >= (len(prefix) - shift) + wl_len

    out = _redact(text, request_id=request_id)
    assert "order_no: 123456" in out
    assert secret not in out
    assert "COOKIE_SESSION" in out


def test_longer_placeholder_must_not_redact_a_whitelisted_value() -> None:
    """EMAIL runs before SSN, and its placeholder is longer than `a@b.co`.

    The whitelisted value is an SSN-shaped dummy so a later rule actually
    matches it. `000-00-0000` is not an issued number. The measured expansion
    has to push that value past the end of the original span; otherwise the
    stale coordinates would still cover it and the bug would not show.
    """
    request_id = "req-whitelist"
    early = "a@b.co"
    placeholder = _redact(early, request_id=request_id)
    assert early not in placeholder
    assert placeholder.startswith("{{AG_") and placeholder.endswith("}}")
    assert placeholder.count("{{") == 1 and "EMAIL" in placeholder
    expansion = len(placeholder) - len(early)
    assert expansion > 0

    wl_value = "000-00-0000"
    wl = f"order_no: {wl_value}"
    prefix = early + " "
    text = prefix + wl
    spans = protected_spans_for_text(text, {_ORDER_NO})
    assert spans == [(len(prefix), len(prefix) + len(wl))]
    value_at = text.index(wl_value)
    assert value_at + expansion >= spans[0][1]
    new_start = spans[0][0] + expansion
    new_end = spans[0][1] + expansion
    assert new_start <= value_at + expansion < new_end

    patterns = _patterns()
    email_at = _index(patterns, "EMAIL")
    ssn_at = _index(patterns, "SSN")
    assert email_at < ssn_at
    assert patterns[email_at][1].fullmatch(early)
    assert patterns[ssn_at][1].fullmatch(wl_value)
    for pid, pat in patterns[:ssn_at]:
        if pid == "EMAIL":
            continue
        assert pat.search(text) is None, pid

    out = _redact(text, request_id=request_id)
    assert early not in out
    assert wl_value in out
