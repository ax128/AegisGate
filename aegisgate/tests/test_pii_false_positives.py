"""Clock times, git SHAs, and non-Luhn digit runs are not PII labels.

The full pattern set (any route that is not one of the three conversation
routes) is where IPV6, CRYPTO_BTC_ADDR and CARD actually run. On the relaxed
conversation routes those ids are off, so a green result there would not say
anything about the rules.
"""

from __future__ import annotations

from dataclasses import dataclass

from aegisgate.adapters.openai_compat.sanitize import _sanitize_text_for_upstream_with_hits
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalMessage, InternalRequest
from aegisgate.filters.redaction import RedactionFilter
from aegisgate.storage.kv import KVStore
from aegisgate.util.checksums import luhn_valid

# Not a conversation route: CARD / IPV6 / CRYPTO_BTC_ADDR are not in the
# relaxed id set, so /v1/chat/completions would leave all three in the clear
# for a reason that has nothing to do with these rules.
_FULL_SET_ROUTE = "/v1/embeddings"

# 40 hex digits, the shape of a git object id. It starts with 1 because that
# is a normal SHA-1 prefix (about one in eight object ids do); the digits are
# repeated 'a' so this cannot be anybody's key or address.
_GIT_SHA = "1" + ("a" * 39)

# The public Visa test PAN with the check digit flipped. Luhn fails, and it
# is not a live card number.
_NON_LUHN_16 = "4111111111111112"

_LUHN_OK = "4111111111111111"
_IPV6 = "2001:db8:85a3:0:0:8a2e:370:7334"
_BTC = "bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"


class _MemoryKVStore(KVStore):
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


def _redact(text: str) -> _Redacted:
    flt = RedactionFilter(_MemoryKVStore())
    ctx = RequestContext(request_id="req-fp", session_id="sess-fp", route=_FULL_SET_ROUTE)
    req = InternalRequest(
        request_id=ctx.request_id,
        session_id=ctx.session_id,
        route=ctx.route,
        model="m",
        messages=[InternalMessage(role="user", content=text)],
    )
    out = flt.process_request(req, ctx)
    return _Redacted(" ".join(m.content for m in out.messages), ctx)


def _kinds(out: _Redacted) -> set[str]:
    kinds: set[str] = set()
    for placeholder in out.ctx.redaction_mapping:
        inner = placeholder.strip("{}")
        parts = inner.split("_")
        if len(parts) < 4 or parts[0] != "AG":
            continue
        kinds.add("_".join(parts[2:-1]))
    return kinds


def _forward(text: str) -> tuple[str, list[dict]]:
    cleaned, hits = _sanitize_text_for_upstream_with_hits(
        text,
        role="user",
        path="messages[0].content",
        field="content",
        relaxed_patterns=False,
    )
    return cleaned, hits


def _hit_ids(hits: list[dict]) -> set[str]:
    return {str(hit.get("pattern")) for hit in hits}


def test_clock_time_is_not_labeled_ipv6() -> None:
    text = "meet at 12:34:56 sharp"
    out = _redact(text)
    assert "12:34:56" in out.text
    assert "IPV6" not in _kinds(out)

    cleaned, hits = _forward(text)
    assert "12:34:56" in cleaned
    assert "IPV6" not in _hit_ids(hits)


def test_git_sha_is_not_labeled_btc() -> None:
    assert len(_GIT_SHA) == 40
    assert all(ch in "0123456789abcdef" for ch in _GIT_SHA)
    text = f"commit {_GIT_SHA}"
    out = _redact(text)
    assert _GIT_SHA in out.text
    assert "CRYPTO_BTC_ADDR" not in _kinds(out)

    cleaned, hits = _forward(text)
    assert _GIT_SHA in cleaned
    assert "CRYPTO_BTC_ADDR" not in _hit_ids(hits)


def test_non_luhn_16_digits_are_not_labeled_card() -> None:
    assert luhn_valid(_NON_LUHN_16) is False
    text = f"ref {_NON_LUHN_16}"
    out = _redact(text)
    assert _NON_LUHN_16 in out.text
    assert "CARD" not in _kinds(out)

    cleaned, hits = _forward(text)
    assert _NON_LUHN_16 in cleaned
    assert "CARD" not in _hit_ids(hits)


def test_shipped_ipv6_btc_and_luhn_pan_stay_labeled() -> None:
    """The tightenings above must not drop the shapes the matrix already ships."""
    ipv6 = _redact(_IPV6)
    assert _IPV6 not in ipv6.text
    assert "IPV6" in _kinds(ipv6)

    btc = _redact(_BTC)
    assert _BTC not in btc.text
    assert "CRYPTO_BTC_ADDR" in _kinds(btc)

    assert luhn_valid(_LUHN_OK) is True
    card = _redact(f"card {_LUHN_OK}")
    assert _LUHN_OK not in card.text
    assert "CARD" in _kinds(card)

    forwarded, hits = _forward(f"card {_LUHN_OK}")
    assert _LUHN_OK not in forwarded
    assert "CARD" in _hit_ids(hits)


def test_colon_mac_after_a_label_is_still_redacted() -> None:
    """``mac:`` fails the MAC lookbehind; IPV6 is the fallback for six hextets."""
    address = "00:1A:2B:3C:4D:5E"
    out = _redact(f"mac:{address}")
    assert address not in out.text
    assert "IPV6" in _kinds(out)
