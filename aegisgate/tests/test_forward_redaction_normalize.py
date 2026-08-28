"""The forward path has to detect on the normalized form — and only detect.

``RedactionFilter`` (the pipeline layer) NFKC-normalizes and strips zero-width
characters before it matches, so it sees a credential that has an invisible
character wedged into it. The forward layer — the pass that rewrites the bytes
actually sent upstream — matched the raw string, so the same value scored as a
hit on one layer and left the gateway in cleartext on the other.

The other half is what must *not* change: normalized text is never written back.
NFKC folds full-width ``，（）：`` to ASCII and NBSP to a plain space, which
would be a client-visible rewrite of every forwarded string rather than only the
ones carrying a credential.
"""

from __future__ import annotations

import re

import pytest

from aegisgate.adapters.openai_compat import sanitize
from aegisgate.adapters.v2_proxy import router as v2_router
from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalMessage, InternalRequest
from aegisgate.filters.redaction import RedactionFilter
from aegisgate.storage.kv import KVStore
from aegisgate.util.masking import NORMALIZED_MATCH_MASK

_ZWSP = "​"
# A token shape already used elsewhere in the suite, with one zero-width
# character wedged in. Raw, the run of token characters is too short to match;
# with the invisibles dropped it is an ordinary credential.
_SPLIT_TOKEN = f"sk-abc{_ZWSP}defghijklmnop"
_PLAIN_TOKEN = _SPLIT_TOKEN.replace(_ZWSP, "")
_FULLWIDTH_TEXT = "参数（可选）：请在配置文件里填写，然后重启。"


class _MemoryKVStore(KVStore):
    def __init__(self) -> None:
        self._mappings: dict[tuple[str, str], dict[str, str]] = {}

    def set_mapping(self, session_id: str, request_id: str, mapping: dict) -> None:
        self._mappings[(session_id, request_id)] = dict(mapping)

    def get_mapping(self, session_id: str, request_id: str) -> dict:
        return dict(self._mappings.get((session_id, request_id), {}))

    def consume_mapping(self, session_id: str, request_id: str) -> dict:
        return self._mappings.pop((session_id, request_id), {})


def _forward(text: str, *, relaxed: bool = True) -> tuple[str, list[dict]]:
    return sanitize._sanitize_text_for_upstream_with_hits(
        text,
        role="user",
        path="input[0].content[0].text",
        field="text",
        relaxed_patterns=relaxed,
    )


def _pipeline_hit(text: str) -> bool:
    """Did E1 ``RedactionFilter`` consider this text a hit?"""
    ctx = RequestContext(
        request_id="reqnorm",
        session_id="sessnorm",
        route="/v1/chat/completions",
        enabled_filters={"redaction"},
    )
    RedactionFilter(_MemoryKVStore()).process_request(
        InternalRequest(
            request_id="reqnorm",
            session_id="sessnorm",
            route="/v1/chat/completions",
            model="test-model",
            messages=[InternalMessage(role="user", content=text)],
        ),
        ctx,
    )
    return bool(ctx.redaction_mapping)


# ── detection now follows the normalized copy ──────────────────────────────


def test_the_raw_form_really_does_not_match() -> None:
    """Guards the premise: without this, the case below proves nothing."""
    token_pattern = next(
        pattern
        for pattern_id, pattern in sanitize._responses_relaxed_redaction_patterns()
        if pattern_id == "TOKEN"
    )
    assert token_pattern.search(_SPLIT_TOKEN) is None
    assert token_pattern.search(_PLAIN_TOKEN) is not None


def test_an_invisible_split_credential_is_redacted_on_the_forward_path() -> None:
    cleaned, hits = _forward(f"here is the key {_SPLIT_TOKEN} for staging")

    assert _SPLIT_TOKEN not in cleaned
    assert "[REDACTED:TOKEN]" in cleaned
    assert [hit["pattern"] for hit in hits] == ["TOKEN"]


def test_the_blob_heuristic_probes_the_stripped_copy() -> None:
    """A zero-width character used to buy a credential a ride inside a "blob".

    ``looks_like_base64_blob`` skips redaction outright, and it refuses to skip
    only when it can see a high-confidence credential shape — which the raw text
    hides.
    """
    filler = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJz" * 6
    # Newlines count as base64 characters, so the ratio test still classifies
    # this as a blob; they are only here to give the token a word boundary.
    blob = f"{filler}\n{_SPLIT_TOKEN}\n{filler}"
    assert len(blob) >= 256
    assert sanitize.looks_like_base64_blob(blob), (
        "premise: the raw text is waved through as a binary blob"
    )

    cleaned, hits = _forward(blob)

    assert _SPLIT_TOKEN not in cleaned
    assert hits


def test_the_two_layers_agree_on_whether_it_is_a_hit() -> None:
    """Replacement syntax may differ ( ``{{AG_…}}`` vs ``[REDACTED:…]`` ); the
    verdict may not."""
    for text in (
        f"here is the key {_SPLIT_TOKEN} for staging",
        f"here is the key {_PLAIN_TOKEN} for staging",
        _FULLWIDTH_TEXT,
        "an ordinary sentence with nothing sensitive in it",
    ):
        cleaned, hits = _forward(text)
        assert bool(hits) == _pipeline_hit(text), text


# ── but nothing normalized is ever written back ────────────────────────────


def test_a_clean_leaf_is_forwarded_byte_for_byte() -> None:
    """Full-width punctuation and NBSP must survive verbatim.

    This one should already pass; it is here so an implementation cannot drift
    into "normalize everything, then write it back".
    """
    text = f"{_FULLWIDTH_TEXT} 结束"
    cleaned, hits = _forward(text)

    assert cleaned == text
    assert not hits


def test_a_surgical_hit_leaves_the_rest_of_the_leaf_untouched() -> None:
    text = f"{_FULLWIDTH_TEXT} token {_PLAIN_TOKEN} 完毕"
    cleaned, _ = _forward(text)

    assert cleaned == f"{_FULLWIDTH_TEXT} token [REDACTED:TOKEN] 完毕"
    assert "参数（可选）：" in cleaned


def test_a_normalized_only_hit_replaces_the_whole_leaf() -> None:
    """Documented consequence: there is no span in the original to substitute."""
    cleaned, _ = _forward(f"{_FULLWIDTH_TEXT} {_SPLIT_TOKEN}")

    assert cleaned == "[REDACTED:TOKEN]"


def test_no_output_of_the_forward_path_is_nfkc_folded() -> None:
    import unicodedata

    text = f"{_FULLWIDTH_TEXT} plain ascii tail"
    cleaned, _ = _forward(text)

    assert cleaned != unicodedata.normalize("NFKC", text)
    assert cleaned == text


# ── V2 keeps the same contract ─────────────────────────────────────────────


def test_v2_forward_path_detects_on_the_normalized_form() -> None:
    value, count, hit_ids, _ = v2_router._redact_text(
        f"here is the key {_SPLIT_TOKEN} for staging", field="text"
    )

    assert _SPLIT_TOKEN not in value
    assert count >= 1
    assert hit_ids


def test_v2_forward_path_does_not_rewrite_a_clean_leaf() -> None:
    text = f"{_FULLWIDTH_TEXT} 结束"
    value, count, hit_ids, _ = v2_router._redact_text(text, field="text")

    assert value == text
    assert count == 0
    assert not hit_ids


@pytest.mark.parametrize("field", ["ciphertext", "signature"])
def test_v2_skip_fields_are_untouched(field: str) -> None:
    value, count, _, _ = v2_router._redact_text(
        f"payload {_SPLIT_TOKEN}", field=field
    )
    assert value == f"payload {_SPLIT_TOKEN}"
    assert count == 0


def test_v2_protected_span_is_not_swept_up_by_the_normalized_probe() -> None:
    """The V1 guard, on the layer that was missing it.

    The raw ``sub`` refuses to rewrite a protected span, which leaves the
    per-rule match count at zero — indistinguishable from "this rule found
    nothing". The normalized probe then finds the same credential in the
    normalized copy and, having no span it may substitute, replaces the entire
    leaf. A newline is enough to produce a differing normalized form, so this
    fired on essentially every multi-line value: "protect this field" became
    "delete this field", and the rest of the leaf went with it.
    """
    text = f"trace_id: {_PLAIN_TOKEN}\nplease keep the rest of this note"

    value, count, hit_ids, _ = v2_router._redact_text(
        text, field="note", whitelist_keys={"trace_id"}
    )

    assert value == text
    assert count == 0
    assert not hit_ids


def test_v2_the_same_leaf_without_the_whitelist_is_still_redacted() -> None:
    """Guards the premise: the protection is what changed the outcome."""
    text = f"trace_id: {_PLAIN_TOKEN}\nplease keep the rest of this note"

    value, count, hit_ids, _ = v2_router._redact_text(text, field="note")

    assert _PLAIN_TOKEN not in value
    assert count >= 1
    assert hit_ids
    # Surgical, not whole-leaf: the surrounding text still has to survive.
    assert "please keep the rest of this note" in value


def test_v2_a_normalized_only_hit_does_not_log_the_whole_leaf() -> None:
    """There is no fragment to mask, so it must not mask the leaf instead.

    ``mask_for_log`` keeps the first three and last two characters. Handed a
    whole leaf, that is an unbounded string in the redaction log line with the
    opening of the message in cleartext — the V1 path uses a fixed marker for
    exactly this reason, and both now read it from ``util.masking``.
    """
    long_leaf = f"{_FULLWIDTH_TEXT} " + ("补充说明。" * 400) + f" {_SPLIT_TOKEN}"
    assert len(long_leaf) > 2000

    value, count, hit_ids, markers = v2_router._redact_text(long_leaf, field="text")

    assert value == "[REDACTED:token]"
    assert count >= 1
    assert hit_ids == ["token"]
    masked = markers[0]["masked_value"]
    assert masked == NORMALIZED_MATCH_MASK
    assert len(masked) < 64
    assert long_leaf[:3] not in masked


def test_both_layers_use_the_same_normalized_match_marker() -> None:
    """One constant, so the two forward paths cannot drift apart on it."""
    assert sanitize._NORMALIZED_MATCH_MASK is NORMALIZED_MATCH_MASK


# ── the shared helper does what both layers rely on ────────────────────────


def test_strip_invisibles_is_a_no_op_on_ordinary_text() -> None:
    from aegisgate.util.text_normalize import strip_invisibles

    text = "ordinary ascii text"
    assert strip_invisibles(text) is text
    assert strip_invisibles(_SPLIT_TOKEN) == _PLAIN_TOKEN
    assert not re.search(r"[​‌‍⁠﻿­]", strip_invisibles(_SPLIT_TOKEN))


# ── the normalized probe respects what the raw pass was told to keep ───────


def test_a_protected_span_is_not_swept_up_by_the_normalized_probe() -> None:
    """A whitelisted value must not turn into a whole-leaf redaction.

    The raw ``sub`` refuses to rewrite a protected span, which leaves the
    per-rule match count at zero — the same state as "this rule found nothing".
    The normalized probe then finds the very same credential in the normalized
    copy and, having no span it may substitute, replaces the entire leaf. For a
    caller that asked to protect one field, "keep this" would become "delete
    this message", and only for leaves that also carry a full-width character.
    """
    text = f"参数（可选）：demo_key: {_PLAIN_TOKEN} 请勿改动"
    cleaned, hits = sanitize._sanitize_text_for_upstream_with_hits(
        text,
        role="user",
        path="messages[0].content[0].text",
        field="text",
        whitelist_keys={"demo_key"},
        relaxed_patterns=True,
    )

    assert cleaned == text
    assert not hits


def test_the_same_leaf_without_the_whitelist_is_still_redacted() -> None:
    """Guards the premise: the protection is what changed the outcome."""
    text = f"参数（可选）：demo_key: {_PLAIN_TOKEN} 请勿改动"
    cleaned, hits = _forward(text)

    assert _PLAIN_TOKEN not in cleaned
    assert hits


def test_a_normalized_only_hit_does_not_log_the_whole_leaf() -> None:
    """There is no fragment to mask, so it must not mask the leaf instead.

    ``mask_for_log`` keeps the first three and last two characters and turns
    everything between into asterisks. Handed a whole leaf that is what goes
    into the redaction log line: unbounded in length, and the opening of the
    message in cleartext.
    """
    long_leaf = f"{_FULLWIDTH_TEXT} " + ("补充说明。" * 400) + f" {_SPLIT_TOKEN}"
    assert len(long_leaf) > 2000

    cleaned, hits = _forward(long_leaf)

    assert cleaned == "[REDACTED:TOKEN]"
    assert [hit["pattern"] for hit in hits] == ["TOKEN"]
    masked = hits[0]["masked_value"]
    assert masked == sanitize._NORMALIZED_MATCH_MASK
    assert len(masked) < 64
    assert long_leaf[:3] not in masked
