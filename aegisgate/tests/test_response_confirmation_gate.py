"""What still counts as "auto-obfuscate the whole answer".

The confirmation flow was removed; ``_needs_confirmation`` now decides whether
the answer is replaced by an obfuscated summary. It used to return True for
*any* ``response_``-prefixed tag, which swept in tags that exist only for the
audit log — ``response_truncated``, written by the length cap, is the plain
case: a long but harmless answer came back as a summary.

``_stream_block_reason`` had the mirror-image rule (``requires_human_review``
plus any ``response_`` tag). It keeps that rule, minus the audit-only tags —
deleting it would have loosened the streaming gate rather than narrowing it,
since the length cap never ran on a stream to begin with. Both sides also read
one frozenset of high-risk tags, so a tag in it cannot end the stream while the
non-streaming answer sails through.
"""

from __future__ import annotations

import pytest

from aegisgate.adapters.openai_compat import router as openai_router
from aegisgate.adapters.openai_compat.stream_utils import (
    RESPONSE_AUDIT_ONLY_TAGS,
    RESPONSE_CONFIRMATION_TAGS,
    _stream_block_reason,
)
from aegisgate.core.context import RequestContext


def _ctx() -> RequestContext:
    return RequestContext(
        request_id="r", session_id="s", route="/v1/chat/completions"
    )


# ── audit-only tags no longer obfuscate ────────────────────────────────────


def test_length_cap_does_not_need_confirmation() -> None:
    ctx = _ctx()
    ctx.security_tags.add("response_truncated")
    assert openai_router._needs_confirmation(ctx) is False


def test_typoglycemia_tag_alone_does_not_need_confirmation() -> None:
    ctx = _ctx()
    ctx.security_tags.add("response_injection_typoglycemia")
    assert openai_router._needs_confirmation(ctx) is False


def test_typoglycemia_tag_with_review_still_needs_confirmation() -> None:
    """Review gates on its own, and this change does not touch the detector.

    ``PromptInjectionDetector`` still decides review from ``contextual_discussion``
    rather than ``effective_discussion``, so the production path keeps raising it
    for typoglycemia without a discussion context. Narrowing the prefix rule does
    not, and does not claim to, stop that.
    """
    ctx = _ctx()
    ctx.security_tags.add("response_injection_typoglycemia")
    ctx.requires_human_review = True
    assert openai_router._needs_confirmation(ctx) is True


# ── the real gates still fire ──────────────────────────────────────────────


def test_block_disposition_still_needs_confirmation() -> None:
    ctx = _ctx()
    ctx.response_disposition = "block"
    assert openai_router._needs_confirmation(ctx) is True


def test_review_still_needs_confirmation_on_its_own() -> None:
    ctx = _ctx()
    ctx.requires_human_review = True
    assert openai_router._needs_confirmation(ctx) is True


@pytest.mark.parametrize("tag", sorted(RESPONSE_CONFIRMATION_TAGS))
def test_every_tag_in_the_set_needs_confirmation(tag: str) -> None:
    ctx = _ctx()
    ctx.security_tags.add(tag)
    assert openai_router._needs_confirmation(ctx) is True


def test_high_risk_command_still_needs_confirmation() -> None:
    """Pinned separately from the parametrisation above.

    ``_stream_block_reason`` writes this one outside its own high-risk literal,
    as an unconditional early return, while ``AnomalyDetector`` only raises
    review once the score reaches the threshold. Copying just the literal would
    have made this response "stream terminated, non-stream allowed".
    """
    ctx = _ctx()
    ctx.security_tags.add("response_anomaly_high_risk_command")
    assert openai_router._needs_confirmation(ctx) is True


# ── streaming and non-streaming agree on the set ───────────────────────────


@pytest.mark.parametrize("tag", sorted(RESPONSE_CONFIRMATION_TAGS))
def test_set_tags_gate_both_sides(tag: str) -> None:
    ctx = _ctx()
    ctx.security_tags.add(tag)
    assert _stream_block_reason(ctx) is not None
    assert openai_router._needs_confirmation(ctx) is True


def test_length_cap_gates_neither_side() -> None:
    ctx = _ctx()
    ctx.security_tags.add("response_truncated")
    assert _stream_block_reason(ctx) is None
    assert openai_router._needs_confirmation(ctx) is False


def test_the_length_cap_does_not_end_the_stream_even_with_review() -> None:
    """The narrowing on the streaming side is the audit-only exclusion, only.

    ``response_truncated`` cannot actually reach this gate in production —
    ``_cap_response_text`` has no streaming caller — so this pins the intent
    rather than a live path: an audit-only tag is not evidence of anything, and
    pairing it with review must not cut a long but harmless answer short.
    """
    ctx = _ctx()
    ctx.requires_human_review = True
    ctx.security_tags.add("response_truncated")
    assert _stream_block_reason(ctx) is None
    assert openai_router._needs_confirmation(ctx) is True


def test_review_plus_a_real_response_tag_still_ends_the_stream() -> None:
    """Deleting this rule outright would have loosened the streaming gate.

    ``PromptInjectionDetector`` raises review for typoglycemia without a
    discussion context, and that tag is not in the confirmation set — which is
    exactly the pair this plan says it does not fix. Non-streaming obfuscates
    it. If the streaming side stopped gating on review, the same response would
    stream out in full: a split decision created here, not inherited.
    """
    ctx = _ctx()
    ctx.requires_human_review = True
    ctx.security_tags.add("response_injection_typoglycemia")
    assert _stream_block_reason(ctx) == "response_human_review_required"
    assert openai_router._needs_confirmation(ctx) is True


def test_review_with_no_response_tag_is_the_remaining_split() -> None:
    """A documented remaining divergence, deliberately not closed here.

    Non-streaming treats ``requires_human_review`` as a gate on its own;
    streaming wants a response-side tag with it. Closing this means changing
    what review does on one of the two sides, which is a separate call.
    """
    ctx = _ctx()
    ctx.requires_human_review = True
    assert _stream_block_reason(ctx) is None
    assert openai_router._needs_confirmation(ctx) is True


def test_the_two_tag_sets_do_not_overlap() -> None:
    """An audit-only tag that also gated would be a contradiction in the file."""
    assert not (RESPONSE_AUDIT_ONLY_TAGS & RESPONSE_CONFIRMATION_TAGS)


def test_the_two_gates_read_the_same_object() -> None:
    assert openai_router.RESPONSE_CONFIRMATION_TAGS is RESPONSE_CONFIRMATION_TAGS
