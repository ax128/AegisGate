"""Restoration TTL expires a mapping only when one exists.

``redaction_created_at`` defaults to context creation and is reset only when a
redaction mapping is stored. A stream that never redacted anything used to be
tagged ``restoration_stale_mapping`` and scored 0.95 once that timestamp was
older than ``restore_ttl_seconds`` (1800), which the stream gate treats as a
block.
"""

from __future__ import annotations

import time

from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalResponse
from aegisgate.filters.restoration import RestorationFilter
from aegisgate.storage.kv import KVStore

_STALE_AGE_SECONDS = 2000
_SECRET = "sk-test-0000"
_TOKEN = "{{AG_REQ_APIKEY_1}}"


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


def _ctx(**overrides: object) -> RequestContext:
    ctx = RequestContext(
        request_id="req-ttl",
        session_id="sess-ttl",
        route="/v1/chat/completions",
        enabled_filters={"restoration"},
    )
    for key, value in overrides.items():
        setattr(ctx, key, value)
    return ctx


def _response(text: str) -> InternalResponse:
    return InternalResponse(
        request_id="req-ttl",
        session_id="sess-ttl",
        model="test-model",
        output_text=text,
    )


def test_empty_mapping_older_than_ttl_does_not_block() -> None:
    """Nothing was redacted, so a 2000s-old timestamp must not block the stream."""
    store = _MemoryKVStore()
    restorer = RestorationFilter(store)
    ctx = _ctx(
        redaction_created_at=time.time() - _STALE_AGE_SECONDS,
        redaction_mapping={},
    )
    text = "partial stream, still talking, nothing was redacted"
    resp = restorer.process_response(_response(text), ctx)

    assert resp.output_text == text
    assert "restoration_stale_mapping" not in ctx.security_tags
    assert ctx.risk_score == 0.0
    assert ctx.requires_human_review is False
    assert ctx.enforcement_actions == []
    assert restorer.report()["hit"] is False


def test_nonempty_mapping_older_than_ttl_still_blocks() -> None:
    """A mapping that exists is still refused once it is older than the TTL."""
    store = _MemoryKVStore()
    restorer = RestorationFilter(store)
    ctx = _ctx(
        redaction_created_at=time.time() - _STALE_AGE_SECONDS,
        redaction_mapping={_TOKEN: _SECRET},
    )
    resp = restorer.process_response(_response(f"the value is {_TOKEN}"), ctx)

    assert _SECRET not in resp.output_text
    assert _TOKEN in resp.output_text
    assert "restoration_stale_mapping" in ctx.security_tags
    assert ctx.risk_score >= 0.95
    assert ctx.requires_human_review is True
    assert "restoration:stale_mapping:block" in ctx.enforcement_actions
    assert not ctx.redaction_mapping


def test_store_only_mapping_older_than_ttl_still_blocks() -> None:
    """TTL still applies when the only copy of the mapping is in the store."""
    store = _MemoryKVStore()
    store.set_mapping("sess-ttl", "req-ttl", {_TOKEN: _SECRET})
    restorer = RestorationFilter(store)
    ctx = _ctx(
        redaction_created_at=time.time() - _STALE_AGE_SECONDS,
        redaction_mapping={},
    )
    resp = restorer.process_response(_response(f"the value is {_TOKEN}"), ctx)

    assert _SECRET not in resp.output_text
    assert _TOKEN in resp.output_text
    assert "restoration_stale_mapping" in ctx.security_tags
    assert ctx.risk_score >= 0.95
    assert ctx.requires_human_review is True
    assert not ctx.redaction_mapping
