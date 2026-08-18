"""B3 / P8 M-1: placeholder regex must see kinds that contain digits (IPV4/IPV6)."""

from __future__ import annotations

import re

from pathlib import Path

import yaml

from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalResponse
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
