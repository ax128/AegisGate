import time

from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalResponse
from aegisgate.filters.restoration import RestorationFilter
from aegisgate.storage.sqlite_store import SqliteKVStore


def test_restoration_blocks_when_placeholder_count_exceeds_policy(tmp_path):
    store = SqliteKVStore(db_path=str(tmp_path / "store.db"))

    mapping = {f"{{{{AG_REQMAX_TOKEN_{i}}}}}": f"token-{i}" for i in range(1, 23)}
    store.set_mapping("s1", "req-max", mapping)

    plugin = RestorationFilter(store)
    ctx = RequestContext(request_id="req-max", session_id="s1", route="/v1/chat/completions", enabled_filters={"restoration"})
    resp = InternalResponse(
        request_id="req-max",
        session_id="s1",
        model="gpt",
        output_text=" ".join(mapping.keys()),
    )

    out = plugin.process_response(resp, ctx)
    assert "token-1" not in out.output_text
    assert ctx.requires_human_review is True


def test_restoration_blocks_stale_mapping_by_ttl(tmp_path):
    store = SqliteKVStore(db_path=str(tmp_path / "store.db"))
    store.set_mapping("s1", "req-ttl", {"{{AG_REQTTL_TOKEN_1}}": "secret"})

    plugin = RestorationFilter(store)
    ctx = RequestContext(request_id="req-ttl", session_id="s1", route="/v1/chat/completions", enabled_filters={"restoration"})
    ctx.redaction_created_at = time.time() - 7200

    resp = InternalResponse(
        request_id="req-ttl",
        session_id="s1",
        model="gpt",
        output_text="{{AG_REQTTL_TOKEN_1}}",
    )

    out = plugin.process_response(resp, ctx)
    assert out.output_text == "{{AG_REQTTL_TOKEN_1}}"
    assert ctx.requires_human_review is True
