from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalResponse
from aegisgate.filters.restoration import RestorationFilter
from aegisgate.storage.sqlite_store import SqliteKVStore


def test_restoration_puts_back_placeholders(tmp_path):
    store = SqliteKVStore(db_path=str(tmp_path / "store.db"))
    store.set_mapping("s1", "r1", {"{{AG_R1_EMAIL_1}}": "a@b.com"})

    plugin = RestorationFilter(store)
    ctx = RequestContext(request_id="r1", session_id="s1", route="/v1/chat/completions", enabled_filters={"restoration"})
    resp = InternalResponse(request_id="r1", session_id="s1", model="gpt", output_text="hello {{AG_R1_EMAIL_1}}")

    out = plugin.process_response(resp, ctx)
    assert out.output_text == "hello a@b.com"
    assert store.get_mapping("s1", "r1") == {}
