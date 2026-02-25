from concurrent.futures import ThreadPoolExecutor

from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalMessage, InternalRequest, InternalResponse
from aegisgate.filters.redaction import RedactionFilter
from aegisgate.filters.restoration import RestorationFilter
from aegisgate.storage.sqlite_store import SqliteKVStore


def test_redaction_restoration_concurrency(tmp_path):
    store = SqliteKVStore(db_path=str(tmp_path / "store.db"))
    total = 200

    def run_case(i: int) -> str:
        redaction = RedactionFilter(store)
        restoration = RestorationFilter(store)
        request_id = f"req-{i}"
        session_id = f"session-{i % 10}"
        email = f"user{i}@example.com"

        req = InternalRequest(
            request_id=request_id,
            session_id=session_id,
            route="/v1/chat/completions",
            model="gpt",
            messages=[InternalMessage(role="user", content=f"email={email}")],
        )
        ctx = RequestContext(
            request_id=request_id,
            session_id=session_id,
            route=req.route,
            enabled_filters={"redaction", "restoration"},
        )

        redacted = redaction.process_request(req, ctx)
        upstream_text = f"echo {redacted.messages[0].content}"

        resp = InternalResponse(
            request_id=request_id,
            session_id=session_id,
            model="gpt",
            output_text=upstream_text,
        )
        restored = restoration.process_response(resp, ctx)

        assert email in restored.output_text
        assert store.get_mapping(session_id, request_id) == {}
        return restored.output_text

    with ThreadPoolExecutor(max_workers=32) as pool:
        outputs = list(pool.map(run_case, range(total)))

    for i, text in enumerate(outputs):
        assert f"user{i}@example.com" in text
