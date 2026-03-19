import json
import queue

from aegisgate.adapters.openai_compat.router import _mark_dangerous_fragments_for_log
from aegisgate.core.context import RequestContext
from aegisgate.core.dangerous_response_log import _resolve_log_path, shutdown_dangerous_response_log_worker
from aegisgate.core.models import InternalResponse
from aegisgate.filters.output_sanitizer import OutputSanitizer


def test_mark_dangerous_fragments_for_log_wraps_exact_fragments():
    ctx = RequestContext(request_id="danger-1", session_id="s1", route="/v1/chat/completions")
    ctx.report_items.append(
        {
            "hit": True,
            "evidence": {"high_risk_command": ["rm -rf /"]},
        }
    )

    marked, fragments = _mark_dangerous_fragments_for_log("prefix rm -rf / suffix", ctx)

    assert marked == "prefix --rm -rf /-- suffix"
    assert fragments == ["rm -rf /"]


def test_output_sanitizer_writes_dangerous_response_log(monkeypatch, tmp_path):
    from aegisgate.core import dangerous_response_log as danger_log
    from aegisgate.config.settings import settings

    log_path = tmp_path / "dangerous_response_samples-2026-03-18.jsonl"
    monkeypatch.setattr(settings, "enable_dangerous_response_log", True)
    monkeypatch.setattr(settings, "dangerous_response_log_path", str(tmp_path / "dangerous_response_samples.jsonl"))
    monkeypatch.setattr(danger_log, "_current_log_date", lambda: "2026-03-18")
    monkeypatch.setattr(danger_log, "_LOG_PATH", log_path)
    monkeypatch.setattr(danger_log, "_LOG_PATH_CONFIG", str(tmp_path / "dangerous_response_samples.jsonl"))
    monkeypatch.setattr(danger_log, "_LOG_PATH_DATE", "2026-03-18")
    monkeypatch.setattr(danger_log, "_resolve_log_path", lambda: log_path)

    plugin = OutputSanitizer()
    resp = InternalResponse(
        request_id="danger-2",
        session_id="s1",
        model="gpt",
        output_text="Please run <script>alert(1)</script> now.",
    )
    ctx = RequestContext(
        request_id="danger-2",
        session_id="s1",
        route="/v1/chat/completions",
        enabled_filters={"output_sanitizer"},
        risk_score=0.4,
    )

    out = plugin.process_response(resp, ctx)
    shutdown_dangerous_response_log_worker()

    assert out.output_text != "Please run <script>alert(1)</script> now."
    payload = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert payload["request_id"] == "danger-2"
    assert payload["source"] == "output_sanitizer"
    assert "--<script-->" in payload["content"]
    assert "<script" in payload["dangerous_fragments"]


def test_resolve_log_path_prefers_configured_path(monkeypatch, tmp_path):
    from aegisgate.core import dangerous_response_log as danger_log
    from aegisgate.config.settings import settings

    configured = tmp_path / "custom-danger.log"
    monkeypatch.setattr(settings, "dangerous_response_log_path", str(configured))
    monkeypatch.setattr(danger_log, "_current_log_date", lambda: "2026-03-18")
    monkeypatch.setattr(danger_log, "_LOG_PATH", None)
    monkeypatch.setattr(danger_log, "_LOG_PATH_CONFIG", None)
    monkeypatch.setattr(danger_log, "_LOG_PATH_DATE", None)

    resolved = _resolve_log_path()

    assert resolved == (tmp_path / "custom-danger-2026-03-18.log")


def test_resolve_log_path_prunes_expired_dated_logs(monkeypatch, tmp_path):
    from aegisgate.core import dangerous_response_log as danger_log
    from aegisgate.config.settings import settings

    configured = tmp_path / "dangerous_response_samples.jsonl"
    expired = tmp_path / "dangerous_response_samples-2026-03-08.jsonl"
    retained = tmp_path / "dangerous_response_samples-2026-03-09.jsonl"
    unrelated = tmp_path / "other-2026-03-01.jsonl"
    expired.write_text("expired\n", encoding="utf-8")
    retained.write_text("retained\n", encoding="utf-8")
    unrelated.write_text("other\n", encoding="utf-8")

    monkeypatch.setattr(settings, "dangerous_response_log_path", str(configured))
    monkeypatch.setattr(danger_log, "_current_log_date", lambda: "2026-03-18")
    monkeypatch.setattr(danger_log, "_LOG_PATH", None)
    monkeypatch.setattr(danger_log, "_LOG_PATH_CONFIG", None)
    monkeypatch.setattr(danger_log, "_LOG_PATH_DATE", None)

    resolved = _resolve_log_path()

    assert resolved == (tmp_path / "dangerous_response_samples-2026-03-18.jsonl")
    assert not expired.exists()
    assert retained.exists()
    assert unrelated.exists()


def test_current_log_date_returns_utc_date():
    from aegisgate.core.dangerous_response_log import _current_log_date
    from datetime import datetime, timezone

    result = _current_log_date()
    # Should be parseable as a UTC date in YYYY-MM-DD format
    assert len(result) == 10
    assert result[4] == "-" and result[7] == "-"
    expected = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
    assert result == expected


def test_shutdown_dangerous_response_log_worker_preserves_live_worker_when_queue_is_full(monkeypatch):
    from aegisgate.core import dangerous_response_log as danger_log

    class FullQueue:
        def __init__(self) -> None:
            self.calls: list[tuple[object | None, float | None]] = []

        def put(self, item, timeout=None):
            self.calls.append((item, timeout))
            raise queue.Full

    class LiveWorker:
        def __init__(self) -> None:
            self.join_calls: list[float | None] = []

        def join(self, timeout=None) -> None:
            self.join_calls.append(timeout)

        def is_alive(self) -> bool:
            return True

    fake_queue = FullQueue()
    fake_worker = LiveWorker()
    monkeypatch.setattr(danger_log, "_LOG_QUEUE", fake_queue)
    monkeypatch.setattr(danger_log, "_LOG_WORKER", fake_worker)
    monkeypatch.setattr(danger_log, "_LOG_PATH", "cached-path")
    monkeypatch.setattr(danger_log, "_LOG_PATH_CONFIG", "cached-config")
    monkeypatch.setattr(danger_log, "_LOG_PATH_DATE", "2026-03-18")

    shutdown_dangerous_response_log_worker(timeout_seconds=0.2)

    assert fake_queue.calls == [(None, 0.2)]
    assert fake_worker.join_calls == [0.2]
    assert danger_log._LOG_WORKER is fake_worker
    assert danger_log._LOG_PATH == "cached-path"
