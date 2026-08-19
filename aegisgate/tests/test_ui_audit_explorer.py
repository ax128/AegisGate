"""Tests for the audit explorer: bounded reverse reads, paging, filters, export.

``logs/audit.jsonl`` is append-only and never rotated, so the one thing these
tests care about most is that querying it stays bounded — no code path may read
the whole file, and paging must always make progress so a caller cannot spin.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aegisgate.core import gateway_ui_routes
from aegisgate.core.audit_query import (
    AuditFilter,
    iter_lines_reverse,
    parse_timestamp,
    query_log,
    resolve_dangerous_sample_path,
    summarize_log,
)

_ROUTES = ("/v1/chat/completions", "/v1/messages", "/v2/proxy")


def _write_audit(path: Path, count: int) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for index in range(count):
            handle.write(
                json.dumps(
                    {
                        "ts": f"2026-08-{(index % 28) + 1:02d}T{index % 24:02d}:00:00+00:00",
                        "request_id": f"r-{index}",
                        "route": _ROUTES[index % 3],
                        "risk_score": round((index % 10) / 10, 1),
                        "request_disposition": "block" if index % 7 == 0 else "allow",
                        "response_disposition": "sanitize" if index % 3 else "pass",
                        "security_tags": ["injection"] if index % 5 == 0 else [],
                        "enforcement_actions": ["auto_sanitize"],
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )


@pytest.fixture()
def audit_file(tmp_path: Path) -> Path:
    path = tmp_path / "audit.jsonl"
    _write_audit(path, 500)
    return path


@pytest.fixture()
def client(audit_file: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        gateway_ui_routes.settings, "audit_log_path", str(audit_file), raising=False
    )
    app = FastAPI()
    gateway_ui_routes.register_ui_routes(app)
    with TestClient(app) as c:
        c.audit_file = audit_file  # type: ignore[attr-defined]
        yield c


class TestReverseReader:
    def test_yields_lines_newest_first_with_correct_offsets(self, tmp_path: Path) -> None:
        path = tmp_path / "x.jsonl"
        path.write_bytes(b"aaa\nbbb\nccc\n")
        got = [(line, offset) for line, offset, _ in iter_lines_reverse(path, 12, 1 << 20)]
        assert got == [("ccc", 8), ("bbb", 4), ("aaa", 0)]

    def test_reassembles_lines_across_chunk_boundaries(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With a 5-byte chunk every record straddles a boundary."""
        from aegisgate.core import audit_query

        monkeypatch.setattr(audit_query, "_CHUNK_SIZE", 5)
        path = tmp_path / "x.jsonl"
        path.write_bytes(b"aaa\nbbb\nccc\n")
        got = [line for line, _, _ in audit_query.iter_lines_reverse(path, 12, 1 << 20)]
        assert got == ["ccc", "bbb", "aaa"]

    def test_handles_a_file_without_a_trailing_newline(self, tmp_path: Path) -> None:
        path = tmp_path / "x.jsonl"
        path.write_bytes(b"aaa\nbbb")
        got = [line for line, _, _ in iter_lines_reverse(path, 7, 1 << 20)]
        assert got == ["bbb", "aaa"]

    def test_stops_at_the_byte_budget(self, tmp_path: Path) -> None:
        path = tmp_path / "x.jsonl"
        path.write_bytes(b"line\n" * 1000)
        scanned = [s for _, _, s in iter_lines_reverse(path, 5000, 100)]
        assert scanned and max(scanned) <= 100


class TestQueryPaging:
    def test_returns_newest_records_first(self, audit_file: Path) -> None:
        result = query_log(audit_file, limit=3)
        assert [i["request_id"] for i in result.items] == ["r-499", "r-498", "r-497"]

    def test_pages_do_not_overlap_or_skip(self, audit_file: Path) -> None:
        seen: list[str] = []
        cursor = None
        for _ in range(10):
            page = query_log(audit_file, cursor=cursor, limit=50)
            seen.extend(i["request_id"] for i in page.items)
            if page.next_cursor is None:
                break
            cursor = page.next_cursor
        assert len(seen) == len(set(seen)), "pages overlapped"
        assert seen == [f"r-{i}" for i in range(499, -1, -1)]

    def test_walk_terminates_and_reports_reaching_the_start(self, audit_file: Path) -> None:
        cursor = None
        pages = 0
        result = None
        while pages < 50:
            result = query_log(audit_file, cursor=cursor, limit=50)
            pages += 1
            if result.next_cursor is None:
                break
            cursor = result.next_cursor
        assert result is not None and result.reached_start is True
        assert pages < 50, "paging did not terminate"

    def test_a_filter_matching_nothing_still_makes_progress(self, audit_file: Path) -> None:
        """Otherwise a caller paging a no-match filter would spin forever."""
        criteria = AuditFilter(text="no-such-token-anywhere")
        cursor = None
        offsets = []
        for _ in range(30):
            page = query_log(audit_file, criteria, cursor=cursor, limit=10, max_scan_bytes=4096)
            assert page.items == []
            if page.next_cursor is None:
                break
            assert cursor is None or page.next_cursor < cursor, "cursor did not move backwards"
            offsets.append(page.next_cursor)
            cursor = page.next_cursor
        assert cursor is None or page.reached_start

    def test_missing_file_is_not_an_error(self, tmp_path: Path) -> None:
        result = query_log(tmp_path / "absent.jsonl")
        assert result.items == []
        assert result.reached_start is True

    def test_malformed_lines_are_counted_and_skipped(self, tmp_path: Path) -> None:
        path = tmp_path / "x.jsonl"
        path.write_text('{"ts":"2026-01-01T00:00:00+00:00","request_id":"ok"}\nnot json\n[]\n',
                        encoding="utf-8")
        result = query_log(path, limit=10)
        assert [i["request_id"] for i in result.items] == ["ok"]
        assert result.malformed_lines == 2

    def test_limit_is_capped(self, audit_file: Path) -> None:
        result = query_log(audit_file, limit=10_000_000)
        assert len(result.items) <= 5_000


class TestFilters:
    def test_route_substring(self, audit_file: Path) -> None:
        result = query_log(audit_file, AuditFilter(route="/v2/"), limit=5)
        assert all(i["route"] == "/v2/proxy" for i in result.items)

    def test_min_risk(self, audit_file: Path) -> None:
        result = query_log(audit_file, AuditFilter(min_risk=0.8), limit=20)
        assert result.items and all(i["risk_score"] >= 0.8 for i in result.items)

    def test_disposition_matches_either_side(self, audit_file: Path) -> None:
        result = query_log(audit_file, AuditFilter(disposition="block"), limit=10)
        assert result.items
        for item in result.items:
            assert "block" in {item["request_disposition"], item["response_disposition"]}

    def test_security_tag(self, audit_file: Path) -> None:
        result = query_log(audit_file, AuditFilter(tag="injection"), limit=10)
        assert result.items and all("injection" in i["security_tags"] for i in result.items)

    def test_time_window(self, audit_file: Path) -> None:
        since = datetime(2026, 8, 20, tzinfo=timezone.utc)
        result = query_log(audit_file, AuditFilter(since=since), limit=200)
        assert result.items
        assert all(parse_timestamp(i["ts"]) >= since for i in result.items)

    def test_request_id_is_exact_not_substring(self, audit_file: Path) -> None:
        result = query_log(audit_file, AuditFilter(request_id="r-4"), limit=10)
        assert [i["request_id"] for i in result.items] == ["r-4"]

    def test_unparseable_timestamp_is_treated_as_no_bound(self) -> None:
        assert parse_timestamp("not-a-date") is None
        assert parse_timestamp("") is None
        assert parse_timestamp("2026-08-19T10:00:00Z") is not None

    def test_naive_timestamp_is_read_as_utc(self) -> None:
        """The datetime-local input in the console sends no zone."""
        assert parse_timestamp("2026-08-19T10:00").tzinfo is timezone.utc


class TestSummary:
    def test_aggregates_the_scanned_window(self, audit_file: Path) -> None:
        summary = summarize_log(audit_file)
        assert summary["available"] is True
        assert summary["records"] == 500
        assert sum(summary["risk_buckets"].values()) == 500
        assert summary["routes"][0]["count"] > 0
        assert summary["tags"][0]["key"] == "injection"

    def test_respects_the_filter(self, audit_file: Path) -> None:
        summary = summarize_log(audit_file, AuditFilter(route="/v2/proxy"))
        assert summary["records"] < 500
        assert all(r["key"] == "/v2/proxy" for r in summary["routes"])

    def test_reports_incompleteness_rather_than_pretending(self, audit_file: Path) -> None:
        summary = summarize_log(audit_file, max_records=10)
        assert summary["records"] == 10
        assert summary["complete"] is False

    def test_missing_file_reports_unavailable(self, tmp_path: Path) -> None:
        summary = summarize_log(tmp_path / "absent.jsonl")
        assert summary["available"] is False


class TestRoutes:
    def test_query_route(self, client) -> None:
        body = client.get("/__ui__/api/audit?limit=3").json()
        assert [i["request_id"] for i in body["items"]] == ["r-499", "r-498", "r-497"]
        assert body["next_cursor"] is not None
        assert body["file_size"] > 0

    def test_query_route_applies_filters(self, client) -> None:
        body = client.get("/__ui__/api/audit?disposition=block&min_risk=0.5&limit=5").json()
        assert body["items"]
        for item in body["items"]:
            assert item["risk_score"] >= 0.5
            assert "block" in {item["request_disposition"], item["response_disposition"]}

    def test_bad_numeric_params_do_not_500(self, client) -> None:
        response = client.get("/__ui__/api/audit?min_risk=abc&limit=xyz&cursor=nope")
        assert response.status_code == 200

    def test_summary_route(self, client) -> None:
        body = client.get("/__ui__/api/audit/summary").json()
        assert body["records"] == 500

    def test_single_record_route(self, client) -> None:
        body = client.get("/__ui__/api/audit/record/r-42").json()
        assert body["items"][0]["request_id"] == "r-42"
        assert client.get("/__ui__/api/audit/record/nope").status_code == 404

    def test_jsonl_export_omits_internal_offset(self, client) -> None:
        response = client.get("/__ui__/api/audit/export?format=jsonl&limit=5")
        assert response.status_code == 200
        assert "_offset" not in response.text
        lines = response.text.strip().splitlines()
        assert len(lines) == 5
        assert json.loads(lines[0])["request_id"] == "r-499"
        assert "attachment" in response.headers["content-disposition"]

    def test_csv_export_has_a_header_and_row_count(self, client) -> None:
        response = client.get("/__ui__/api/audit/export?format=csv&limit=4")
        assert response.status_code == 200
        rows = response.text.strip().splitlines()
        assert rows[0].startswith("ts,request_id")
        assert len(rows) == 5
        assert response.headers["x-aegis-export-rows"] == "4"

    def test_csv_export_neutralises_formula_injection(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A route recorded as `=cmd|...` must not execute when opened in Excel."""
        path = tmp_path / "audit.jsonl"
        path.write_text(
            json.dumps({"ts": "2026-08-19T00:00:00+00:00", "request_id": "x",
                        "route": "=cmd|' /C calc'!A0"}) + "\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(gateway_ui_routes.settings, "audit_log_path", str(path), raising=False)
        app = FastAPI()
        gateway_ui_routes.register_ui_routes(app)
        with TestClient(app) as c:
            text = c.get("/__ui__/api/audit/export?format=csv").text
        assert "'=cmd" in text
        assert not any(cell.startswith("=cmd") for cell in text.split(","))

    def test_invalid_export_format_is_rejected(self, client) -> None:
        assert client.get("/__ui__/api/audit/export?format=xlsx").status_code == 400

    def test_routes_report_a_disabled_audit_log(
        self, client, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(gateway_ui_routes.settings, "audit_log_path", "", raising=False)
        for path in ("/__ui__/api/audit", "/__ui__/api/audit/summary",
                     "/__ui__/api/audit/record/x", "/__ui__/api/audit/export"):
            response = client.get(path)
            assert response.status_code == 404, path
            assert response.json()["error"] == "audit_log_disabled"


class TestDangerousSamples:
    def test_unknown_date_cannot_steer_the_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The date is matched against enumerated files, never interpolated."""
        for candidate in ("../../etc/passwd", "2026-01-01", "", "..%2F..%2Fetc"):
            assert resolve_dangerous_sample_path(candidate) is None

    def test_route_404s_on_an_unknown_date(self, client) -> None:
        response = client.get("/__ui__/api/dangerous_samples?date=../../etc/passwd")
        assert response.status_code == 404

    def test_dates_route_reports_the_feature_flag(self, client) -> None:
        body = client.get("/__ui__/api/dangerous_samples/dates").json()
        assert "enabled" in body
        assert isinstance(body["items"], list)
