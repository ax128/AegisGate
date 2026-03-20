"""Tests for aegisgate.filters.base — abstract filter contract."""

from __future__ import annotations

from aegisgate.core.context import RequestContext
from aegisgate.core.models import InternalMessage, InternalRequest, InternalResponse
from aegisgate.filters.base import BaseFilter


class _ConcreteFilter(BaseFilter):
    name = "test_filter"


def _make_ctx(*, enabled_filters: set[str] | None = None) -> RequestContext:
    return RequestContext(
        request_id="t-1",
        session_id="s-1",
        route="/v1/chat/completions",
        enabled_filters=enabled_filters or set(),
    )


def _make_request() -> InternalRequest:
    return InternalRequest(
        request_id="t-1", session_id="s-1", route="/v1/chat/completions",
        model="gpt", messages=[InternalMessage(role="user", content="hi")],
    )


def _make_response() -> InternalResponse:
    return InternalResponse(
        request_id="t-1", session_id="s-1", model="gpt", output_text="hello",
    )


def test_enabled_true():
    f = _ConcreteFilter()
    ctx = _make_ctx(enabled_filters={"test_filter"})
    assert f.enabled(ctx) is True


def test_enabled_false():
    f = _ConcreteFilter()
    ctx = _make_ctx(enabled_filters={"other_filter"})
    assert f.enabled(ctx) is False


def test_process_request_passthrough():
    f = _ConcreteFilter()
    req = _make_request()
    ctx = _make_ctx()
    result = f.process_request(req, ctx)
    assert result is req


def test_process_response_passthrough():
    f = _ConcreteFilter()
    resp = _make_response()
    ctx = _make_ctx()
    result = f.process_response(resp, ctx)
    assert result is resp


def test_report_defaults():
    f = _ConcreteFilter()
    report = f.report()
    assert report["filter"] == "test_filter"
    assert report["hit"] is False
    assert report["risk_score"] == 0.0
