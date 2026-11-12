"""After a pipeline timeout, the worker thread must not keep writing ctx.

The timeout is injected on the settings object for this test only. The default
filter_pipeline_timeout_s stays unchanged.
"""

from __future__ import annotations

import asyncio
import gc
import threading
from typing import Any

import pytest

from aegisgate.adapters.openai_compat.router import (
    _run_request_pipeline,
    _run_response_pipeline,
)
from aegisgate.core.context import PipelineCancelToken, RequestContext
from aegisgate.core.models import InternalRequest, InternalResponse
from aegisgate.core.pipeline import Pipeline
from aegisgate.filters.base import BaseFilter
from aegisgate.filters.exact_value_redaction import ExactValueRedactionFilter

@pytest.fixture(autouse=True)
def _release_function_local_filter_classes():
    """Function-local filters form a refcycle via ``__mro__`` and outlive the test.

    ``test_doc_alignment`` counts ``BaseFilter.__subclasses__()``. Collecting
    here keeps that count stable no matter which file runs first.
    """

    yield
    gc.collect()


_TIMEOUT_S = 0.2
_HOLD_NAME = "hold_for_timeout"
_LATE_NAME = "late_writer"
_INFLIGHT_REASON = "inflight_disposition"
_RESPONSE_FILTER_NAME = "response_writer"
_RESPONSE_REASON = "response_filter_ran"


def _blocking_filters(
    entered: threading.Event,
    release: threading.Event,
    wrote: threading.Event,
) -> tuple[BaseFilter, BaseFilter]:
    """Build the hold/late pair inside the test so they are not import-time subclasses.

    ``test_doc_alignment`` counts ``BaseFilter.__subclasses__()``. A class
    statement at module import would change that count for the whole session.
    """

    class _HoldFilter(BaseFilter):
        name = _HOLD_NAME

        def __init__(self, entered: threading.Event, release: threading.Event) -> None:
            self._entered = entered
            self._release = release

        def process_request(
            self, req: InternalRequest, ctx: RequestContext
        ) -> InternalRequest:
            self._entered.set()
            self._release.wait(timeout=5)
            # Already inside this call when the timeout handler stored block.
            ctx.request_disposition = "sanitize"
            ctx.disposition_reasons.append(_INFLIGHT_REASON)
            return req

        def process_response(
            self, resp: InternalResponse, ctx: RequestContext
        ) -> InternalResponse:
            self._entered.set()
            self._release.wait(timeout=5)
            ctx.response_disposition = "sanitize"
            ctx.disposition_reasons.append(_INFLIGHT_REASON)
            return resp

    class _LateWriter(BaseFilter):
        name = _LATE_NAME

        def __init__(self, wrote: threading.Event) -> None:
            self._wrote = wrote

        def _mark(self, ctx: RequestContext) -> None:
            ctx.risk_score = 99.0
            ctx.request_disposition = "allow"
            ctx.response_disposition = "allow"
            ctx.disposition_reasons.append("late_filter_write")
            ctx.security_tags.add("late_filter_write")
            self._wrote.set()

        def process_request(
            self, req: InternalRequest, ctx: RequestContext
        ) -> InternalRequest:
            self._mark(ctx)
            return req

        def process_response(
            self, resp: InternalResponse, ctx: RequestContext
        ) -> InternalResponse:
            self._mark(ctx)
            return resp

    return _HoldFilter(entered, release), _LateWriter(wrote)


def _snapshot(ctx: RequestContext) -> dict[str, Any]:
    return {
        "risk_score": ctx.risk_score,
        "request_disposition": ctx.request_disposition,
        "response_disposition": ctx.response_disposition,
        "disposition_reasons": list(ctx.disposition_reasons),
        "security_tags": set(ctx.security_tags),
        "enforcement_actions": list(ctx.enforcement_actions),
        "report_items": list(ctx.report_items),
        "redaction_mapping": dict(ctx.redaction_mapping),
    }


def _ctx() -> RequestContext:
    ctx = RequestContext(
        request_id="rq-cancel",
        session_id="sq-cancel",
        route="/v1/chat/completions",
    )
    ctx.enabled_filters.update({_HOLD_NAME, _LATE_NAME})
    return ctx


def _request() -> InternalRequest:
    return InternalRequest(
        request_id="rq-cancel",
        session_id="sq-cancel",
        route="/v1/chat/completions",
        model="test-model",
    )


def _response() -> InternalResponse:
    return InternalResponse(
        request_id="rq-cancel",
        session_id="sq-cancel",
        model="test-model",
        output_text="hello",
    )


async def _drive_until_timeout(
    runner: Any,
    payload: Any,
    ctx: RequestContext,
    *,
    entered: threading.Event,
    release: threading.Event,
    finished: threading.Event,
) -> None:
    task = asyncio.create_task(runner(None, payload, ctx))
    assert await asyncio.to_thread(entered.wait, 5), "worker did not enter the pipeline"
    await task
    assert "filter_pipeline_timeout" in ctx.security_tags
    before = _snapshot(ctx)
    release.set()
    assert await asyncio.to_thread(finished.wait, 5), "worker did not finish after release"
    after = _snapshot(ctx)
    assert after == before, f"worker wrote ctx after timeout: before={before} after={after}"


@pytest.mark.parametrize("action", ["block", "pass"])
def test_request_pipeline_timeout_stops_worker_writing_ctx(
    monkeypatch: pytest.MonkeyPatch,
    action: str,
) -> None:
    entered = threading.Event()
    release = threading.Event()
    wrote = threading.Event()
    finished = threading.Event()
    hold, late = _blocking_filters(entered, release, wrote)
    pipeline = Pipeline(request_filters=[hold, late], response_filters=[])

    def run_sync(
        req: InternalRequest,
        ctx: RequestContext,
        cancel_token: PipelineCancelToken | None = None,
    ) -> InternalRequest:
        try:
            return pipeline.run_request(req, ctx, cancel_token)
        finally:
            finished.set()

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_request_pipeline_sync",
        run_sync,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.settings.filter_pipeline_timeout_s",
        _TIMEOUT_S,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.settings.request_pipeline_timeout_action",
        action,
    )

    ctx = _ctx()
    asyncio.run(
        _drive_until_timeout(
            _run_request_pipeline,
            _request(),
            ctx,
            entered=entered,
            release=release,
            finished=finished,
        )
    )
    assert not wrote.is_set()
    assert "late_filter_write" not in ctx.disposition_reasons
    if action == "block":
        assert ctx.request_disposition == "block"
        assert "request_filter_timeout" in ctx.disposition_reasons
        assert _INFLIGHT_REASON not in ctx.disposition_reasons


def test_response_pipeline_timeout_stops_worker_writing_ctx(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = threading.Event()
    release = threading.Event()
    wrote = threading.Event()
    finished = threading.Event()
    hold, late = _blocking_filters(entered, release, wrote)
    pipeline = Pipeline(request_filters=[], response_filters=[hold, late])

    def run_sync(
        resp: InternalResponse,
        ctx: RequestContext,
        cancel_token: PipelineCancelToken | None = None,
    ) -> InternalResponse:
        try:
            return pipeline.run_response(resp, ctx, cancel_token)
        finally:
            finished.set()

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_response_pipeline_sync",
        run_sync,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.settings.filter_pipeline_timeout_s",
        _TIMEOUT_S,
    )

    ctx = _ctx()
    asyncio.run(
        _drive_until_timeout(
            _run_response_pipeline,
            _response(),
            ctx,
            entered=entered,
            release=release,
            finished=finished,
        )
    )
    assert not wrote.is_set()
    assert "late_filter_write" not in ctx.disposition_reasons
    assert ctx.response_disposition == "block"
    assert "filter_timeout" in ctx.disposition_reasons
    assert _INFLIGHT_REASON not in ctx.disposition_reasons


def test_request_timeout_pass_still_runs_response_filters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """pass releases the request. The same ctx must still filter the response."""

    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    class _QuietHold(BaseFilter):
        name = _HOLD_NAME

        def process_request(
            self, req: InternalRequest, ctx: RequestContext
        ) -> InternalRequest:
            entered.set()
            release.wait(timeout=5)
            return req

    request_pipeline = Pipeline(
        request_filters=[_QuietHold()], response_filters=[]
    )

    def run_request_sync(
        req: InternalRequest,
        ctx: RequestContext,
        cancel_token: PipelineCancelToken | None = None,
    ) -> InternalRequest:
        try:
            return request_pipeline.run_request(req, ctx, cancel_token)
        finally:
            finished.set()

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_request_pipeline_sync",
        run_request_sync,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.settings.filter_pipeline_timeout_s",
        _TIMEOUT_S,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.settings.request_pipeline_timeout_action",
        "pass",
    )

    ctx = _ctx()
    asyncio.run(
        _drive_until_timeout(
            _run_request_pipeline,
            _request(),
            ctx,
            entered=entered,
            release=release,
            finished=finished,
        )
    )

    ran = threading.Event()

    class _ResponseWriter(BaseFilter):
        name = _RESPONSE_FILTER_NAME

        def process_response(
            self, resp: InternalResponse, ctx: RequestContext
        ) -> InternalResponse:
            ran.set()
            ctx.response_disposition = "sanitize"
            ctx.disposition_reasons.append(_RESPONSE_REASON)
            return resp

    ctx.enabled_filters.add(_RESPONSE_FILTER_NAME)
    response_pipeline = Pipeline(
        request_filters=[], response_filters=[_ResponseWriter()]
    )

    def run_response_sync(
        resp: InternalResponse,
        ctx: RequestContext,
        cancel_token: PipelineCancelToken | None = None,
    ) -> InternalResponse:
        return response_pipeline.run_response(resp, ctx, cancel_token)

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router._run_response_pipeline_sync",
        run_response_sync,
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.settings.filter_pipeline_timeout_s",
        5.0,
    )
    asyncio.run(_run_response_pipeline(None, _response(), ctx))
    assert ran.is_set(), "response filter did not run after request timeout action=pass"
    assert ctx.response_disposition == "sanitize"
    assert _RESPONSE_REASON in ctx.disposition_reasons


def test_filter_enabled_observes_pipeline_cancelled() -> None:
    ctx = RequestContext(request_id="rq", session_id="sq", route="/v1/chat/completions")
    ctx.enabled_filters.add(_LATE_NAME)

    class _Probe(BaseFilter):
        name = _LATE_NAME

    probe = _Probe()
    token = PipelineCancelToken()
    ctx.pipeline_cancel_token = token
    assert probe.enabled(ctx) is True
    token.cancel()
    assert probe.enabled(ctx) is False

    exact = ExactValueRedactionFilter()
    ctx.forward_filter_overrides["exact_value_redaction"] = True
    assert exact.enabled(ctx) is False


def test_cancelled_pipeline_skips_filter_that_ignores_enabled() -> None:
    class _Stubborn(BaseFilter):
        name = "stubborn"

        def enabled(self, ctx: RequestContext) -> bool:
            return True

        def process_request(
            self, req: InternalRequest, ctx: RequestContext
        ) -> InternalRequest:
            ctx.risk_score = 7.0
            ctx.disposition_reasons.append("stubborn_write")
            return req

    ctx = _ctx()
    token = PipelineCancelToken()
    token.cancel()
    ctx.pipeline_cancel_token = token
    Pipeline(request_filters=[_Stubborn()], response_filters=[]).run_request(
        _request(), ctx, token
    )
    assert ctx.risk_score == 0.0
    assert ctx.disposition_reasons == []
    assert ctx.report_items == []


def test_pipeline_error_path_does_not_write_ctx_after_cancel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # logger.exception keeps the traceback, and pytest keeps the log record.
    # That would pin this function-local filter class for the rest of the session
    # and change BaseFilter.__subclasses__() for test_doc_alignment.
    monkeypatch.setattr(
        "aegisgate.core.pipeline.logger.exception",
        lambda *args, **kwargs: None,
    )

    token = PipelineCancelToken()

    class _Boom(BaseFilter):
        name = "boom"

        def enabled(self, ctx: RequestContext) -> bool:
            return True

        def process_request(
            self, req: InternalRequest, ctx: RequestContext
        ) -> InternalRequest:
            token.cancel()
            raise RuntimeError("filter failed after cancel")

    ctx = _ctx()
    ctx.pipeline_cancel_token = token
    Pipeline(request_filters=[_Boom()], response_filters=[]).run_request(
        _request(), ctx, token
    )


def test_run_request_uses_submitted_token_not_the_one_later_stored_on_ctx() -> None:
    """A queued call must keep the token submitted with it.

    The pool does not have to be full. The token for this call is already
    cancelled, and ctx now holds a different uncancelled token, the way a
    later response call replaces it before the queued request task starts.
    """

    armed = PipelineCancelToken()
    armed.cancel()
    ctx = _ctx()
    ctx.enabled_filters.add("queued_writer")
    ctx.pipeline_cancel_token = PipelineCancelToken()

    class _QueuedWriter(BaseFilter):
        name = "queued_writer"

        def process_request(
            self, req: InternalRequest, ctx: RequestContext
        ) -> InternalRequest:
            ctx.risk_score = 4.0
            ctx.request_disposition = "sanitize"
            ctx.disposition_reasons.append("queued_request_write")
            return req

    Pipeline(request_filters=[_QueuedWriter()], response_filters=[]).run_request(
        _request(), ctx, armed
    )
    assert ctx.risk_score == 0.0
    assert ctx.request_disposition == "allow"
    assert "queued_request_write" not in ctx.disposition_reasons
    assert ctx.request_disposition == "allow"
    assert ctx.disposition_reasons == []
    assert ctx.report_items == []
    assert ctx.enforcement_actions == []
