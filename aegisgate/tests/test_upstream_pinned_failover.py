"""Pinned-IP failover must not POST again after the request has been sent."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable

import httpx
import pytest

from aegisgate.adapters.openai_compat import upstream as upstream_mod
from aegisgate.adapters.openai_compat.router import _iter_forward_stream_with_pinning
from aegisgate.adapters.openai_compat.upstream import (
    _forward_json_pinned,
    _forward_stream_lines_pinned,
)

_FIRST = "203.0.113.10"
_SECOND = "203.0.113.20"
_PARTIAL = b"data: partial\n\n"
_SECOND_FRAME = b"data: from-second\n\n"
_PAYLOAD = {"model": "gpt-test", "messages": [{"role": "user", "content": "ping"}]}
_HEADERS = {"content-type": "application/json"}
_HOST_HEADER = "api.example.test"


def _connect_urls() -> tuple[str, ...]:
    return (
        f"http://{_FIRST}/v1/chat/completions",
        f"http://{_SECOND}/v1/chat/completions",
    )


class _Frames(httpx.AsyncByteStream):
    def __init__(self, frames: list[bytes]) -> None:
        self._frames = frames

    async def __aiter__(self) -> AsyncIterator[bytes]:  # type: ignore[override]
        for frame in self._frames:
            yield frame


class _PartialThenReadError(httpx.AsyncByteStream):
    async def __aiter__(self) -> AsyncIterator[bytes]:  # type: ignore[override]
        yield _PARTIAL
        raise httpx.ReadError("peer closed")


def _install_client(
    monkeypatch: pytest.MonkeyPatch,
    handler: Callable[[httpx.Request], httpx.Response],
) -> httpx.AsyncClient:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=10.0)
    monkeypatch.setattr(upstream_mod, "_upstream_async_client", client)
    return client


def _counting_handler(
    hosts: list[str],
    *,
    fail_first: Exception | None,
    stream_frames: list[bytes] | None,
) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        hosts.append(request.url.host)
        if request.url.host == _FIRST and fail_first is not None:
            raise fail_first
        if stream_frames is not None:
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=_Frames(stream_frames),
            )
        return httpx.Response(200, json={"id": "from-second"})

    return handler


async def test_stream_pinned_does_not_resend_after_a_chunk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A chunk already handed downstream means the POST was sent; do not try the next IP."""
    hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hosts.append(request.url.host)
        if request.url.host == _FIRST:
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=_PartialThenReadError(),
            )
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=_Frames([_SECOND_FRAME]),
        )

    client = _install_client(monkeypatch, handler)
    chunks: list[bytes] = []
    caught: BaseException | None = None
    try:
        async for chunk in _forward_stream_lines_pinned(
            url="http://api.example.test/v1/chat/completions",
            payload=_PAYLOAD,
            headers=_HEADERS,
            connect_urls=_connect_urls(),
            host_header=_HOST_HEADER,
        ):
            chunks.append(chunk)
    except RuntimeError as exc:
        caught = exc
    finally:
        await client.aclose()

    assert hosts == [_FIRST], f"hosts={hosts!r} chunks={chunks!r} error={caught!r}"
    assert chunks == [_PARTIAL], chunks
    assert caught is not None and str(caught).startswith("upstream_unreachable:"), caught


async def test_stream_pinned_switches_target_on_connect_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ConnectError means the request was not sent, so the next pinned IP is fair game."""
    hosts: list[str] = []
    handler = _counting_handler(
        hosts,
        fail_first=httpx.ConnectError("connection refused"),
        stream_frames=[_SECOND_FRAME],
    )
    client = _install_client(monkeypatch, handler)
    try:
        chunks = [
            chunk
            async for chunk in _forward_stream_lines_pinned(
                url="http://api.example.test/v1/chat/completions",
                payload=_PAYLOAD,
                headers=_HEADERS,
                connect_urls=_connect_urls(),
                host_header=_HOST_HEADER,
            )
        ]
    finally:
        await client.aclose()

    assert hosts == [_FIRST, _SECOND], hosts
    assert chunks == [_SECOND_FRAME]


async def test_json_pinned_does_not_retry_read_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ReadTimeout means the POST already went out; resending bills the upstream twice."""
    hosts: list[str] = []
    handler = _counting_handler(
        hosts,
        fail_first=httpx.ReadTimeout("timed out"),
        stream_frames=None,
    )
    client = _install_client(monkeypatch, handler)
    caught: BaseException | None = None
    try:
        await _forward_json_pinned(
            url="http://api.example.test/v1/chat/completions",
            payload=_PAYLOAD,
            headers=_HEADERS,
            connect_urls=_connect_urls(),
            host_header=_HOST_HEADER,
        )
    except RuntimeError as exc:
        caught = exc
    finally:
        await client.aclose()

    assert hosts == [_FIRST], f"hosts={hosts!r} error={caught!r}"
    assert caught is not None and str(caught).startswith("upstream_unreachable:"), caught


@pytest.mark.parametrize("exc_type", [httpx.ConnectError, httpx.ConnectTimeout])
async def test_json_pinned_switches_target_on_connect_failure(
    monkeypatch: pytest.MonkeyPatch,
    exc_type: type[httpx.HTTPError],
) -> None:
    """ConnectError and ConnectTimeout are the only JSON failures that may change IP."""
    hosts: list[str] = []
    handler = _counting_handler(
        hosts,
        fail_first=exc_type("connect failed"),
        stream_frames=None,
    )
    client = _install_client(monkeypatch, handler)
    try:
        status, body = await _forward_json_pinned(
            url="http://api.example.test/v1/chat/completions",
            payload=_PAYLOAD,
            headers=_HEADERS,
            connect_urls=_connect_urls(),
            host_header=_HOST_HEADER,
        )
    finally:
        await client.aclose()

    assert hosts == [_FIRST, _SECOND], (exc_type, hosts)
    assert status == 200
    assert body == {"id": "from-second"}


async def test_bootstrap_retry_does_not_resend_pinned_read_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Outer stream retries must not POST a pinned target again after ReadTimeout.

    ``_iter_forward_stream_with_pinning`` retries ``upstream_unreachable`` before
    the first byte when ``stream_bootstrap_retries`` is set. That second call
    would send a request the pinned forward already put on the wire.
    """
    hosts: list[str] = []
    handler = _counting_handler(
        hosts,
        fail_first=httpx.ReadTimeout("timed out"),
        stream_frames=[_SECOND_FRAME],
    )
    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.settings.stream_bootstrap_retries",
        1,
    )
    client = _install_client(monkeypatch, handler)
    chunks: list[bytes] = []
    caught: BaseException | None = None
    try:
        async for chunk in _iter_forward_stream_with_pinning(
            url="http://api.example.test/v1/chat/completions",
            payload=_PAYLOAD,
            headers=_HEADERS,
            connect_urls=_connect_urls(),
            host_header=_HOST_HEADER,
        ):
            chunks.append(chunk)
    except RuntimeError as exc:
        caught = exc
    finally:
        await client.aclose()

    assert hosts == [_FIRST], f"hosts={hosts!r} chunks={chunks!r} error={caught!r}"
    assert chunks == []
    assert caught is not None and str(caught).startswith("upstream_unreachable:"), caught


async def test_bootstrap_retry_still_walks_pinned_targets_on_connect_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A connect failure never sent the request, so the opt-in bootstrap retry may try again."""
    hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hosts.append(request.url.host)
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(
        "aegisgate.adapters.openai_compat.router.settings.stream_bootstrap_retries",
        1,
    )
    client = _install_client(monkeypatch, handler)
    caught: BaseException | None = None
    try:
        async for _chunk in _iter_forward_stream_with_pinning(
            url="http://api.example.test/v1/chat/completions",
            payload=_PAYLOAD,
            headers=_HEADERS,
            connect_urls=_connect_urls(),
            host_header=_HOST_HEADER,
        ):
            pass
    except RuntimeError as exc:
        caught = exc
    finally:
        await client.aclose()

    assert hosts == [_FIRST, _SECOND, _FIRST, _SECOND], hosts
    assert caught is not None and str(caught).startswith("upstream_unreachable:"), caught
