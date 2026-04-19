from __future__ import annotations

from dataclasses import dataclass
from typing import Any, AsyncGenerator, Awaitable, Callable, Mapping, Sequence

from fastapi.responses import JSONResponse, StreamingResponse

from aegisgate.core.context import RequestContext


@dataclass(slots=True)
class PreparedStreamTransport:
    upstream_base: str
    upstream_url: str
    connect_urls: tuple[str, ...]
    host_header: str
    forward_headers: Mapping[str, str]


async def prepare_stream_transport(
    *,
    ctx: RequestContext,
    request_headers: Mapping[str, str],
    request_path: str,
    forced_upstream_base: str | None,
    resolve_upstream_base: Callable[
        [Mapping[str, str]], Awaitable[tuple[str, tuple[str, ...], str]]
    ],
    build_upstream_url: Callable[[str, str], str],
    build_connect_urls_for_path: Callable[[str, tuple[str, ...]], tuple[str, ...]],
    build_forward_headers: Callable[[Mapping[str, str]], Mapping[str, str]],
    with_trace_forward_headers: Callable[[Mapping[str, str], str], dict[str, str]],
    invalid_upstream_response: Callable[[str], JSONResponse],
    invalid_upstream_logger: Callable[[str, str], None],
) -> PreparedStreamTransport | JSONResponse:
    connect_bases: tuple[str, ...] = ()
    host_header = ""
    try:
        if forced_upstream_base:
            upstream_base = forced_upstream_base
        else:
            upstream_base, connect_bases, host_header = await resolve_upstream_base(
                request_headers
            )
        upstream_url = build_upstream_url(request_path, upstream_base)
        connect_urls = build_connect_urls_for_path(request_path, connect_bases)
    except ValueError as exc:
        detail = str(exc)
        invalid_upstream_logger(ctx.request_id, detail)
        return invalid_upstream_response(detail)

    return PreparedStreamTransport(
        upstream_base=upstream_base,
        upstream_url=upstream_url,
        connect_urls=connect_urls,
        host_header=host_header,
        forward_headers=with_trace_forward_headers(
            build_forward_headers(request_headers),
            ctx.request_id,
        ),
    )


def build_bypass_stream_response(
    *,
    ctx: RequestContext,
    payload: dict[str, Any],
    transport: PreparedStreamTransport,
    audit: Callable[[], None],
    build_streaming_response: Callable[[AsyncGenerator[bytes, None]], StreamingResponse],
    iter_forward_stream: Callable[
        [PreparedStreamTransport, dict[str, Any]], AsyncGenerator[bytes, None]
    ],
    stream_runtime_reason: Callable[[str], str],
    runtime_error_chunks: Callable[[str, str], Sequence[bytes]],
    internal_error_chunks: Callable[[str], Sequence[bytes]],
    on_before_stream: Callable[[], None] | None = None,
    unexpected_failure_logger: Callable[[str], None] | None = None,
) -> StreamingResponse:
    if on_before_stream is not None:
        on_before_stream()

    async def bypass_generator() -> AsyncGenerator[bytes, None]:
        try:
            async for line in iter_forward_stream(transport, payload):
                yield line
        except RuntimeError as exc:
            detail = str(exc)
            reason = stream_runtime_reason(detail)
            ctx.response_disposition = "block"
            ctx.disposition_reasons.append(reason)
            ctx.enforcement_actions.append(f"upstream:{reason}")
            for chunk in runtime_error_chunks(detail, reason):
                yield chunk
        except Exception as exc:  # pragma: no cover - fail-safe
            detail = f"gateway_internal_error: {exc}"
            ctx.response_disposition = "block"
            ctx.disposition_reasons.append("gateway_internal_error")
            ctx.enforcement_actions.append("upstream:gateway_internal_error")
            if unexpected_failure_logger is not None:
                unexpected_failure_logger(ctx.request_id)
            for chunk in internal_error_chunks(detail):
                yield chunk
        finally:
            audit()

    return build_streaming_response(bypass_generator())


def maybe_build_bypass_stream_response(
    *,
    transport: PreparedStreamTransport,
    filter_mode: str | None,
    is_upstream_whitelisted: Callable[[str], bool],
    build_passthrough_response: Callable[[PreparedStreamTransport], StreamingResponse],
    build_whitelist_response: Callable[[PreparedStreamTransport], StreamingResponse],
) -> StreamingResponse | None:
    if filter_mode == "passthrough":
        return build_passthrough_response(transport)
    if is_upstream_whitelisted(transport.upstream_base):
        return build_whitelist_response(transport)
    return None


def handoff_guarded_generator(
    generator: AsyncGenerator[bytes, None],
    *,
    build_streaming_response: Callable[[AsyncGenerator[bytes, None]], StreamingResponse],
) -> StreamingResponse:
    return build_streaming_response(generator)
