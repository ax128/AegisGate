"""``/__fwd__/`` passthrough route: the true-reverse-proxy face of host forwarding.

``HostForwardMiddleware`` rewrites every non-LLM request on a matched forward
domain to ``/__fwd__/<original path>``. This route serves it by forwarding the
method, headers, body and query to the rule's upstream base **without touching
the path**, and streaming the response back.

Why a dedicated prefix instead of a catch-all: ``POST /v1/<other>`` is already
FULL-matched by ``generic_provider_proxy`` and ``/v2/*`` by the v2 router, so a
catch-all registered last would never see them. Rewriting the prefix makes
"everything else passes through" true. The route is also what keeps the request
inside ``security_boundary_middleware`` (loopback, body cap, header smuggling) —
answering directly from the middleware would bypass all of it.
"""

from __future__ import annotations

from typing import Any, Mapping
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from starlette.background import BackgroundTask

from aegisgate.util.ip_safety import request_host_header
from aegisgate.util.logger import logger

_FORWARD_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


def _build_forward_headers(request: Request) -> dict[str, str]:
    from aegisgate.adapters.v2_proxy.router import _build_forward_headers as build

    return build(request)


def _build_client_response_headers(headers: Mapping[str, str]) -> dict[str, str]:
    from aegisgate.adapters.v2_proxy.router import (
        _build_client_response_headers as build,
    )

    return build(headers)


async def _upstream_client() -> httpx.AsyncClient:
    from aegisgate.adapters.v2_proxy.router import _get_v2_async_client

    return await _get_v2_async_client()


def _upstream_url(rule: Any, path: str, query: str) -> str:
    url = f"{rule.upstream_base}{path}"
    if query:
        return f"{url}?{query}"
    return url


def _unreachable_response(exc: httpx.HTTPError) -> JSONResponse:
    detail = (str(exc) or "").strip() or "connection_failed_or_timeout"
    logger.warning("forward upstream unreachable error=%s", detail)
    return JSONResponse(
        status_code=502,
        content={
            "error": {
                "message": f"upstream_unreachable: {detail}",
                "type": "aegisgate_forward_error",
                "code": "upstream_unreachable",
            }
        },
    )


async def _forward_request(request: Request, rule: Any) -> Response:
    path = str(request.scope.get("aegis_forward_path") or "/")
    if not path.startswith("/"):
        path = f"/{path}"
    url = _upstream_url(rule, path, request.url.query)

    parsed = urlparse(rule.upstream_base)
    headers = _build_forward_headers(request)
    host_header = request_host_header(parsed)
    if host_header:
        headers["Host"] = host_header
    extensions: dict[str, str] | None = None
    if parsed.scheme == "https" and parsed.hostname:
        extensions = {"sni_hostname": parsed.hostname}

    body = await request.body()
    client = await _upstream_client()
    try:
        upstream_request = client.build_request(
            request.method,
            url,
            headers=headers,
            content=body,
            extensions=extensions,
        )
        upstream = await client.send(upstream_request, stream=True)
    except httpx.HTTPError as exc:
        return _unreachable_response(exc)

    response_headers = _build_client_response_headers(upstream.headers)
    logger.debug(
        "forward passthrough method=%s host=%s path=%s -> status=%s",
        request.method,
        getattr(rule, "host", ""),
        path,
        upstream.status_code,
    )
    # Streamed so SSE and long responses are not buffered. The body is never
    # rewritten, so aiter_bytes (decoded) plus dropping content-encoding is the
    # same contract the v2 streaming path uses.
    return StreamingResponse(
        upstream.aiter_bytes(),
        status_code=upstream.status_code,
        headers=response_headers,
        background=BackgroundTask(upstream.aclose),
    )


async def forward_passthrough(request: Request) -> Response:
    """Serve ``/__fwd__/<path>``; 404 when no forward rule is active.

    Without a rule this is the same 404 body a client gets for any unknown path
    today. A client that requests ``/__fwd__/x`` directly on a forward domain is
    forwarded with the original path ``/__fwd__/x`` (the middleware rewrites it
    once more), so the route never self-references.
    """
    rule = request.scope.get("aegis_forward_rule")
    if rule is None:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    return await _forward_request(request, rule)


def register_forward_routes(app: FastAPI) -> None:
    app.add_api_route(
        "/__fwd__/{_ignored:path}",
        forward_passthrough,
        methods=_FORWARD_METHODS,
        name="forward-passthrough",
    )
