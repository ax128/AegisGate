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
from urllib.parse import urlparse, urlunparse

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


def _client_scheme(request: Request) -> str:
    """The scheme the client saw, trusting X-Forwarded-Proto only from a trusted proxy."""
    from aegisgate.core.gateway_network import trusted_forwarded_proto

    proto = trusted_forwarded_proto(request)
    if proto in {"http", "https"}:
        return proto
    return request.url.scheme or "http"


def rewrite_location(
    value: str, *, upstream_host: str, gateway_origin: str
) -> str:
    """Map an absolute upstream Location back onto the gateway. Relative stays put."""
    if not value:
        return value
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return value
    if (parsed.hostname or "").strip().lower() != upstream_host:
        return value
    gateway = urlparse(gateway_origin)
    netloc = gateway.netloc or gateway.path
    return urlunparse(
        (gateway.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
    )


def rewrite_set_cookie(
    value: str, *, upstream_host: str, gateway_host: str
) -> str:
    """Rewrite ``Domain=`` on one Set-Cookie, or drop it when it cannot be mapped.

    A ``Domain`` naming the upstream host (or a parent of it) maps onto the
    gateway host. Anything else is removed rather than passed through, so the
    cookie degrades to a host-only cookie for the gateway instead of leaking the
    upstream domain to the client.
    """
    if not value:
        return value
    parts = value.split(";")
    out = [parts[0]]
    for attribute in parts[1:]:
        stripped = attribute.strip()
        if stripped.lower().startswith("domain="):
            domain = stripped[len("domain=") :].strip().lstrip(".").lower()
            if domain and (domain == upstream_host or upstream_host.endswith(f".{domain}")):
                out.append(f" Domain={gateway_host}")
            continue
        out.append(attribute)
    return ";".join(out)


def rewrite_access_control_allow_origin(
    value: str, *, upstream_origin: str, gateway_origin: str
) -> str:
    """Replace an exact upstream-origin ACAO; ``*`` and unrelated values stay."""
    if value.strip() == upstream_origin:
        return gateway_origin
    return value


def build_forward_response_headers(
    upstream_headers: Mapping[str, str],
    *,
    upstream_base: str,
    gateway_host: str,
    gateway_scheme: str,
) -> tuple[dict[str, str], list[str]]:
    """Build the client-facing response headers, rewriting the three URL-bearing ones.

    Unlike ``_build_client_response_headers`` (which drops ``set-cookie``) this
    keeps every Set-Cookie as its own header: each one is rewritten separately and
    ``dict`` cannot represent the duplicates.
    """
    parsed_upstream = urlparse(upstream_base)
    upstream_host = (parsed_upstream.hostname or "").strip().lower()
    upstream_origin = f"{parsed_upstream.scheme}://{parsed_upstream.netloc}"
    gateway_origin = f"{gateway_scheme}://{gateway_host}"

    headers = _build_client_response_headers(upstream_headers)

    location = upstream_headers.get("location")
    if location:
        headers["location"] = rewrite_location(
            location, upstream_host=upstream_host, gateway_origin=gateway_origin
        )
    acao = upstream_headers.get("access-control-allow-origin")
    if acao:
        headers["access-control-allow-origin"] = rewrite_access_control_allow_origin(
            acao,
            upstream_origin=upstream_origin,
            gateway_origin=gateway_origin,
        )

    get_list = getattr(upstream_headers, "get_list", None)
    if callable(get_list):
        raw_cookies = list(get_list("set-cookie"))
    else:
        raw = upstream_headers.get("set-cookie")
        raw_cookies = [raw] if raw else []
    cookies = [
        rewrite_set_cookie(
            cookie, upstream_host=upstream_host, gateway_host=gateway_host
        )
        for cookie in raw_cookies
    ]
    return headers, cookies


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

    response_headers, cookies = build_forward_response_headers(
        upstream.headers,
        upstream_base=rule.upstream_base,
        gateway_host=getattr(rule, "host", "") or "",
        gateway_scheme=_client_scheme(request),
    )
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
    response = StreamingResponse(
        upstream.aiter_bytes(),
        status_code=upstream.status_code,
        headers=response_headers,
        background=BackgroundTask(upstream.aclose),
    )
    # Set-Cookie cannot ride in the headers mapping: every value is its own header
    # and rewriting must stay per-cookie. Deliberate divergence from the v2 path,
    # which drops Set-Cookie entirely.
    for cookie in cookies:
        response.headers.append("set-cookie", cookie)
    return response


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
