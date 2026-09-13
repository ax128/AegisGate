"""``/__fwd__/`` passthrough route: the true-reverse-proxy face of host forwarding.

``HostForwardMiddleware`` rewrites every non-LLM request on a matched forward
domain to ``/__fwd__/<original path>``. This route serves it by forwarding the
method, headers, body and query to the rule's upstream base **without rewriting
the path** — it is sent still percent-encoded, as the client sent it; only
literal ``.`` / ``..`` segments are resolved, clamped at the root — and streaming
the response back byte for byte.

Why a dedicated prefix instead of a catch-all: ``POST /v1/<other>`` is already
FULL-matched by ``generic_provider_proxy`` and ``/v2/*`` by the v2 router, so a
catch-all registered last would never see them. Rewriting the prefix makes
"everything else passes through" true. The route is also what keeps the request
inside ``security_boundary_middleware`` (loopback, body cap, header smuggling) —
answering directly from the middleware would bypass all of it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, Mapping
from urllib.parse import quote, urlparse

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from starlette.background import BackgroundTask

from aegisgate.config.settings import settings
from aegisgate.util.ip_safety import request_host_header
from aegisgate.util.logger import logger

_FORWARD_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

# The console's own cookies (gateway_auth._UI_SESSION_COOKIE) are scoped to the
# gateway host, which on a forward domain is also the upstream's host. They are
# the gateway's credentials and never leave it.
_GATEWAY_COOKIE_PREFIX = "aegis_ui_"

# Characters left alone when a decoded path has to be re-encoded.
_PATH_SAFE = "/:@!$&'()*+,;=-._~"


def _build_forward_headers(request: Request) -> dict[str, str]:
    from aegisgate.adapters.v2_proxy.router import _build_forward_headers as build
    from aegisgate.core.gateway_network import rewrite_forwarding_headers_for_upstream

    headers = build(request)
    rewrite_forwarding_headers_for_upstream(request, headers)
    _strip_gateway_cookies(headers)
    return headers


def _strip_gateway_cookies(headers: dict[str, str]) -> None:
    for key in [name for name in headers if name.lower() == "cookie"]:
        kept = [
            part.strip()
            for part in headers[key].split(";")
            if part.strip()
            and not part.strip().split("=", 1)[0].strip().startswith(_GATEWAY_COOKIE_PREFIX)
        ]
        if kept:
            headers[key] = "; ".join(kept)
        else:
            del headers[key]


def _build_client_response_headers(headers: Mapping[str, str]) -> dict[str, str]:
    from aegisgate.adapters.v2_proxy.router import (
        _build_client_response_headers as build,
    )

    out = build(headers)
    # v2 decodes the body and therefore drops these two. This face relays the
    # upstream's bytes as they are (aiter_raw), so they travel with them: the
    # client decodes what the upstream encoded, and downloads keep their length.
    for name in ("content-encoding", "content-length"):
        value = headers.get(name)
        if value is not None:
            out[name] = value
    return out


async def _upstream_client() -> httpx.AsyncClient:
    from aegisgate.adapters.v2_proxy.router import _get_v2_async_client

    return await _get_v2_async_client()


def _remove_dot_segments(path: str) -> str:
    """RFC 3986 §5.2.4 on literal ``.`` / ``..`` segments, clamped at the root.

    httpx would otherwise resolve them *after* the upstream base is prepended,
    letting ``/../x`` climb out of a base that carries a path.
    """
    segments = path.split("/")
    out: list[str] = []
    for segment in segments[1:]:
        if segment == ".":
            continue
        if segment == "..":
            if out:
                out.pop()
            continue
        out.append(segment)
    result = "/" + "/".join(out)
    if segments[-1] in {".", ".."} and not result.endswith("/"):
        result += "/"
    return result


def _upstream_path(request: Request) -> str:
    """The request path as the client sent it (still percent-encoded)."""
    raw = request.scope.get("aegis_forward_raw_path")
    if not isinstance(raw, str) or not raw:
        decoded = str(request.scope.get("aegis_forward_path") or "/")
        raw = quote(decoded, safe=_PATH_SAFE)
    if not raw.startswith("/"):
        raw = f"/{raw}"
    return _remove_dot_segments(raw)


def _upstream_url(rule: Any, path: str, query: str) -> str:
    url = f"{rule.upstream_base}{path}"
    if query:
        return f"{url}?{query}"
    return url


def _unreachable_response(exc: httpx.HTTPError) -> JSONResponse:
    detail = (str(exc) or "").strip() or "connection_failed_or_timeout"
    logger.warning("forward upstream unreachable error=%s", detail)
    # Same shape as v2's upstream_unreachable, without the exception text: on a
    # public forward domain it would hand internal addresses to any client.
    return JSONResponse(
        status_code=502,
        content={
            "error": {
                "message": "upstream_unreachable",
                "type": "aegisgate_forward_error",
                "code": "upstream_unreachable",
            }
        },
    )


def _body_cap(request: Request) -> int:
    boundary = getattr(request.state, "security_boundary", None)
    if isinstance(boundary, dict):
        try:
            return int(boundary.get("max_request_body_bytes") or 0)
        except (TypeError, ValueError):
            pass
    return int(settings.forward_max_request_body_bytes)


async def _request_content(
    request: Request,
) -> tuple[Any, dict[str, str], Response | None]:
    """What to send upstream as the body, extra headers for it, or a 413.

    With ``Content-Length`` the body is streamed straight through under that
    length, so a large upload is never held in memory. A chunked body without a
    length is buffered, bounded by the boundary's cap for this request — the
    boundary itself only reads POST/PUT/PATCH bodies. Anything else has no body.
    """
    content_length = (request.headers.get("content-length") or "").strip()
    if content_length:
        return request.stream(), {"Content-Length": content_length}, None
    if "chunked" not in (request.headers.get("transfer-encoding") or "").lower():
        return b"", {}, None
    cap = _body_cap(request)
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if cap > 0 and len(body) > cap:
            from aegisgate.core.gateway_auth import _blocked_response

            return None, {}, _blocked_response(status_code=413, reason="request_body_too_large")
    return bytes(body), {}, None


async def _relay_body(upstream: Any) -> AsyncIterator[bytes]:
    """Upstream bytes as they arrive; the upstream response is closed however it ends.

    ``StreamingResponse`` skips its background task when the iterator raises, so
    closing only there leaked the pooled connection every time a long SSE stream
    was reset or timed out.
    """
    try:
        async for chunk in upstream.aiter_raw():
            yield chunk
    except httpx.HTTPError as exc:
        logger.warning("forward upstream stream interrupted error=%s", exc)
    finally:
        await upstream.aclose()


async def _forward_request(request: Request, rule: Any) -> Response:
    path = _upstream_path(request)
    # From the scope, not request.url: Starlette rebuilds request.url from the
    # *decoded* path, so a %3F in it would swallow the real query string.
    query = bytes(request.scope.get("query_string") or b"").decode("latin-1")
    url = _upstream_url(rule, path, query)

    parsed = urlparse(rule.upstream_base)
    headers = _build_forward_headers(request)
    host_header = request_host_header(parsed)
    if host_header:
        headers["Host"] = host_header
    extensions: dict[str, str] | None = None
    if parsed.scheme == "https" and parsed.hostname:
        extensions = {"sni_hostname": parsed.hostname}

    content, body_headers, rejected = await _request_content(request)
    if rejected is not None:
        return rejected
    headers.update(body_headers)
    client = await _upstream_client()
    try:
        upstream_request = client.build_request(
            request.method,
            url,
            headers=headers,
            content=content,
            extensions=extensions,
        )
        upstream = await client.send(upstream_request, stream=True)
    except httpx.HTTPError as exc:
        return _unreachable_response(exc)

    response_headers = _build_client_response_headers(upstream.headers)
    logger.info(
        "forward passthrough host=%s mode=%s method=%s path=%s status=%s",
        getattr(rule, "host", ""),
        getattr(rule, "filters_mode", ""),
        request.method,
        path,
        upstream.status_code,
    )
    # Streamed so SSE and long responses are not buffered; the body is relayed
    # byte for byte (see _build_client_response_headers).
    return StreamingResponse(
        _relay_body(upstream),
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
