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

import re
from collections.abc import AsyncIterator
from typing import Any, Mapping
from urllib.parse import quote, urlparse, urlunparse

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


# host or host:port, as a client (or a trusted proxy on its behalf) sends it.
_CLIENT_NETLOC_RE = re.compile(r"^[A-Za-z0-9.-]+(?::[0-9]{1,5})?$")


def _client_scheme(request: Request) -> str:
    """The scheme the client saw, trusting X-Forwarded-Proto only from a trusted proxy."""
    from aegisgate.core.gateway_network import trusted_forwarded_proto

    proto = trusted_forwarded_proto(request)
    if proto in {"http", "https"}:
        return proto
    return request.url.scheme or "http"


def _client_netloc(request: Request, rule_host: str) -> str:
    """The ``host[:port]`` the client addressed, for URLs handed back to it.

    The rule host has no port by definition, so using it alone sends a client on
    ``api.ag.com:18080`` to port 80/443. The client's value is taken only when it
    routes to this rule's host (so it is the name the request was matched on) and
    is a plain host[:port]; otherwise the rule host stands.
    """
    from aegisgate.core.gateway_network import trusted_forwarded_host
    from aegisgate.core.gw_forwards import route_host

    raw = (trusted_forwarded_host(request) or request.headers.get("host") or "").strip()
    if raw and _CLIENT_NETLOC_RE.match(raw) and route_host(raw) == rule_host:
        return raw.lower()
    return rule_host


def rewrite_location(
    value: str, *, upstream_host: str, gateway_origin: str
) -> str:
    """Map an upstream Location back onto the gateway. Relative stays put.

    Absolute (``https://up/x``) and scheme-relative (``//up/x``) URLs naming the
    upstream host are both rewritten; the latter stays scheme-relative.
    """
    if not value:
        return value
    parsed = urlparse(value)
    scheme_relative = not parsed.scheme and value.startswith("//")
    if not parsed.netloc or not (scheme_relative or parsed.scheme in {"http", "https"}):
        return value
    if (parsed.hostname or "").strip().lower().rstrip(".") != upstream_host:
        return value
    gateway = urlparse(gateway_origin)
    netloc = gateway.netloc or gateway.path
    return urlunparse(
        (
            "" if scheme_relative else gateway.scheme,
            netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


def rewrite_set_cookie(
    value: str, *, upstream_host: str, gateway_host: str
) -> str | None:
    """Rewrite ``Domain=`` on one Set-Cookie; ``None`` means drop the whole cookie.

    A ``Domain`` naming the upstream host (or a parent of it) maps onto the
    gateway host. Anything else is removed rather than passed through, so the
    cookie degrades to a host-only cookie for the gateway instead of leaking the
    upstream domain to the client.

    A cookie named like the console's own (``aegis_ui_*``) is dropped whole: on a
    forward domain the upstream shares the gateway's host, and letting it set one
    would overwrite (or plant) the console session.
    """
    if not value:
        return value
    parts = value.split(";")
    name = parts[0].split("=", 1)[0].strip()
    if name.startswith(_GATEWAY_COOKIE_PREFIX):
        return None
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


def _normalized_origin(value: str) -> str:
    """``scheme://host[:port]`` lower-cased, default port dropped; other values as-is."""
    candidate = value.strip()
    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return candidate
    try:
        port = parsed.port
    except ValueError:
        return candidate
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    default_port = 443 if scheme == "https" else 80
    suffix = f":{port}" if port is not None and port != default_port else ""
    return f"{scheme}://{host}{suffix}"


def rewrite_access_control_allow_origin(
    value: str, *, upstream_origin: str, gateway_origin: str
) -> str:
    """Replace an ACAO naming the upstream origin; ``*`` and unrelated values stay."""
    if _normalized_origin(value) == _normalized_origin(upstream_origin):
        return gateway_origin
    return value


def build_forward_response_headers(
    upstream_headers: Mapping[str, str],
    *,
    upstream_base: str,
    gateway_host: str,
    gateway_netloc: str,
    gateway_scheme: str,
) -> tuple[dict[str, str], list[str]]:
    """Build the client-facing response headers, rewriting the three URL-bearing ones.

    Unlike ``_build_client_response_headers`` (which drops ``set-cookie``) this
    keeps every Set-Cookie as its own header: each one is rewritten separately and
    ``dict`` cannot represent the duplicates. ``gateway_netloc`` (host[:port] the
    client used) goes into URLs; ``gateway_host`` (no port) into cookie domains.
    """
    parsed_upstream = urlparse(upstream_base)
    upstream_host = (parsed_upstream.hostname or "").strip().lower()
    upstream_origin = f"{parsed_upstream.scheme}://{parsed_upstream.netloc}"
    gateway_origin = f"{gateway_scheme}://{gateway_netloc}"

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
    cookies: list[str] = []
    for cookie in raw_cookies:
        rewritten = rewrite_set_cookie(
            cookie, upstream_host=upstream_host, gateway_host=gateway_host
        )
        if rewritten:
            cookies.append(rewritten)
    return headers, cookies


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

    rule_host = getattr(rule, "host", "") or ""
    response_headers, cookies = build_forward_response_headers(
        upstream.headers,
        upstream_base=rule.upstream_base,
        gateway_host=rule_host,
        gateway_netloc=_client_netloc(request, rule_host),
        gateway_scheme=_client_scheme(request),
    )
    logger.info(
        "forward passthrough host=%s mode=%s method=%s path=%s status=%s",
        getattr(rule, "host", ""),
        getattr(rule, "filters_mode", ""),
        request.method,
        path,
        upstream.status_code,
    )
    # Streamed so SSE and long responses are not buffered; the body is relayed
    # byte for byte (see _build_client_response_headers). Only headers change.
    response = StreamingResponse(
        _relay_body(upstream),
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
