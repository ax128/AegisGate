"""Host-based forwarding middleware.

Registered *inside* ``GWTokenRewriteMiddleware`` and *outside*
``security_boundary_middleware``: the token path is the more specific routing key
and must win, while the boundary's checks (loopback, body cap, HMAC, header
smuggling) must still apply to everything this middleware forwards.

Two branches for a matched host:

* the three known LLM POST routes keep their path and are handed to the V1
  pipeline with the same scope contract the token middleware injects, so the
  per-rule filter switches (see ``_apply_filter_mode``) can act on them;
* everything else is rewritten to ``/__fwd__/<original path>`` and served by the
  passthrough route. Rewriting rather than registering a catch-all is what makes
  "everything else passes through" true for ``POST /v1/<other>`` and ``/v2/*``:
  those paths are already FULL-matched by earlier routes, so a catch-all would
  never see them.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import quote

from starlette.requests import Request

from aegisgate.config.settings import settings
from aegisgate.core import gw_forwards
from aegisgate.core.gw_forwards import route_host
from aegisgate.util.logger import logger

# Paths that always stay on the gateway, even on a forwarded host. Serving the
# console or the admin API from a public forward domain would be a privilege
# escalation; the cost is that an upstream with a colliding path (/metrics,
# /health) is shadowed. See docs/UPSTREAM-QUICKSTART.md.
_RESERVED_PATHS: frozenset[str] = frozenset(
    {
        "/",
        "/health",
        "/ready",
        "/robots.txt",
        "/favicon.ico",
        "/metrics",
        "/__ui__",
        "/__ui__/assets",
        "/__gw__",
    }
)

# Only these POST routes run the V1 filter pipeline. Everything else on the host
# — other /v1 paths, other methods, /v2/*, /relay/* — is forwarded verbatim.
_LLM_ROUTES: frozenset[str] = frozenset(
    {"/v1/chat/completions", "/v1/responses", "/v1/messages"}
)

_ROUTE_LABEL = "forward"


def _is_reserved_path(path: str) -> bool:
    if path in _RESERVED_PATHS:
        return True
    for reserved in _RESERVED_PATHS:
        if reserved != "/" and path.startswith(reserved + "/"):
            return True
    return False


def _raw_header_count(scope: dict[str, Any], name: bytes) -> int:
    return sum(
        1
        for raw_name, _raw_value in scope.get("headers", [])
        if raw_name.lower() == name
    )


def _original_raw_path(scope: dict[str, Any], path: str) -> bytes:
    """The request path exactly as the client sent it (still percent-encoded).

    ``scope["path"]`` is already decoded, so rebuilding the upstream URL from it
    would turn ``%2F`` into a separator, ``%3F`` into the start of the query and
    ``%23`` into a fragment. Without a ``raw_path`` the decoded path is
    re-encoded, which keeps ``?`` / ``#`` / ``%`` from changing the URL shape.
    """
    raw_path = scope.get("raw_path")
    if isinstance(raw_path, (bytes, bytearray)) and raw_path.startswith(b"/"):
        return bytes(raw_path)
    return quote(path, safe="/:@!$&'()*+,;=-._~").encode("ascii")


def _trust_header_names() -> set[bytes]:
    ub = settings.upstream_base_header
    gk = settings.gateway_key_header
    return {
        ub.lower().encode("latin-1"),
        ub.replace("-", "_").lower().encode("latin-1"),
        gk.lower().encode("latin-1"),
        gk.replace("-", "_").lower().encode("latin-1"),
        b"x-aegis-redaction-whitelist",
        b"x_aegis_redaction_whitelist",
        b"x-aegis-forward-host",
        b"x_aegis_forward_host",
    }


def strip_client_trust_headers(scope: dict[str, Any]) -> list[tuple[bytes, bytes]]:
    """Drop client-supplied trust headers; only middleware may inject them."""
    skip = _trust_header_names()
    return [
        (name, value)
        for name, value in scope.get("headers", [])
        if name.lower() not in skip
    ]


async def _reject(
    scope: dict[str, Any],
    receive: Any,
    send: Any,
    *,
    status_code: int,
    reason: str,
    detail: str | None = None,
) -> None:
    # Imported lazily: gateway.py imports this module to register the middleware.
    from aegisgate.core.gateway import _record_request_observability
    from aegisgate.core.gateway_auth import _blocked_response
    from aegisgate.observability.tracing import trace_span

    method = str(scope.get("method") or "GET").upper()
    started_at = time.perf_counter()
    with trace_span("gateway.request", http_method=method, http_route=_ROUTE_LABEL) as span:
        response = _blocked_response(
            status_code=status_code, reason=reason, detail=detail
        )
        _record_request_observability(
            method=method,
            route_label=_ROUTE_LABEL,
            started_at=started_at,
            status_code=status_code,
            reject_reason=reason,
            span=span,
        )
        await response(scope, receive, send)


class HostForwardMiddleware:
    """Resolve the routing host and split LLM traffic from the passthrough face."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        # Token path already owns the request.
        if scope.get("aegis_token_authenticated"):
            await self.app(scope, receive, send)
            return
        if not settings.enable_gateway_forward:
            await self.app(scope, receive, send)
            return

        if _raw_header_count(scope, b"host") > 1:
            logger.warning(
                "forward reject duplicate host header path=%s", scope.get("path")
            )
            await _reject(
                scope,
                receive,
                send,
                status_code=400,
                reason="duplicate_host_header",
                detail="multiple Host headers are not allowed",
            )
            return

        from aegisgate.core.gateway_network import trusted_forwarded_host

        request = Request(scope)
        raw_host = trusted_forwarded_host(request) or (
            request.headers.get("host") or ""
        )
        host = route_host(raw_host)
        if not host:
            await self.app(scope, receive, send)
            return

        rule = gw_forwards.get(host)
        denied = gw_forwards.denied_reason(host) if rule is None else None
        if rule is None and denied is None:
            # Not a forward domain: unchanged behaviour, no injection.
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path") or "/")
        # Reserved paths are resolved before any rule-state answer: /health, the
        # console and the admin API must keep answering the way they do today on
        # an internal-only, disabled or invalid forward domain — the last being
        # exactly when the operator needs the console to fix the file.
        if _is_reserved_path(path):
            await self.app(scope, receive, send)
            return

        if denied is not None:
            reason, _detail = denied
            logger.warning(
                "forward reject host=%s reason=%s path=%s", host, reason, path
            )
            # The validation detail stays in the log and the console: it names
            # startup flags and the rule's posture, which an unauthenticated
            # client has no business reading.
            await _reject(
                scope,
                receive,
                send,
                status_code=403,
                reason=reason,
                detail="该网关域名的转发规则当前不可用",
            )
            return

        assert rule is not None
        if not rule.enabled:
            logger.warning("forward reject host=%s reason=forward_rule_disabled", host)
            await _reject(
                scope,
                receive,
                send,
                status_code=403,
                reason=gw_forwards.REASON_RULE_DISABLED,
                detail="该网关域名的转发规则已停用",
            )
            return

        if rule.expose == "internal":
            from aegisgate.core.gateway import _internal_after_xff_downgrade

            client_ip, is_internal = _internal_after_xff_downgrade(request)
            if not is_internal:
                logger.warning(
                    "forward reject host=%s reason=forward_expose_internal client=%s",
                    host,
                    client_ip,
                )
                await _reject(
                    scope,
                    receive,
                    send,
                    status_code=403,
                    reason="forward_expose_internal",
                    detail="该转发规则仅允许内网客户端访问",
                )
                return

        method = str(scope.get("method") or "GET").upper()
        normalized_path = path.rstrip("/") or "/"
        if method == "POST" and normalized_path in _LLM_ROUTES:
            await self.app(
                self._llm_scope(scope, host, rule), receive, send
            )
            return

        await self.app(self._passthrough_scope(scope, path, rule), receive, send)

    def _llm_scope(self, scope, host: str, rule: gw_forwards.ForwardRule) -> dict[str, Any]:
        from aegisgate.core.gateway import _trusted_scope_id

        new_scope = dict(scope)
        new_scope["aegis_token_authenticated"] = True
        # Not purely numeric, so the boundary's public-numeric-token gate does not
        # apply; H-21 namespacing needs a stable value per forward domain.
        new_scope["aegis_gateway_token"] = f"forward:{host}"
        new_scope["aegis_tenant_id"] = _trusted_scope_id("forward", host)
        # The rule stores the upstream root; the V1 forwarder drops /v1 from the
        # request path, so the base it gets must carry it.
        new_scope["aegis_upstream_base"] = rule.llm_upstream_base
        new_scope["aegis_redaction_whitelist_keys"] = []
        new_scope["aegis_filter_mode"] = None
        new_scope["aegis_forward_rule"] = rule
        new_scope["headers"] = strip_client_trust_headers(scope)
        logger.debug("forward llm host=%s path=%s", host, new_scope.get("path"))
        return new_scope

    def _passthrough_scope(
        self, scope, path: str, rule: gw_forwards.ForwardRule
    ) -> dict[str, Any]:
        new_scope = dict(scope)
        original_raw = _original_raw_path(scope, path)
        new_path = f"/__fwd__{path}"
        new_scope["path"] = new_path
        new_scope["raw_path"] = b"/__fwd__" + original_raw
        new_scope["root_path"] = ""
        # Note the absence of aegis_token_authenticated on purpose: the
        # passthrough face is not an authenticated route, and /v2/* must not fall
        # into the gateway's own v2 proxy.
        new_scope["aegis_forward_rule"] = rule
        new_scope["aegis_forward_path"] = path
        # What the upstream URL is built from: the path as sent, still encoded.
        new_scope["aegis_forward_raw_path"] = original_raw.decode("latin-1")
        new_scope["headers"] = strip_client_trust_headers(scope)
        logger.debug("forward passthrough host=%s path=%s -> %s", rule.host, path, new_path)
        return new_scope
