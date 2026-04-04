"""
上游解析、网关校验与 HTTP 转发。从 router 拆出，便于维护与单测。
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
from typing import Any, AsyncGenerator, Mapping
from urllib.parse import urlparse, urlunparse

import hashlib
import httpx
from fastapi import Request

from aegisgate.config.settings import settings
from aegisgate.util.ip_safety import (
    bound_connect_url,
    resolve_public_ips,
    request_host_header as _ip_request_host_header,
)
from aegisgate.util.logger import logger
from aegisgate.util.redaction_whitelist import normalize_whitelist_keys

# 与 router 内路由前缀一致，用于从 request_path 剥掉网关前缀得到上游 path
GATEWAY_PREFIX = "/v1"

_HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
_REDACTION_WHITELIST_HEADER = "x-aegis-redaction-whitelist"
_TRACE_REQUEST_ID_HEADER = "x-aegis-request-id"
_UPSTREAM_SOURCE_HEADER = "x-aegis-upstream-source"
_SCOPE_UPSTREAM_SOURCE = "scope"
_CLIENT_UPSTREAM_SOURCE = "client"
_upstream_async_client: httpx.AsyncClient | None = None
_upstream_client_lock = asyncio.Lock()


def _upstream_http_limits() -> httpx.Limits:
    return httpx.Limits(
        max_connections=max(10, int(settings.upstream_max_connections)),
        max_keepalive_connections=max(
            5, int(settings.upstream_max_keepalive_connections)
        ),
    )


def _upstream_http_timeout() -> httpx.Timeout:
    timeout = float(settings.upstream_timeout_seconds)
    # connect is capped at 30s; read/write/pool use the full timeout for long-running LLM requests
    connect = min(timeout, 30.0)
    return httpx.Timeout(connect=connect, read=timeout, write=timeout, pool=timeout)


async def _get_upstream_async_client() -> httpx.AsyncClient:
    global _upstream_async_client
    if _upstream_async_client is not None:
        return _upstream_async_client
    async with _upstream_client_lock:
        if _upstream_async_client is None:
            _upstream_async_client = httpx.AsyncClient(
                http2=False,
                timeout=_upstream_http_timeout(),
                limits=_upstream_http_limits(),
            )
    return _upstream_async_client


async def close_upstream_async_client() -> None:
    global _upstream_async_client
    if _upstream_async_client is not None:
        await _upstream_async_client.aclose()
        _upstream_async_client = None


def _normalize_upstream_base(raw_base: str) -> str:
    candidate = raw_base.strip()
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("invalid_upstream_scheme")
    if not parsed.netloc:
        raise ValueError("invalid_upstream_host")
    if parsed.query or parsed.fragment:
        raise ValueError("invalid_upstream_query_fragment")
    cleaned_path = parsed.path.rstrip("/")
    return urlunparse((parsed.scheme, parsed.netloc, cleaned_path, "", "", ""))


async def _resolve_public_upstream_ips(
    hostname: str,
) -> tuple[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...], str | None]:
    """Resolve hostname via shared async DNS with SSRF protection."""
    return await resolve_public_ips(hostname)


async def _validate_client_upstream_base(
    upstream_base: str,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    """Validate upstream base and return resolved IPs for DNS pinning."""
    parsed = urlparse(upstream_base)
    hostname = (parsed.hostname or "").strip().lower()
    resolved, error = await resolve_public_ips(hostname)
    if error is not None:
        raise ValueError(error)
    return resolved


def _header_value(headers: Mapping[str, str], target: str) -> str:
    for key, value in headers.items():
        if key.lower() == target.lower():
            return value
    return ""


def _trace_request_id(headers: Mapping[str, str]) -> str:
    request_id = _header_value(headers, _TRACE_REQUEST_ID_HEADER).strip()
    return request_id or "-"


def _effective_gateway_headers(request: Request) -> dict[str, str]:
    """从请求中取 headers 供网关校验与转发使用（仅 Header，不含 Query）。"""
    headers = dict(request.headers)
    # Strip any client-supplied internal trust headers. These are only allowed
    # to be injected from the gateway middleware scope.
    _strip = {
        _UPSTREAM_SOURCE_HEADER,
        _UPSTREAM_SOURCE_HEADER.replace("-", "_"),
        _REDACTION_WHITELIST_HEADER,
        _REDACTION_WHITELIST_HEADER.replace("-", "_"),
        "x-aegis-filter-mode",
        "x_aegis_filter_mode",
        "x-aegis-token-hint",
        "x_aegis_token_hint",
    }
    _strip_lower = {name.lower() for name in _strip}
    headers = {k: v for k, v in headers.items() if k.lower() not in _strip_lower}
    injected_upstream_base = request.scope.get("aegis_upstream_base")
    if isinstance(injected_upstream_base, str) and injected_upstream_base.strip():
        headers[settings.upstream_base_header] = injected_upstream_base.strip()
        headers[_UPSTREAM_SOURCE_HEADER] = _SCOPE_UPSTREAM_SOURCE
    injected_whitelist_keys = normalize_whitelist_keys(
        request.scope.get("aegis_redaction_whitelist_keys")
    )
    if injected_whitelist_keys:
        headers[_REDACTION_WHITELIST_HEADER] = ",".join(injected_whitelist_keys)
    injected_filter_mode = request.scope.get("aegis_filter_mode")
    if injected_filter_mode:
        headers["x-aegis-filter-mode"] = injected_filter_mode
    # H-21: Inject a short token hash so inner handlers can namespace session_ids
    # per authenticated token, preventing cross-session forgery.
    injected_token = str(request.scope.get("aegis_gateway_token") or "").strip()
    if injected_token:
        token_hint = hashlib.sha256(injected_token.encode("utf-8")).hexdigest()[:12]
        headers["x-aegis-token-hint"] = token_hint
    return headers


async def _resolve_upstream_base(
    headers: Mapping[str, str],
) -> tuple[str, tuple[str, ...], str]:
    """Resolve upstream base URL with DNS pinning for SSRF protection.

    Returns (base_url, connect_urls, host_header).
    connect_urls: tuple of URLs with hostnames replaced by resolved IPs.
                  Empty tuple means no pinning needed (trusted/scope source or default).
    host_header:  original Host header to set when using pinned connect_urls.
    """
    raw = _header_value(headers, settings.upstream_base_header)
    if raw.strip():
        normalized = _normalize_upstream_base(raw)
        source = _header_value(headers, _UPSTREAM_SOURCE_HEADER).strip().lower()
        if source != _SCOPE_UPSTREAM_SOURCE:
            resolved_ips = await _validate_client_upstream_base(normalized)
            if resolved_ips:
                parsed = urlparse(normalized)
                connect_urls = tuple(
                    bound_connect_url(parsed, addr) for addr in resolved_ips
                )
                host_hdr = _ip_request_host_header(parsed)
                return normalized, connect_urls, host_hdr
        return normalized, (), ""
    # 未提供 x-upstream-base 时使用默认上游（如 AEGIS_UPSTREAM_BASE_URL=http://localhost:8317/v1）
    default = (settings.upstream_base_url or "").strip()
    if not default:
        raise ValueError("missing_upstream_base")
    return _normalize_upstream_base(default), (), ""


def _resolve_gateway_key(headers: Mapping[str, str]) -> str:
    primary = _header_value(headers, settings.gateway_key_header)
    if primary.strip():
        return primary.strip()
    fallback = _header_value(headers, settings.gateway_key_header.replace("-", "_"))
    return fallback.strip()


def _build_upstream_url(request_path: str, upstream_base: str) -> str:
    route_path = request_path or "/"
    query = ""
    if "?" in route_path:
        route_path, query = route_path.split("?", 1)
    if route_path == GATEWAY_PREFIX:
        route_path = "/"
    elif route_path.startswith(f"{GATEWAY_PREFIX}/"):
        route_path = route_path[len(GATEWAY_PREFIX) :]
    if not route_path.startswith("/"):
        route_path = f"/{route_path}"
    url = f"{upstream_base}{route_path}"
    if query:
        return f"{url}?{query}"
    return url


def _parse_whitelist_bases() -> set[str]:
    raw = settings.upstream_whitelist_url_list.strip()
    if not raw:
        return set()
    values: set[str] = set()
    for item in raw.split(","):
        candidate = item.strip()
        if not candidate:
            continue
        try:
            values.add(_normalize_upstream_base(candidate))
        except ValueError:
            logger.warning("ignore invalid whitelist upstream base: %s", candidate)
    return values


def _is_upstream_whitelisted(upstream_base: str) -> bool:
    whitelist = _parse_whitelist_bases()
    if not whitelist:
        return False
    return _normalize_upstream_base(upstream_base) in whitelist


def _build_forward_headers(headers: Mapping[str, str]) -> dict[str, str]:
    forwarded: dict[str, str] = {}
    excluded = {
        "host",
        "content-length",
        settings.upstream_base_header.lower(),
        settings.upstream_base_header.replace("-", "_").lower(),
        settings.gateway_key_header.lower(),
        settings.gateway_key_header.replace("-", "_").lower(),
        *_HOP_BY_HOP_HEADERS,
    }
    for key, value in headers.items():
        lowered = key.lower()
        if lowered in excluded:
            continue
        if lowered.startswith("x-aegis-") or lowered.startswith("x_aegis_"):
            continue
        forwarded[key] = value

    if not any(name.lower() == "content-type" for name in forwarded):
        forwarded["Content-Type"] = "application/json"
    return forwarded


def _decode_json_or_text(body: bytes) -> dict[str, Any] | str:
    text = body.decode("utf-8", errors="replace")
    if not text:
        return ""
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
        return text
    except json.JSONDecodeError:
        return text


def _safe_error_detail(payload: dict[str, Any] | str) -> str:
    if isinstance(payload, str):
        return payload[:600]
    if isinstance(payload.get("error"), str):
        return payload["error"][:600]
    return json.dumps(payload, ensure_ascii=False)[:600]


async def _forward_json(
    url: str, payload: dict[str, Any], headers: Mapping[str, str]
) -> tuple[int, dict[str, Any] | str]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    trace_request_id = _trace_request_id(headers)
    logger.debug(
        "forward_json start request_id=%s url=%s payload_bytes=%d",
        trace_request_id,
        url,
        len(body),
    )
    client = await _get_upstream_async_client()
    try:
        response = await client.post(url=url, content=body, headers=dict(headers))
        logger.debug(
            "forward_json done request_id=%s url=%s status=%s",
            trace_request_id,
            url,
            response.status_code,
        )
        return response.status_code, _decode_json_or_text(response.content)
    except httpx.HTTPError as exc:
        detail = (str(exc) or "").strip() or "connection_failed_or_timeout"
        logger.warning(
            "forward_json http_error request_id=%s url=%s error=%s",
            trace_request_id,
            url,
            detail,
        )
        raise RuntimeError(f"upstream_unreachable: {detail}") from exc


def _normalized_host_for_sni(host_header: str) -> str | None:
    host = (host_header or "").strip()
    if not host:
        return None
    if host.startswith("["):
        end = host.find("]")
        if end == -1:
            return None
        normalized = host[1:end]
    else:
        # host:port → host ; plain host stays unchanged
        normalized = host.rsplit(":", 1)[0] if ":" in host else host
    normalized = normalized.strip()
    if not normalized:
        return None
    try:
        ipaddress.ip_address(normalized)
        return None
    except ValueError:
        return normalized


def _bound_connect_request(
    headers: Mapping[str, str],
    *,
    host_header: str,
    connect_url: str,
) -> tuple[dict[str, str], dict[str, str] | None]:
    bound_headers = dict(headers)
    if host_header:
        bound_headers["Host"] = host_header
    sni_hostname = (
        _normalized_host_for_sni(host_header)
        if connect_url.lower().startswith("https://")
        else None
    )
    extensions = {"sni_hostname": sni_hostname} if sni_hostname else None
    return bound_headers, extensions


async def _forward_json_pinned(
    *,
    url: str,
    payload: dict[str, Any],
    headers: Mapping[str, str],
    connect_urls: tuple[str, ...],
    host_header: str,
) -> tuple[int, dict[str, Any] | str]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    trace_request_id = _trace_request_id(headers)
    logger.debug(
        "forward_json pinned start request_id=%s url=%s targets=%d payload_bytes=%d",
        trace_request_id,
        url,
        len(connect_urls),
        len(body),
    )
    client = await _get_upstream_async_client()
    last_error: httpx.HTTPError | None = None
    for connect_url in connect_urls:
        try:
            bound_headers, extensions = _bound_connect_request(
                headers, host_header=host_header, connect_url=connect_url
            )
            response = await client.post(
                url=connect_url,
                content=body,
                headers=bound_headers,
                extensions=extensions,
            )
            logger.debug(
                "forward_json pinned done request_id=%s connect_url=%s status=%s",
                trace_request_id,
                connect_url,
                response.status_code,
            )
            return response.status_code, _decode_json_or_text(response.content)
        except httpx.HTTPError as exc:
            last_error = exc
            logger.warning(
                "forward_json pinned http_error request_id=%s connect_url=%s error=%s",
                trace_request_id,
                connect_url,
                str(exc) or "connection_failed_or_timeout",
            )
    detail = (
        (str(last_error) or "").strip() if last_error is not None else ""
    ) or "connection_failed_or_timeout"
    raise RuntimeError(f"upstream_unreachable: {detail}") from last_error


async def _forward_stream_lines(
    url: str,
    payload: dict[str, Any],
    headers: Mapping[str, str],
) -> AsyncGenerator[bytes, None]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    trace_request_id = _trace_request_id(headers)
    logger.debug(
        "forward_stream start request_id=%s url=%s payload_bytes=%d",
        trace_request_id,
        url,
        len(body),
    )
    client = await _get_upstream_async_client()
    try:
        async with client.stream(
            "POST", url=url, content=body, headers=dict(headers)
        ) as resp:
            logger.debug(
                "forward_stream connected request_id=%s url=%s status=%s",
                trace_request_id,
                url,
                resp.status_code,
            )
            if resp.status_code >= 400:
                detail = _safe_error_detail(_decode_json_or_text(await resp.aread()))
                raise RuntimeError(f"upstream_http_error:{resp.status_code}:{detail}")
            async for chunk in resp.aiter_bytes():
                if chunk:
                    yield chunk
    except httpx.HTTPError as exc:
        detail = (str(exc) or "").strip() or "connection_failed_or_timeout"
        logger.warning(
            "forward_stream http_error request_id=%s url=%s error=%s",
            trace_request_id,
            url,
            detail,
        )
        raise RuntimeError(f"upstream_unreachable: {detail}") from exc


async def _forward_stream_lines_pinned(
    *,
    url: str,
    payload: dict[str, Any],
    headers: Mapping[str, str],
    connect_urls: tuple[str, ...],
    host_header: str,
) -> AsyncGenerator[bytes, None]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    trace_request_id = _trace_request_id(headers)
    logger.debug(
        "forward_stream pinned start request_id=%s url=%s targets=%d payload_bytes=%d",
        trace_request_id,
        url,
        len(connect_urls),
        len(body),
    )
    client = await _get_upstream_async_client()
    last_error: httpx.HTTPError | None = None
    for connect_url in connect_urls:
        try:
            bound_headers, extensions = _bound_connect_request(
                headers, host_header=host_header, connect_url=connect_url
            )
            async with client.stream(
                "POST",
                url=connect_url,
                content=body,
                headers=bound_headers,
                extensions=extensions,
            ) as resp:
                logger.debug(
                    "forward_stream pinned connected request_id=%s connect_url=%s status=%s",
                    trace_request_id,
                    connect_url,
                    resp.status_code,
                )
                if resp.status_code >= 400:
                    detail = _safe_error_detail(
                        _decode_json_or_text(await resp.aread())
                    )
                    raise RuntimeError(f"upstream_http_error:{resp.status_code}:{detail}")
                async for chunk in resp.aiter_bytes():
                    if chunk:
                        yield chunk
                return
        except httpx.HTTPError as exc:
            last_error = exc
            logger.warning(
                "forward_stream pinned http_error request_id=%s connect_url=%s error=%s",
                trace_request_id,
                connect_url,
                str(exc) or "connection_failed_or_timeout",
            )
    detail = (
        (str(last_error) or "").strip() if last_error is not None else ""
    ) or "connection_failed_or_timeout"
    raise RuntimeError(f"upstream_unreachable: {detail}") from last_error
