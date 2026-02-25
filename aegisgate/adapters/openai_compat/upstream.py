"""
上游解析、网关校验与 HTTP 转发。从 router 拆出，便于维护与单测。
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, AsyncGenerator, Mapping
from urllib.parse import urlparse, urlunparse

import httpx
from fastapi import Request

from aegisgate.config.settings import settings
from aegisgate.util.logger import logger

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

_upstream_async_client: httpx.AsyncClient | None = None
_upstream_client_lock: Any = None


def _upstream_http_limits() -> httpx.Limits:
    return httpx.Limits(
        max_connections=max(10, int(settings.upstream_max_connections)),
        max_keepalive_connections=max(5, int(settings.upstream_max_keepalive_connections)),
    )


def _upstream_http_timeout() -> httpx.Timeout:
    timeout = float(settings.upstream_timeout_seconds)
    return httpx.Timeout(connect=timeout, read=timeout, write=timeout, pool=timeout)


async def _get_upstream_async_client() -> httpx.AsyncClient:
    global _upstream_async_client, _upstream_client_lock
    if _upstream_async_client is not None:
        return _upstream_async_client
    if _upstream_client_lock is None:
        _upstream_client_lock = asyncio.Lock()
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


def _header_value(headers: Mapping[str, str], target: str) -> str:
    for key, value in headers.items():
        if key.lower() == target.lower():
            return value
    return ""


def _effective_gateway_headers(request: Request) -> dict[str, str]:
    """从请求中取 headers 供网关校验与转发使用（仅 Header，不含 Query）。"""
    return dict(request.headers)


def _resolve_upstream_base(headers: Mapping[str, str]) -> str:
    raw = _header_value(headers, settings.upstream_base_header)
    if not raw.strip():
        raise ValueError("missing_upstream_base")
    return _normalize_upstream_base(raw)


def _resolve_gateway_key(headers: Mapping[str, str]) -> str:
    primary = _header_value(headers, settings.gateway_key_header)
    if primary.strip():
        return primary.strip()
    fallback = _header_value(headers, settings.gateway_key_header.replace("-", "_"))
    return fallback.strip()


def _validate_gateway_headers(headers: Mapping[str, str]) -> tuple[bool, str, str]:
    upstream_raw = _header_value(headers, settings.upstream_base_header).strip()
    gateway_key_raw = _resolve_gateway_key(headers).strip()
    if not upstream_raw or not gateway_key_raw:
        logger.warning(
            "gateway header validation failed missing upstream_or_key upstream_present=%s key_present=%s",
            bool(upstream_raw),
            bool(gateway_key_raw),
        )
        return False, "invalid_parameters", "X-Upstream-Base or gateway-key is missing"
    if not settings.gateway_key:
        logger.error("gateway header validation failed gateway-key misconfigured on server")
        return False, "gateway_misconfigured", "gateway-key is not configured on server"
    if gateway_key_raw != settings.gateway_key:
        logger.warning("gateway header validation failed key mismatch")
        return False, "gateway_auth_failed", "gateway-key is invalid"
    logger.debug("gateway header validation passed")
    return True, "", ""


def _build_upstream_url(request_path: str, upstream_base: str) -> str:
    route_path = request_path or "/"
    if route_path == GATEWAY_PREFIX:
        route_path = "/"
    elif route_path.startswith(f"{GATEWAY_PREFIX}/"):
        route_path = route_path[len(GATEWAY_PREFIX):]
    if not route_path.startswith("/"):
        route_path = f"/{route_path}"
    return f"{upstream_base}{route_path}"


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
        settings.gateway_key_header.lower(),
        settings.gateway_key_header.replace("-", "_").lower(),
        *_HOP_BY_HOP_HEADERS,
    }
    for key, value in headers.items():
        lowered = key.lower()
        if lowered in excluded:
            continue
        if lowered.startswith("x-aegis-"):
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


async def _forward_json(url: str, payload: dict[str, Any], headers: Mapping[str, str]) -> tuple[int, dict[str, Any] | str]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    logger.debug("forward_json start url=%s payload_bytes=%d", url, len(body))
    client = await _get_upstream_async_client()
    try:
        response = await client.post(url=url, content=body, headers=dict(headers))
        logger.debug("forward_json done url=%s status=%s", url, response.status_code)
        return response.status_code, _decode_json_or_text(response.content)
    except httpx.HTTPError as exc:
        detail = (str(exc) or "").strip() or "connection_failed_or_timeout"
        logger.warning("forward_json http_error url=%s error=%s", url, detail)
        raise RuntimeError(f"upstream_unreachable: {detail}") from exc


async def _forward_stream_lines(
    url: str,
    payload: dict[str, Any],
    headers: Mapping[str, str],
) -> AsyncGenerator[bytes, None]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    logger.debug("forward_stream start url=%s payload_bytes=%d", url, len(body))
    client = await _get_upstream_async_client()
    try:
        async with client.stream("POST", url=url, content=body, headers=dict(headers)) as resp:
            logger.debug("forward_stream connected url=%s status=%s", url, resp.status_code)
            if resp.status_code >= 400:
                detail = _safe_error_detail(_decode_json_or_text(await resp.aread()))
                raise RuntimeError(f"upstream_http_error:{resp.status_code}:{detail}")
            async for line in resp.aiter_lines():
                yield f"{line}\n".encode("utf-8")
    except httpx.HTTPError as exc:
        detail = (str(exc) or "").strip() or "connection_failed_or_timeout"
        logger.warning("forward_stream http_error url=%s error=%s", url, detail)
        raise RuntimeError(f"upstream_unreachable: {detail}") from exc
