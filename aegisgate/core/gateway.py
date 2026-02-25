"""FastAPI app entry."""

from __future__ import annotations

import asyncio
import re

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.requests import Request as StarletteRequest

from aegisgate.adapters.openai_compat.router import (
    clear_pending_confirmations_on_startup,
    close_semantic_async_client,
    prune_pending_confirmations,
    router as openai_router,
)
from aegisgate.adapters.openai_compat.upstream import close_upstream_async_client
from aegisgate.adapters.relay_compat.router import router as relay_router
from aegisgate.config.settings import settings
from aegisgate.core.audit import shutdown_audit_worker
from aegisgate.core.gw_tokens import find_token as gw_tokens_find_token, get as gw_tokens_get, load as gw_tokens_load, register as gw_tokens_register, unregister as gw_tokens_unregister
from aegisgate.core.security_boundary import (
    build_nonce_cache,
    build_signature_payload,
    now_ts,
    verify_hmac_signature,
)
from aegisgate.util.logger import logger

# /v1/__gw__/t/{token}/chat/completions -> token + rest
_GW_TOKEN_PATH_RE = re.compile(r"^/v1/__gw__/t/([^/]+)/(.*)$")

app = FastAPI(title=settings.app_name)
app.include_router(openai_router, prefix="/v1")
if settings.enable_relay_endpoint:
    app.include_router(relay_router, prefix="/relay")
_nonce_cache = build_nonce_cache()
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
_pending_prune_task: asyncio.Task | None = None


def _blocked_response(status_code: int, reason: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": reason,
            "aegisgate": {
                "action": "block",
                "risk_score": 1.0,
                "reasons": [reason],
            },
        },
    )


@app.middleware("http")
async def security_boundary_middleware(request: Request, call_next):
    boundary = {
        "loopback_only": settings.enforce_loopback_only,
        "auth_required": settings.enable_request_hmac_auth,
        "auth_verified": False,
        "replay_checked": False,
        "max_request_body_bytes": settings.max_request_body_bytes,
    }
    request.state.security_boundary = boundary
    logger.debug(
        "boundary enter method=%s path=%s loopback_only=%s hmac=%s",
        request.method,
        request.url.path,
        settings.enforce_loopback_only,
        settings.enable_request_hmac_auth,
    )

    if request.url.path == "/health":
        return await call_next(request)

    cached_body: bytes | None = None
    content_length_header = request.headers.get("content-length", "").strip()
    if settings.max_request_body_bytes > 0 and request.method.upper() in {"POST", "PUT", "PATCH"} and content_length_header:
        try:
            content_length = int(content_length_header)
        except ValueError:
            await request.body()
            boundary["rejected_reason"] = "invalid_content_length"
            logger.warning("boundary reject invalid content-length path=%s", request.url.path)
            return _blocked_response(status_code=400, reason="invalid_content_length")
        if content_length > settings.max_request_body_bytes:
            await request.body()
            boundary["rejected_reason"] = "request_body_too_large"
            logger.warning(
                "boundary reject oversize request content_length=%s max=%s path=%s",
                content_length,
                settings.max_request_body_bytes,
                request.url.path,
            )
            return _blocked_response(status_code=413, reason="request_body_too_large")
    elif settings.max_request_body_bytes > 0 and request.method.upper() in {"POST", "PUT", "PATCH"}:
        cached_body = await request.body()
        if len(cached_body) > settings.max_request_body_bytes:
            boundary["rejected_reason"] = "request_body_too_large"
            logger.warning(
                "boundary reject oversize request actual_size=%s max=%s path=%s",
                len(cached_body),
                settings.max_request_body_bytes,
                request.url.path,
            )
            return _blocked_response(status_code=413, reason="request_body_too_large")

    if settings.enforce_loopback_only:
        client_host = request.client.host if request.client else ""
        if client_host not in _LOOPBACK_HOSTS:
            await request.body()
            boundary["rejected_reason"] = "loopback_only_reject"
            logger.warning("boundary reject non-loopback host=%s path=%s", client_host, request.url.path)
            return _blocked_response(status_code=403, reason="loopback_only_reject")

    if settings.enable_request_hmac_auth:
        secret = settings.request_hmac_secret
        if not secret:
            logger.error("request hmac auth enabled but secret is empty")
            return _blocked_response(status_code=500, reason="hmac_misconfigured")

        signature = request.headers.get(settings.request_signature_header)
        timestamp = request.headers.get(settings.request_timestamp_header)
        nonce = request.headers.get(settings.request_nonce_header)
        if not signature or not timestamp or not nonce:
            boundary["rejected_reason"] = "hmac_header_missing"
            return _blocked_response(status_code=401, reason="hmac_header_missing")

        try:
            ts_int = int(timestamp)
        except ValueError:
            boundary["rejected_reason"] = "hmac_timestamp_invalid"
            return _blocked_response(status_code=401, reason="hmac_timestamp_invalid")

        current_ts = now_ts()
        if abs(current_ts - ts_int) > settings.request_replay_window_seconds:
            boundary["rejected_reason"] = "hmac_timestamp_out_of_window"
            return _blocked_response(status_code=401, reason="hmac_timestamp_out_of_window")

        replayed = _nonce_cache.check_and_store(
            nonce=nonce,
            now_ts=current_ts,
            window_seconds=settings.request_replay_window_seconds,
        )
        boundary["replay_checked"] = True
        if replayed:
            boundary["rejected_reason"] = "replay_nonce_detected"
            return _blocked_response(status_code=409, reason="replay_nonce_detected")

        body = cached_body if cached_body is not None else await request.body()
        payload = build_signature_payload(timestamp=timestamp, nonce=nonce, body=body)
        if not verify_hmac_signature(secret=secret, payload=payload, presented=signature):
            boundary["rejected_reason"] = "hmac_signature_invalid"
            return _blocked_response(status_code=401, reason="hmac_signature_invalid")

        boundary["auth_verified"] = True
        logger.info("boundary hmac verified path=%s", request.url.path)

    response = await call_next(request)
    if boundary.get("auth_verified"):
        response.headers["x-aegis-auth-verified"] = "true"
    logger.debug(
        "boundary pass method=%s path=%s auth_verified=%s",
        request.method,
        request.url.path,
        bool(boundary.get("auth_verified")),
    )
    return response


@app.middleware("http")
async def gw_token_rewrite_middleware(request: Request, call_next):
    """
    将 /v1/__gw__/t/{token}/... 重写为 /v1/... 并注入 X-Upstream-Base、gateway-key。
    必须最后注册以便最先执行，这样路由才能收到重写后的 path。
    """
    path = request.url.path or "/"
    m = _GW_TOKEN_PATH_RE.match(path)
    if not m:
        return await call_next(request)
    token, rest = m.group(1), m.group(2)
    mapping = gw_tokens_get(token)
    if not mapping:
        logger.warning("gw_token not found token=%s path=%s", token, path)
        return JSONResponse(status_code=404, content={"error": "token_not_found", "detail": "token invalid or expired"})
    new_path = f"/v1/{rest}" if rest else "/v1"
    ub = mapping["upstream_base"]
    gk = mapping["gateway_key"]
    scope = dict(request.scope)
    scope["path"] = new_path
    scope["root_path"] = ""
    scope["raw_path"] = new_path.encode("utf-8")
    headers = list(scope.get("headers") or [])
    # 使用 token 访问时以映射为准：移除客户端可能携带的网关相关 header（含下划线形式），避免与 token 映射冲突
    ub_name = settings.upstream_base_header.encode("latin-1")
    gk_name = settings.gateway_key_header.encode("latin-1")
    ub_alt = settings.upstream_base_header.replace("-", "_").encode("latin-1")
    gk_alt = settings.gateway_key_header.replace("-", "_").encode("latin-1")
    skip = (ub_name.lower(), gk_name.lower(), ub_alt.lower(), gk_alt.lower())
    headers = [(k, v) for k, v in headers if k.lower() not in skip]
    headers.append((ub_name, ub.encode("utf-8")))
    headers.append((gk_name, gk.encode("utf-8")))
    scope["headers"] = headers
    new_request = StarletteRequest(scope, request.receive)
    return await call_next(new_request)


# 注册时禁止使用的示例/占位 upstream_base，避免用户未替换就提交
_FORBIDDEN_UPSTREAM_BASE_EXAMPLES = frozenset(
    u.rstrip("/").lower()
    for u in (
        "https://your-upstream.example.com/v1",
        "http://your-upstream.example.com/v1",
    )
)


@app.post("/__gw__/register")
async def gw_register(request: Request) -> JSONResponse:
    """一次性注册：返回短 token 与 baseUrl，映射写入 config/gw_tokens.json。"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid_json"})
    upstream_base = (body.get("upstream_base") or "").strip()
    gateway_key = (body.get("gateway_key") or "").strip()
    if not upstream_base or not gateway_key:
        return JSONResponse(
            status_code=400,
            content={"error": "missing_params", "detail": "upstream_base and gateway_key required"},
        )
    upstream_normalized = upstream_base.rstrip("/").lower()
    if upstream_normalized in _FORBIDDEN_UPSTREAM_BASE_EXAMPLES:
        return JSONResponse(
            status_code=400,
            content={
                "error": "example_upstream_forbidden",
                "detail": "upstream_base 不能使用文档中的示例地址，请替换为你的真实上游地址后再注册。",
            },
        )
    upstream_base_normalized = upstream_base.rstrip("/")
    token, already_registered = gw_tokens_register(upstream_base_normalized, gateway_key)
    base_url = f"http://{settings.host}:{settings.port}/v1/__gw__/t/{token}"
    if already_registered:
        return JSONResponse(
            content={
                "already_registered": True,
                "detail": "该 upstream_base + gateway_key 已注册过，返回已有 token。",
                "token": token,
                "baseUrl": base_url,
            },
        )
    return JSONResponse(content={"token": token, "baseUrl": base_url})


@app.post("/__gw__/lookup")
async def gw_lookup(request: Request) -> JSONResponse:
    """根据 upstream_base + gateway_key 查询已注册的 token，避免忘记。不存在返回 404。"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid_json"})
    upstream_base = (body.get("upstream_base") or "").strip()
    gateway_key = (body.get("gateway_key") or "").strip()
    if not upstream_base or not gateway_key:
        return JSONResponse(
            status_code=400,
            content={"error": "missing_params", "detail": "upstream_base and gateway_key required"},
        )
    upstream_normalized = upstream_base.rstrip("/").lower()
    if upstream_normalized in _FORBIDDEN_UPSTREAM_BASE_EXAMPLES:
        return JSONResponse(
            status_code=400,
            content={
                "error": "example_upstream_forbidden",
                "detail": "upstream_base 不能使用文档中的示例地址。",
            },
        )
    token = gw_tokens_find_token(upstream_base, gateway_key)
    if token is None:
        return JSONResponse(
            status_code=404,
            content={
                "error": "not_found",
                "detail": "该 upstream_base + gateway_key 未注册，请先调用 /__gw__/register 注册。",
            },
        )
    base_url = f"http://{settings.host}:{settings.port}/v1/__gw__/t/{token}"
    return JSONResponse(content={"token": token, "baseUrl": base_url})


@app.post("/__gw__/unregister")
async def gw_unregister(request: Request) -> JSONResponse:
    """删除 token 映射：body 传 token，删除后写回 config。"""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid_json"})
    token = (body.get("token") or "").strip()
    if not token:
        return JSONResponse(status_code=400, content={"error": "missing_token"})
    if gw_tokens_unregister(token):
        return JSONResponse(content={"ok": True, "message": "token removed"})
    return JSONResponse(status_code=404, content={"error": "token_not_found"})


@app.get("/health")
def health() -> dict:
    logger.info("health check")
    return {"status": "ok"}


@app.on_event("shutdown")
async def shutdown_cleanup() -> None:
    global _pending_prune_task
    if _pending_prune_task is not None:
        _pending_prune_task.cancel()
        try:
            await _pending_prune_task
        except asyncio.CancelledError:
            pass
        _pending_prune_task = None
    await close_upstream_async_client()
    await close_semantic_async_client()
    shutdown_audit_worker()


async def _pending_prune_loop() -> None:
    interval = max(5, int(settings.pending_prune_interval_seconds))
    while True:
        try:
            if settings.enable_thread_offload:
                await asyncio.to_thread(prune_pending_confirmations, int(now_ts()))
            else:
                prune_pending_confirmations(int(now_ts()))
        except Exception as exc:  # pragma: no cover - operational guard
            logger.warning("pending prune task failed: %s", exc)
        await asyncio.sleep(interval)


@app.on_event("startup")
async def startup_background_tasks() -> None:
    try:
        gw_tokens_load()
    except Exception as exc:  # pragma: no cover
        logger.warning("gw_tokens load on startup failed: %s", exc)
    # 重启后清空待确认记录，仅本次运行期间的新请求可被确认放行
    try:
        n = clear_pending_confirmations_on_startup()
        if n:
            logger.info("cleared %d pending confirmation(s) on startup", n)
    except Exception as exc:  # pragma: no cover
        logger.warning("clear pending confirmations on startup failed: %s", exc)
    global _pending_prune_task
    if settings.enable_pending_prune_task and _pending_prune_task is None:
        _pending_prune_task = asyncio.create_task(_pending_prune_loop(), name="aegisgate-pending-prune")
