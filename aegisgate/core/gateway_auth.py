"""UI session, CSRF, and admin authentication helpers."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import time

from fastapi import Request
from fastapi.responses import JSONResponse, Response

from aegisgate.config.settings import settings
from aegisgate.core.gateway_keys import _ensure_gateway_key
from aegisgate.core.gateway_network import (
    _real_client_ip,
    trusted_forwarded_host,
    trusted_forwarded_proto,
)


_UI_SESSION_COOKIE = "aegis_ui_session"

# sha256(cookie) -> issued_at. One entry per logged-out cookie, dropped once
# that cookie would fail the TTL check. Not a generation counter: logging out
# one browser must not sign out any other session. Process-local, same as the
# UI login rate limiter — a restart forgets the table.
_revoked_ui_sessions: dict[str, int] = {}
_revoked_ui_sessions_lock = threading.Lock()


def _blocked_response(status_code: int, reason: str, detail: str | None = None) -> JSONResponse:
    # Sanitize detail: never expose internal exception info to client.
    safe_detail = reason
    if detail:
        safe = detail.strip()
        if not any(marker in safe for marker in ("Traceback", "File ", "line ", "Error:", "Exception:")):
            safe_detail = safe
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "message": safe_detail,
                "type": "aegisgate_error",
                "code": reason,
            },
            "error_code": reason,
            "detail": safe_detail,
            "aegisgate": {
                "action": "block",
                "risk_score": 1.0,
                "reasons": [reason],
            },
        },
    )


def _verify_admin_gateway_key(body: dict) -> bool:
    """Constant-time comparison of gateway_key from request body against configured key."""
    provided = str(body.get("gateway_key") or "").strip()
    expected = (settings.gateway_key or "").strip()
    if not provided or not expected:
        return False
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


def _is_passthrough_read_path(path: str) -> bool:
    return path == "/__ui__" or path.startswith("/__ui__/")


def _is_public_ui_path(path: str) -> bool:
    import posixpath

    normalized = posixpath.normpath(path)
    return normalized in {
        "/__ui__/login",
        "/__ui__/health",
        "/__ui__/api/login",
    } or normalized.startswith("/__ui__/assets/")


def _apply_ui_security_headers(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    return response


def _ui_client_fingerprint(request: Request) -> str:
    client_ip = _real_client_ip(request)
    user_agent = (request.headers.get("user-agent") or "").strip()[:200]
    raw = f"{client_ip}|{user_agent}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _ui_session_signature(issued_at: int, fingerprint: str, nonce: str = "") -> str:
    secret = _ensure_gateway_key().encode("utf-8")
    payload = f"ui:{issued_at}:{fingerprint}:{nonce}".encode("utf-8")
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def _create_ui_session_token(request: Request) -> str:
    issued_at = int(time.time())
    nonce = secrets.token_hex(16)
    fingerprint = _ui_client_fingerprint(request)
    return f"{issued_at}.{nonce}.{_ui_session_signature(issued_at, fingerprint, nonce)}"


def _ui_session_issued_at(token: str) -> int | None:
    if not token or "." not in token:
        return None
    try:
        issued_at = int(token.split(".", 1)[0])
    except ValueError:
        return None
    if issued_at <= 0:
        return None
    return issued_at


def _ui_session_revocation_key(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _ui_session_revocation_expired(issued_at: int, now: float) -> bool:
    # Same boundary as _is_valid_ui_session: the cookie is already dead when
    # this is true, so the revocation entry no longer changes the answer.
    return now - issued_at > settings.local_ui_session_ttl_seconds


def _drop_expired_ui_session_revocations(now: float) -> None:
    """Caller holds ``_revoked_ui_sessions_lock``."""
    expired = [
        key
        for key, issued_at in _revoked_ui_sessions.items()
        if _ui_session_revocation_expired(issued_at, now)
    ]
    for key in expired:
        del _revoked_ui_sessions[key]


def revoke_ui_session(token: str) -> None:
    """Make this exact UI cookie fail validation until its own TTL elapses."""
    value = (token or "").strip()
    issued_at = _ui_session_issued_at(value)
    if issued_at is None:
        return
    now = time.time()
    if _ui_session_revocation_expired(issued_at, now):
        return
    key = _ui_session_revocation_key(value)
    with _revoked_ui_sessions_lock:
        _drop_expired_ui_session_revocations(now)
        _revoked_ui_sessions[key] = issued_at


def _ui_session_is_revoked(token: str) -> bool:
    if _ui_session_issued_at(token) is None:
        return False
    now = time.time()
    key = _ui_session_revocation_key(token)
    with _revoked_ui_sessions_lock:
        _drop_expired_ui_session_revocations(now)
        return key in _revoked_ui_sessions


def _ui_csrf_token(session_token: str) -> str:
    secret = _ensure_gateway_key().encode("utf-8")
    return hmac.new(secret, f"csrf:{session_token}".encode("utf-8"), hashlib.sha256).hexdigest()


def _is_valid_ui_session(token: str, request: Request) -> bool:
    value = (token or "").strip()
    if not value or "." not in value:
        return False
    parts = value.split(".", 2)
    if len(parts) == 3:
        issued_at_str, nonce, signature = parts
    elif len(parts) == 2:
        # Legacy format without nonce — allow validation but will never match
        # new signatures, so old sessions expire naturally.
        issued_at_str, signature = parts
        nonce = ""
    else:
        return False
    try:
        issued_at = int(issued_at_str)
    except ValueError:
        return False
    if issued_at <= 0:
        return False
    if time.time() - issued_at > settings.local_ui_session_ttl_seconds:
        return False
    expected = _ui_session_signature(issued_at, _ui_client_fingerprint(request), nonce)
    if not hmac.compare_digest(signature, expected):
        return False
    return not _ui_session_is_revoked(value)


def _is_ui_authenticated(request: Request) -> bool:
    return _is_valid_ui_session(request.cookies.get(_UI_SESSION_COOKIE, ""), request)


def _verify_ui_csrf(request: Request) -> bool:
    session_token = request.cookies.get(_UI_SESSION_COOKIE, "")
    if not _is_valid_ui_session(session_token, request):
        return False
    presented = (request.headers.get("x-aegis-ui-csrf") or "").strip()
    if not presented:
        return False
    expected = _ui_csrf_token(session_token)
    return hmac.compare_digest(presented, expected)


def _string_field(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _sanitize_public_host(raw_host: str) -> str:
    host = (raw_host or "").strip()
    if not host:
        return f"127.0.0.1:{settings.port}"
    if re.search(r"[^A-Za-z0-9.\-:\[\]]", host):
        return f"127.0.0.1:{settings.port}"
    lowered = host.lower()
    if lowered in {"0.0.0.0", "::", "[::]"}:
        return f"127.0.0.1:{settings.port}"
    if lowered.startswith("0.0.0.0:"):
        return f"127.0.0.1:{host.split(':', 1)[1]}"
    if lowered.startswith("[::]:"):
        return f"127.0.0.1:{host.rsplit(':', 1)[1]}"
    return host


def _public_base_url(request: Request) -> str:
    forwarded_proto = trusted_forwarded_proto(request)
    forwarded_host = trusted_forwarded_host(request)
    scheme = forwarded_proto if forwarded_proto in {"http", "https"} else request.url.scheme or "http"
    host_header = (request.headers.get("host") or "").strip()
    host = _sanitize_public_host(forwarded_host or host_header or f"{settings.host}:{settings.port}")
    return f"{scheme}://{host}"


def _gateway_token_base_url(request: Request, token: str) -> str:
    return f"{_public_base_url(request)}/v1/__gw__/t/{token.strip()}"
