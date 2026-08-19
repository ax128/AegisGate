"""Optimistic concurrency for the console's whole-file writes.

Rules YAML, ``config/.env``, compose files and the exact-value list are all
edited read-modify-write: the console loads the whole document, changes part of
it, and writes the whole thing back. The write itself is atomic, but nothing
checked that the document had not changed in between — so two browser tabs (or
two admins) each saving would silently discard the other's edit, and for the
rules file that means a security policy quietly rolled back.

Each of those resources now carries an ``ETag`` derived from the bytes on disk.
A write that carries ``If-Match`` is verified against the current state and
rejected with ``409`` when it does not match, together with the current ETag so
the client can reload and re-apply.

``If-Match`` is honoured when present rather than demanded: existing API clients
and scripts that never send it keep working exactly as before. The console
always sends it, so the console always gets the protection.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from fastapi import Request
from fastapi.responses import JSONResponse

# Returned for a resource whose backing file does not exist yet, so "create it"
# and "replace the version I saw" stay distinguishable.
ABSENT_ETAG = '"absent"'
IF_MATCH_HEADER = "if-match"


def etag_for_bytes(payload: bytes) -> str:
    return '"' + hashlib.sha256(payload).hexdigest()[:32] + '"'


def etag_for_file(path: Path) -> str:
    """Strong ETag over the file's current bytes, or ``ABSENT_ETAG``."""
    try:
        return etag_for_bytes(path.read_bytes())
    except (OSError, ValueError):
        return ABSENT_ETAG


def _normalize(raw: str) -> str:
    """Accept both quoted and bare forms, and the weak-validator prefix."""
    value = raw.strip()
    if value.startswith("W/"):
        value = value[2:].strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value
    return f'"{value}"'


def if_match_conflict(request: Request, current_etag: str) -> JSONResponse | None:
    """Return a 409 response when the request's ``If-Match`` is stale.

    ``None`` means the write may proceed: either no ``If-Match`` was sent, it is
    the wildcard, or it matches the current state.
    """
    header = request.headers.get(IF_MATCH_HEADER)
    if header is None:
        return None
    candidates = [part for part in header.split(",") if part.strip()]
    if any(part.strip() == "*" for part in candidates):
        return None
    if any(_normalize(part) == current_etag for part in candidates):
        return None
    return JSONResponse(
        status_code=409,
        content={
            "error": "etag_mismatch",
            "detail": "该配置已被其他会话修改，请刷新后重新提交，避免覆盖对方的改动",
            "current_etag": current_etag,
        },
        headers={"ETag": current_etag},
    )


def with_etag(response: JSONResponse, etag: str) -> JSONResponse:
    """Stamp *response* with *etag* and return it, for use in a return statement."""
    response.headers["ETag"] = etag
    return response
