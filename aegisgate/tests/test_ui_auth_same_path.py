"""Auth and routing must judge the same path.

Collapsing a path before the public-UI check can treat it as the login page
while the router matches the raw path to a different route. Dot segments are
rejected before either decision. A leading double slash is not rewritten into
a UI route.
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from aegisgate.core.gateway import app


async def _raw(method: str, path: str) -> tuple[int, dict, str]:
    """Call the ASGI app with a path httpx would normalize away."""
    messages: list[dict] = []
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("latin-1"),
        "query_string": b"",
        "headers": [
            (b"host", b"127.0.0.1:18080"),
            (b"content-type", b"application/json"),
        ],
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 18080),
    }
    sent = False

    async def receive() -> dict:
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        body = b"{}" if method != "GET" else b""
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message: dict) -> None:
        messages.append(message)

    await app(scope, receive, send)
    status = 0
    location = ""
    chunks: list[bytes] = []
    for message in messages:
        if message["type"] == "http.response.start":
            status = int(message["status"])
            for key, value in message.get("headers") or []:
                if key.lower() == b"location":
                    location = value.decode("latin-1")
        elif message["type"] == "http.response.body":
            chunks.append(message.get("body") or b"")
    raw = b"".join(chunks)
    if not raw:
        return status, {}, location
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        # Login and other pages answer with HTML. Callers that need a JSON
        # body assert on the parsed object; a document is not one.
        return status, {}, location
    if not isinstance(parsed, dict):
        return status, {}, location
    return status, parsed, location


async def test_normpath_public_path_is_not_dispatched_to_another_route() -> None:
    """normpath makes this the public login page; the router matches compose."""
    status, body, _location = await _raw("GET", "/__ui__/api/compose/../../login")

    assert status == 400, body
    assert body["error"]["code"] == "invalid_path"
    assert body.get("error") != "not_allowed"


async def test_ui_parent_segment_is_not_a_v1_route() -> None:
    status, body, location = await _raw("POST", "/__ui__/../v1/chat/completions")

    assert status == 400, (status, location, body)
    assert body["error"]["code"] == "invalid_path"
    assert location != "/__ui__/login"
    assert body["error"]["code"] != "token_route_required"


async def test_double_slash_ui_api_is_not_the_ui_route() -> None:
    status, body, _location = await _raw("GET", "//__ui__/api/tokens")

    assert status == 404, body
    assert body == {"detail": "Not Found"}

    real_status, real_body, _location = await _raw("GET", "/__ui__/api/tokens")
    assert real_status == 401
    assert real_body["error"] == "ui_auth_required"


async def test_plain_login_path_stays_public() -> None:
    status, _body, location = await _raw("GET", "/__ui__/login")

    assert status == 200
    assert location == ""


def _location_path(location: str) -> str:
    if "://" in location:
        return urlsplit(location).path
    return location


async def test_public_health_with_one_trailing_slash_reaches_the_router() -> None:
    status, body, location = await _raw("GET", "/__ui__/health/")

    assert status == 307, (status, location, body)
    assert _location_path(location) == "/__ui__/health"


async def test_public_login_with_one_trailing_slash_reaches_the_router() -> None:
    status, body, location = await _raw("POST", "/__ui__/api/login/")

    assert status == 307, (status, location, body)
    assert _location_path(location) == "/__ui__/api/login"
    assert body.get("error") != "ui_auth_required"


async def test_internal_empty_segment_stays_on_the_raw_path() -> None:
    status, body, location = await _raw("GET", "/__ui__//login")

    assert status == 303, (status, location, body)
    assert location == "/__ui__/login"


async def test_plain_v1_path_is_not_rejected_as_a_dot_segment() -> None:
    status, body, _location = await _raw("POST", "/v1/chat/completions")

    assert status != 400
    assert body["error"]["code"] == "token_route_required"
