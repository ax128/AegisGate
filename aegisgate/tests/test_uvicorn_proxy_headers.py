"""The gateway reads the TCP peer itself; uvicorn must not rewrite it first.

Every trust decision (``AEGIS_ENFORCE_LOOPBACK_ONLY``, ``AEGIS_TRUSTED_PROXY_IPS``,
the XFF downgrade, the forwarding headers sent upstream) assumes
``request.client`` / ``request.url.scheme`` are the direct connection. uvicorn's
``--proxy-headers`` is on by default and trusts 127.0.0.1 (or whatever
``FORWARDED_ALLOW_IPS`` says), replacing both from ``X-Forwarded-For`` /
``X-Forwarded-Proto`` before the app runs — so a same-host reverse proxy was
seen as its client, and a loopback client could pick the scheme.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegisgate.config import settings as settings_module

_REPO_ROOT = Path(__file__).resolve().parents[2]

# Every place that starts (or tells a reader to start) the gateway under uvicorn.
_LAUNCH_FILES = (
    "Dockerfile",
    "scripts/local_launcher.py",
    "README.md",
    "README_zh.md",
    "SKILL.md",
    "WEBUI-QUICKSTART.md",
    "UPSTREAM-QUICKSTART.md",
    "OTHER_TERMINAL_CLIENTS_USAGE.md",
    "config/README.md",
)

_LAUNCH_LINE = re.compile(r"uvicorn.*aegisgate\.core\.gateway:app")


def test_every_uvicorn_launch_turns_proxy_headers_off() -> None:
    launches: list[str] = []
    offenders: list[str] = []
    for name in _LAUNCH_FILES:
        path = _REPO_ROOT / name
        if not path.is_file():
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not _LAUNCH_LINE.search(line):
                continue
            launches.append(f"{name}:{number}")
            if "--no-proxy-headers" not in line:
                offenders.append(f"{name}:{number}: {line.strip()}")
    assert "Dockerfile:" in " ".join(launches)
    assert "scripts/local_launcher.py:" in " ".join(launches)
    assert offenders == []


def test_uvicorn_proxy_headers_turn_a_same_host_proxy_into_its_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Why the flag above exists: what Caddyfile.example's same-host block sends.
    from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

    from aegisgate.core.gateway import app

    monkeypatch.setattr(
        settings_module.settings, "enforce_loopback_only", True, raising=False
    )
    headers = {"X-Forwarded-For": "203.0.113.9", "X-Forwarded-Proto": "https"}

    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        direct = client.get("/foo", headers=headers)
    # The proxy is a loopback peer: past the boundary, to the ordinary 404.
    assert direct.status_code == 404

    wrapped = ProxyHeadersMiddleware(app, trusted_hosts="127.0.0.1")
    with TestClient(wrapped, client=("127.0.0.1", 50000)) as client:
        rewritten = client.get("/foo", headers=headers)
    # uvicorn's default replaced the peer with the proxy's client.
    assert rewritten.status_code == 403
    assert "loopback_only_reject" in rewritten.text
