"""X-Forwarded-For is resolved from the right, not the client-controlled left hop.

A trusted proxy that appends (nginx ``$proxy_add_x_forwarded_for``) leaves the
caller-supplied leftmost value in place. That value must not become the client
IP, and an unparseable rightmost hop must not count as internal.
"""

from __future__ import annotations

import pytest
from starlette.requests import Request

from aegisgate.core import gateway_network


def _request(client_host: str, xff: str | list[str] | None = None) -> Request:
    raw_headers: list[tuple[bytes, bytes]] = []
    values = [xff] if isinstance(xff, str) else list(xff or [])
    for value in values:
        raw_headers.append((b"x-forwarded-for", value.encode("latin-1")))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": raw_headers,
        "client": (client_host, 1234),
        "server": ("127.0.0.1", 18080),
    }
    return Request(scope)


def _trust(monkeypatch: pytest.MonkeyPatch, trusted_proxy_ips: str) -> None:
    monkeypatch.setattr(gateway_network.settings, "trusted_proxy_ips", trusted_proxy_ips)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_exact", None)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_networks", None)


def test_trusted_proxy_skips_spoofed_leftmost_localhost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust(monkeypatch, "10.0.0.2")
    resolved = gateway_network._real_client_ip(
        _request("10.0.0.2", "localhost, 203.0.113.9")
    )
    # 203.0.113.0/24 is TEST-NET-3, which this CPython treats as private, so
    # _is_internal_ip is true. The check is which hop was selected.
    assert resolved == "203.0.113.9"


def test_trusted_proxy_skips_spoofed_leftmost_loopback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust(monkeypatch, "10.0.0.2")
    resolved = gateway_network._real_client_ip(
        _request("10.0.0.2", "127.0.0.1, 203.0.113.9")
    )
    assert resolved == "203.0.113.9"


def test_trusted_cidr_chain_stops_at_first_untrusted_hop_from_the_right(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust(monkeypatch, "10.0.0.0/8")
    resolved = gateway_network._real_client_ip(
        _request("10.0.0.2", "203.0.113.9, 10.0.0.7")
    )
    assert resolved == "203.0.113.9"
    spoofed = gateway_network._real_client_ip(
        _request("10.0.0.2", "localhost, 203.0.113.9, 10.0.0.7")
    )
    assert spoofed == "203.0.113.9"


def test_unparseable_rightmost_hop_is_non_internal_sentinel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust(monkeypatch, "10.0.0.2")
    resolved = gateway_network._real_client_ip(
        _request("10.0.0.2", "203.0.113.9, garbage")
    )
    assert resolved == "unknown"
    assert gateway_network._is_internal_ip(resolved) is False
    assert gateway_network._is_loopback_ip(resolved) is False


def test_multiple_xff_headers_are_merged_in_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust(monkeypatch, "10.0.0.2")
    resolved = gateway_network._real_client_ip(
        _request("10.0.0.2", ["127.0.0.1, 198.51.100.1", "203.0.113.9"])
    )
    assert resolved == "203.0.113.9"


def test_ipv4_mapped_direct_peer_is_a_trusted_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust(monkeypatch, "10.0.0.2")
    resolved = gateway_network._real_client_ip(
        _request("::ffff:10.0.0.2", "203.0.113.9")
    )
    assert resolved == "203.0.113.9"


def test_untrusted_direct_peer_ignores_xff(monkeypatch: pytest.MonkeyPatch) -> None:
    _trust(monkeypatch, "10.0.0.2")
    resolved = gateway_network._real_client_ip(_request("203.0.113.50", "127.0.0.1"))
    assert resolved == "203.0.113.50"


def test_unparseable_direct_peer_keeps_the_raw_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TestClient reports client.host as ``testclient``; that string must survive."""
    _trust(monkeypatch, "10.0.0.2")
    resolved = gateway_network._real_client_ip(_request("testclient", "127.0.0.1"))
    assert resolved == "testclient"


def test_trusted_proxy_without_xff_keeps_the_direct_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust(monkeypatch, "10.0.0.2")
    assert gateway_network._real_client_ip(_request("10.0.0.2")) == "10.0.0.2"


def test_all_trusted_hops_fall_back_to_the_leftmost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust(monkeypatch, "10.0.0.0/8")
    resolved = gateway_network._real_client_ip(
        _request("10.0.0.2", "10.0.0.7, 10.0.0.8")
    )
    assert resolved == "10.0.0.7"
