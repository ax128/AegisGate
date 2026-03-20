from aegisgate.core import gateway_network


def test_parse_trusted_proxy_ips_skips_invalid_entries(monkeypatch):
    monkeypatch.setattr(
        gateway_network.settings,
        "trusted_proxy_ips",
        "127.0.0.1, not-an-ip, 10.0.0.0/24, bad/cidr, ::1",
    )
    monkeypatch.setattr(gateway_network, "_trusted_proxy_exact", None)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_networks", None)

    gateway_network._parse_trusted_proxy_ips()

    assert gateway_network._trusted_proxy_exact == {"127.0.0.1", "::1"}
    assert gateway_network._trusted_proxy_networks is not None
    assert len(gateway_network._trusted_proxy_networks) == 1
    assert str(gateway_network._trusted_proxy_networks[0]) == "10.0.0.0/24"


def test_is_trusted_proxy_supports_exact_and_cidr(monkeypatch):
    monkeypatch.setattr(gateway_network.settings, "trusted_proxy_ips", "127.0.0.1, 10.0.0.0/24, bad/cidr")
    monkeypatch.setattr(gateway_network, "_trusted_proxy_exact", None)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_networks", None)

    assert gateway_network._is_trusted_proxy("127.0.0.1") is True
    assert gateway_network._is_trusted_proxy("10.0.0.8") is True
    assert gateway_network._is_trusted_proxy("10.0.1.8") is False
    assert gateway_network._is_trusted_proxy("not-an-ip") is False


def test_real_client_ip_trusts_xff_only_for_trusted_proxy(make_request, monkeypatch):
    monkeypatch.setattr(gateway_network.settings, "trusted_proxy_ips", "127.0.0.1")
    monkeypatch.setattr(gateway_network, "_trusted_proxy_exact", None)
    monkeypatch.setattr(gateway_network, "_trusted_proxy_networks", None)

    trusted = make_request(
        "/v1/chat/completions",
        headers={"x-forwarded-for": "203.0.113.9, 127.0.0.1"},
        client_host="127.0.0.1",
    )
    untrusted = make_request(
        "/v1/chat/completions",
        headers={"x-forwarded-for": "203.0.113.10"},
        client_host="198.51.100.7",
    )

    assert gateway_network._real_client_ip(trusted) == "203.0.113.9"
    assert gateway_network._real_client_ip(untrusted) == "198.51.100.7"


def test_is_loopback_ip_supports_bracketed_ipv6_and_invalid_host():
    assert gateway_network._is_loopback_ip("[::1]") is True
    assert gateway_network._is_loopback_ip(" [::1] ") is True
    assert gateway_network._is_loopback_ip("localhost") is True
    assert gateway_network._is_loopback_ip("example.com") is False


def test_is_internal_ip_identifies_private_link_local_and_public():
    assert gateway_network._is_internal_ip("192.168.1.9") is True
    assert gateway_network._is_internal_ip(" [::1] ") is True
    assert gateway_network._is_internal_ip("169.254.10.20") is True
    assert gateway_network._is_internal_ip("8.8.8.8") is False
    assert gateway_network._is_internal_ip("") is False
