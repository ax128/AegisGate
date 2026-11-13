"""Network utility functions — trusted proxy, loopback, internal IP checks."""

from __future__ import annotations

import ipaddress

from fastapi import Request

from aegisgate.config.settings import settings
from aegisgate.util.logger import logger

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
# Not an IP, so _is_internal_ip and _is_loopback_ip are both false.
_UNKNOWN_CLIENT = "unknown"

# ---------------------------------------------------------------------------
# Trusted proxy handling
# ---------------------------------------------------------------------------
_trusted_proxy_exact: set[str] | None = None
_trusted_proxy_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] | None = None


def _normalize_ip_host(host: str) -> str:
    normalized = (host or "").strip()
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1].strip()
    return normalized


def _parse_trusted_proxy_ips() -> None:
    """Parse AEGIS_TRUSTED_PROXY_IPS into exact IPs and CIDR networks."""
    global _trusted_proxy_exact, _trusted_proxy_networks
    exact: set[str] = set()
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    raw = (settings.trusted_proxy_ips or "").strip()
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        if "/" in token:
            try:
                networks.append(ipaddress.ip_network(token, strict=False))
            except ValueError:
                logger.warning("trusted_proxy_ips: invalid CIDR %s, skipped", token)
        else:
            try:
                exact.add(str(ipaddress.ip_address(token)))
            except ValueError:
                logger.warning("trusted_proxy_ips: invalid IP %s, skipped", token)
    _trusted_proxy_exact = exact
    _trusted_proxy_networks = networks


def _is_trusted_proxy(ip_str: str) -> bool:
    """Check if an IP is in the trusted proxy list (exact match or CIDR)."""
    global _trusted_proxy_exact, _trusted_proxy_networks
    if _trusted_proxy_exact is None:
        _parse_trusted_proxy_ips()
    if _trusted_proxy_exact is None or _trusted_proxy_networks is None:
        return False
    if not _trusted_proxy_exact and not _trusted_proxy_networks:
        return False
    if ip_str in _trusted_proxy_exact:
        return True
    if _trusted_proxy_networks:
        try:
            addr = ipaddress.ip_address(ip_str)
            return any(addr in net for net in _trusted_proxy_networks)
        except ValueError:
            pass
    return False


def _parse_hop(value: str) -> str | None:
    """Return a normalized IP, or None when ``value`` is not an address.

    IPv4-mapped IPv6 (``::ffff:10.0.0.2``) is unwrapped so it matches an IPv4
    trusted-proxy entry. ``localhost`` is intentionally not an IP: a client can
    type it into X-Forwarded-For, and it must not count as loopback.
    """
    try:
        ip = ipaddress.ip_address(_normalize_ip_host(value))
    except ValueError:
        return None
    mapped = getattr(ip, "ipv4_mapped", None)
    return str(mapped or ip)


def _real_client_ip(request: Request) -> str:
    """Client IP, trusting X-Forwarded-For only from a trusted proxy.

    An appending proxy keeps whatever the client put on the left, so the
    leftmost hop is not the client. Walk from the right, skip hops that are
    themselves trusted proxies, and stop at the first other address. A hop that
    is not an IP is ``unknown`` rather than internal. No header, or a chain of
    only trusted proxies, falls back to the leftmost parsed hop, then the
    direct peer.

    A direct peer that does not parse (TestClient's ``testclient``) is returned
    unchanged so callers keep seeing that raw host.
    """
    raw_direct = request.client.host if request.client else ""
    direct_ip = _parse_hop(raw_direct)
    if direct_ip is None:
        return (raw_direct or "").strip()
    if not _is_trusted_proxy(direct_ip):
        return direct_ip
    hops = [
        hop.strip()
        for raw in request.headers.getlist("x-forwarded-for")
        for hop in raw.split(",")
        if hop.strip()
    ]
    for hop in reversed(hops):
        ip = _parse_hop(hop)
        if ip is None:
            return _UNKNOWN_CLIENT
        if not _is_trusted_proxy(ip):
            return ip
    if hops:
        return _parse_hop(hops[0]) or direct_ip
    return direct_ip


def trusted_forwarded_host(request: Request) -> str:
    """First ``X-Forwarded-Host`` value, only when the direct peer is a trusted proxy.

    This is the single read point for ``X-Forwarded-Host`` in the codebase: both
    the public-base-URL builder and the host-forwarding router go through it, so
    the trust decision cannot drift between them.
    """
    direct_ip = (request.client.host if request.client else "").strip()
    if not _is_trusted_proxy(direct_ip):
        return ""
    return (request.headers.get("x-forwarded-host") or "").split(",")[0].strip()


def client_facing_host(request: Request) -> str:
    """The host the client addressed: trusted ``X-Forwarded-Host``, else ``Host``.

    Raw value (port included). Host forwarding routes on it and writes URLs back
    with it, so both go through here rather than repeating the fallback.
    """
    return trusted_forwarded_host(request) or (request.headers.get("host") or "")


def trusted_forwarded_proto(request: Request) -> str:
    """First ``X-Forwarded-Proto`` value (lower-cased), trusted-proxy gated."""
    direct_ip = (request.client.host if request.client else "").strip()
    if not _is_trusted_proxy(direct_ip):
        return ""
    return (
        (request.headers.get("x-forwarded-proto") or "")
        .split(",")[0]
        .strip()
        .lower()
    )


_CLIENT_FORWARDING_HEADERS = frozenset(
    {
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-port",
        "x-forwarded-proto",
        "x-real-ip",
    }
)
_PROXY_UNOWNED_HEADERS = frozenset({"forwarded", "x-real-ip"})


def rewrite_forwarding_headers_for_upstream(
    request: Request, headers: dict[str, str]
) -> None:
    """Make the forwarding headers an upstream receives ones the gateway vouches for.

    From an untrusted peer they are whatever the client typed: an upstream on the
    same host sees the gateway as 127.0.0.1 and commonly trusts
    ``X-Forwarded-For``, so passing them along would let a public client claim to
    be local there. Those are dropped and replaced with the direct peer, scheme
    and ``Host``.

    Behind a trusted proxy the ``X-Forwarded-*`` set is the proxy's and passes
    through. ``X-Real-IP`` and ``Forwarded`` are not reliably the proxy's — Caddy,
    for one, relays both exactly as the client sent them — so they are dropped
    and ``X-Real-IP`` is restated from the client IP the gateway resolved.

    Lives next to ``trusted_forwarded_host`` so every ``X-Forwarded-Host``
    decision stays in this module.
    """
    direct_ip = (request.client.host if request.client else "").strip()
    if _is_trusted_proxy(direct_ip):
        for key in [name for name in headers if name.lower() in _PROXY_UNOWNED_HEADERS]:
            del headers[key]
        client_ip = _real_client_ip(request)
        if client_ip:
            headers["X-Real-IP"] = client_ip
        return
    for key in [name for name in headers if name.lower() in _CLIENT_FORWARDING_HEADERS]:
        del headers[key]
    if direct_ip:
        headers["X-Forwarded-For"] = direct_ip
    headers["X-Forwarded-Proto"] = request.url.scheme or "http"
    host = (request.headers.get("host") or "").strip()
    if host:
        headers["X-Forwarded-Host"] = host


def _is_loopback_ip(host: str) -> bool:
    normalized = _normalize_ip_host(host)
    if not normalized:
        return False
    if normalized in _LOOPBACK_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return ip.is_loopback


def _is_internal_ip(host: str) -> bool:
    normalized = _normalize_ip_host(host)
    if not normalized:
        return False
    if normalized in _LOOPBACK_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local
