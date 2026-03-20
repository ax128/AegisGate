"""Network utility functions — trusted proxy, loopback, internal IP checks."""

from __future__ import annotations

import ipaddress

from fastapi import Request

from aegisgate.config.settings import settings
from aegisgate.util.logger import logger

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}

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


def _real_client_ip(request: Request) -> str:
    """
    Determine the real client IP.
    Only trust X-Forwarded-For when the direct connection comes from a trusted proxy.
    """
    direct_ip = (request.client.host if request.client else "").strip()
    if not _is_trusted_proxy(direct_ip):
        return direct_ip
    xff = (request.headers.get("x-forwarded-for") or "").strip()
    if xff:
        return xff.split(",", 1)[0].strip()
    return direct_ip


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
