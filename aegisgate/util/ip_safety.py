"""Shared IP safety and SSRF protection utilities."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Any
from urllib.parse import urlunparse

from aegisgate.util.logger import logger

SSRF_METADATA_HOSTS = frozenset(
    {
        "169.254.169.254",
        "169.254.170.2",
        "metadata.google.internal",
        "metadata.goog",
    }
)


def is_blocked_ip(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Check if an IP address is internal/private/reserved.

    Handles IPv4-mapped IPv6 addresses by unpacking to the underlying IPv4 address first.
    """
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return not addr.is_global or addr.is_reserved


async def resolve_public_ips(
    hostname: str,
) -> tuple[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...], str | None]:
    """Resolve hostname to public IPs using async DNS. Returns (ips, error_message).

    Uses asyncio loop.getaddrinfo to avoid blocking the event loop.
    Fail-closed: DNS failures or empty results return an error.
    """
    lowered = (hostname or "").strip().lower().strip(".")
    if not lowered:
        return (), "invalid_upstream_host"
    if lowered in SSRF_METADATA_HOSTS or lowered in {
        "localhost",
        "localhost.localdomain",
    }:
        return (), "target url points to an internal/private address (SSRF protection)"
    if lowered.endswith(".internal"):
        return (), "target url points to an internal/private address (SSRF protection)"

    try:
        literal_addr = ipaddress.ip_address(lowered)
    except ValueError:
        literal_addr = None

    if literal_addr is not None:
        if is_blocked_ip(literal_addr):
            return (
                (),
                "target url points to an internal/private address (SSRF protection)",
            )
        return (literal_addr,), None

    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(lowered, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        logger.warning(
            "dns lookup failed host=%s — blocking (fail-closed)",
            lowered,
        )
        return (), "target url points to an internal/private address (SSRF protection)"

    resolved: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for family, _socktype, _proto, _canonname, sockaddr in infos:
        candidate = sockaddr[0]
        try:
            addr = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if family in {socket.AF_INET, socket.AF_INET6}:
            resolved.add(addr)

    if not resolved:
        logger.warning(
            "dns resolved empty host=%s — blocking (fail-closed)",
            lowered,
        )
        return (), "target url points to an internal/private address (SSRF protection)"

    if any(is_blocked_ip(addr) for addr in resolved):
        return (), "target url points to an internal/private address (SSRF protection)"

    return tuple(sorted(resolved, key=lambda a: (a.version, int(a)))), None


def format_connect_host(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Format an IP address for use in a URL netloc (brackets for IPv6)."""
    text = str(addr)
    return f"[{text}]" if addr.version == 6 else text


def bound_connect_url(
    parsed: Any,
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> str:
    """Build a URL that connects directly to a verified IP address."""
    connect_host = format_connect_host(addr)
    if parsed.port is not None:
        connect_host = f"{connect_host}:{parsed.port}"
    auth = ""
    if parsed.username:
        auth = parsed.username
        if parsed.password is not None:
            auth = f"{auth}:{parsed.password}"
        auth = f"{auth}@"
    netloc = f"{auth}{connect_host}"
    return urlunparse(
        (
            parsed.scheme,
            netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            "",
        )
    )


def request_host_header(parsed: Any) -> str:
    """Build the Host header value from a parsed URL."""
    host = parsed.hostname or ""
    if not host:
        return ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if parsed.port is not None:
        return f"{host}:{parsed.port}"
    return host
