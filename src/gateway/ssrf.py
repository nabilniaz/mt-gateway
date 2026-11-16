"""Upstream URL validation (server-side request forgery guard).

Runs whenever a route is written (seed file at startup or admin API at runtime). An upstream
must be plain http(s) with no credentials, and its host must resolve only to public IPs, unless
the operator named that host in UPSTREAM_ALLOWED_PRIVATE_HOSTS (for example the private
`demo-upstream` component on App Platform).
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable, Collection
from urllib.parse import urlsplit

Resolver = Callable[[str, int], Awaitable[list[str]]]


class UnsafeUpstream(ValueError):
    pass


async def system_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


def is_public_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])  # drop an IPv6 zone id
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 is loopback
    # is_global is False for private, loopback, link-local (incl. 169.254.169.254 metadata),
    # shared (100.64/10), reserved and unspecified ranges.
    return ip.is_global and not ip.is_multicast


async def validate_upstream(
    url: str,
    *,
    allowed_private_hosts: Collection[str],
    resolver: Resolver = system_resolver,
) -> None:
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as err:
        raise UnsafeUpstream(f"upstream {url!r} is not a valid URL: {err}") from None
    if parts.scheme not in ("http", "https"):
        raise UnsafeUpstream(f"upstream {url!r} must use http or https")
    if parts.username is not None or parts.password is not None:
        raise UnsafeUpstream("upstream URL must not contain credentials")
    if parts.query or parts.fragment:
        raise UnsafeUpstream("upstream URL must not contain a query string or fragment")
    host = (parts.hostname or "").lower()
    if not host:
        raise UnsafeUpstream(f"upstream {url!r} has no host")
    if host in allowed_private_hosts:
        return

    try:
        ipaddress.ip_address(host)
        addresses = [host]  # an IP literal needs no lookup
    except ValueError:
        addresses = await _resolve(resolver, host, port or (443 if parts.scheme == "https" else 80))
    for address in addresses:
        if not is_public_ip(address):
            raise UnsafeUpstream(
                f"upstream host {host!r} resolves to non-public address {address}; "
                "add it to UPSTREAM_ALLOWED_PRIVATE_HOSTS if this is intended"
            )


async def _resolve(resolver: Resolver, host: str, port: int) -> list[str]:
    try:
        addresses = await resolver(host, port)
    except OSError:
        raise UnsafeUpstream(f"upstream host {host!r} does not resolve") from None
    if not addresses:
        raise UnsafeUpstream(f"upstream host {host!r} does not resolve")
    return addresses
