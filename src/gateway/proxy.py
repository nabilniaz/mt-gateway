"""Header and URL rewriting for the upstream call.

Inbound: drop hop-by-hop headers (they describe one TCP hop, not the request), the caller's
`Authorization` (upstreams must never see gateway tokens), and every identity or forwarding
header a caller could spoof. Then add gateway-owned headers the upstream can trust.

Outbound: return the upstream's headers minus hop-by-hop ones and ones the gateway owns.
"""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import quote

from gateway.models import Route

HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)

_DROP_INBOUND = frozenset(
    {
        "host",  # httpx sets it from the upstream URL
        "content-length",  # recomputed from the buffered body
        "authorization",  # cookies, by contrast, pass through: they belong to the upstream
        "forwarded",
        "x-real-ip",
        "x-request-id",
        "do-connecting-ip",
    }
)
_DROP_INBOUND_PREFIXES = ("x-tenant-", "x-forwarded-")

# The gateway sets these on responses itself.
_DROP_OUTBOUND = frozenset({"x-request-id", "x-ratelimit-limit", "x-ratelimit-remaining"})

# RFC 3986 characters that are safe to leave unescaped inside a path.
_PATH_SAFE = "/:@!$&'()*+,;=-._~"

Header = tuple[str, str]


def _connection_listed(headers: Iterable[Header]) -> set[str]:
    """Headers named in `Connection: a, b` are also hop-by-hop for this message."""
    listed: set[str] = set()
    for name, value in headers:
        if name.lower() == "connection":
            listed.update(t.strip().lower() for t in value.split(",") if t.strip())
    return listed


def upstream_request_headers(
    incoming: Iterable[Header],
    *,
    request_id: str,
    tenant_id: str,
    client_ip: str | None,
    scheme: str,
) -> list[Header]:
    incoming = list(incoming)
    drop = HOP_BY_HOP | _DROP_INBOUND | _connection_listed(incoming)
    headers = [
        (name, value)
        for name, value in incoming
        if name.lower() not in drop and not name.lower().startswith(_DROP_INBOUND_PREFIXES)
    ]
    headers += [
        ("x-request-id", request_id),
        ("x-tenant-id", tenant_id),
        ("x-forwarded-proto", scheme),
    ]
    if client_ip:
        headers.append(("x-forwarded-for", client_ip))
    return headers


def downstream_response_headers(
    upstream: Iterable[tuple[bytes, bytes]],
) -> list[tuple[bytes, bytes]]:
    upstream = list(upstream)
    decoded = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in upstream]
    drop = HOP_BY_HOP | _DROP_OUTBOUND | _connection_listed(decoded)
    return [(k.lower(), v) for k, v in upstream if k.decode("latin-1").lower() not in drop]


def upstream_url(base: str, route: Route, path: str, query: str) -> str:
    """Join the upstream base URL with the (optionally prefix-stripped) request path.

    `/orders/42` on route `/orders` -> upstream `https://svc/v1` becomes `https://svc/v1/42`.
    `path` is the decoded, normalized path; it is re-encoded here exactly once.
    """
    if route.strip_prefix:
        remainder = path[len(route.prefix) :] if route.prefix != "/" else path
    else:
        remainder = path
    url = base.rstrip("/") + quote(remainder, safe=_PATH_SAFE)
    if not url.split("://", 1)[1].count("/"):
        url += "/"  # bare host: always send a path
    return f"{url}?{query}" if query else url
