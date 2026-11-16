"""Canary traffic split: send `percent`% of a route's requests to an alternate upstream.

The bucket is a hash of (tenant_id, request_id) rather than `random()`: it is uniform, needs no
shared state, and any assignment can be reproduced exactly from the audit log.
"""

from __future__ import annotations

import hashlib

from gateway.models import Route


def bucket(tenant_id: str, request_id: str) -> int:
    """A stable number from 0 to 99 for this request."""
    digest = hashlib.sha256(f"{tenant_id}:{request_id}".encode()).digest()
    return int.from_bytes(digest[:8], "big") % 100


def choose_upstream(route: Route, tenant_id: str, request_id: str) -> tuple[str, bool]:
    """Return (upstream_url, is_canary)."""
    canary = route.canary
    if canary is None or canary.percent == 0 or not canary.applies_to(tenant_id):
        return route.upstream, False
    if bucket(tenant_id, request_id) < canary.percent:
        return canary.upstream, True
    return route.upstream, False
