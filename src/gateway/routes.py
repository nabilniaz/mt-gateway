"""The route table and tenant store: immutable snapshots, swapped atomically on write.

Readers (every proxied request) read `.snapshot` once and use it to the end, without locking.
Writers (the admin API) take an asyncio.Lock, build a whole new snapshot, and replace one
reference. Because Python reference assignment is atomic, a reader sees either the old table or
the new one, never a mix.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from gateway.models import Route, Tenant
from gateway.paths import has_prefix


class RouteConflict(ValueError):
    pass


@dataclass(frozen=True)
class RouteSnapshot:
    routes: tuple[Route, ...]
    """Sorted longest prefix first, so the first match is the most specific one."""

    @classmethod
    def build(cls, routes: Iterable[Route]) -> RouteSnapshot:
        by_id: dict[str, Route] = {}
        by_prefix: dict[str, str] = {}
        for route in routes:
            if route.route_id in by_id:
                raise RouteConflict(f"duplicate route_id {route.route_id!r}")
            if route.prefix in by_prefix:
                raise RouteConflict(
                    f"prefix {route.prefix!r} is already used by route {by_prefix[route.prefix]!r}"
                )
            by_id[route.route_id] = route
            by_prefix[route.prefix] = route.route_id
        ordered = sorted(by_id.values(), key=lambda r: (-len(r.prefix), r.prefix))
        return cls(tuple(ordered))

    def match(self, path: str) -> Route | None:
        for route in self.routes:
            if has_prefix(path, route.prefix):
                return route
        return None

    def get(self, route_id: str) -> Route | None:
        return next((r for r in self.routes if r.route_id == route_id), None)


class RouteTable:
    def __init__(self, routes: Iterable[Route] = ()) -> None:
        self._snapshot = RouteSnapshot.build(routes)
        self._lock = asyncio.Lock()

    @property
    def snapshot(self) -> RouteSnapshot:
        return self._snapshot

    async def put(self, route: Route) -> bool:
        """Create or replace a route. Returns True if it was created."""
        async with self._lock:
            current = self._snapshot
            others = [r for r in current.routes if r.route_id != route.route_id]
            self._snapshot = RouteSnapshot.build([*others, route])
            return len(others) == len(current.routes)

    async def delete(self, route_id: str) -> bool:
        async with self._lock:
            current = self._snapshot
            remaining = [r for r in current.routes if r.route_id != route_id]
            if len(remaining) == len(current.routes):
                return False
            self._snapshot = RouteSnapshot.build(remaining)
            return True


class TenantStore:
    def __init__(self, tenants: Iterable[Tenant] = ()) -> None:
        by_id: dict[str, Tenant] = {}
        for tenant in tenants:
            if tenant.tenant_id in by_id:
                raise ValueError(f"duplicate tenant_id {tenant.tenant_id!r}")
            by_id[tenant.tenant_id] = tenant
        self._tenants: Mapping[str, Tenant] = MappingProxyType(by_id)
        self._lock = asyncio.Lock()

    def get(self, tenant_id: str) -> Tenant | None:
        return self._tenants.get(tenant_id)

    def all(self) -> list[Tenant]:
        return sorted(self._tenants.values(), key=lambda t: t.tenant_id)

    async def put(self, tenant: Tenant) -> bool:
        async with self._lock:
            updated = dict(self._tenants)
            created = tenant.tenant_id not in updated
            updated[tenant.tenant_id] = tenant
            self._tenants = MappingProxyType(updated)
            return created
