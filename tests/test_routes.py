import asyncio
from typing import Any

import pytest
from pydantic import ValidationError

from gateway.models import Route, Tenant, TokenRequest
from gateway.routes import RouteConflict, RouteSnapshot, RouteTable, TenantStore


def route(route_id: str, prefix: str, **extra: Any) -> Route:
    return Route(route_id=route_id, prefix=prefix, upstream="https://example.com", **extra)


def test_longest_prefix_wins_regardless_of_insert_order() -> None:
    snap = RouteSnapshot.build(
        [route("orders", "/orders"), route("admin_orders", "/orders/admin"), route("a", "/a")]
    )
    assert snap.match("/orders/admin/7").route_id == "admin_orders"  # type: ignore[union-attr]
    assert snap.match("/orders/7").route_id == "orders"  # type: ignore[union-attr]
    assert snap.match("/orders").route_id == "orders"  # type: ignore[union-attr]
    assert snap.match("/ordersX") is None
    assert snap.match("/other") is None


def test_duplicate_prefix_or_id_rejected() -> None:
    with pytest.raises(RouteConflict, match="already used"):
        RouteSnapshot.build([route("a", "/x"), route("b", "/x/")])
    with pytest.raises(RouteConflict, match="duplicate route_id"):
        RouteSnapshot.build([route("a", "/x"), route("a", "/y")])


@pytest.mark.parametrize("prefix", ["/", "/admin", "/admin/x", "/healthz", "/a/../b", "x"])
def test_route_prefix_validation(prefix: str) -> None:
    with pytest.raises(ValidationError):
        route("r", prefix)


def test_route_prefix_trailing_slash_is_normalized() -> None:
    assert route("r", "/orders/").prefix == "/orders"
    assert route("r", "/administrator").prefix == "/administrator"  # not under /admin


@pytest.mark.parametrize(
    "extra",
    [
        {"timeout_seconds": 31},
        {"timeout_seconds": 0},
        {"required_scopes": ["has space"]},
        {"canary": {"upstream": "https://x", "percent": 101}},
        {"canary": {"upstream": "https://x", "percent": 5, "tenants": ["Not_Valid"]}},
        {"circuit_breaker": {"failure_threshold": 0}},
        {"unknown_field": 1},
    ],
)
def test_route_field_validation(extra: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        route("r", "/r", **extra)


def test_route_is_immutable() -> None:
    r = route("r", "/r")
    with pytest.raises(ValidationError):
        r.prefix = "/other"  # type: ignore[misc]


def test_tenant_validation() -> None:
    t = Tenant(tenant_id="acme", allowed_paths=["/orders/", "/echo"], max_scopes=["orders:read"])
    assert t.allowed_paths == ("/orders", "/echo")
    with pytest.raises(ValidationError, match="admin scope"):
        Tenant(tenant_id="acme", max_scopes=["admin"])
    with pytest.raises(ValidationError):
        Tenant(tenant_id="ACME")
    with pytest.raises(ValidationError):
        Tenant(tenant_id="acme", rate_limit_per_minute=-1)
    with pytest.raises(ValidationError):
        Tenant(tenant_id="acme", allowed_paths=["/a/../b"])


def test_token_request_ttl_bounds() -> None:
    assert TokenRequest(tenant_id="acme").ttl_seconds == 900
    with pytest.raises(ValidationError):
        TokenRequest(tenant_id="acme", ttl_seconds=901)


async def test_put_and_delete_swap_snapshots_without_touching_old_ones() -> None:
    table = RouteTable([route("a", "/a")])
    before = table.snapshot
    assert await table.put(route("b", "/b")) is True
    assert await table.put(route("b", "/b2")) is False  # replace
    assert [r.route_id for r in before.routes] == ["a"]  # a reader's snapshot never changes
    assert table.snapshot.get("b").prefix == "/b2"  # type: ignore[union-attr]
    assert await table.delete("b") is True
    assert await table.delete("b") is False
    assert [r.route_id for r in table.snapshot.routes] == ["a"]


async def test_conflicting_put_leaves_table_unchanged() -> None:
    table = RouteTable([route("a", "/a")])
    before = table.snapshot
    with pytest.raises(RouteConflict):
        await table.put(route("b", "/a"))
    assert table.snapshot is before


async def test_concurrent_writes_are_serialized() -> None:
    table = RouteTable()
    await asyncio.gather(*(table.put(route(f"r{i}", f"/r{i}")) for i in range(50)))
    assert len(table.snapshot.routes) == 50


async def test_tenant_store() -> None:
    store = TenantStore([Tenant(tenant_id="acme")])
    assert store.get("acme") is not None
    assert store.get("nobody") is None
    assert await store.put(Tenant(tenant_id="acme", enabled=False)) is False
    assert store.get("acme").enabled is False  # type: ignore[union-attr]
    assert await store.put(Tenant(tenant_id="globex")) is True
    assert [t.tenant_id for t in store.all()] == ["acme", "globex"]
    with pytest.raises(ValueError, match="duplicate"):
        TenantStore([Tenant(tenant_id="a"), Tenant(tenant_id="a")])
