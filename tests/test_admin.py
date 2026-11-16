from collections.abc import AsyncIterator
from typing import Any

import pytest
from structlog.testing import capture_logs

from tests.harness import Harness, build_harness


@pytest.fixture
async def h() -> AsyncIterator[Harness]:
    async with build_harness() as harness:
        yield harness


NEW_ROUTE = {"prefix": "/canary", "upstream": "http://canary.test/v2", "required_scopes": []}


# --- authentication ---------------------------------------------------------------------------


async def test_admin_requires_a_token(h: Harness) -> None:
    resp = await h.get("/admin/routes", token=None)
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "missing_token"


async def test_tenant_token_gets_403_admin_required(h: Harness) -> None:
    resp = await h.get("/admin/routes")
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "admin_required"


async def test_garbage_token_gets_401(h: Harness) -> None:
    resp = await h.get("/admin/routes", token="nope")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "invalid_token"


async def test_revoked_admin_token(h: Harness) -> None:
    issued = h.gateway.tokens.issue_admin_token("alice")
    h.gateway.tokens.revocations.revoke(issued.jti)
    resp = await h.get("/admin/routes", token=issued.token)
    assert resp.json()["error"]["code"] == "token_revoked"


async def test_unknown_admin_path_is_not_proxied(h: Harness) -> None:
    resp = await h.get("/admin/../../etc/passwd")
    assert resp.status_code in (400, 403)
    assert sum(h.calls.values()) == 0


# --- routes -----------------------------------------------------------------------------------


async def test_list_routes(h: Harness) -> None:
    resp = await h.admin("GET", "/admin/routes")
    assert resp.status_code == 200
    ids = [r["route_id"] for r in resp.json()]
    assert ids[0] == "echo_admin"  # longest prefix first
    assert set(ids) >= {"echo", "down", "flaky"}


async def test_route_added_at_runtime_serves_traffic_immediately(h: Harness) -> None:
    assert (await h.get("/canary/x")).status_code == 404
    resp = await h.admin("PUT", "/admin/routes/canary", json=NEW_ROUTE)
    assert resp.status_code == 201
    assert resp.json()["route_id"] == "canary"
    proxied = await h.get("/canary/x")
    assert proxied.status_code == 200
    assert proxied.json()["upstream"] == "canary"
    assert proxied.json()["path"] == "/v2/x"


async def test_route_update_and_delete(h: Harness) -> None:
    await h.admin("PUT", "/admin/routes/canary", json=NEW_ROUTE)
    updated = {**NEW_ROUTE, "upstream": "http://primary.test/v9"}
    assert (await h.admin("PUT", "/admin/routes/canary", json=updated)).status_code == 200
    assert (await h.get("/canary/x")).json()["path"] == "/v9/x"
    assert (await h.admin("DELETE", "/admin/routes/canary")).status_code == 204
    assert (await h.get("/canary/x")).status_code == 404
    resp = await h.admin("DELETE", "/admin/routes/canary")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "route_not_found"


@pytest.mark.parametrize(
    ("body", "fragment"),
    [
        ({**NEW_ROUTE, "upstream": "http://metadata.test/latest"}, "non-public"),
        ({**NEW_ROUTE, "upstream": "http://169.254.169.254/"}, "non-public"),
        ({**NEW_ROUTE, "upstream": "file:///etc/passwd"}, "http or https"),
        ({**NEW_ROUTE, "upstream": "http://user:pw@primary.test"}, "credentials"),
        ({**NEW_ROUTE, "canary": {"upstream": "http://metadata.test", "percent": 5}}, "non-public"),
        ({**NEW_ROUTE, "prefix": "/echo"}, "already used"),
        ({**NEW_ROUTE, "prefix": "/admin/x"}, "reserved"),
        ({**NEW_ROUTE, "prefix": "/a/../b"}, "prefix"),
        ({**NEW_ROUTE, "timeout_seconds": 999}, "timeout_seconds"),
        ({"prefix": "/x"}, "upstream"),
    ],
)
async def test_invalid_routes_rejected_with_422(
    h: Harness, body: dict[str, Any], fragment: str
) -> None:
    resp = await h.admin("PUT", "/admin/routes/canary", json=body)
    assert resp.status_code == 422, resp.text
    error = resp.json()["error"]
    assert error["code"] == "validation_error"
    assert fragment in error["message"]
    assert h.gateway.routes.snapshot.get("canary") is None


async def test_allowlisted_private_host_is_accepted(h: Harness) -> None:
    body = {**NEW_ROUTE, "upstream": "http://internal.test:8080"}
    assert (await h.admin("PUT", "/admin/routes/canary", json=body)).status_code == 201


async def test_bad_route_id_rejected(h: Harness) -> None:
    resp = await h.admin("PUT", "/admin/routes/Bad%20Id", json=NEW_ROUTE)
    assert resp.status_code == 422


async def test_export_matches_seed_file_format(h: Harness) -> None:
    from gateway.models import RoutesFile

    resp = await h.admin("GET", "/admin/routes/export")
    parsed = RoutesFile.model_validate(resp.json())
    assert {r.route_id for r in parsed.routes} == {
        r.route_id for r in h.gateway.routes.snapshot.routes
    }


async def test_admin_changes_are_audited(h: Harness) -> None:
    with capture_logs() as logs:
        await h.admin("PUT", "/admin/routes/canary", json=NEW_ROUTE)
        await h.admin("DELETE", "/admin/routes/canary")
    events = [e for e in logs if e["event"] == "admin"]
    assert [e["action"] for e in events] == ["route.create", "route.delete"]
    assert all(e["actor"] == "alice" for e in events)


# --- tenants ----------------------------------------------------------------------------------


async def test_disable_tenant_takes_effect_on_next_request(h: Harness) -> None:
    token = h.token()
    assert (await h.get("/echo/x", token=token)).status_code == 200
    tenants = {t["tenant_id"]: t for t in (await h.admin("GET", "/admin/tenants")).json()}
    acme = {k: v for k, v in tenants["acme"].items() if k != "tenant_id"}
    resp = await h.admin("PUT", "/admin/tenants/acme", json={**acme, "enabled": False})
    assert resp.status_code == 200
    blocked = await h.get("/echo/x", token=token)
    assert blocked.status_code == 403
    assert blocked.json()["error"]["code"] == "tenant_disabled"


async def test_create_tenant_rejects_admin_scope(h: Harness) -> None:
    resp = await h.admin("PUT", "/admin/tenants/evil", json={"max_scopes": ["admin"]})
    assert resp.status_code == 422
    resp = await h.admin("PUT", "/admin/tenants/newco", json={"allowed_paths": ["/echo"]})
    assert resp.status_code == 201


# --- tokens -----------------------------------------------------------------------------------


async def test_issue_token_and_use_it(h: Harness) -> None:
    resp = await h.admin(
        "POST", "/admin/tokens", json={"tenant_id": "acme", "scopes": ["echo:read"]}
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["token_type"] == "Bearer"
    assert (await h.get("/echo/x", token=body["token"])).status_code == 200


@pytest.mark.parametrize(
    "body",
    [
        {"tenant_id": "acme", "scopes": ["orders:write"]},  # not in max_scopes
        {"tenant_id": "acme", "scopes": ["admin"]},
        {"tenant_id": "initech", "scopes": ["echo:read"]},  # disabled
        {"tenant_id": "ghost", "scopes": []},
        {"tenant_id": "acme", "ttl_seconds": 3600},
    ],
)
async def test_issue_token_cannot_over_grant(h: Harness, body: dict[str, Any]) -> None:
    resp = await h.admin("POST", "/admin/tokens", json=body)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "validation_error"


async def test_revoke_token(h: Harness) -> None:
    issued = (
        await h.admin("POST", "/admin/tokens", json={"tenant_id": "acme", "scopes": ["echo:read"]})
    ).json()
    resp = await h.admin("POST", "/admin/tokens/revoke", json={"jti": issued["jti"]})
    assert resp.status_code == 204
    blocked = await h.get("/echo/x", token=issued["token"])
    assert blocked.json()["error"]["code"] == "token_revoked"


async def test_wrong_method_on_admin_path(h: Harness) -> None:
    resp = await h.admin("PATCH", "/admin/routes")
    assert resp.status_code == 405
    assert resp.json()["error"]["code"] == "method_not_allowed"


async def test_openapi_docs_available(h: Harness) -> None:
    resp = await h.get("/admin/openapi.json", token=None)
    assert resp.status_code == 200
    assert "/admin/routes/{route_id}" in resp.json()["paths"]
