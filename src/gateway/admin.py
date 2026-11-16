"""Admin API under /admin. Every endpoint requires an admin token (signed with GATEWAY_ADMIN_KEY
and carrying the `admin` scope). A valid *tenant* token gets 403 admin_required; anything else
gets 401. Every change is written to the audit log with the operator's identity.

Changes live in memory. App Platform wipes the container filesystem on each deploy, so the
durable source of truth is the committed seed files; `GET /admin/routes/export` returns the
current table in that file's format so a runtime change can be committed.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Path, Request, Response

from gateway.audit import audit_admin
from gateway.auth import AuthError, Claims, bearer_token
from gateway.errors import GatewayError
from gateway.models import (
    RevokeRequest,
    Route,
    RouteSpec,
    Tenant,
    TenantSpec,
    TokenRequest,
    TokenResponse,
    dump,
)
from gateway.pipeline import Gateway
from gateway.routes import RouteConflict
from gateway.ssrf import UnsafeUpstream

router = APIRouter(prefix="/admin", tags=["admin"])

RouteIdPath = Annotated[str, Path(pattern=r"^[a-z0-9_-]{1,64}$")]
TenantIdPath = Annotated[str, Path(pattern=r"^[a-z0-9-]{1,64}$")]


def _gateway(request: Request) -> Gateway:
    gateway: Gateway = request.app.state.gateway
    return gateway


def _request_id(request: Request) -> str:
    return str(request.state.request_id)


async def require_admin(request: Request) -> Claims:
    gateway = _gateway(request)
    token = bearer_token(request.headers.get("authorization"))
    try:
        return gateway.tokens.verify_admin_token(token)
    except AuthError as admin_error:
        try:
            gateway.tokens.verify_tenant_token(token)
        except AuthError:
            raise admin_error from None
        raise GatewayError(403, "admin_required", "An admin token is required.") from None


Admin = Annotated[Claims, Depends(require_admin)]
GatewayDep = Annotated[Gateway, Depends(_gateway)]


def _invalid(message: str) -> GatewayError:
    return GatewayError(422, "validation_error", message)


# --- routes -----------------------------------------------------------------------------------


@router.get("/routes")
async def list_routes(admin: Admin, gateway: GatewayDep) -> list[dict[str, Any]]:
    return [dump(r) for r in gateway.routes.snapshot.routes]


@router.get("/routes/export")
async def export_routes(admin: Admin, gateway: GatewayDep) -> dict[str, Any]:
    """The current table in `config/routes.json` format, ready to commit."""
    routes = sorted(gateway.routes.snapshot.routes, key=lambda r: r.route_id)
    return {"routes": [dump(r) for r in routes]}


@router.put("/routes/{route_id}")
async def put_route(
    route_id: RouteIdPath,
    spec: RouteSpec,
    admin: Admin,
    gateway: GatewayDep,
    request: Request,
    response: Response,
) -> dict[str, Any]:
    route = Route(route_id=route_id, **spec.model_dump())
    try:
        await gateway.validate_route(route)
        created = await gateway.routes.put(route)
    except (UnsafeUpstream, RouteConflict) as err:
        raise _invalid(str(err)) from None
    response.status_code = 201 if created else 200
    audit_admin(
        _request_id(request),
        admin.sub,
        "route.create" if created else "route.replace",
        route_id,
        route=dump(route),
    )
    return dump(route)


@router.delete("/routes/{route_id}", status_code=204)
async def delete_route(
    route_id: RouteIdPath, admin: Admin, gateway: GatewayDep, request: Request
) -> None:
    if not await gateway.routes.delete(route_id):
        raise GatewayError(404, "route_not_found", f"No route with id {route_id!r}.")
    audit_admin(_request_id(request), admin.sub, "route.delete", route_id)


# --- tenants ----------------------------------------------------------------------------------


@router.get("/tenants")
async def list_tenants(admin: Admin, gateway: GatewayDep) -> list[dict[str, Any]]:
    return [dump(t) for t in gateway.tenants.all()]


@router.put("/tenants/{tenant_id}")
async def put_tenant(
    tenant_id: TenantIdPath,
    spec: TenantSpec,
    admin: Admin,
    gateway: GatewayDep,
    request: Request,
    response: Response,
) -> dict[str, Any]:
    tenant = Tenant(tenant_id=tenant_id, **spec.model_dump())
    created = await gateway.tenants.put(tenant)
    response.status_code = 201 if created else 200
    action = "tenant.create" if created else "tenant.replace"
    audit_admin(_request_id(request), admin.sub, action, tenant_id, tenant=dump(tenant))
    return dump(tenant)


# --- tokens -----------------------------------------------------------------------------------


@router.post("/tokens", status_code=201)
async def issue_token(
    body: TokenRequest, admin: Admin, gateway: GatewayDep, request: Request
) -> TokenResponse:
    tenant = gateway.tenants.get(body.tenant_id)
    if tenant is None or not tenant.enabled:
        raise _invalid(f"tenant {body.tenant_id!r} is unknown or disabled")
    over_grant = sorted(set(body.scopes) - set(tenant.max_scopes))
    if over_grant:
        raise _invalid(f"scopes not allowed for this tenant: {', '.join(over_grant)}")
    issued = gateway.tokens.issue_tenant_token(body.tenant_id, list(body.scopes), body.ttl_seconds)
    audit_admin(
        _request_id(request),
        admin.sub,
        "token.issue",
        body.tenant_id,
        jti=issued.jti,
        scopes=sorted(body.scopes),
        expires_at=issued.expires_at,
    )
    return TokenResponse(token=issued.token, jti=issued.jti, expires_at=issued.expires_at)


@router.post("/tokens/revoke", status_code=204)
async def revoke_token(
    body: RevokeRequest, admin: Admin, gateway: GatewayDep, request: Request
) -> None:
    gateway.tokens.revocations.revoke(body.jti)
    audit_admin(_request_id(request), admin.sub, "token.revoke", body.jti)


# --- upstream health --------------------------------------------------------------------------


@router.get("/upstreams")
async def upstream_health(admin: Admin, gateway: GatewayDep) -> dict[str, Any]:
    """Circuit-breaker state for every upstream that has received traffic."""
    return gateway.breakers.snapshot()
