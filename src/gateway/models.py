"""Validated data shapes: tenants, routes, and admin API bodies.

Models are frozen (immutable). The route table and tenant store rely on that: a snapshot handed
to a request can never change underneath it.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from gateway.auth import ADMIN_SCOPE
from gateway.config import MAX_TOKEN_TTL_SECONDS
from gateway.paths import normalize_prefix

TenantId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9-]{1,64}$")]
RouteId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9_-]{1,64}$")]
Scope = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9:._-]{1,64}$")]
UpstreamUrl = Annotated[str, StringConstraints(min_length=1, max_length=2048)]

# Paths the gateway serves itself. No route may claim them.
RESERVED_PREFIXES = ("/admin", "/healthz")


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


def _check_prefixes(prefixes: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(normalize_prefix(p) for p in prefixes)


# --- Tenants ----------------------------------------------------------------------------------


class TenantSpec(_Frozen):
    enabled: bool = True
    allowed_paths: tuple[str, ...] = Field(default=(), max_length=100)
    rate_limit_per_minute: int = Field(default=60, ge=0, le=1_000_000)
    max_scopes: tuple[Scope, ...] = Field(default=(), max_length=100)

    @field_validator("allowed_paths")
    @classmethod
    def _paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _check_prefixes(value)

    @field_validator("max_scopes")
    @classmethod
    def _scopes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if ADMIN_SCOPE in value:
            raise ValueError("the admin scope can never be granted to a tenant")
        return value


class Tenant(TenantSpec):
    tenant_id: TenantId


# --- Routes -----------------------------------------------------------------------------------


class BreakerConfig(_Frozen):
    failure_threshold: int = Field(default=5, ge=1, le=1000)
    cooldown_seconds: float = Field(default=30.0, gt=0, le=3600)
    half_open_max_probes: int = Field(default=1, ge=1, le=100)


class CanaryConfig(_Frozen):
    upstream: UpstreamUrl
    percent: int = Field(ge=0, le=100)
    tenants: tuple[TenantId, ...] | None = None
    """If set, only these tenants are split; everyone else always gets the primary."""

    def applies_to(self, tenant_id: str) -> bool:
        return self.tenants is None or tenant_id in self.tenants


class RouteSpec(_Frozen):
    prefix: str
    upstream: UpstreamUrl
    strip_prefix: bool = True
    required_scopes: tuple[Scope, ...] = ()
    timeout_seconds: float = Field(default=10.0, gt=0, le=30)
    circuit_breaker: BreakerConfig | None = None
    canary: CanaryConfig | None = None

    @field_validator("prefix")
    @classmethod
    def _prefix(cls, value: str) -> str:
        prefix = normalize_prefix(value)
        for reserved in RESERVED_PREFIXES:
            if prefix == "/" or prefix == reserved or prefix.startswith(reserved + "/"):
                raise ValueError(f"prefix {prefix!r} overlaps reserved gateway path {reserved}")
        return prefix

    def upstreams(self) -> list[str]:
        return [self.upstream] + ([self.canary.upstream] if self.canary else [])


class Route(RouteSpec):
    route_id: RouteId


# --- Seed files -------------------------------------------------------------------------------


class RoutesFile(_Frozen):
    routes: tuple[Route, ...]


class TenantsFile(_Frozen):
    tenants: tuple[Tenant, ...]


# --- Admin API bodies -------------------------------------------------------------------------


class TokenRequest(_Frozen):
    tenant_id: TenantId
    scopes: tuple[Scope, ...] = Field(default=(), max_length=100)
    ttl_seconds: int = Field(default=MAX_TOKEN_TTL_SECONDS, ge=1, le=MAX_TOKEN_TTL_SECONDS)


class TokenResponse(_Frozen):
    token: str
    token_type: str = "Bearer"  # noqa: S105  (a token type label, not a secret)
    jti: str
    expires_at: int


class RevokeRequest(_Frozen):
    jti: Annotated[str, StringConstraints(min_length=1, max_length=128)]


def dump(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="json")
