"""Runtime settings, read from environment variables (and a local `.env` file in development).

On DigitalOcean App Platform every value here is an app-spec environment variable; the two
signing keys are encrypted SECRET variables. Nothing is read from files inside the image except
the committed seed files for routes and tenants.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated, Any

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

MIN_KEY_BYTES = 32
KID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
ADMIN_KID = "admin"

# Fixed security parameters. They are constants rather than settings on purpose: loosening them
# should take a code change and a review, not an environment variable.
AUDIENCE = "mt-gateway"
MAX_TOKEN_TTL_SECONDS = 900
CLOCK_LEEWAY_SECONDS = 30


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
        frozen=True,
    )

    # --- Signing keys -------------------------------------------------------------------------
    jwt_keys: dict[str, SecretStr] = Field(validation_alias="GATEWAY_JWT_KEYS")
    """Tenant-token signing keys as JSON, `{"<kid>": "<secret>"}`. Several keys allow rotation."""

    jwt_active_kid: str | None = Field(default=None, validation_alias="GATEWAY_JWT_ACTIVE_KID")
    """Key used to sign new tokens. Defaults to the last key in GATEWAY_JWT_KEYS."""

    admin_key: SecretStr = Field(validation_alias="GATEWAY_ADMIN_KEY")
    """Separate key for admin tokens, so a leaked tenant key cannot mint admin tokens."""

    issuer: str = Field(default="mt-gateway", validation_alias="GATEWAY_ISSUER")

    # --- Server -------------------------------------------------------------------------------
    host: str = "0.0.0.0"  # noqa: S104  (the container must listen on all interfaces)
    port: int = Field(default=8080, ge=1, le=65535)
    log_level: str = "INFO"

    # --- Seed files (read once at startup; the container filesystem is not persistent) --------
    routes_file: Path = Path("config/routes.json")
    tenants_file: Path = Path("config/tenants.json")

    # --- Request handling ---------------------------------------------------------------------
    max_body_bytes: int = Field(default=1_048_576, ge=0)
    trust_proxy_headers: bool = False
    """True only behind a known proxy (App Platform) that sets the client-IP header."""

    upstream_allowed_private_hosts: Annotated[frozenset[str], NoDecode] = frozenset()
    """Comma-separated hosts allowed to resolve to private IPs, e.g. `demo-upstream`."""

    # --- Upstream client ----------------------------------------------------------------------
    connect_timeout_seconds: float = Field(default=3.0, gt=0, le=30)
    write_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    pool_timeout_seconds: float = Field(default=2.0, gt=0, le=30)
    max_connections: int = Field(default=100, ge=1, le=10_000)

    # --- Circuit-breaker defaults (a route can override them) ---------------------------------
    breaker_failure_threshold: int = Field(default=5, ge=1, le=1000)
    breaker_cooldown_seconds: float = Field(default=30.0, gt=0, le=3600)
    breaker_half_open_max_probes: int = Field(default=1, ge=1, le=100)

    @field_validator("upstream_allowed_private_hosts", mode="before")
    @classmethod
    def _split_hosts(cls, value: Any) -> Any:
        if isinstance(value, str):
            return frozenset(h.strip().lower() for h in value.split(",") if h.strip())
        return value

    @field_validator("jwt_keys")
    @classmethod
    def _check_jwt_keys(cls, keys: dict[str, SecretStr]) -> dict[str, SecretStr]:
        if not keys:
            raise ValueError("GATEWAY_JWT_KEYS must contain at least one key")
        for kid, secret in keys.items():
            if not KID_PATTERN.fullmatch(kid):
                raise ValueError(f"invalid kid {kid!r}: use 1-64 of [A-Za-z0-9._-]")
            if kid == ADMIN_KID:
                raise ValueError(f"kid {ADMIN_KID!r} is reserved for admin tokens")
            if len(secret.get_secret_value().encode()) < MIN_KEY_BYTES:
                raise ValueError(f"key {kid!r} must be at least {MIN_KEY_BYTES} bytes")
        return keys

    @field_validator("admin_key")
    @classmethod
    def _check_admin_key(cls, key: SecretStr) -> SecretStr:
        if len(key.get_secret_value().encode()) < MIN_KEY_BYTES:
            raise ValueError(f"GATEWAY_ADMIN_KEY must be at least {MIN_KEY_BYTES} bytes")
        return key

    @model_validator(mode="after")
    def _check_consistency(self) -> Settings:
        if self.jwt_active_kid is not None and self.jwt_active_kid not in self.jwt_keys:
            raise ValueError("GATEWAY_JWT_ACTIVE_KID must name a key in GATEWAY_JWT_KEYS")
        admin = self.admin_key.get_secret_value()
        if any(s.get_secret_value() == admin for s in self.jwt_keys.values()):
            raise ValueError("GATEWAY_ADMIN_KEY must differ from every tenant signing key")
        return self

    @property
    def signing_kid(self) -> str:
        """The kid used for new tenant tokens: explicit, or the most recently added key."""
        return self.jwt_active_kid or list(self.jwt_keys)[-1]
