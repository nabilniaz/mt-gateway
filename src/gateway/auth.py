"""Token issuance and verification.

Tenant tokens and admin tokens are both HS256 JWTs, but they are signed with different keys:
tenant tokens with a key from GATEWAY_JWT_KEYS (chosen by the `kid` header), admin tokens with
GATEWAY_ADMIN_KEY. The algorithm list is pinned to HS256, so `alg: none` and RS256/HS256
key-confusion tokens are rejected before any key is used.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import jwt

from gateway.config import (
    ADMIN_KID,
    AUDIENCE,
    CLOCK_LEEWAY_SECONDS,
    MAX_TOKEN_TTL_SECONDS,
    Settings,
)
from gateway.errors import GatewayError

ALGORITHM = "HS256"
ADMIN_SCOPE = "admin"
REQUIRED_CLAIMS = ["iss", "aud", "sub", "iat", "exp", "jti"]

Clock = Callable[[], float]


class AuthError(GatewayError):
    """401 with the RFC 6750 `WWW-Authenticate` header."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(401, code, message, {"WWW-Authenticate": 'Bearer error="invalid_token"'})


def missing_token() -> AuthError:
    return AuthError("missing_token", "Authorization: Bearer <token> header is required.")


def invalid_token() -> AuthError:
    # Deliberately generic: the caller learns that the token failed, not which check failed.
    return AuthError("invalid_token", "Token is invalid.")


@dataclass(frozen=True)
class Claims:
    sub: str
    scopes: frozenset[str]
    jti: str
    iat: int
    exp: int


@dataclass(frozen=True)
class IssuedToken:
    token: str
    jti: str
    expires_at: int


class RevocationList:
    """In-memory `jti` denylist. Entries expire once every token they could match has expired."""

    def __init__(self, clock: Clock = time.time) -> None:
        self._clock = clock
        self._until: dict[str, float] = {}

    def revoke(self, jti: str) -> None:
        self._until[jti] = self._clock() + MAX_TOKEN_TTL_SECONDS + CLOCK_LEEWAY_SECONDS

    def is_revoked(self, jti: str) -> bool:
        now = self._clock()
        expired = [k for k, until in self._until.items() if until <= now]
        for k in expired:
            del self._until[k]
        return jti in self._until

    def __len__(self) -> int:
        return len(self._until)


def bearer_token(authorization: str | None) -> str:
    """Extract the token from an `Authorization: Bearer <token>` header value."""
    if not authorization:
        raise missing_token()
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise invalid_token()
    return token.strip()


class TokenService:
    def __init__(
        self,
        settings: Settings,
        clock: Clock = time.time,
        revocations: RevocationList | None = None,
    ) -> None:
        self._settings = settings
        self._clock = clock
        self.revocations = revocations or RevocationList(clock)

    # --- issuing ------------------------------------------------------------------------------

    def issue_tenant_token(
        self, tenant_id: str, scopes: list[str], ttl_seconds: int = MAX_TOKEN_TTL_SECONDS
    ) -> IssuedToken:
        if ADMIN_SCOPE in scopes:
            raise ValueError("the admin scope can never be issued to a tenant")
        kid = self._settings.signing_kid
        key = self._settings.jwt_keys[kid].get_secret_value()
        return self._issue(tenant_id, scopes, ttl_seconds, key, kid)

    def issue_admin_token(
        self, operator: str, ttl_seconds: int = MAX_TOKEN_TTL_SECONDS
    ) -> IssuedToken:
        key = self._settings.admin_key.get_secret_value()
        return self._issue(operator, [ADMIN_SCOPE], ttl_seconds, key, ADMIN_KID)

    def _issue(
        self, sub: str, scopes: list[str], ttl_seconds: int, key: str, kid: str
    ) -> IssuedToken:
        if not 1 <= ttl_seconds <= MAX_TOKEN_TTL_SECONDS:
            raise ValueError(f"ttl_seconds must be between 1 and {MAX_TOKEN_TTL_SECONDS}")
        now = int(self._clock())
        jti = str(uuid.uuid4())
        payload = {
            "iss": self._settings.issuer,
            "aud": AUDIENCE,
            "sub": sub,
            "scopes": sorted(set(scopes)),
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": jti,
        }
        token = jwt.encode(payload, key, algorithm=ALGORITHM, headers={"kid": kid})
        return IssuedToken(token=token, jti=jti, expires_at=now + ttl_seconds)

    # --- verifying ----------------------------------------------------------------------------

    def verify_tenant_token(self, token: str) -> Claims:
        kid = _unverified_kid(token)
        secret = self._settings.jwt_keys.get(kid) if kid is not None else None
        if secret is None:
            raise invalid_token()
        claims = self._decode(token, secret.get_secret_value())
        if ADMIN_SCOPE in claims.scopes:
            raise invalid_token()
        return claims

    def verify_admin_token(self, token: str) -> Claims:
        if _unverified_kid(token) != ADMIN_KID:
            raise invalid_token()
        return self._decode(token, self._settings.admin_key.get_secret_value())

    def _decode(self, token: str, key: str) -> Claims:
        try:
            payload: dict[str, Any] = jwt.decode(
                token,
                key,
                algorithms=[ALGORITHM],
                audience=AUDIENCE,
                issuer=self._settings.issuer,
                leeway=CLOCK_LEEWAY_SECONDS,
                options={"require": REQUIRED_CLAIMS},
            )
        except jwt.ExpiredSignatureError:
            raise AuthError("token_expired", "Token has expired.") from None
        except jwt.InvalidTokenError:
            raise invalid_token() from None

        sub, jti, scopes = payload["sub"], payload["jti"], payload.get("scopes")
        iat, exp = payload["iat"], payload["exp"]
        if not (isinstance(sub, str) and sub and isinstance(jti, str) and jti):
            raise invalid_token()
        if not (isinstance(scopes, list) and all(isinstance(s, str) for s in scopes)):
            raise invalid_token()
        if not (isinstance(iat, int) and isinstance(exp, int)):
            raise invalid_token()
        # Defense in depth: even a correctly signed token may not live longer than the maximum.
        if exp - iat > MAX_TOKEN_TTL_SECONDS:
            raise invalid_token()
        if self.revocations.is_revoked(jti):
            raise AuthError("token_revoked", "Token has been revoked.")
        return Claims(sub=sub, scopes=frozenset(scopes), jti=jti, iat=iat, exp=exp)


def _unverified_kid(token: str) -> str | None:
    """Read `kid` from the header to pick the key. The header is not trusted for anything else."""
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError:
        raise invalid_token() from None
    kid = header.get("kid")
    return kid if isinstance(kid, str) else None
