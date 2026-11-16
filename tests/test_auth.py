import time
import uuid
from typing import Any

import jwt
import pytest

from gateway.auth import AuthError, RevocationList, TokenService, bearer_token
from gateway.config import Settings
from tests.conftest import ADMIN_KEY, OLD_TENANT_KEY, TENANT_KEY, FakeClock


@pytest.fixture
def tokens(settings: Settings) -> TokenService:
    return TokenService(settings)


def claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    base: dict[str, Any] = {
        "iss": "mt-gateway",
        "aud": "mt-gateway",
        "sub": "acme",
        "scopes": ["orders:read"],
        "iat": now,
        "exp": now + 300,
        "jti": str(uuid.uuid4()),
    }
    base.update(overrides)
    return {k: v for k, v in base.items() if v is not None}


def sign(
    payload: dict[str, Any], key: str = TENANT_KEY, kid: str = "k1", alg: str = "HS256"
) -> str:
    return jwt.encode(payload, key, algorithm=alg, headers={"kid": kid})


def assert_auth_error(code: str, fn: Any, *args: Any) -> None:
    with pytest.raises(AuthError) as exc:
        fn(*args)
    assert exc.value.status == 401
    assert exc.value.code == code
    assert exc.value.headers["WWW-Authenticate"].startswith("Bearer")


def test_issue_then_verify_roundtrip(tokens: TokenService) -> None:
    issued = tokens.issue_tenant_token("acme", ["orders:read", "orders:read", "echo:read"], 600)
    header = jwt.get_unverified_header(issued.token)
    assert header == {"alg": "HS256", "typ": "JWT", "kid": "k1"}
    c = tokens.verify_tenant_token(issued.token)
    assert c.sub == "acme"
    assert c.scopes == {"orders:read", "echo:read"}
    assert c.jti == issued.jti
    assert c.exp - c.iat == 600


def test_old_key_still_verifies_during_rotation(tokens: TokenService) -> None:
    token = sign(claims(), key=OLD_TENANT_KEY, kid="old")
    assert tokens.verify_tenant_token(token).sub == "acme"


@pytest.mark.parametrize(
    ("header", "code"),
    [(None, "missing_token"), ("", "missing_token"), ("Basic abc", "invalid_token"),
     ("Bearer", "invalid_token"), ("Bearer   ", "invalid_token")],
)  # fmt: skip
def test_bearer_header_parsing(header: str | None, code: str) -> None:
    assert_auth_error(code, bearer_token, header)


def test_bearer_header_ok() -> None:
    assert bearer_token("bearer abc.def.ghi") == "abc.def.ghi"


def test_rejects_garbage(tokens: TokenService) -> None:
    assert_auth_error("invalid_token", tokens.verify_tenant_token, "not-a-jwt")


def test_rejects_alg_none(tokens: TokenService) -> None:
    token = jwt.encode(claims(), None, algorithm="none", headers={"kid": "k1"})
    assert_auth_error("invalid_token", tokens.verify_tenant_token, token)


@pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning")
def test_rejects_other_hmac_algorithm(tokens: TokenService) -> None:
    token = sign(claims(), alg="HS512")
    assert_auth_error("invalid_token", tokens.verify_tenant_token, token)


def test_rejects_wrong_signature(tokens: TokenService) -> None:
    token = sign(claims(), key="attacker-chosen-key-that-is-long-enough!!")
    assert_auth_error("invalid_token", tokens.verify_tenant_token, token)


@pytest.mark.parametrize("kid", ["unknown", "admin"])
def test_rejects_unknown_or_admin_kid(tokens: TokenService, kid: str) -> None:
    assert_auth_error("invalid_token", tokens.verify_tenant_token, sign(claims(), kid=kid))


def test_rejects_missing_kid(tokens: TokenService) -> None:
    token = jwt.encode(claims(), TENANT_KEY, algorithm="HS256")
    assert_auth_error("invalid_token", tokens.verify_tenant_token, token)


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "someone-else"},
        {"aud": "other-service"},
        {"sub": None},
        {"jti": None},
        {"exp": None},
        {"iat": None},
        {"scopes": None},
        {"scopes": "orders:read"},
        {"scopes": [1, 2]},
        {"sub": ""},
        {"iat": int(time.time()), "exp": int(time.time()) + 3600},  # longer than 15 minutes
        {"iat": int(time.time()) + 600, "exp": int(time.time()) + 900},  # issued in the future
        {"scopes": ["admin"]},  # tenant keys can never carry admin
    ],
)
def test_rejects_bad_claims(tokens: TokenService, overrides: dict[str, Any]) -> None:
    assert_auth_error("invalid_token", tokens.verify_tenant_token, sign(claims(**overrides)))


def test_expired_token(tokens: TokenService) -> None:
    now = int(time.time())
    token = sign(claims(iat=now - 400, exp=now - 31))
    assert_auth_error("token_expired", tokens.verify_tenant_token, token)


def test_leeway_accepts_slightly_expired(tokens: TokenService) -> None:
    now = int(time.time())
    token = sign(claims(iat=now - 400, exp=now - 10))
    assert tokens.verify_tenant_token(token).sub == "acme"


def test_revoked_token(tokens: TokenService) -> None:
    issued = tokens.issue_tenant_token("acme", ["orders:read"])
    tokens.revocations.revoke(issued.jti)
    assert_auth_error("token_revoked", tokens.verify_tenant_token, issued.token)


def test_revocation_list_forgets_entries_after_max_lifetime(clock: FakeClock) -> None:
    revs = RevocationList(clock)
    revs.revoke("j1")
    assert revs.is_revoked("j1")
    clock.advance(900 + 30 + 1)
    assert not revs.is_revoked("j1")
    assert len(revs) == 0


def test_admin_token_roundtrip(tokens: TokenService) -> None:
    issued = tokens.issue_admin_token("alice")
    c = tokens.verify_admin_token(issued.token)
    assert c.sub == "alice"
    assert c.scopes == {"admin"}


def test_admin_and_tenant_tokens_are_not_interchangeable(tokens: TokenService) -> None:
    admin = tokens.issue_admin_token("alice").token
    tenant = tokens.issue_tenant_token("acme", ["orders:read"]).token
    assert_auth_error("invalid_token", tokens.verify_tenant_token, admin)
    assert_auth_error("invalid_token", tokens.verify_admin_token, tenant)
    forged = sign(claims(scopes=["admin"]), key=TENANT_KEY, kid="admin")
    assert_auth_error("invalid_token", tokens.verify_admin_token, forged)
    assert tokens.verify_admin_token(sign(claims(scopes=["admin"]), ADMIN_KEY, "admin"))


def test_issue_validates_input(tokens: TokenService) -> None:
    with pytest.raises(ValueError, match="admin scope"):
        tokens.issue_tenant_token("acme", ["admin"])
    with pytest.raises(ValueError, match="ttl_seconds"):
        tokens.issue_tenant_token("acme", [], ttl_seconds=901)
    with pytest.raises(ValueError, match="ttl_seconds"):
        tokens.issue_tenant_token("acme", [], ttl_seconds=0)
