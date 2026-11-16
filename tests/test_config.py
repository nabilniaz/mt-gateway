import json

import pytest
from pydantic import SecretStr, ValidationError

from gateway.config import Settings

GOOD = "x" * 32
ADMIN = "a" * 32


def make(**overrides: object) -> Settings:
    values: dict[str, object] = {"jwt_keys": {"k1": SecretStr(GOOD)}, "admin_key": ADMIN}
    values.update(overrides)
    return Settings(_env_file=None, **values)  # type: ignore[call-arg, arg-type]


def test_defaults() -> None:
    s = make()
    assert s.port == 8080
    assert s.max_body_bytes == 1_048_576
    assert s.signing_kid == "k1"
    assert s.trust_proxy_headers is False


def test_reads_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GATEWAY_JWT_KEYS", json.dumps({"old": "o" * 32, "new": "n" * 32}))
    monkeypatch.setenv("GATEWAY_ADMIN_KEY", ADMIN)
    monkeypatch.setenv("UPSTREAM_ALLOWED_PRIVATE_HOSTS", "demo-upstream, LocalHost ,")
    monkeypatch.setenv("PORT", "9090")
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.signing_kid == "new"  # last key wins: append a key to rotate
    assert s.upstream_allowed_private_hosts == frozenset({"demo-upstream", "localhost"})
    assert s.port == 9090


def test_active_kid_must_exist() -> None:
    with pytest.raises(ValidationError, match="ACTIVE_KID"):
        make(jwt_active_kid="missing")


@pytest.mark.parametrize(
    ("keys", "match"),
    [
        ({}, "at least one key"),
        ({"k1": "short"}, "at least 32 bytes"),
        ({"bad kid!": GOOD}, "invalid kid"),
        ({"admin": GOOD}, "reserved"),
    ],
)
def test_rejects_bad_tenant_keys(keys: dict[str, str], match: str) -> None:
    with pytest.raises(ValidationError, match=match):
        make(jwt_keys=keys)


def test_rejects_short_admin_key() -> None:
    with pytest.raises(ValidationError, match="GATEWAY_ADMIN_KEY"):
        make(admin_key="short")


def test_admin_key_must_differ_from_tenant_keys() -> None:
    with pytest.raises(ValidationError, match="must differ"):
        make(admin_key=GOOD)


def test_secrets_are_masked_in_repr() -> None:
    assert GOOD not in repr(make())
