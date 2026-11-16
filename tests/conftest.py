"""Shared test fixtures: deterministic settings and a controllable clock."""

from __future__ import annotations

import time

import pytest
from pydantic import SecretStr

from gateway.config import Settings

TENANT_KEY = "tenant-signing-key-for-tests-0123456789"
OLD_TENANT_KEY = "old-tenant-signing-key-for-tests-012345"
ADMIN_KEY = "admin-signing-key-for-tests-0123456789ab"


class FakeClock:
    """One clock for wall time and monotonic time, advanced by hand."""

    def __init__(self, start: float | None = None) -> None:
        self.now = time.time() if start is None else start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "jwt_keys": {"old": SecretStr(OLD_TENANT_KEY), "k1": SecretStr(TENANT_KEY)},
        "admin_key": SecretStr(ADMIN_KEY),
        "upstream_allowed_private_hosts": frozenset({"internal.test"}),
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)  # type: ignore[call-arg, arg-type]


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()
