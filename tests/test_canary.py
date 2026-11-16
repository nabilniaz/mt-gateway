import uuid
from typing import Any

import pytest

from gateway.canary import bucket, choose_upstream
from gateway.models import Route


def route(**canary: Any) -> Route:
    return Route(
        route_id="r",
        prefix="/r",
        upstream="https://v1",
        canary={"upstream": "https://v2", **canary} if canary else None,  # type: ignore[arg-type]
    )


def test_bucket_is_deterministic_and_in_range() -> None:
    assert bucket("acme", "req-1") == bucket("acme", "req-1")
    assert all(0 <= bucket("acme", str(i)) < 100 for i in range(1000))


def test_no_canary_means_primary() -> None:
    assert choose_upstream(route(), "acme", "x") == ("https://v1", False)


@pytest.mark.parametrize(("percent", "expected"), [(0, False), (100, True)])
def test_extremes(percent: int, expected: bool) -> None:
    r = route(percent=percent)
    assert all(choose_upstream(r, "acme", str(i))[1] is expected for i in range(200))


def test_split_is_close_to_percent() -> None:
    r = route(percent=20)
    hits = sum(choose_upstream(r, "acme", str(uuid.uuid4()))[1] for _ in range(10_000))
    assert 1800 < hits < 2200  # 20% +/- 2 points (about 5 standard deviations)


def test_tenant_restriction() -> None:
    r = route(percent=100, tenants=["acme"])
    assert choose_upstream(r, "acme", "x") == ("https://v2", True)
    assert choose_upstream(r, "globex", "x") == ("https://v1", False)
