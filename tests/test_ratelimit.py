from gateway.ratelimit import SlidingWindowLimiter
from tests.conftest import FakeClock

MINUTE_START = 1_800_000_000.0 - (1_800_000_000 % 60)


def limiter_at(offset: float) -> tuple[SlidingWindowLimiter, FakeClock]:
    clock = FakeClock(MINUTE_START + offset)
    return SlidingWindowLimiter(clock), clock


def burn(limiter: SlidingWindowLimiter, n: int, limit: int, key: str = "acme") -> int:
    return sum(limiter.hit(key, limit).allowed for _ in range(n))


def test_allows_exactly_limit_in_a_fresh_window() -> None:
    limiter, _ = limiter_at(0)
    assert burn(limiter, 10, limit=5) == 5
    denied = limiter.hit("acme", 5)
    assert not denied.allowed
    assert denied.remaining == 0
    assert denied.retry_after >= 1


def test_remaining_counts_down() -> None:
    limiter, _ = limiter_at(0)
    assert [limiter.hit("acme", 3).remaining for _ in range(3)] == [2, 1, 0]


def test_tenants_are_independent() -> None:
    limiter, _ = limiter_at(0)
    assert burn(limiter, 5, limit=5, key="acme") == 5
    assert limiter.hit("globex", 5).allowed


def test_guide_example() -> None:
    """Limit 100, previous minute 80, current 30, 15 s in: estimate 80*0.75+30 = 90 -> allowed."""
    limiter, clock = limiter_at(0)
    burn(limiter, 80, limit=1000)
    clock.advance(60 + 15)
    burn(limiter, 30, limit=1000)
    decision = limiter.hit("acme", 100)
    assert decision.allowed
    assert decision.remaining == 9  # 100 - 90 - 1


def test_no_double_burst_at_minute_boundary() -> None:
    """A fixed window would allow 2x the limit across :59 -> :00. Sliding window does not."""
    limiter, clock = limiter_at(59)
    assert burn(limiter, 100, limit=100) == 100
    clock.advance(2)  # now 1 s into the next minute
    assert burn(limiter, 100, limit=100) <= 2


def test_quota_fully_recovers_after_two_idle_minutes() -> None:
    limiter, clock = limiter_at(30)
    burn(limiter, 100, limit=100)
    clock.advance(150)
    assert burn(limiter, 100, limit=100) == 100


def test_retry_after_when_current_window_is_full() -> None:
    limiter, clock = limiter_at(45)
    burn(limiter, 10, limit=10)
    d = limiter.hit("acme", 10)
    # The next minute starts in 15 s, but at exactly :00 the estimate is still 10 (not < 10).
    assert d.retry_after == 16
    clock.advance(d.retry_after)
    assert limiter.hit("acme", 10).allowed


def test_retry_after_when_previous_window_carries_weight() -> None:
    limiter, clock = limiter_at(0)
    burn(limiter, 60, limit=60)
    clock.advance(60)  # previous=60, current=0, elapsed=0 -> estimate 60, full
    d = limiter.hit("acme", 60)
    assert not d.allowed
    assert d.retry_after == 1
    clock.advance(d.retry_after)
    assert limiter.hit("acme", 60).allowed


def test_retry_after_is_honest() -> None:
    """Waiting exactly retry_after seconds is always enough for one request."""
    for offset in (0, 10, 30, 59.5):
        for burst in (20, 50, 100):
            limiter, clock = limiter_at(offset)
            burn(limiter, burst, limit=100)
            clock.advance(60)
            burn(limiter, 200, limit=100)
            d = limiter.hit("acme", 100)
            assert not d.allowed
            clock.advance(d.retry_after)
            assert limiter.hit("acme", 100).allowed, (offset, burst, d.retry_after)


def test_zero_limit_blocks_everything() -> None:
    limiter, _ = limiter_at(0)
    d = limiter.hit("acme", 0)
    assert not d.allowed
    assert d.retry_after == 60
