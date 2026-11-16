from gateway.breaker import BreakerRegistry, CircuitBreaker, State
from gateway.models import BreakerConfig
from tests.conftest import FakeClock


def breaker(
    clock: FakeClock, threshold: int = 3, cooldown: float = 10, probes: int = 1
) -> CircuitBreaker:
    config = BreakerConfig(
        failure_threshold=threshold, cooldown_seconds=cooldown, half_open_max_probes=probes
    )
    return CircuitBreaker(config, clock)


def fail(b: CircuitBreaker, n: int) -> None:
    for _ in range(n):
        assert b.allow()
        b.record_failure()


def test_opens_after_threshold_consecutive_failures(clock: FakeClock) -> None:
    b = breaker(clock)
    fail(b, 2)
    assert b.state is State.CLOSED
    fail(b, 1)
    assert b.state is State.OPEN
    assert not b.allow()


def test_success_resets_the_count(clock: FakeClock) -> None:
    b = breaker(clock)
    fail(b, 2)
    assert b.allow()
    b.record_success()
    fail(b, 2)
    assert b.state is State.CLOSED


def test_half_open_probe_success_closes(clock: FakeClock) -> None:
    b = breaker(clock)
    fail(b, 3)
    clock.advance(9.9)
    assert not b.allow()
    clock.advance(0.1)
    assert b.allow()  # the probe
    assert b.state is State.HALF_OPEN
    assert not b.allow()  # only one probe at a time
    b.record_success()
    assert b.state is State.CLOSED
    assert b.allow()


def test_half_open_probe_failure_reopens_with_fresh_cooldown(clock: FakeClock) -> None:
    b = breaker(clock)
    fail(b, 3)
    clock.advance(10)
    assert b.allow()
    b.record_failure()
    assert b.state is State.OPEN
    clock.advance(9)
    assert not b.allow()
    clock.advance(1)
    assert b.allow()


def test_multiple_probes(clock: FakeClock) -> None:
    b = breaker(clock, probes=2)
    fail(b, 3)
    clock.advance(10)
    assert b.allow()
    assert b.allow()
    assert not b.allow()


def test_release_frees_a_probe_slot(clock: FakeClock) -> None:
    b = breaker(clock)
    fail(b, 3)
    clock.advance(10)
    assert b.allow()
    b.release()  # client went away mid-probe
    assert b.allow()  # not stuck half-open


def test_late_results_while_open_are_ignored(clock: FakeClock) -> None:
    b = breaker(clock)
    fail(b, 3)
    b.record_success()
    assert b.state is State.OPEN
    b.record_failure()
    clock.advance(10)
    assert b.allow()


def test_registry_shares_breaker_per_upstream_and_updates_config(clock: FakeClock) -> None:
    reg = BreakerRegistry(clock)
    a = reg.get("http://x", BreakerConfig(failure_threshold=5))
    b = reg.get("http://x", BreakerConfig(failure_threshold=2))
    assert a is b
    assert a.config.failure_threshold == 2
    assert reg.get("http://y", BreakerConfig()) is not a
    assert reg.snapshot()["http://x"]["state"] == "closed"
