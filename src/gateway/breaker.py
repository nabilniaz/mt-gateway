"""Per-upstream circuit breaker: closed -> open -> half-open -> closed (or back to open).

closed     Normal. Consecutive failures are counted; a success resets the count.
open       After `failure_threshold` consecutive failures. Calls are refused (503) without
           touching the upstream until `cooldown_seconds` have passed.
half-open  After the cooldown. Up to `half_open_max_probes` calls are let through as probes;
           a probe success closes the breaker, a probe failure re-opens it (cooldown restarts).

Failures are connect errors, timeouts and upstream 5xx. A 4xx is the caller's fault, so it
counts as a success. Time comes from a monotonic clock, so wall-clock jumps cannot affect it.
"""

from __future__ import annotations

import enum
import time
from collections.abc import Callable
from dataclasses import dataclass

from gateway.models import BreakerConfig


class State(enum.StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreaker:
    config: BreakerConfig
    clock: Callable[[], float] = time.monotonic
    state: State = State.CLOSED
    failures: int = 0
    opened_at: float = 0.0
    probes_in_flight: int = 0

    def allow(self) -> bool:
        """Ask before calling the upstream. Every True must be followed by exactly one of
        record_success / record_failure / release."""
        if self.state is State.OPEN:
            if self.clock() - self.opened_at < self.config.cooldown_seconds:
                return False
            self.state = State.HALF_OPEN
            self.probes_in_flight = 0
        if self.state is State.HALF_OPEN:
            if self.probes_in_flight >= self.config.half_open_max_probes:
                return False
            self.probes_in_flight += 1
        return True

    def record_success(self) -> None:
        if self.state is State.OPEN:
            return  # a slow call from before the breaker opened; ignore it
        self.state = State.CLOSED
        self.failures = 0
        self.probes_in_flight = 0

    def record_failure(self) -> None:
        if self.state is State.OPEN:
            return
        if self.state is State.HALF_OPEN:
            self._open()
            return
        self.failures += 1
        if self.failures >= self.config.failure_threshold:
            self._open()

    def release(self) -> None:
        """The call ended without a verdict (e.g. the client disconnected). Free the probe slot
        so the breaker cannot get stuck half-open."""
        if self.state is State.HALF_OPEN and self.probes_in_flight > 0:
            self.probes_in_flight -= 1

    def _open(self) -> None:
        self.state = State.OPEN
        self.opened_at = self.clock()
        self.probes_in_flight = 0

    def snapshot(self) -> dict[str, object]:
        return {
            "state": self.state.value,
            "consecutive_failures": self.failures,
            "failure_threshold": self.config.failure_threshold,
            "cooldown_seconds": self.config.cooldown_seconds,
        }


class BreakerRegistry:
    """One breaker per upstream URL, so routes sharing an upstream share its health."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._breakers: dict[str, CircuitBreaker] = {}

    def get(self, upstream: str, config: BreakerConfig) -> CircuitBreaker:
        breaker = self._breakers.get(upstream)
        if breaker is None:
            breaker = self._breakers[upstream] = CircuitBreaker(config, self._clock)
        else:
            breaker.config = config  # the latest route config wins
        return breaker

    def snapshot(self) -> dict[str, dict[str, object]]:
        return {url: b.snapshot() for url, b in sorted(self._breakers.items())}
