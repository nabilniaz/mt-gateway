"""Per-tenant per-minute quota using a sliding-window counter.

Two counters per tenant: requests in the current clock minute and in the previous one. The
number of requests in the last 60 seconds is estimated as

    estimate = previous * (1 - elapsed / 60) + current

which assumes the previous minute's requests were spread evenly. Unlike a fixed window it does
not reset to zero at :00, so a tenant cannot fire 2x its quota across a minute boundary.

`hit()` checks and increments with no `await` in between. Under asyncio's single thread that
makes it atomic: two concurrent requests cannot both take the last slot.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from dataclasses import dataclass

WINDOW_SECONDS = 60


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    limit: int
    remaining: int
    retry_after: int
    """Whole seconds until a request would be allowed again (0 when allowed)."""


@dataclass
class _Window:
    start: int
    previous: int = 0
    current: int = 0


class SlidingWindowLimiter:
    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._windows: dict[str, _Window] = {}

    def hit(self, key: str, limit: int) -> RateDecision:
        now = self._clock()
        window_start = int(now // WINDOW_SECONDS) * WINDOW_SECONDS
        w = self._windows.get(key)
        if w is None:
            w = self._windows[key] = _Window(start=window_start)
        elif window_start != w.start:
            # Roll forward. If more than one full window passed, the previous one was empty.
            w.previous = w.current if window_start - w.start == WINDOW_SECONDS else 0
            w.current = 0
            w.start = window_start

        if limit <= 0:
            return RateDecision(False, limit, 0, WINDOW_SECONDS)

        elapsed = now - window_start
        estimate = w.previous * (1 - elapsed / WINDOW_SECONDS) + w.current
        if estimate < limit:
            w.current += 1
            remaining = max(0, math.floor(limit - estimate - 1))
            return RateDecision(True, limit, remaining, 0)
        return RateDecision(False, limit, 0, self._retry_after(w, limit, elapsed))

    @staticmethod
    def _retry_after(w: _Window, limit: int, elapsed: float) -> int:
        """Seconds until the estimate drops below the limit, assuming no further requests."""
        if w.current < limit:
            # Wait for enough of the previous window's weight to slide out:
            # previous * (1 - t/60) + current < limit  =>  t > 60 * (1 - (limit - current) / prev)
            target = WINDOW_SECONDS * (1 - (limit - w.current) / w.previous)
            wait = target - elapsed
        else:
            # The current window alone is full. In the next window it becomes `previous`:
            # current * (1 - t/60) < limit  =>  t > 60 * (1 - limit / current)
            wait = (WINDOW_SECONDS - elapsed) + WINDOW_SECONDS * (1 - limit / w.current)
        # The check is `estimate < limit`, so the caller must arrive strictly after `wait`.
        # The epsilon absorbs float noise (1.9999999 must round like 2.0).
        return max(1, math.floor(wait + 1e-9) + 1)
