"""Rate limiting for ``rate_limit`` policy rules."""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Callable, Dict, Hashable, Protocol, Tuple


class RateLimiter(Protocol):
    def acquire(self, key: Hashable, max_calls: int, window: float) -> Tuple[bool, int]:
        """Record a call if under the limit.

        Returns ``(allowed, count)`` where *count* is the number of calls in
        the window *before* this one.  Denied calls are not recorded.
        """
        ...


class InMemoryRateLimiter:
    """Thread-safe sliding-window limiter.

    State is per process: limits reset on restart and aren't shared between
    server workers.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._hits: Dict[Hashable, deque] = {}

    def acquire(self, key: Hashable, max_calls: int, window: float) -> Tuple[bool, int]:
        now = self._clock()
        cutoff = now - window
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and hits[0] <= cutoff:
                hits.popleft()
            count = len(hits)
            if count >= max_calls:
                return False, count
            hits.append(now)
            return True, count

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()
