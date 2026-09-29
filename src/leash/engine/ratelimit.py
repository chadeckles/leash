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


class FileRateLimiter:
    """Sliding-window limiter persisted to a JSON file.

    For short-lived processes such as agent hooks, where every tool call runs
    in a fresh interpreter.  A lock file serializes concurrent callers.  Uses
    wall-clock time so windows survive across processes.
    """

    def __init__(self, path, clock: Callable[[], float] = time.time) -> None:
        from pathlib import Path

        self.path = Path(path)
        self._clock = clock

    def _key(self, key: Hashable) -> str:
        return "\x1f".join(map(str, key)) if isinstance(key, tuple) else str(key)

    def acquire(self, key: Hashable, max_calls: int, window: float) -> Tuple[bool, int]:
        import json
        import os

        from leash.filelock import locked

        now = self._clock()
        k = self._key(key)
        with locked(self.path.with_name(self.path.name + ".lock")):
            try:
                state = json.loads(self.path.read_text())
                if not isinstance(state, dict):
                    state = {}
            except (OSError, ValueError):
                state = {}
            hits = [t for t in state.get(k, []) if isinstance(t, (int, float)) and t > now - window]
            count = len(hits)
            ok = count < max_calls
            if ok:
                hits.append(now)
            state[k] = hits
            # Drop keys whose newest hit is older than a day to bound file size.
            state = {key_: v for key_, v in state.items() if v and v[-1] > now - 86400}
            tmp = self.path.with_name(self.path.name + ".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                json.dump(state, fh)
            os.replace(tmp, self.path)
            return ok, count
