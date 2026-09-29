"""Lightweight Prometheus metrics for Leash.

Zero external dependencies — generates Prometheus text exposition format
directly.  Exposed at ``GET /metrics`` in ``app/main.py``.

Counters tracked:

- ``leash_authorize_total{decision}`` — authorize calls by allow/deny
- ``leash_authorize_latency_seconds`` — histogram-style sum/count
- ``leash_audit_entries_total`` — audit entries created
- ``leash_agents_registered_total`` — agent registrations
- ``leash_policy_evaluations_total`` — policy engine evaluations
- ``leash_http_requests_total{method,path,status}`` — request counts

Usage in route handlers::

    from leash.server.core.metrics import METRICS

    METRICS.inc("authorize_total", labels={"decision": "allow"})
    METRICS.observe("authorize_latency_seconds", elapsed)

The ``/metrics`` endpoint is unauthenticated (standard Prometheus scrape).
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Dict, Optional


class _Metrics:
    """Thread-safe in-process metrics store."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Dict[str, float] = defaultdict(float)
        self._summaries: Dict[str, Dict[str, float]] = {}
        self._start_time = time.monotonic()

    # ── Counter ──

    def inc(self, name: str, value: float = 1, labels: Optional[Dict[str, str]] = None) -> None:
        """Increment a counter."""
        key = self._make_key(name, labels)
        with self._lock:
            self._counters[key] += value

    def get(self, name: str, labels: Optional[Dict[str, str]] = None) -> float:
        """Read a counter value (for testing)."""
        key = self._make_key(name, labels)
        with self._lock:
            return self._counters.get(key, 0)

    # ── Summary (sum + count) ──

    def observe(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Record an observation (for latency tracking)."""
        key = self._make_key(name, labels)
        with self._lock:
            if key not in self._summaries:
                self._summaries[key] = {"sum": 0.0, "count": 0.0}
            self._summaries[key]["sum"] += value
            self._summaries[key]["count"] += 1

    # ── Exposition ──

    def render(self) -> str:
        """Return Prometheus text exposition format."""
        lines: list[str] = []
        with self._lock:
            # Counters
            emitted_help: set[str] = set()
            for key, val in sorted(self._counters.items()):
                base = key.split("{")[0] if "{" in key else key
                full = f"leash_{base}"
                if full not in emitted_help:
                    lines.append(f"# HELP {full} Leash counter")
                    lines.append(f"# TYPE {full} counter")
                    emitted_help.add(full)
                prometheus_key = f"leash_{key}"
                lines.append(f"{prometheus_key} {val}")

            # Summaries
            for key, data in sorted(self._summaries.items()):
                base = key.split("{")[0] if "{" in key else key
                full = f"leash_{base}"
                if full not in emitted_help:
                    lines.append(f"# HELP {full} Leash summary")
                    lines.append(f"# TYPE {full} summary")
                    emitted_help.add(full)
                prometheus_key = f"leash_{key}"
                lines.append(f"{prometheus_key}_sum {data['sum']:.6f}")
                lines.append(f"{prometheus_key}_count {int(data['count'])}")

            # Uptime gauge
            uptime = time.monotonic() - self._start_time
            lines.append("# HELP leash_uptime_seconds Seconds since process start")
            lines.append("# TYPE leash_uptime_seconds gauge")
            lines.append(f"leash_uptime_seconds {uptime:.1f}")

        lines.append("")
        return "\n".join(lines)

    # ── Internal ──

    @staticmethod
    def _make_key(name: str, labels: Optional[Dict[str, str]] = None) -> str:
        if not labels:
            return name
        parts = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        return f"{name}{{{parts}}}"


# Singleton
METRICS = _Metrics()
