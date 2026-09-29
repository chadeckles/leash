"""Leash Live Dashboard — curses-based TUI for monitoring agents in real time.

Usage::

    # Run directly
    leash dashboard

    # Or via the CLI
    leash dashboard

    # Custom server URL and refresh rate
    leash dashboard --url http://prod:8000 --refresh 5

Displays:
- Server health & uptime
- Authorize decision counters (allow/deny) with live rates
- Registered agents with last-seen timestamps
- Recent audit log entries
- Policy overview
- Top HTTP endpoints by request count
- Suspicious chain detection alerts

Requires a running Leash server. Uses only stdlib (curses) + httpx.
Press 'q' to quit, 'r' to force refresh, arrow keys to scroll.
"""

from __future__ import annotations

import argparse
import curses
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

LEASH_URL = os.getenv("LEASH_URL", "http://localhost:8000")
REFRESH_SECONDS = 2


# ═══════════════════════════════════════════════════════════════════════════
# Data fetching
# ═══════════════════════════════════════════════════════════════════════════

class LeashFetcher:
    """Pulls data from Leash API endpoints."""

    def __init__(self, base_url: str, token: Optional[str] = None):
        self.base_url = base_url
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self.client = httpx.Client(base_url=base_url, headers=headers, timeout=5)
        self.last_error: Optional[str] = None

    def _get(self, path: str, params: Optional[dict] = None) -> Optional[dict]:
        try:
            resp = self.client.get(path, params=params)
            if resp.status_code == 200:
                self.last_error = None
                return resp.json()
            elif resp.status_code == 401:
                self.last_error = "401 Unauthorized — provide --token"
                return None
            else:
                self.last_error = f"HTTP {resp.status_code} on {path}"
                return None
        except httpx.ConnectError:
            self.last_error = f"Cannot connect to {self.base_url}"
            return None
        except Exception as e:
            self.last_error = str(e)[:60]
            return None

    def _post(self, path: str, json: Optional[dict] = None) -> Optional[dict]:
        try:
            resp = self.client.post(path, json=json or {})
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception:
            return None

    def get_health(self) -> bool:
        try:
            resp = self.client.get("/health")
            return resp.status_code == 200
        except Exception:
            return False

    def get_metrics_raw(self) -> Optional[str]:
        try:
            resp = self.client.get("/metrics")
            if resp.status_code == 200:
                return resp.text
        except Exception:
            pass
        return None

    def get_agents(self) -> Optional[dict]:
        return self._get("/agents", {"limit": 50})

    def get_audit_summary(self) -> Optional[dict]:
        return self._get("/audit/summary")

    def get_audit_recent(self, limit: int = 15) -> Optional[dict]:
        return self._get("/audit", {"limit": limit})

    def get_chains(self) -> Optional[dict]:
        return self._post("/audit/chains", {"limit": 200, "window": 3600})

    def close(self):
        self.client.close()


# ═══════════════════════════════════════════════════════════════════════════
# Metrics parser
# ═══════════════════════════════════════════════════════════════════════════

def parse_metrics(raw: str) -> Dict[str, Any]:
    """Parse Prometheus text format into a usable dict."""
    result: Dict[str, Any] = {
        "authorize_allow": 0,
        "authorize_deny": 0,
        "agents_registered": 0,
        "audit_entries": 0,
        "uptime_seconds": 0,
        "http_paths": [],
    }

    http_counts: Dict[str, int] = {}
    http_latency_sum: Dict[str, float] = {}
    http_latency_count: Dict[str, int] = {}

    for line in raw.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # authorize_total
        m = re.match(r'leash_authorize_total\{decision="(\w+)"\}\s+([\d.]+)', line)
        if m:
            if m.group(1) == "allow":
                result["authorize_allow"] = int(float(m.group(2)))
            elif m.group(1) == "deny":
                result["authorize_deny"] = int(float(m.group(2)))
            continue

        # agents_registered_total
        m = re.match(r'leash_agents_registered_total\s+([\d.]+)', line)
        if m:
            result["agents_registered"] = int(float(m.group(1)))
            continue

        # audit_entries_total
        m = re.match(r'leash_audit_entries_total\s+([\d.]+)', line)
        if m:
            result["audit_entries"] = int(float(m.group(1)))
            continue

        # uptime
        m = re.match(r'leash_uptime_seconds\s+([\d.]+)', line)
        if m:
            result["uptime_seconds"] = float(m.group(1))
            continue

        # http_requests_total
        m = re.match(
            r'leash_http_requests_total\{method="(\w+)",path="([^"]+)",status="(\d+)"\}\s+([\d.]+)',
            line,
        )
        if m:
            method, path, _status, count = m.group(1), m.group(2), m.group(3), int(float(m.group(4)))
            key = f"{method} {path}"
            http_counts[key] = http_counts.get(key, 0) + count
            continue

        # http_request_duration_seconds
        m = re.match(
            r'leash_http_request_duration_seconds\{method="(\w+)",path="([^"]+)"\}_sum\s+([\d.]+)',
            line,
        )
        if m:
            key = f"{m.group(1)} {m.group(2)}"
            http_latency_sum[key] = float(m.group(3))
            continue

        m = re.match(
            r'leash_http_request_duration_seconds\{method="(\w+)",path="([^"]+)"\}_count\s+([\d.]+)',
            line,
        )
        if m:
            key = f"{m.group(1)} {m.group(2)}"
            http_latency_count[key] = int(float(m.group(3)))
            continue

    # Build sorted HTTP paths
    paths = []
    for key, count in sorted(http_counts.items(), key=lambda x: -x[1]):
        avg_ms = 0.0
        if key in http_latency_sum and key in http_latency_count and http_latency_count[key] > 0:
            avg_ms = (http_latency_sum[key] / http_latency_count[key]) * 1000
        paths.append({"path": key, "count": count, "avg_ms": avg_ms})
    result["http_paths"] = paths

    return result


def format_uptime(seconds: float) -> str:
    """Convert seconds into a human-readable uptime string."""
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        m = int(seconds // 60)
        s = int(seconds % 60)
        return f"{m}m {s}s"
    else:
        h = int(seconds // 3600)
        m = int((seconds % 3600) // 60)
        return f"{h}h {m}m"


def time_ago(ts_str: str) -> str:
    """Convert an ISO timestamp to a relative 'X ago' string."""
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        delta = (now - ts).total_seconds()
        if delta < 0:
            delta = abs(delta)
        if delta < 60:
            return f"{int(delta)}s ago"
        elif delta < 3600:
            return f"{int(delta // 60)}m ago"
        elif delta < 86400:
            return f"{int(delta // 3600)}h ago"
        else:
            return f"{int(delta // 86400)}d ago"
    except Exception:
        return ts_str[:16] if ts_str else "—"


# ═══════════════════════════════════════════════════════════════════════════
# Dashboard state
# ═══════════════════════════════════════════════════════════════════════════

class DashboardState:
    """Holds all fetched data for a single render cycle."""

    def __init__(self):
        self.healthy: bool = False
        self.error: Optional[str] = None
        self.metrics: Dict[str, Any] = {}
        self.agents: List[dict] = []
        self.agents_total: int = 0
        self.audit_entries: List[dict] = []
        self.audit_total: int = 0
        self.summary: Optional[dict] = None
        self.chains: List[dict] = []
        self.last_refresh: float = 0
        # For rate calculation
        self._prev_allow: int = 0
        self._prev_deny: int = 0
        self._prev_time: float = 0
        self.allow_rate: float = 0  # per second
        self.deny_rate: float = 0

    def refresh(self, fetcher: LeashFetcher) -> None:
        self.healthy = fetcher.get_health()
        self.error = fetcher.last_error

        raw_metrics = fetcher.get_metrics_raw()
        if raw_metrics:
            self.metrics = parse_metrics(raw_metrics)
            # Calculate rates
            now = time.monotonic()
            curr_allow = self.metrics.get("authorize_allow", 0)
            curr_deny = self.metrics.get("authorize_deny", 0)
            if self._prev_time > 0:
                dt = now - self._prev_time
                if dt > 0:
                    self.allow_rate = (curr_allow - self._prev_allow) / dt
                    self.deny_rate = (curr_deny - self._prev_deny) / dt
            self._prev_allow = curr_allow
            self._prev_deny = curr_deny
            self._prev_time = now

        agents_data = fetcher.get_agents()
        if agents_data:
            self.agents = agents_data.get("agents", [])
            self.agents_total = agents_data.get("total", len(self.agents))

        audit_data = fetcher.get_audit_recent(15)
        if audit_data:
            self.audit_entries = audit_data.get("entries", [])
            self.audit_total = audit_data.get("total", 0)

        summary = fetcher.get_audit_summary()
        if summary:
            self.summary = summary

        chains = fetcher.get_chains()
        if chains:
            self.chains = chains.get("matches", [])

        self.last_refresh = time.monotonic()


# ═══════════════════════════════════════════════════════════════════════════
# Curses rendering
# ═══════════════════════════════════════════════════════════════════════════

# Color pair IDs
C_NORMAL = 0
C_HEADER = 1
C_OK = 2
C_WARN = 3
C_ERROR = 4
C_DIM = 5
C_ACCENT = 6
C_BAR_ALLOW = 7
C_BAR_DENY = 8


def init_colors():
    """Set up color pairs if the terminal supports them."""
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(C_HEADER, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(C_OK, curses.COLOR_GREEN, -1)
    curses.init_pair(C_WARN, curses.COLOR_YELLOW, -1)
    curses.init_pair(C_ERROR, curses.COLOR_RED, -1)
    curses.init_pair(C_DIM, curses.COLOR_WHITE, -1)
    curses.init_pair(C_ACCENT, curses.COLOR_CYAN, -1)
    curses.init_pair(C_BAR_ALLOW, curses.COLOR_BLACK, curses.COLOR_GREEN)
    curses.init_pair(C_BAR_DENY, curses.COLOR_BLACK, curses.COLOR_RED)


def safe_addstr(win, y: int, x: int, text: str, attr=0):
    """Write text to a curses window, safely truncating if needed."""
    max_y, max_x = win.getmaxyx()
    if y >= max_y or x >= max_x:
        return
    available = max_x - x - 1
    if available <= 0:
        return
    try:
        win.addnstr(y, x, text, available, attr)
    except curses.error:
        pass


def draw_bar(win, y: int, x: int, width: int, allow: int, deny: int):
    """Draw a colored allow/deny ratio bar."""
    total = allow + deny
    if total == 0 or width < 4:
        safe_addstr(win, y, x, "—" * width, curses.color_pair(C_DIM))
        return
    allow_w = max(1, int(width * allow / total)) if allow > 0 else 0
    deny_w = max(1, int(width * deny / total)) if deny > 0 else 0
    # Adjust to fill exactly width
    if allow_w + deny_w < width:
        if allow >= deny:
            allow_w = width - deny_w
        else:
            deny_w = width - allow_w
    elif allow_w + deny_w > width:
        if allow >= deny:
            allow_w = width - deny_w
        else:
            deny_w = width - allow_w

    if allow_w > 0:
        safe_addstr(win, y, x, " " * allow_w, curses.color_pair(C_BAR_ALLOW))
    if deny_w > 0:
        safe_addstr(win, y, x + allow_w, " " * deny_w, curses.color_pair(C_BAR_DENY))


def render(stdscr, state: DashboardState, url: str, scroll_offset: int) -> int:
    """Render the full dashboard. Returns the total content height."""
    stdscr.erase()
    max_y, max_x = stdscr.getmaxyx()
    w = max_x  # usable width

    if w < 40 or max_y < 10:
        safe_addstr(stdscr, 0, 0, "Terminal too small (need 40x10+)", curses.color_pair(C_ERROR))
        stdscr.refresh()
        return 1

    row = -scroll_offset  # virtual row (negative = above viewport)

    def out(y_offset: int, x: int, text: str, attr=0):
        actual_y = row + y_offset
        if 0 <= actual_y < max_y:
            safe_addstr(stdscr, actual_y, x, text, attr)

    # ── Header bar ──
    header = " LEASH DASHBOARD "
    ts = time.strftime("%H:%M:%S")
    status_icon = "✔" if state.healthy else "✘"
    right = f" {status_icon} {ts} "
    pad = w - len(header) - len(right)
    if pad < 0:
        pad = 0
    header_line = header + "─" * pad + right
    out(0, 0, header_line[:w], curses.color_pair(C_HEADER) | curses.A_BOLD)
    row += 2

    # ── Error banner ──
    if state.error and not state.healthy:
        out(0, 2, f"⚠  {state.error}", curses.color_pair(C_ERROR) | curses.A_BOLD)
        row += 2

    # ── Server Info ──
    out(0, 2, "SERVER", curses.color_pair(C_ACCENT) | curses.A_BOLD)
    row += 1

    uptime = format_uptime(state.metrics.get("uptime_seconds", 0))
    health_str = "✔ healthy" if state.healthy else "✘ unreachable"
    health_color = curses.color_pair(C_OK) if state.healthy else curses.color_pair(C_ERROR)
    out(0, 4, "Status: ", curses.color_pair(C_DIM))
    out(0, 12, health_str, health_color | curses.A_BOLD)
    out(0, 28, f"Uptime: {uptime}", curses.color_pair(C_DIM))
    out(0, 48, f"URL: {url}", curses.color_pair(C_DIM))
    row += 2

    # ── Authorize Decisions ──
    out(0, 2, "AUTHORIZE DECISIONS", curses.color_pair(C_ACCENT) | curses.A_BOLD)
    row += 1

    allow = state.metrics.get("authorize_allow", 0)
    deny = state.metrics.get("authorize_deny", 0)
    total = allow + deny
    pct_allow = (allow / total * 100) if total else 0
    pct_deny = (deny / total * 100) if total else 0

    out(0, 4, f"✔ Allow: {allow:>6d} ({pct_allow:4.1f}%)", curses.color_pair(C_OK))
    rate_str = f"  {state.allow_rate:.1f}/s" if state.allow_rate > 0.05 else ""
    out(0, 30, rate_str, curses.color_pair(C_DIM))
    row += 1
    out(0, 4, f"✘ Deny:  {deny:>6d} ({pct_deny:4.1f}%)", curses.color_pair(C_ERROR))
    rate_str = f"  {state.deny_rate:.1f}/s" if state.deny_rate > 0.05 else ""
    out(0, 30, rate_str, curses.color_pair(C_DIM))
    row += 1
    out(0, 4, f"  Total: {total:>6d}", curses.color_pair(C_DIM))
    row += 1

    # Draw allow/deny bar
    bar_width = min(w - 8, 50)
    actual_bar_y = row
    if 0 <= actual_bar_y < max_y:
        draw_bar(stdscr, actual_bar_y, 4, bar_width, allow, deny)
        # Legend
        legend_x = 4 + bar_width + 2
        if legend_x + 20 < w:
            safe_addstr(stdscr, actual_bar_y, legend_x, "■", curses.color_pair(C_OK))
            safe_addstr(stdscr, actual_bar_y, legend_x + 1, " allow ", curses.color_pair(C_DIM))
            safe_addstr(stdscr, actual_bar_y, legend_x + 8, "■", curses.color_pair(C_ERROR))
            safe_addstr(stdscr, actual_bar_y, legend_x + 9, " deny", curses.color_pair(C_DIM))
    row += 2

    # ── Agents ──
    out(0, 2, f"AGENTS ({state.agents_total})", curses.color_pair(C_ACCENT) | curses.A_BOLD)
    row += 1

    if state.agents:
        name_w = max(len(a.get("name", "")) for a in state.agents[:10])
        name_w = max(name_w, 6)
        name_w = min(name_w, 28)

        out(0, 4, f"{'NAME':<{name_w}}  {'VENDOR':10}  {'TYPE':10}  LAST SEEN",
            curses.color_pair(C_DIM) | curses.A_UNDERLINE)
        row += 1

        for a in state.agents[:10]:
            name = (a.get("name") or "?")[:name_w]
            vendor = (a.get("vendor") or "—")[:10]
            atype = (a.get("agent_type") or "—")[:10]
            seen = time_ago(a.get("last_seen", ""))
            out(0, 4, f"{name:<{name_w}}  {vendor:10}  {atype:10}  {seen}",
                curses.color_pair(C_NORMAL))
            row += 1

        if state.agents_total > 10:
            out(0, 4, f"  ... and {state.agents_total - 10} more", curses.color_pair(C_DIM))
            row += 1
    else:
        out(0, 4, "No agents registered", curses.color_pair(C_DIM))
        row += 1
    row += 1

    # ── Audit Summary ──
    out(0, 2, f"AUDIT LOG ({state.audit_total} entries)", curses.color_pair(C_ACCENT) | curses.A_BOLD)
    row += 1

    if state.summary:
        s = state.summary
        deny_rate_pct = s.get("deny_rate", 0) * 100
        dr_color = curses.color_pair(C_WARN) if deny_rate_pct > 50 else curses.color_pair(C_DIM)
        out(0, 4, f"Allow: {s.get('total_allowed', 0)}  Deny: {s.get('total_denied', 0)}  "
                   f"Deny rate: {deny_rate_pct:.1f}%", dr_color)
        row += 1

        # Per-action breakdown (top 6)
        actions = s.get("actions", [])
        if actions:
            actions_sorted = sorted(actions, key=lambda a: -a.get("count", 0))[:6]
            for a in actions_sorted:
                act = a.get("action", "?")[:22]
                cnt = a.get("count", 0)
                al = a.get("allowed", 0)
                dn = a.get("denied", 0)
                out(0, 6, f"{act:22s}  {cnt:3d}x (✔{al} ✘{dn})", curses.color_pair(C_DIM))
                row += 1
    row += 1

    # ── Chain Alerts ──
    if state.chains:
        out(0, 2, f"⚠ SUSPICIOUS CHAINS ({len(state.chains)})",
            curses.color_pair(C_WARN) | curses.A_BOLD)
        row += 1
        for ch in state.chains[:5]:
            pattern = ch.get("pattern", "?")
            agent = ch.get("agent_id", "?")[:12]
            actions = " → ".join(ch.get("actions", []))
            out(0, 4, f"[{pattern}] {agent}..  {actions}",
                curses.color_pair(C_WARN))
            row += 1
        row += 1

    # ── Recent Audit Entries ──
    out(0, 2, "RECENT ACTIVITY", curses.color_pair(C_ACCENT) | curses.A_BOLD)
    row += 1

    if state.audit_entries:
        for e in state.audit_entries[:12]:
            decision = e.get("policy_decision", "?")
            icon = "✔" if decision == "allow" else "✘"
            icon_color = curses.color_pair(C_OK) if decision == "allow" else curses.color_pair(C_ERROR)
            ts = time_ago(e.get("timestamp", ""))
            agent = (e.get("agent_id") or "?")[:10]
            action = (e.get("action") or "?")[:24]

            actual_y = row
            if 0 <= actual_y < max_y:
                safe_addstr(stdscr, actual_y, 4, icon, icon_color)
                safe_addstr(stdscr, actual_y, 6, f"{ts:>8s}", curses.color_pair(C_DIM))
                safe_addstr(stdscr, actual_y, 15, f"{agent:10s}", curses.color_pair(C_NORMAL))
                safe_addstr(stdscr, actual_y, 26, action, curses.color_pair(C_NORMAL))
            row += 1
    else:
        out(0, 4, "No audit entries yet", curses.color_pair(C_DIM))
        row += 1
    row += 1

    # ── HTTP Traffic ──
    http_paths = state.metrics.get("http_paths", [])
    if http_paths:
        out(0, 2, "HTTP TRAFFIC (top endpoints)", curses.color_pair(C_ACCENT) | curses.A_BOLD)
        row += 1
        for p in http_paths[:8]:
            path = p["path"][:35]
            count = p["count"]
            avg = p["avg_ms"]
            out(0, 4, f"{path:35s} {count:>5d} reqs", curses.color_pair(C_DIM))
            if avg > 0:
                ms_color = curses.color_pair(C_WARN) if avg > 100 else curses.color_pair(C_DIM)
                out(0, 50, f" avg {avg:>6.1f}ms", ms_color)
            row += 1
        row += 1

    # ── Footer ──
    footer = " q:quit  r:refresh  ↑↓:scroll "
    footer_y = max_y - 1
    safe_addstr(stdscr, footer_y, 0, " " * w, curses.color_pair(C_HEADER))
    safe_addstr(stdscr, footer_y, (w - len(footer)) // 2, footer,
                curses.color_pair(C_HEADER))

    stdscr.refresh()

    # Return total content height for scroll limits
    return row + scroll_offset


# ═══════════════════════════════════════════════════════════════════════════
# Main loop
# ═══════════════════════════════════════════════════════════════════════════

def dashboard_main(stdscr, url: str, token: Optional[str], refresh: int):
    """Main curses event loop."""
    curses.curs_set(0)  # hide cursor
    stdscr.timeout(200)  # non-blocking getch, 200ms
    init_colors()

    fetcher = LeashFetcher(url, token)
    state = DashboardState()
    scroll_offset = 0
    content_height = 0
    last_fetch = 0

    try:
        while True:
            # Fetch data periodically
            now = time.monotonic()
            if now - last_fetch >= refresh:
                state.refresh(fetcher)
                last_fetch = now

            # Render
            content_height = render(stdscr, state, url, scroll_offset)

            # Handle input
            key = stdscr.getch()
            if key == ord("q") or key == ord("Q") or key == 27:  # q or ESC
                break
            elif key == ord("r") or key == ord("R"):
                last_fetch = 0  # force refresh
            elif key == curses.KEY_DOWN:
                max_y = stdscr.getmaxyx()[0]
                if scroll_offset < content_height - max_y + 5:
                    scroll_offset += 1
            elif key == curses.KEY_UP:
                if scroll_offset > 0:
                    scroll_offset -= 1
            elif key == curses.KEY_PPAGE:  # Page Up
                scroll_offset = max(0, scroll_offset - 10)
            elif key == curses.KEY_NPAGE:  # Page Down
                max_y = stdscr.getmaxyx()[0]
                scroll_offset = min(content_height - max_y + 5, scroll_offset + 10)
            elif key == curses.KEY_HOME:
                scroll_offset = 0
            elif key == curses.KEY_RESIZE:
                scroll_offset = 0
    finally:
        fetcher.close()


def run(url: str = LEASH_URL, token: Optional[str] = None, refresh: int = REFRESH_SECONDS):
    """Entry point — wraps curses.wrapper."""
    curses.wrapper(dashboard_main, url, token, refresh)


def main():
    """CLI entry point for ``leash dashboard``."""
    parser = argparse.ArgumentParser(
        prog="leash dashboard",
        description="Leash live terminal dashboard",
    )
    parser.add_argument("--url", default=LEASH_URL, help="Leash server URL")
    parser.add_argument("--token", help="JWT token for authentication")
    parser.add_argument("--token-file", help="Path to JSON file with 'token' field")
    parser.add_argument("--refresh", type=int, default=REFRESH_SECONDS,
                        help=f"Refresh interval in seconds (default: {REFRESH_SECONDS})")

    args = parser.parse_args()

    token = args.token
    if not token and args.token_file:
        import json
        from pathlib import Path
        p = Path(args.token_file)
        if p.exists():
            token = json.loads(p.read_text()).get("token")
    if not token:
        from leash.cli import _load_token

        token = _load_token(None, None)

    run(url=args.url, token=token, refresh=args.refresh)


if __name__ == "__main__":
    main()
