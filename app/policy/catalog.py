"""What each agent tool can actually do, in plain English.

Used by the simple ``tools:`` policy format (for decision reasons and typo
checks) and by ``leash scan openclaw`` (to explain an agent's capabilities).

Each entry: ``does`` completes the sentence "it can …", ``risk`` is
high / medium / low, ``default`` is the safe starting effect, and the
optional ``limit`` is a rate limit applied whenever the tool is allowed.
"""

from __future__ import annotations

from typing import Any

OPENCLAW_TOOLS: dict[str, dict[str, Any]] = {
    # Files
    "read":             {"group": "Files", "risk": "low", "default": "allow",
                         "does": "read files in its workspace"},
    "write":            {"group": "Files", "risk": "high", "default": "deny",
                         "does": "create or overwrite any file it can reach"},
    "edit":             {"group": "Files", "risk": "high", "default": "deny",
                         "does": "change the contents of existing files"},
    "apply_patch":      {"group": "Files", "risk": "high", "default": "deny",
                         "does": "rewrite many files at once with a code patch"},
    # Running code
    "exec":             {"group": "Running code", "risk": "high", "default": "deny",
                         "does": "run any shell command on your computer",
                         "owasp": ["ASI06", "LLM06"]},
    "process":          {"group": "Running code", "risk": "high", "default": "deny",
                         "does": "start and control long-running background programs"},
    "code_execution":   {"group": "Running code", "risk": "high", "default": "deny",
                         "does": "write and run its own code"},
    # Web
    "web_search":       {"group": "Web", "risk": "low", "default": "allow",
                         "does": "search the web"},
    "web_fetch":        {"group": "Web", "risk": "medium", "default": "allow",
                         "does": "download any web page (which may contain hidden instructions)"},
    "x_search":         {"group": "Web", "risk": "low", "default": "allow",
                         "does": "search posts on X/Twitter"},
    "browser":          {"group": "Web", "risk": "high", "default": "deny",
                         "does": "drive a real web browser: click, type, and use sites you are logged in to",
                         "owasp": ["ASI02"]},
    "canvas":           {"group": "Web", "risk": "medium", "default": "deny",
                         "does": "draw interactive pages on your screen and paired devices"},
    # Memory and sessions
    "memory_search":    {"group": "Memory and sessions", "risk": "low", "default": "allow",
                         "does": "search its long-term memory"},
    "memory_get":       {"group": "Memory and sessions", "risk": "low", "default": "allow",
                         "does": "read saved memory entries"},
    "sessions_list":    {"group": "Memory and sessions", "risk": "low", "default": "allow",
                         "does": "list its chat sessions"},
    "sessions_history": {"group": "Memory and sessions", "risk": "low", "default": "allow",
                         "does": "read past conversations"},
    "session_status":   {"group": "Memory and sessions", "risk": "low", "default": "allow",
                         "does": "check its own status"},
    "sessions_send":    {"group": "Memory and sessions", "risk": "medium", "default": "allow",
                         "does": "send messages to its other sessions and agents",
                         "limit": {"max_calls": 30, "window": 60}},
    "sessions_spawn":   {"group": "Memory and sessions", "risk": "high", "default": "deny",
                         "does": "start new AI agents that work on their own"},
    # System
    "cron":             {"group": "System", "risk": "medium", "default": "allow",
                         "does": "schedule tasks that run later without you watching",
                         "limit": {"max_calls": 20, "window": 3600}},
    "gateway":          {"group": "System", "risk": "high", "default": "deny",
                         "does": "change OpenClaw's own settings and restart it"},
    "nodes":            {"group": "System", "risk": "high", "default": "deny",
                         "does": "control your paired phones and other computers"},
}

CATALOGS: dict[str, dict[str, dict[str, Any]]] = {
    "openclaw": OPENCLAW_TOOLS,
}


def catalog_for(agent: Any) -> dict[str, dict[str, Any]] | None:
    """Return the tool catalog for an agent name/pattern (or list of them), if known."""
    names = agent if isinstance(agent, list) else [agent]
    for name in names:
        if not isinstance(name, str):
            continue
        for key, catalog in CATALOGS.items():
            if key in name.lower():
                return catalog
    return None
