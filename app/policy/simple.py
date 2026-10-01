"""The simple policy format: one ``tool: allow|deny`` line per tool.

    agent: openclaw
    tools:
      read: allow       # read files in its workspace
      exec: deny        # run any shell command on your computer

It is expanded into the full rules format before anything else looks at it
(engine, validator, policy API), so every existing feature and security
check applies unchanged. Optional keys:

    everything_else: deny     # tools not listed (default: deny)
    mode: observe             # log would-be denials instead of blocking
    name / description / priority
    rules: [...]              # full-format rules, checked before tools:
"""

from __future__ import annotations

import difflib
import re
from typing import Any

from app.policy.catalog import catalog_for

DEFAULT_PRIORITY = 20
SIMPLE_KEYS = {"agent", "tools", "everything_else"}
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def is_simple(doc: Any) -> bool:
    return isinstance(doc, dict) and "tools" in doc


def _agent_patterns(agent: Any) -> list[Any]:
    values = agent if isinstance(agent, list) else [agent]
    out: list[Any] = []
    for v in values:
        if isinstance(v, str) and v and "*" not in v and "?" not in v and not _UUID.match(v):
            out.append(f"*{v}*")
        else:
            out.append(v)
    return out


def _reason(tool: str, effect: Any, info: dict | None, policy: str) -> str:
    if info and effect == "allow":
        return f"{tool} is allowed — it can {info['does']}"
    if info and effect == "deny":
        return f"{tool} is blocked — it could {info['does']}"
    return f"{tool} is set to {effect} in policy '{policy}'"


def expand(doc: dict[str, Any]) -> dict[str, Any]:
    """Return the full-format equivalent of a simple policy (non-simple docs unchanged)."""
    if not is_simple(doc):
        return doc
    agent = doc.get("agent", doc.get("agents"))
    first = agent[0] if isinstance(agent, list) and agent else agent
    slug = str(first or "agent").strip("*") or "agent"
    catalog = catalog_for(agent) or {}

    out = {k: v for k, v in doc.items() if k not in SIMPLE_KEYS | {"agents", "rules"}}
    out.setdefault("name", f"{slug}-policy")
    out.setdefault("priority", DEFAULT_PRIORITY)
    out["agents"] = _agent_patterns(agent) if agent is not None else []

    rules: list[Any] = list(doc.get("rules") or [])
    tools = doc.get("tools")
    if isinstance(tools, dict):
        for tool, value in tools.items():
            effect = value.strip().lower() if isinstance(value, str) else value
            info = catalog.get(str(tool))
            rule: dict[str, Any] = {
                "action": str(tool),
                "effect": effect,
                "reason": _reason(str(tool), effect, info, out["name"]),
            }
            if info and info.get("owasp"):
                rule["owasp"] = list(info["owasp"])
            if info and info.get("limit") and effect == "allow":
                rule["rate_limit"] = dict(info["limit"])
            rules.append(rule)

    rest = doc.get("everything_else", "deny")
    rest = rest.strip().lower() if isinstance(rest, str) else rest
    rules.append({
        "action": "*",
        "effect": rest,
        "reason": "Not listed under tools:, so it is "
                  + ("allowed" if rest == "allow" else "denied") + " by default",
    })
    out["rules"] = rules
    return out


def lint(doc: dict[str, Any], source: str = "<inline>") -> list[str]:
    """Errors specific to the simple format, phrased for beginners."""
    errors: list[str] = []
    if doc.get("agent") is None and doc.get("agents") is None:
        errors.append(f"{source}: add 'agent: <name>' — which agent does this policy apply to?")
    tools = doc.get("tools")
    if not isinstance(tools, dict) or not tools:
        return errors + [f"{source}: 'tools:' must list tools, one per line, like 'exec: deny'"]
    catalog = catalog_for(doc.get("agent", doc.get("agents"))) or {}
    for tool, value in tools.items():
        if not isinstance(value, str) or value.strip().lower() not in ("allow", "deny"):
            errors.append(f"{source}: tools.{tool} is {value!r} — use allow or deny")
        if catalog and str(tool) not in catalog:
            close = difflib.get_close_matches(str(tool), catalog, n=1, cutoff=0.75)
            if close:
                errors.append(f"{source}: unknown tool '{tool}' — did you mean '{close[0]}'?")
    rest = doc.get("everything_else", "deny")
    if not isinstance(rest, str) or rest.strip().lower() not in ("allow", "deny"):
        errors.append(f"{source}: everything_else is {rest!r} — use allow or deny")
    return errors


def render(agent: str, settings: dict[str, str] | None = None, header: str = "") -> str:
    """Render a commented simple policy for *agent* (catalog defaults unless *settings* given)."""
    catalog = catalog_for(agent) or {}
    settings = settings or {t: i["default"] for t, i in catalog.items()}
    width = max((len(t) for t in settings), default=4) + 1
    icon = {"high": "🔴", "medium": "🟠", "low": "🟢"}
    lines = [header.rstrip(), ""] if header else []
    lines += [f"agent: {agent}", "", "tools:"]
    group = None
    for tool, effect in settings.items():
        info = catalog.get(tool)
        if info and info["group"] != group:
            group = info["group"]
            lines.append(f"  # ── {group} " + "─" * max(4, 50 - len(group)))
        pad = " " * (width - len(tool) + 6 - len(effect))
        note = f"  # {icon[info['risk']]} can {info['does']}" if info else ""
        if info and info.get("limit"):
            m = info["limit"]
            per = {60: "minute", 3600: "hour", 86400: "day"}.get(m["window"], f"{m['window']}s")
            note += f" (max {m['max_calls']} per {per} when allowed)"
        lines.append(f"  {tool}: {effect}{pad}{note}")
    lines += ["", "everything_else: deny    # any tool not listed above", ""]
    return "\n".join(lines)
