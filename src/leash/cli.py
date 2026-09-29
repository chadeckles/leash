"""Leash CLI – manage agents, policies, and audit from the command line.

Quick start (zero config)::

    leash start                        # run the server (needs `leash[server]`)
    leash agents list                  # auto-registers on first run!

Or initialize explicitly::

    leash init                         # register + cache token

Usage::

    # Bootstrap
    leash init                        # register CLI agent, cache JWT
    leash init --name my-bot          # custom agent name

    # Agent commands
    leash agents list
    leash agents show <agent-id>
    leash agents permissions <agent-id>

    # Policy commands
    leash policy list
    leash policy validate ~/.leash/policies/
    leash policy test --action email.send --agent my-agent-id

    # Audit commands
    leash audit summary
    leash audit log --agent <id> --limit 20
    leash audit scan --agent <id>

    # System
    leash status
    leash dashboard

Requires a running Leash server (default http://localhost:8000).
Token auto-cached to ~/.leash/token.json (under $LEASH_HOME) on first use.
Override with --token or --token-file if needed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

import httpx

from leash import __version__, paths


LEASH_URL = os.getenv("LEASH_URL", "http://localhost:8000")
_TOKEN_DIR = paths.leash_home()
_TOKEN_FILE = paths.token_file()


def _cached_identity_files():
    """CLI and agent identity files (``~/.leash/*.json`` and ``~/.leash/agents/*.json``)."""
    for d in (_TOKEN_DIR, paths.agents_dir()):
        if d.is_dir():
            yield from sorted(d.glob("*.json"))


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _get_client(base_url: str, token: str | None = None) -> httpx.Client:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(base_url=base_url, headers=headers, timeout=15)


def _load_token(token: str | None, token_file: str | None) -> str | None:
    """Resolve a JWT token from flag → file → ~/.leash → local .leash_identity."""
    if token:
        return token
    if token_file:
        p = Path(token_file).expanduser()
        if p.exists():
            data = json.loads(p.read_text())
            return data.get("token", "")
    # Try global cache
    if _TOKEN_FILE.exists():
        try:
            data = json.loads(_TOKEN_FILE.read_text())
            return data.get("token", "")
        except (json.JSONDecodeError, KeyError):
            pass
    # Try local SDK identity file
    default = Path(".leash_identity.json")
    if default.exists():
        try:
            data = json.loads(default.read_text())
            return data.get("token", "")
        except (json.JSONDecodeError, KeyError):
            pass
    return None


def _save_token(agent_id: str, token: str, name: str) -> None:
    """Cache identity to ~/.leash/token.json."""
    paths.write_private(_TOKEN_FILE, json.dumps({
        "agent_id": agent_id,
        "token": token,
        "name": name,
    }, indent=2))


def _admin_key() -> str | None:
    """Resolve the server's admin bootstrap key (env var, then local key file)."""
    key = os.getenv("LEASH_ADMIN_KEY", "").strip()
    if key:
        return key
    key_file = paths.keys_dir() / "admin.key"
    try:
        if key_file.exists():
            return key_file.read_text().strip()
    except OSError:
        pass
    return None


def _auto_init(base_url: str, name: str = "cli-admin") -> str:
    """Register (or re-use) a CLI agent and cache the token. Returns the JWT."""
    client = _get_client(base_url)
    try:
        # Check if we already have a cached agent_id we can rotate
        if _TOKEN_FILE.exists():
            try:
                cached = json.loads(_TOKEN_FILE.read_text())
                aid = cached.get("agent_id")
                old_token = cached.get("token")
                if aid and old_token:
                    rot_client = _get_client(base_url, old_token)
                    rot = rot_client.post(f"/agents/{aid}/rotate")
                    if rot.is_success:
                        new_token = rot.json()["token"]
                        _save_token(aid, new_token, cached.get("name", name))
                        print(f"  ↻ Token refreshed for '{cached.get('name', name)}'", file=sys.stderr)
                        return new_token
            except Exception:
                pass  # fall through to fresh registration

        admin_headers = {}
        admin_key = _admin_key()
        if admin_key:
            admin_headers["X-Leash-Admin-Key"] = admin_key
        resp = client.post("/agents", json={"name": name, "agent_type": "cli"}, headers=admin_headers)
        resp.raise_for_status()
    except httpx.ConnectError:
        print(f"Error: Cannot reach Leash at {base_url}", file=sys.stderr)
        print("  Start the server: leash start   (install with: uv tool install 'leash[server]')", file=sys.stderr)
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        print(f"Error: Registration failed ({e.response.status_code})", file=sys.stderr)
        if e.response.status_code in (401, 403):
            print(
                "  The CLI registers as an admin and needs the server's admin key.\n"
                f"  Run the CLI on the server host (key is read from {paths.keys_dir() / 'admin.key'}),\n"
                "  or set LEASH_ADMIN_KEY. For Docker:\n"
                "    export LEASH_ADMIN_KEY=$(docker exec leash-server cat /data/keys/admin.key)",
                file=sys.stderr,
            )
        sys.exit(1)

    data = resp.json()
    _save_token(data["agent_id"], data["token"], name)
    print(f"  ✔ Auto-registered as '{name}' (id={data['agent_id'][:12]}…)", file=sys.stderr)
    print(f"  Token cached to {_TOKEN_FILE}", file=sys.stderr)
    return data["token"]


def _require_token(args: argparse.Namespace) -> str:
    """Get a token from flags/cache, or auto-register on the fly."""
    tok = _load_token(getattr(args, "token", None), getattr(args, "token_file", None))
    if tok:
        return tok
    # No token anywhere — auto-register
    return _auto_init(getattr(args, "url", LEASH_URL))


def _find_agent_token(agent_id: str) -> str | None:
    """Search cached ~/.leash/*.json files for a token belonging to *agent_id*.

    Identity enforcement requires API calls to use the target agent's own
    JWT rather than the CLI-admin token.  This helper resolves the correct
    token from the on-disk cache that ``agents register`` writes.
    """
    for path in _cached_identity_files():
        try:
            data = json.loads(path.read_text())
            if data.get("agent_id") == agent_id:
                return data.get("token")
        except (json.JSONDecodeError, KeyError):
            continue
    return None


def _resolve_agent_id(client: httpx.Client, identifier: str) -> tuple[str, str | None]:
    """Resolve an agent name or ID to a (agent_id, agent_token) tuple.

    If *identifier* looks like a UUID it is returned as-is.  Otherwise the
    ``/agents`` list is searched for an exact name match.  Returns the
    agent's own cached token when available (needed for identity enforcement).
    """
    # If it already looks like a UUID, return it directly
    if len(identifier) == 36 and identifier.count("-") == 4:
        return identifier, _find_agent_token(identifier)

    # Try local cache first (fast, no network)
    for path in _cached_identity_files():
        try:
            data = json.loads(path.read_text())
            if data.get("name") == identifier:
                return data["agent_id"], data.get("token")
        except (json.JSONDecodeError, KeyError):
            continue

    # Fall back to the API
    try:
        resp = client.get("/agents", params={"limit": 200})
        if resp.is_success:
            for a in resp.json().get("agents", []):
                if a["name"] == identifier:
                    aid = a["agent_id"]
                    return aid, _find_agent_token(aid)
    except Exception:
        pass

    # Can't resolve — return as-is (the server will reject it with a clear error)
    return identifier, None


def _fmt_time(ts: str | None) -> str:
    if not ts:
        return "—"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return ts[:16] if ts else "—"


# ═══════════════════════════════════════════════════════════════════════════
# init
# ═══════════════════════════════════════════════════════════════════════════

def cmd_init(args: argparse.Namespace) -> None:
    """Register a CLI agent and cache the token."""
    # Check if we already have a cached token
    existing = _load_token(None, None)
    if existing and not args.force:
        print(f"\n  Already initialized. Token cached at {_TOKEN_FILE}")
        print("  Run with --force to re-register.\n")
        return

    name = args.name or "cli-admin"
    _auto_init(args.url, name=name)
    print("\n  ✔ Ready! Try: leash agents list\n", file=sys.stderr)


# ═══════════════════════════════════════════════════════════════════════════
# agents list
# ═══════════════════════════════════════════════════════════════════════════

def cmd_agents_list(args: argparse.Namespace) -> None:
    token = _require_token(args)
    client = _get_client(args.url, token)

    params: dict = {"limit": args.limit, "offset": 0}
    if args.vendor:
        params["vendor"] = args.vendor
    if args.type:
        params["agent_type"] = args.type

    resp = client.get("/agents", params=params)
    resp.raise_for_status()
    data = resp.json()

    agents = data.get("agents", [])
    total = data.get("total", len(agents))

    if not agents:
        print("\n  No agents registered.\n")
        return

    # Column widths
    name_w = max(len(a.get("name", "")) for a in agents)
    name_w = max(name_w, 4)

    print(f"\n  {'NAME':<{name_w}}  {'ID':36}  {'VENDOR':12}  {'TYPE':10}  LAST SEEN")
    print(f"  {'─' * name_w}  {'─' * 36}  {'─' * 12}  {'─' * 10}  {'─' * 16}")

    for a in agents:
        name = a.get("name", "?")
        aid = a.get("agent_id", "?")
        vendor = a.get("vendor", "—") or "—"
        atype = a.get("agent_type", "—") or "—"
        seen = _fmt_time(a.get("last_seen_at") or a.get("last_seen"))
        print(f"  {name:<{name_w}}  {aid:36}  {vendor:12}  {atype:10}  {seen}")

    print(f"\n  {total} agent(s) total\n")


# ═══════════════════════════════════════════════════════════════════════════
# agents register
# ═══════════════════════════════════════════════════════════════════════════

def cmd_agents_register(args: argparse.Namespace) -> None:
    """Register a new agent and show which policies it matches."""
    token = _require_token(args)
    client = _get_client(args.url, token)

    payload = {"name": args.name}
    if args.vendor:
        payload["vendor"] = args.vendor
    if args.type:
        payload["agent_type"] = args.type
    if args.description:
        payload["description"] = args.description
    if args.tag:
        payload["tags"] = args.tag

    # Check if an agent with this name already exists
    check = client.get("/agents", params={"limit": 200})
    if check.is_success:
        existing = [a for a in check.json().get("agents", []) if a["name"] == args.name]
        if existing:
            a = existing[0]
            aid = a["agent_id"]
            token_path = paths.agent_identity_file(args.name)

            print(f"\n  ⚠  An agent named '{args.name}' is already registered.")
            print(f"  ID:      {aid}")
            print(f"  Vendor:  {a.get('vendor') or '—'}")
            print(f"  Type:    {a.get('agent_type') or '—'}")
            if token_path.exists():
                print(f"  Token:   {token_path}")
            print()
            print(f"  To refresh its token:   leash agents register --name '{args.name}' --force")
            print(f"  To delete & re-create:  leash agents delete {args.name}")

            if not getattr(args, "force", False):
                print()
                return

            # --force was given — rotate keys and refresh token
            agent_own_token = _find_agent_token(aid)
            rot_client = _get_client(args.url, agent_own_token or token)
            rot_resp = rot_client.post(f"/agents/{aid}/rotate")
            if rot_resp.is_success:
                agent_token = rot_resp.json()["token"]
                paths.write_private(
                    token_path, json.dumps({"agent_id": aid, "token": agent_token, "name": args.name}, indent=2)
                )
                print(f"  ↻ Token refreshed for '{args.name}'")
                print(f"  Token → {token_path}\n")
            else:
                print(f"  ✘ Could not refresh token (HTTP {rot_resp.status_code}).")
                print(f"  Try: leash agents delete {args.name} && leash agents register --name '{args.name}'\n",
                       file=sys.stderr)
                sys.exit(1)
            return

    resp = client.post("/agents", json=payload)
    if resp.status_code == 422:
        print(f"\n  ✘ Validation error: {resp.json().get('detail')}\n", file=sys.stderr)
        sys.exit(1)
    resp.raise_for_status()
    data = resp.json()

    aid = data["agent_id"]
    agent_token = data["token"]

    print(f"\n  ✔ Registered '{args.name}'")
    print(f"  ID:     {aid}")
    print(f"  Type:   {data.get('agent_type') or '—'}")
    print(f"  Vendor: {data.get('vendor') or '—'}")

    # Show which policies immediately apply (using the new agent's own token)
    try:
        new_client = _get_client(args.url, agent_token)
        pol_resp = new_client.get(f"/agents/{aid}/permissions")
        if pol_resp.is_success:
            perms = pol_resp.json()
            allowed = perms.get("allowed_actions", 0)
            denied = perms.get("denied_actions", 0)
            policies = {p["policy_name"] for p in perms.get("permissions", [])}
            print(f"\n  Policies applied: {', '.join(sorted(policies)) or 'default (deny-all)'}")
            print(f"  Effective rules:  ✔ {allowed} allow   ✘ {denied} deny")
    except Exception:
        pass

    # Save the new agent's token
    token_path = paths.agent_identity_file(args.name)
    paths.write_private(
        token_path, json.dumps({"agent_id": aid, "token": agent_token, "name": args.name}, indent=2)
    )
    print(f"\n  Token saved \u2192 {token_path}")
    print(f"  Use with SDK: LeashAgent(name='{args.name}')  (picks up this identity automatically)")
    print()


# ═══════════════════════════════════════════════════════════════════════════
# agents deregister
# ═══════════════════════════════════════════════════════════════════════════

def cmd_agents_deregister(args: argparse.Namespace) -> None:
    """Remove an agent from Leash."""
    token = _require_token(args)
    client = _get_client(args.url, token)

    # ── resolve name → id ───────────────────────────────────────────────
    agent_id = args.agent_id
    agent_name = None  # will be set if we can resolve it

    if len(agent_id) != 36 or "-" not in agent_id:
        check = client.get("/agents", params={"limit": 200})
        if check.is_success:
            matches = [a for a in check.json().get("agents", []) if a["name"] == agent_id]
            if not matches:
                print(f"\n  No agent named '{agent_id}' found.\n", file=sys.stderr)
                sys.exit(1)
            if len(matches) > 1:
                print(f"\n  Multiple agents named '{agent_id}' found (use ID):", file=sys.stderr)
                for m in matches:
                    print(f"    {m['agent_id']}  {m['name']}", file=sys.stderr)
                sys.exit(1)
            agent_name = matches[0]["name"]
            agent_id = matches[0]["agent_id"]

    # ── confirmation ────────────────────────────────────────────────────
    display = agent_name or agent_id
    if not getattr(args, "yes", False):
        print(f"\n  About to delete agent '{display}' (ID: {agent_id})")
        print("  This will revoke its token and remove all identity data.")
        answer = input("  Continue? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("  Cancelled.\n")
            return

    # ── delete (use the agent's own token for identity enforcement) ─────
    agent_token = _find_agent_token(agent_id) or token
    del_client = _get_client(args.url, agent_token)
    resp = del_client.delete(f"/agents/{agent_id}")
    if resp.status_code == 404:
        print(f"\n  Agent '{display}' not found.\n", file=sys.stderr)
        sys.exit(1)
    if resp.status_code == 403:
        print(f"\n  ✘ Permission denied — the cached token for '{display}' may be stale.", file=sys.stderr)
        print(f"  Try: leash agents register --name '{display}' --force  (to refresh the token first)\n", file=sys.stderr)
        sys.exit(1)
    resp.raise_for_status()

    # ── clean up cached token file ──────────────────────────────────────
    removed_file = False
    for path in _cached_identity_files():
        try:
            data = json.loads(path.read_text())
            if data.get("agent_id") == agent_id:
                path.unlink()
                removed_file = True
        except Exception:
            continue

    print(f"\n  ✔ Deleted '{display}' (ID: {agent_id})")
    if removed_file:
        print("  Cached token removed.")
    print()

def cmd_agents_show(args: argparse.Namespace) -> None:
    # Bootstrap a client to resolve the identifier
    token = _require_token(args)
    client = _get_client(args.url, token)
    agent_id, agent_token = _resolve_agent_id(client, args.agent_id)
    # Re-create client with the agent's own token for identity enforcement
    client = _get_client(args.url, agent_token or token)

    resp = client.get(f"/agents/{agent_id}")
    if resp.status_code == 404:
        print(f"\n  Agent '{args.agent_id}' not found.\n", file=sys.stderr)
        sys.exit(1)
    resp.raise_for_status()
    a = resp.json()

    print(f"\n  Agent: {a.get('name', '?')}")
    print(f"  ID:      {a.get('agent_id', '?')}")
    print(f"  Vendor:  {a.get('vendor') or '—'}")
    print(f"  Type:    {a.get('agent_type') or '—'}")
    print(f"  Tags:    {', '.join(a.get('tags') or []) or '—'}")
    print(f"  Created: {_fmt_time(a.get('created_at'))}")
    print(f"  Seen:    {_fmt_time(a.get('last_seen_at') or a.get('last_seen'))}")
    if a.get("description"):
        print(f"  Desc:    {a['description']}")
    print()


# ═══════════════════════════════════════════════════════════════════════════
# agents permissions
# ═══════════════════════════════════════════════════════════════════════════

def cmd_agents_permissions(args: argparse.Namespace) -> None:
    # Bootstrap a client to resolve the identifier
    token = _require_token(args)
    client = _get_client(args.url, token)
    agent_id, agent_token = _resolve_agent_id(client, args.agent_id)
    # Re-create client with the agent's own token for identity enforcement
    client = _get_client(args.url, agent_token or token)

    resp = client.get(f"/agents/{agent_id}/permissions")
    if resp.status_code == 404:
        print(f"\n  Agent '{args.agent_id}' not found.\n", file=sys.stderr)
        sys.exit(1)
    resp.raise_for_status()
    data = resp.json()

    perms = data.get("permissions", [])
    total = data.get("total_rules", len(perms))
    allowed = data.get("allowed_actions", 0)
    denied = data.get("denied_actions", 0)

    display = args.agent_id if args.agent_id != agent_id else agent_id
    print(f"\n  Effective permissions for: {display}")
    print(f"  Rules: {total} (✔ {allowed} allow, ✘ {denied} deny)")
    print(f"  {'─' * 60}")

    for p in perms:
        icon = "✔" if p["effect"] == "allow" else "✘"
        action = p["action"]
        if p.get("resource"):
            action += f" resource={p['resource']}"
        extras = []
        if p.get("has_conditions"):
            extras.append("ABAC")
        if p.get("has_rate_limit"):
            extras.append("rate-limited")
        extra_str = f" [{', '.join(extras)}]" if extras else ""
        policy = p.get("policy_name", "?")
        pri = p.get("policy_priority", "?")
        print(f"  {icon} {action}{extra_str} ← {policy} (pri {pri})")

    print()


# ═══════════════════════════════════════════════════════════════════════════
# policy list
# ═══════════════════════════════════════════════════════════════════════════

def cmd_policy_list(args: argparse.Namespace) -> None:
    token = _require_token(args)
    client = _get_client(args.url, token)

    resp = client.get("/policies/managed", params={"limit": args.limit})
    resp.raise_for_status()
    data = resp.json()

    managed = data.get("policies", [])

    # Also show YAML policies by listing the directory
    yaml_dir = paths.policies_dir()
    yaml_policies: list[dict] = []
    if yaml_dir.exists():
        import yaml as _yaml
        for f in sorted(yaml_dir.glob("*.y*ml")):
            try:
                doc = _yaml.safe_load(f.read_text())
                if doc:
                    yaml_policies.append({
                        "name": doc.get("name", f.stem),
                        "priority": doc.get("priority", 0),
                        "agents": doc.get("agents", []),
                        "rules": len(doc.get("rules", [])),
                        "source": "yaml",
                    })
            except Exception:
                yaml_policies.append({"name": f.stem, "source": "yaml", "error": True})

    print("\n  ── YAML Policies (from disk) ──")
    if yaml_policies:
        for p in yaml_policies:
            if p.get("error"):
                print(f"  ⚠ {p['name']} (parse error)")
            else:
                agents = ", ".join(p.get("agents", [])) or "*"
                print(f"  • {p['name']:30s} pri={p['priority']:3d}  rules={p['rules']:2d}  agents=[{agents}]")
    else:
        print("  (none)")

    print("\n  ── Managed Policies (from DB) ──")
    if managed:
        for p in managed:
            status = "active" if p.get("active") else "inactive"
            print(f"  • {p['name']:30s} pri={p['priority']:3d}  [{status}]  updated={_fmt_time(p.get('updated_at'))}")
    else:
        print("  (none)")
    print()


# ═══════════════════════════════════════════════════════════════════════════
# policy validate
# ═══════════════════════════════════════════════════════════════════════════

def cmd_policy_validate(args: argparse.Namespace) -> None:
    from leash.engine.validator import validate_policy_file

    targets: list[Path] = []
    for p in args.path:
        path = Path(p)
        if path.is_dir():
            targets.extend(sorted(path.glob("*.y*ml")))
        elif path.is_file():
            targets.append(path)
        else:
            print(f"  ✘ {p}: not found", file=sys.stderr)

    if not targets:
        print("  No YAML files found to validate.", file=sys.stderr)
        sys.exit(1)

    total_errors = 0
    for t in targets:
        errors = validate_policy_file(t)
        if errors:
            total_errors += len(errors)
            print(f"\n  ✘ {t}")
            for e in errors:
                # Strip the filename prefix since we already printed it
                msg = e.split(": ", 1)[-1] if ": " in e else e
                print(f"    → {msg}")
        else:
            print(f"  ✔ {t}")

    print()
    if total_errors:
        print(f"  {total_errors} error(s) in {len(targets)} file(s)\n")
        sys.exit(1)
    else:
        print(f"  All {len(targets)} file(s) valid\n")


# ═══════════════════════════════════════════════════════════════════════════
# policy test (live authorize or dry-run)
# ═══════════════════════════════════════════════════════════════════════════

def cmd_policy_test(args: argparse.Namespace) -> None:
    token = _require_token(args)
    client = _get_client(args.url, token)

    # Resolve agent name → UUID so name-based policy matching works
    agent_id, agent_token = _resolve_agent_id(client, args.agent)
    if agent_token:
        # Use the agent's own token for identity enforcement
        client = _get_client(args.url, agent_token)
    display_name = args.agent if args.agent != agent_id else agent_id

    if args.policy_file:
        # Dry-run against a candidate policy
        policy_yaml = Path(args.policy_file).read_text()
        actions = [{"action": a} for a in args.action]
        resp = client.post("/policies/dry-run", json={
            "policy_yaml": policy_yaml,
            "agent_id": agent_id,
            "actions": actions,
        })
        resp.raise_for_status()
        data = resp.json()
        print(f"\n  Dry-run against: {args.policy_file}")
        print(f"  Agent: {display_name}")
        print(f"  {'─' * 50}")
        for r in data["results"]:
            icon = "✔" if r["decision"] == "allow" else "✘"
            owasp = f"  [{', '.join(r.get('owasp') or [])}]" if r.get("owasp") else ""
            print(f"  {icon} {r['action']:30s} → {r['decision']:5s}  {r['reason']}{owasp}")
        print(f"\n  {data['summary']}\n")
    else:
        # Live authorize checks
        print("\n  Live policy check")
        print(f"  Agent: {display_name}")
        print(f"  {'─' * 50}")
        for action in args.action:
            resp = client.post("/authorize", json={
                "agent_id": agent_id,
                "action": action,
            })
            resp.raise_for_status()
            r = resp.json()
            icon = "✔" if r["decision"] == "allow" else "✘"
            policy = r.get("matched_policy", "—")
            rule = r.get("matched_rule", "—")
            owasp = f"  [{', '.join(r.get('owasp') or [])}]" if r.get("owasp") else ""
            print(f"  {icon} {action:30s} → {r['decision']:5s}  via {policy}/{rule}{owasp}")
        print()


# ═══════════════════════════════════════════════════════════════════════════
# audit summary
# ═══════════════════════════════════════════════════════════════════════════

def cmd_audit_summary(args: argparse.Namespace) -> None:
    token = _require_token(args)
    client = _get_client(args.url, token)

    resp = client.get("/audit/summary")
    resp.raise_for_status()
    data = resp.json()

    total = data.get("total_entries", 0)
    allowed = data.get("total_allowed", 0)
    denied = data.get("total_denied", 0)
    rate = (denied / total * 100) if total else 0

    print("\n  Audit Summary")
    print(f"  {'─' * 40}")
    print(f"  Total actions:  {total}")
    print(f"  Allowed:        {allowed}")
    print(f"  Denied:         {denied}")
    print(f"  Deny rate:      {rate:.1f}%")

    breakdown = data.get("per_action", {})
    if breakdown:
        print("\n  Per-action breakdown:")
        for action, counts in sorted(breakdown.items(), key=lambda x: -(x[1].get("total", 0))):
            t = counts.get("total", 0)
            a = counts.get("allowed", 0)
            d = counts.get("denied", 0)
            print(f"    {action:30s}  {t:3d}x (✔{a} ✘{d})")
    print()


# ═══════════════════════════════════════════════════════════════════════════
# audit log
# ═══════════════════════════════════════════════════════════════════════════

def cmd_audit_log(args: argparse.Namespace) -> None:
    token = _require_token(args)
    client = _get_client(args.url, token)

    params: dict = {"limit": args.limit}
    if args.agent:
        params["agent_id"] = args.agent
    if args.decision:
        params["decision"] = args.decision
    if args.action:
        params["action"] = args.action

    resp = client.get("/audit", params=params)
    resp.raise_for_status()
    data = resp.json()

    entries = data.get("entries", [])
    total = data.get("total", len(entries))

    if not entries:
        print("\n  No audit entries found.\n")
        return

    print(f"\n  Audit Log ({len(entries)} of {total})")
    print(f"  {'─' * 70}")

    for e in entries:
        decision = e.get("policy_decision") or e.get("decision") or "?"
        icon = "✔" if decision == "allow" else "✘"
        ts = _fmt_time(e.get("timestamp"))
        action = e.get("action", "?")
        agent = e.get("agent_id", "?")[:12]
        reason = e.get("reason", "")[:40]
        print(f"  {icon} {ts}  {agent:12s}  {action:25s}  {reason}")
    print()


# ═══════════════════════════════════════════════════════════════════════════
# audit scan (chain detection)
# ═══════════════════════════════════════════════════════════════════════════

def cmd_audit_scan(args: argparse.Namespace) -> None:
    token = _require_token(args)
    client = _get_client(args.url, token)

    # Build agent_id → name lookup for friendly output
    agent_names: dict[str, str] = {}
    try:
        agents_resp = client.get("/agents", params={"limit": 200})
        if agents_resp.is_success:
            for a in agents_resp.json().get("agents", []):
                agent_names[a["agent_id"]] = a["name"]
    except Exception:
        pass

    def agent_label(aid: str) -> str:
        name = agent_names.get(aid)
        return f"{name} ({aid[:8]}…)" if name else aid[:12] + "…"

    body: dict = {"window": args.window, "limit": args.limit}
    if args.agent:
        body["agent_id"] = args.agent

    resp = client.post("/audit/scan", json=body)
    resp.raise_for_status()
    data = resp.json()

    # Severity icons
    SEV = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    }

    # Overall status banner
    status = data["status"]
    if status == "clean":
        banner = "  ✅ CLEAN — no issues found"
    elif status == "warnings":
        banner = "  ⚠️  WARNINGS — review findings below"
    else:
        banner = "  🚨 CRITICAL — immediate attention required"

    print("\n  Leash Audit Security Scan")
    print(f"  {'─' * 55}")
    print(f"  Entries scanned: {data['entries_scanned']}")
    print(f"  Checks run:      {data['checks_run']}")
    print(f"  Total findings:  {data['total_findings']}")
    if data["total_findings"] > 0:
        counts = []
        for sev, key in [("critical", "critical_count"), ("high", "high_count"),
                         ("medium", "medium_count"), ("low", "low_count")]:
            n = data.get(key, 0)
            if n > 0:
                counts.append(f"{SEV[sev]} {n} {sev}")
        if counts:
            print(f"  Breakdown:       {', '.join(counts)}")
    print(f"\n{banner}\n")

    # Per-check results
    for check in data.get("checks", []):
        findings = check.get("findings", [])

        if check["status"] == "pass":
            print(f"  ✔ {check['title']}")
            print(f"    {check.get('summary', 'OK')}")
        else:
            icon = "✘" if check["status"] == "fail" else "⚠"
            print(f"  {icon} {check['title']}")
            print(f"    {check.get('summary', '')}")
            for f in findings[:8]:
                agent_str = f"  ({agent_label(f['agent_id'])})" if f.get("agent_id") else ""
                print(f"    {SEV.get(f['severity'], '?')} [{f['severity'].upper()}] {f['title']}{agent_str}")
                if f.get("detail"):
                    detail = f["detail"]
                    if len(detail) > 90:
                        detail = detail[:87] + "..."
                    print(f"      {detail}")
            if len(findings) > 8:
                print(f"    … and {len(findings) - 8} more")
        print()


# ═══════════════════════════════════════════════════════════════════════════
# audit export
# ═══════════════════════════════════════════════════════════════════════════

def cmd_audit_export(args: argparse.Namespace) -> None:
    """Export audit log as JSONL to stdout (pipe to file, jq, log collector)."""
    token = _require_token(args)
    client = _get_client(args.url, token)

    params: dict = {"format": "jsonl", "limit": args.limit}
    if args.since:
        params["since"] = args.since
    if args.agent:
        params["agent_id"] = args.agent
    if args.decision:
        params["decision"] = args.decision
    if args.action:
        params["action"] = args.action

    resp = client.get("/audit/export", params=params)
    resp.raise_for_status()

    content = resp.text.strip()
    if not content:
        print("  No audit entries found matching filters.", file=sys.stderr)
        return

    lines = content.split("\n")
    if args.pretty:
        for line in lines:
            try:
                obj = json.loads(line)
                print(json.dumps(obj, indent=2))
            except json.JSONDecodeError:
                print(line)
    else:
        # Raw JSONL to stdout (pipe-friendly)
        for line in lines:
            print(line)


# ═══════════════════════════════════════════════════════════════════════════
# status
# ═══════════════════════════════════════════════════════════════════════════

def cmd_status(args: argparse.Namespace) -> None:
    client = _get_client(args.url)

    # Health
    try:
        resp = client.get("/health")
        if resp.status_code == 200:
            print(f"\n  ✔ Leash is running at {args.url}")
        else:
            print(f"\n  ⚠ Leash returned {resp.status_code}")
    except httpx.ConnectError:
        print(f"\n  ✘ Cannot reach Leash at {args.url}")
        sys.exit(1)

    # Metrics (if available)
    try:
        resp = client.get("/metrics")
        if resp.status_code == 200:
            lines = resp.text.strip().split("\n")
            metrics = [line for line in lines if not line.startswith("#") and line.strip()]
            print(f"  Metrics: {len(metrics)} data points")

            # Group: show key aggregate metrics first, then a compact summary
            key_prefixes = (
                "leash_agents_registered",
                "leash_audit_entries",
                "leash_authorize_total",
                "leash_policies_loaded",
            )
            key_metrics = [m for m in metrics if any(m.startswith(p) for p in key_prefixes)]
            other_metrics = [m for m in metrics if m not in key_metrics]

            for m in key_metrics:
                print(f"    {m}")

            if other_metrics:
                # Show a compact summary of remaining metrics
                http_count = sum(1 for m in other_metrics if "http_request" in m and "duration" not in m)
                duration_count = sum(1 for m in other_metrics if "duration" in m)
                rest = len(other_metrics) - http_count - duration_count
                parts = []
                if http_count:
                    parts.append(f"{http_count} HTTP counters")
                if duration_count:
                    parts.append(f"{duration_count} latency metrics")
                if rest > 0:
                    parts.append(f"{rest} other")
                print(f"    + {', '.join(parts)}")
    except Exception:
        pass

    print()


# ═══════════════════════════════════════════════════════════════════════════
# scan (security surface scanner)
# ═══════════════════════════════════════════════════════════════════════════

def cmd_scan(args: argparse.Namespace) -> None:
    """Scan an MCP server's tool surface for security risks."""
    from leash.scanner import (
        MCPScanner,
        classify_tools,
        analyze_policy_coverage,
        generate_policy,
        format_scan_table,
    )

    # Parse upstream command (strip leading --)
    upstream = args.upstream_cmd
    if upstream and upstream[0] == "--":
        upstream = upstream[1:]

    if not upstream:
        print("\n  ✘ No MCP server command provided.", file=sys.stderr)
        print("  Usage: leash scan -- npx -y @modelcontextprotocol/server-filesystem /data\n", file=sys.stderr)
        sys.exit(1)

    # Step 1: Discover tools from the MCP server
    print(f"\n  Connecting to: {' '.join(upstream)}", file=sys.stderr)
    scanner = MCPScanner(upstream, timeout=args.timeout)
    try:
        tools = scanner.discover()
    except RuntimeError as exc:
        print(f"\n  ✘ Scan failed: {exc}\n", file=sys.stderr)
        sys.exit(1)

    if not tools:
        print("\n  ⚠ No tools discovered from the MCP server.\n", file=sys.stderr)
        sys.exit(0)

    print(f"  Discovered {len(tools)} tools — classifying...\n", file=sys.stderr)

    # Step 2: Classify and check coverage
    classified = classify_tools(tools)
    scan = analyze_policy_coverage(
        classified,
        agent_id=args.agent or "",
        agent_name=args.agent_name or "",
    )
    scan.target = " ".join(upstream)

    # Step 3: Output
    if args.format == "json":
        print(json.dumps(scan.to_dict(), indent=2))
    else:
        print(format_scan_table(scan))

    # Step 4: Generate policy if requested
    gen_policy = args.generate_policy or args.save_policy
    if gen_policy:
        policy_yaml = generate_policy(
            scan,
            policy_name=args.policy_name,
            agent_pattern=args.agent_pattern,
        )
        if args.save_policy:
            Path(args.save_policy).write_text(policy_yaml)
            print(f"\n  ✔ Policy written to {args.save_policy}")
            print(f"  Validate with: leash policy validate {args.save_policy}\n")
        else:
            print(f"\n{'─' * 60}")
            print("  Generated starter policy:\n")
            print(policy_yaml)


# ═══════════════════════════════════════════════════════════════════════════
# Parser
# ═══════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════
# doctor (health-check)
# ═══════════════════════════════════════════════════════════════════════════

def cmd_doctor(args: argparse.Namespace) -> None:
    """Run a comprehensive health-check against the Leash deployment."""
    checks: list[dict] = []

    def _check(name: str, status: str, detail: str, severity: str = "info") -> None:
        checks.append({"check": name, "status": status, "detail": detail, "severity": severity})

    # ── 1. Server reachability ─────────────────────────────────────────────
    client = _get_client(args.url)
    try:
        resp = client.get("/health")
        if resp.status_code == 200:
            _check("server", "pass", f"Leash is running at {args.url}")
        else:
            _check("server", "fail", f"Server returned HTTP {resp.status_code}", "critical")
    except Exception:
        _check("server", "fail", f"Cannot reach Leash at {args.url}", "critical")
        _print_doctor(checks, args)
        sys.exit(1)

    # Need auth for the remaining checks
    token = _load_token(args.token, getattr(args, "token_file", None))
    if not token:
        _check("auth", "warn", "No token found — run 'leash init' first. Skipping authenticated checks.", "medium")
        _print_doctor(checks, args)
        return
    _check("auth", "pass", "Token loaded")
    auth_client = _get_client(args.url, token)

    # ── 2. Server key age ──────────────────────────────────────────────────
    try:
        keys_path = paths.keys_dir()
        priv_key = keys_path / "server_private.pem"
        if priv_key.exists():
            key_stat = priv_key.stat()
            age_days = (datetime.now() - datetime.fromtimestamp(key_stat.st_mtime)).days
            perms = oct(key_stat.st_mode & 0o777)
            if age_days > 90:
                _check("key_age", "warn", f"Server signing key is {age_days} days old — run 'leash server rotate-keys'", "medium")
            else:
                _check("key_age", "pass", f"Server signing key age: {age_days} days")
            if perms != "0o600":
                _check("key_perms", "warn", f"Private key permissions are {perms} (expected 0o600)", "medium")
            else:
                _check("key_perms", "pass", "Private key permissions: 0o600")
        else:
            _check("key_age", "info", "Key check skipped — not running on server host")
    except ImportError:
        _check("key_age", "info", "Key check skipped — app module not available (remote CLI)")

    # ── 3. Stale agents (no activity in 30+ days) ─────────────────────────
    try:
        resp = auth_client.get("/agents", params={"limit": 200})
        if resp.is_success:
            agents = resp.json().get("agents", [])
            stale = []
            for a in agents:
                last_seen = a.get("last_seen_at")
                if last_seen:
                    try:
                        ls = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                        age = (datetime.now(ls.tzinfo) - ls).days
                        if age > 30:
                            stale.append(f"{a['name']} ({age}d)")
                    except (ValueError, TypeError):
                        pass
                else:
                    stale.append(f"{a['name']} (never seen)")
            if stale:
                _check("stale_agents", "warn",
                       f"{len(stale)} stale agent(s): {', '.join(stale[:5])}"
                       + (f" … and {len(stale)-5} more" if len(stale) > 5 else ""),
                       "low")
            else:
                _check("stale_agents", "pass", f"All {len(agents)} agent(s) active within 30 days")
        else:
            _check("stale_agents", "warn", f"Could not list agents (HTTP {resp.status_code})", "low")
    except Exception as exc:
        _check("stale_agents", "warn", f"Agent check failed: {exc}", "low")

    # ── 4. Orphaned policies (no matching agents) ─────────────────────────
    try:
        resp = auth_client.get("/policies/overview")
        if resp.is_success:
            overview = resp.json()
            yaml_policies = overview.get("yaml_policies", [])
            managed_active = overview.get("managed_active", 0)
            total = len(yaml_policies) + managed_active
            # Check if any YAML policy has zero matching agents
            unmatched = [p["name"] for p in yaml_policies if p.get("matched_agents", 0) == 0 and p.get("name") != "default"]
            if unmatched:
                _check("orphan_policies", "warn",
                       f"{len(unmatched)} policy(ies) match no agents: {', '.join(unmatched[:5])}",
                       "low")
            else:
                _check("orphan_policies", "pass", f"{total} policy(ies) loaded, all matched")
        else:
            _check("orphan_policies", "info", "Policy overview not available")
    except Exception:
        _check("orphan_policies", "info", "Policy overview check skipped")

    # ── 5. Policy coverage gaps (agents with no matching policies) ────────
    try:
        resp_agents = auth_client.get("/agents", params={"limit": 500})
        if resp_agents.is_success:
            agents = resp_agents.json().get("agents", [])
            uncovered = []
            for a in agents:
                try:
                    perm_resp = auth_client.get(f"/agents/{a['agent_id']}/permissions")
                    if perm_resp.is_success:
                        perms = perm_resp.json()
                        permissions = perms.get("permissions", [])
                        # Extract unique policy names from the permissions list
                        policy_names = {p.get("policy_name", "") for p in permissions}
                        non_default = [p for p in policy_names if p != "default"]
                        if not non_default:
                            uncovered.append(a["name"])
                except Exception:
                    pass
            if uncovered:
                _check("coverage_gaps", "warn",
                       f"{len(uncovered)} agent(s) only match the default catch-all: {', '.join(uncovered[:5])}"
                       + (f" … and {len(uncovered)-5} more" if len(uncovered) > 5 else ""),
                       "medium")
            else:
                _check("coverage_gaps", "pass", f"All {len(agents)} agent(s) have dedicated policy coverage")
    except Exception:
        _check("coverage_gaps", "info", "Coverage gap check skipped")

    # ── 6. Audit integrity (hash chain + deny storms) ─────────────────────
    try:
        scan_resp = auth_client.post("/audit/scan", json={"limit": 500, "window": 3600})
        if scan_resp.is_success:
            scan = scan_resp.json()
            if scan["status"] == "clean":
                _check("audit_integrity", "pass",
                       f"Audit scan clean — {scan['entries_scanned']} entries, {scan['checks_run']} checks")
            else:
                findings = scan.get("total_findings", 0)
                critical = scan.get("critical_count", 0)
                high = scan.get("high_count", 0)
                sev = "critical" if critical > 0 else "high" if high > 0 else "medium"
                _check("audit_integrity", "fail",
                       f"Audit scan found {findings} issue(s) "
                       f"(🔴 {critical} critical, 🟠 {high} high) — run 'leash audit scan' for details",
                       sev)
        else:
            _check("audit_integrity", "info", f"Audit scan returned HTTP {scan_resp.status_code}")
    except Exception:
        _check("audit_integrity", "info", "Audit scan check skipped")

    # ── 7. Policy YAML validation (local files) ───────────────────────────
    try:
        from leash.engine.validator import validate_policy_yaml
        policy_dir = paths.policies_dir()
        if policy_dir.exists():
            errors = []
            yaml_files = list(policy_dir.glob("*.yaml")) + list(policy_dir.glob("*.yml"))
            for yf in yaml_files:
                issues = validate_policy_yaml(yf.read_text())
                # Filter out "missing reason" warnings — only keep real errors
                real_errors = [i for i in issues if "recommended" not in i.lower()]
                if real_errors:
                    errors.append(f"{yf.name}: {real_errors[0]}")
            if errors:
                _check("policy_yaml", "fail",
                       f"{len(errors)} invalid policy file(s): {'; '.join(errors[:3])}", "high")
            else:
                _check("policy_yaml", "pass", f"{len(yaml_files)} policy file(s) valid")
        else:
            _check("policy_yaml", "info", "Policy directory not found (not running on server host)")
    except ImportError:
        _check("policy_yaml", "info", "Policy validation skipped — app module not available")

    _print_doctor(checks, args)


def _print_doctor(checks: list[dict], args: argparse.Namespace) -> None:
    """Render doctor results to stdout."""
    if getattr(args, "json_out", False):
        passed = sum(1 for c in checks if c["status"] == "pass")
        total = len(checks)
        print(json.dumps({"passed": passed, "total": total, "checks": checks}, indent=2))
        return

    ICONS = {"pass": "✔", "fail": "✘", "warn": "⚠", "info": "ℹ"}
    COLORS = {"pass": "\033[32m", "fail": "\033[31m", "warn": "\033[33m", "info": "\033[36m"}
    RESET = "\033[0m"

    print("\n  Leash Doctor")
    print(f"  {'─' * 55}")

    for c in checks:
        icon = ICONS.get(c["status"], "?")
        color = COLORS.get(c["status"], "")
        print(f"  {color}{icon}{RESET} {c['check']}: {c['detail']}")

    passed = sum(1 for c in checks if c["status"] == "pass")
    warnings = sum(1 for c in checks if c["status"] == "warn")
    failures = sum(1 for c in checks if c["status"] == "fail")
    total = len(checks)

    print(f"  {'─' * 55}")
    summary_parts = [f"{passed}/{total} passed"]
    if warnings:
        summary_parts.append(f"{warnings} warning(s)")
    if failures:
        summary_parts.append(f"{failures} failure(s)")

    if failures:
        print(f"  🚨 {', '.join(summary_parts)}")
    elif warnings:
        print(f"  ⚠️  {', '.join(summary_parts)}")
    else:
        print(f"  ✅ {', '.join(summary_parts)} — looking healthy!")
    print()


# ═══════════════════════════════════════════════════════════════════════════
# server
# ═══════════════════════════════════════════════════════════════════════════

def cmd_server(args: argparse.Namespace) -> None:
    """Start the Leash server (uvicorn)."""
    try:
        import uvicorn
        import fastapi  # noqa: F401
    except ImportError:
        print("  ✘ The Leash server isn't installed. Install it with:\n"
              "      uv tool install 'leash[server]'      (or: pip install 'leash[server]')",
              file=sys.stderr)
        sys.exit(1)

    host = args.host
    port = args.port
    reload = args.reload

    print(f"\n  🐕 Starting Leash server on http://{host}:{port}")
    if reload:
        print("  ↻  Auto-reload enabled (watching for file changes)")
    print(f"  📄 API docs at http://{host}:{port}/docs")
    print(f"  📊 Dashboard at http://{host}:{port}/dashboard")
    print(f"  📁 Policies in {paths.policies_dir()}  (state: {paths.leash_home()})")
    print()

    uvicorn.run(
        "leash.server.main:app",
        host=host,
        port=port,
        reload=reload,
    )


# ═══════════════════════════════════════════════════════════════════════════
# server key rotation
# ═══════════════════════════════════════════════════════════════════════════

def cmd_rotate_server_keys(args: argparse.Namespace) -> None:
    """Rotate the server signing keys via the admin API endpoint."""
    token = _require_token(args)
    client = _get_client(args.url, token)

    # Show current key info first
    print("\n  Current server key status:")
    try:
        info_resp = client.get("/admin/key-info")
        if info_resp.is_success:
            info = info_resp.json()
            age = info.get("age_days", "?")
            perms = info.get("permissions", "?")
            has_prev = info.get("has_previous_key", False)
            print(f"    Age:              {age} days")
            print(f"    Permissions:      {perms}")
            print(f"    Previous key:     {'yes' if has_prev else 'none'}")
            print()
    except Exception:
        print("    (could not fetch key info)")
        print()

    if not getattr(args, "yes", False):
        print("  ⚠  This will:")
        print("    • Archive the current signing key as 'previous'")
        print("    • Generate a new signing key for all future JWTs & signatures")
        print("    • Existing JWTs remain valid (verified via previous key)")
        print("    • Existing audit signatures remain verifiable")
        print()
        confirm = input("  Proceed with server key rotation? [y/N] ").strip().lower()
        if confirm not in ("y", "yes"):
            print("  Cancelled.\n")
            return

    resp = client.post("/admin/rotate-server-keys")
    if resp.is_success:
        result = resp.json()
        print(f"  ✔ Server keys rotated at {result.get('rotated_at', 'now')}")
        print(f"    Previous key archived: {result.get('previous_key_archived', False)}")
        print(f"    {result.get('note', '')}")
        print()
        print("  Next steps:")
        print("    • Agents will auto-refresh tokens on next 401")
        print("    • Or force refresh: leash agents register --name <agent> --force")
        print("    • The old key is kept for verification — no data is lost")
        print()
    elif resp.status_code == 401:
        print("  ✘ Authentication failed — run 'leash init' first", file=sys.stderr)
    elif resp.status_code == 403:
        print("  ✘ Requires admin privileges (agent_type must be cli, admin, or ops)", file=sys.stderr)
    else:
        print(f"  ✘ Server returned HTTP {resp.status_code}: {resp.text}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="leash",
        description="Leash CLI – AI agent governance from the command line",
    )
    parser.add_argument("--version", action="version", version=f"leash {__version__}")
    parser.add_argument("--url", default=LEASH_URL, help="Leash server URL")
    parser.add_argument("--token", help="JWT token for authentication")
    parser.add_argument("--token-file", help="Path to JSON file with 'token' field")

    sub = parser.add_subparsers(dest="command", required=True)

    # ── init ──
    init_p = sub.add_parser("init", help="Register CLI agent & cache token (run this first!)")
    init_p.add_argument("--name", default="cli-admin", help="Agent name (default: cli-admin)")
    init_p.add_argument("--force", action="store_true", help="Re-register even if already initialized")

    # ── agents ──
    agents_parser = sub.add_parser("agents", help="Manage agents")
    agents_sub = agents_parser.add_subparsers(dest="agents_command", required=True)

    # agents register
    ar = agents_sub.add_parser("register", help="Register a new agent")
    ar.add_argument("--name", "-n", required=True, help="Agent name (must match your policy pattern, e.g. 'my-code-bot')")
    ar.add_argument("--vendor", "-v", help="Vendor or framework (e.g. langchain, openai, anthropic, aider)")
    ar.add_argument("--type", "-t", help="Agent type (e.g. coding, research, email, ops)")
    ar.add_argument("--description", "-d", help="What this agent does")
    ar.add_argument("--tag", action="append", metavar="TAG", help="Tag (repeatable, e.g. --tag production --tag backend)")
    ar.add_argument("--force", "-f", action="store_true", help="Overwrite token if agent name already exists")

    # agents list
    al = agents_sub.add_parser("list", help="List registered agents")
    al.add_argument("--vendor", help="Filter by vendor")
    al.add_argument("--type", help="Filter by agent type")
    al.add_argument("--limit", type=int, default=50, help="Max results (default: 50)")

    # agents deregister / delete (alias)
    for alias in ("deregister", "delete"):
        adereg = agents_sub.add_parser(alias, help="Remove an agent from Leash")
        adereg.add_argument("agent_id", help="Agent ID or exact name")
        adereg.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompt")

    # agents show
    ash = agents_sub.add_parser("show", help="Show agent details")
    ash.add_argument("agent_id", help="Agent ID")

    # agents permissions
    ap = agents_sub.add_parser("permissions", help="Show effective permissions")
    ap.add_argument("agent_id", help="Agent ID")

    # ── policy ──
    policy_parser = sub.add_parser("policy", help="Manage policies")
    policy_sub = policy_parser.add_subparsers(dest="policy_command", required=True)

    # policy list
    pl = policy_sub.add_parser("list", help="List all policies (YAML + managed)")
    pl.add_argument("--limit", type=int, default=50, help="Max managed policies")

    # policy validate
    pv = policy_sub.add_parser("validate", help="Validate policy YAML file(s)")
    pv.add_argument("path", nargs="+", help="YAML file or directory to validate")

    # policy test
    pt = policy_sub.add_parser("test", help="Test actions against policies")
    pt.add_argument("--action", "-a", action="append", required=True, help="Action to test (repeatable)")
    pt.add_argument("--agent", default="test-agent", help="Agent name or ID to test as")
    pt.add_argument("--policy-file", "-f", help="Candidate YAML (uses dry-run)")

    # ── audit ──
    audit_parser = sub.add_parser("audit", help="Audit log commands")
    audit_sub = audit_parser.add_subparsers(dest="audit_command", required=True)

    # audit summary
    audit_sub.add_parser("summary", help="Show audit summary stats")

    # audit log
    alog = audit_sub.add_parser("log", help="Show audit log entries")
    alog.add_argument("--agent", help="Filter by agent ID")
    alog.add_argument("--decision", choices=["allow", "deny", "observe_deny"], help="Filter by decision")
    alog.add_argument("--action", help="Filter by action name")
    alog.add_argument("--limit", type=int, default=20, help="Max entries (default: 20)")

    # audit scan
    ascan = audit_sub.add_parser("scan", help="Scan for suspicious action chains")
    ascan.add_argument("--agent", help="Limit scan to specific agent")
    ascan.add_argument("--window", type=int, default=3600, help="Chain window in seconds")
    ascan.add_argument("--limit", type=int, default=100, help="Max entries to scan")

    # audit export
    aexport = audit_sub.add_parser("export", help="Export audit log as JSONL (pipe-friendly)")
    aexport.add_argument("--since", help="Only entries after this time (ISO-8601 or duration: 24h, 7d, 30m)")
    aexport.add_argument("--agent", help="Filter by agent ID")
    aexport.add_argument("--decision", choices=["allow", "deny", "observe_deny"], help="Filter by decision")
    aexport.add_argument("--action", help="Filter by action name")
    aexport.add_argument("--limit", type=int, default=10000, help="Max entries (default: 10000)")
    aexport.add_argument("--pretty", action="store_true", help="Pretty-print each JSON event (not pipe-friendly)")

    # ── status ──
    sub.add_parser("status", help="Check Leash server health and metrics")

    # ── server (aliased as 'start') ──
    server_p = sub.add_parser("start", help="Start the Leash server")
    server_p.add_argument("--host", default=os.getenv("HOST", "127.0.0.1"),
                          help="Bind address (default: 127.0.0.1; use 0.0.0.0 to expose on the network)")
    server_p.add_argument("--port", "-p", type=int, default=8000, help="Port (default: 8000)")
    server_p.add_argument("--reload", action="store_true", help="Auto-reload on code changes (development)")

    # ── server key management ──
    server_mgmt = sub.add_parser("server", help="Server administration commands")
    server_sub = server_mgmt.add_subparsers(dest="server_command", required=True)

    rotate_keys_p = server_sub.add_parser("rotate-keys", help="Rotate the server signing key-pair")
    rotate_keys_p.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompt")

    # ── scan ──
    scan_p = sub.add_parser("scan", help="Scan an MCP server's tool surface for security risks")
    scan_p.add_argument("--generate-policy", action="store_true", help="Generate a starter YAML policy from scan results")
    scan_p.add_argument("--save-policy", metavar="FILE", help="Write generated policy to a file (implies --generate-policy)")
    scan_p.add_argument("--format", choices=["table", "json"], default="table", help="Output format (default: table)")
    scan_p.add_argument("--agent", help="Agent ID to check policy coverage against")
    scan_p.add_argument("--agent-name", help="Agent name pattern to check policy coverage against")
    scan_p.add_argument("--policy-name", default="auto-scan-policy", help="Name for generated policy (default: auto-scan-policy)")
    scan_p.add_argument("--agent-pattern", default='"*"', help="Agent pattern in generated policy (default: \"*\")")
    scan_p.add_argument("--timeout", type=float, default=30.0, help="Timeout in seconds for MCP server connection (default: 30)")
    scan_p.add_argument("upstream_cmd", nargs=argparse.REMAINDER, help="MCP server command (after --)")

    # ── dashboard ──
    dash = sub.add_parser("dashboard", help="Live terminal dashboard")
    dash.add_argument("--refresh", type=int, default=2, help="Refresh interval in seconds (default: 2)")

    # ── doctor ──
    doc_p = sub.add_parser("doctor", help="Health-check your Leash deployment")
    doc_p.add_argument("--json", dest="json_out", action="store_true", help="Output results as JSON")

    args = parser.parse_args()

    # Dispatch
    if args.command == "init":
        cmd_init(args)
    elif args.command == "agents":
        {"list": cmd_agents_list, "register": cmd_agents_register, "deregister": cmd_agents_deregister, "delete": cmd_agents_deregister, "show": cmd_agents_show, "permissions": cmd_agents_permissions}[args.agents_command](args)
    elif args.command == "policy":
        {"list": cmd_policy_list, "validate": cmd_policy_validate, "test": cmd_policy_test}[args.policy_command](args)
    elif args.command == "audit":
        {"summary": cmd_audit_summary, "log": cmd_audit_log, "scan": cmd_audit_scan, "export": cmd_audit_export}[args.audit_command](args)
    elif args.command == "status":
        cmd_status(args)
    elif args.command == "start":
        cmd_server(args)
    elif args.command == "server":
        {"rotate-keys": cmd_rotate_server_keys}[args.server_command](args)
    elif args.command == "scan":
        cmd_scan(args)
    elif args.command == "dashboard":
        from leash.dashboard import run as run_dashboard
        token = _require_token(args)
        run_dashboard(url=args.url, token=token, refresh=args.refresh)
    elif args.command == "doctor":
        cmd_doctor(args)


if __name__ == "__main__":
    main()
