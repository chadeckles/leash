"""``leash mcp ...``: protect MCP servers used by apps that have no hooks
(Claude Desktop, VS Code, Windsurf).  See docs/docs/mcp.md."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from leash.mcp import clients


def register(sub) -> None:
    mcp_p = sub.add_parser("mcp", help="Protect MCP servers in Claude Desktop, VS Code and Windsurf")
    mcp_sub = mcp_p.add_subparsers(dest="mcp_command", required=True)

    run_p = mcp_sub.add_parser("run", help="Run an MCP server behind Leash (used in MCP client configs)")
    run_p.add_argument("--client", help="Which app starts this server (e.g. claude-desktop)")
    run_p.add_argument("--name", help="The server's name in the app's config")
    run_p.add_argument("--server", metavar="URL", help="Check calls with a Leash server instead of local policies")
    run_p.add_argument("cmd", nargs=argparse.REMAINDER, help="-- the MCP server command")

    client_names = ", ".join(clients.CLIENTS)
    wrap_p = mcp_sub.add_parser("wrap", help="Route an app's MCP servers through Leash")
    wrap_p.add_argument("clients", nargs="*", metavar="APP", help=f"{client_names} (default: all found)")
    wrap_p.add_argument("--only", action="append", metavar="SERVER", help="Only wrap this server (repeatable)")
    wrap_p.add_argument("--dry-run", action="store_true", help="Show what would change")

    unwrap_p = mcp_sub.add_parser("unwrap", help="Restore an app's original MCP server commands")
    unwrap_p.add_argument("clients", nargs="*", metavar="APP", help=f"{client_names} (default: all)")
    unwrap_p.add_argument("--dry-run", action="store_true", help="Show what would change")

    status_p = mcp_sub.add_parser("status", help="Show MCP apps, servers, and tools Leash is holding back")
    status_p.add_argument("--json", dest="json_out", action="store_true", help="Output JSON")

    trust_p = mcp_sub.add_parser("trust", help="Review and accept changed MCP tool descriptions")
    trust_p.add_argument("server", help="Server name, as shown by `leash mcp status`")
    trust_p.add_argument("--client", help="Only for this app")
    trust_p.add_argument("--tool", action="append", help="Only this tool (repeatable)")
    trust_p.add_argument("--yes", "-y", action="store_true", help="Don't ask for confirmation")


def dispatch(args: argparse.Namespace) -> None:
    {"run": cmd_run, "wrap": cmd_wrap, "unwrap": cmd_unwrap, "status": cmd_status,
     "trust": cmd_trust}[args.mcp_command](args)


def _valid_clients(names: List[str]) -> List[str]:
    bad = [n for n in names if n not in clients.CLIENTS]
    if bad:
        print(f"  ✘ Unknown app {', '.join(bad)}. Choose from: {', '.join(clients.CLIENTS)}", file=sys.stderr)
        sys.exit(2)
    return names


# ── run ────────────────────────────────────────────────────────────────────

def cmd_run(args: argparse.Namespace) -> None:
    cmd = args.cmd[1:] if args.cmd[:1] == ["--"] else args.cmd
    if not cmd:
        print("usage: leash mcp run [--client APP] [--name NAME] -- <server command> [args...]", file=sys.stderr)
        sys.exit(2)
    if args.server:
        import logging

        from leash.mcp_proxy import MCPProxy

        logging.basicConfig(level=logging.INFO, format="[leash-mcp] %(levelname)s %(message)s", stream=sys.stderr)
        proxy = MCPProxy(upstream_cmd=cmd, leash_url=args.server, agent_name=args.client or "mcp-proxy")
        try:
            proxy.start()
        except KeyboardInterrupt:
            pass
        finally:
            proxy.stop()
        return
    from leash.mcp.proxy import run

    sys.exit(run(cmd, client=args.client, name=args.name))


# ── wrap / unwrap ──────────────────────────────────────────────────────────

def _report(change: clients.Change, verb: str, dry_run: bool) -> None:
    label = clients.label(change.client)
    if change.error:
        print(f"  ! {label}: {change.error}")
        return
    if change.changed:
        prefix = f"Would {verb.lower()}" if dry_run else verb
        print(f"  ✔ {label}: {prefix} {', '.join(change.changed)} → {change.path}")
        if change.backup:
            print(f"      backup: {change.backup}")
    for name, why in change.skipped:
        print(f"  – {label}: skipped {name} ({why})")


def wrap_clients(names: List[str], only: Optional[List[str]] = None, dry_run: bool = False) -> List[str]:
    """Wrap every local server of *names*; returns the apps that changed."""
    changed = []
    for name in names:
        change = clients.wrap(name, only, dry_run)
        _report(change, "Wrapped", dry_run)
        if change.changed:
            changed.append(name)
    return changed


def cmd_wrap(args: argparse.Namespace) -> None:
    names = _valid_clients(args.clients) or clients.detect()
    if not names:
        print("  No MCP apps found (looked for Claude Desktop, VS Code and Windsurf).")
        print("  Claude Code, Copilot CLI, Cursor, Codex and OpenClaw don't need this: `leash setup` covers their MCP tools.")
        return
    changed = wrap_clients(names, args.only, args.dry_run)
    if changed and not args.dry_run:
        print(f"\n  Restart {clients.label(changed[0]) if len(changed) == 1 else 'those apps'} so the change takes effect.")
        print("  Undo any time with:  leash mcp unwrap")
    elif not changed:
        print("  Nothing to wrap: every local MCP server is already behind Leash (or there are none).")


def unwrap_all(names: Optional[List[str]] = None, dry_run: bool = False) -> bool:
    any_changed = False
    for name in names or list(clients.CLIENTS):
        if not clients.config_path(name).exists():
            continue
        change = clients.unwrap(name, None, dry_run)
        _report(change, "Unwrapped", dry_run)
        any_changed |= bool(change.changed)
    return any_changed


def cmd_unwrap(args: argparse.Namespace) -> None:
    if not unwrap_all(_valid_clients(args.clients), args.dry_run):
        print("  Nothing to unwrap.")


# ── status / trust ─────────────────────────────────────────────────────────

def status_rows() -> List[dict]:
    from leash.mcp.pins import Pins

    pins = {(p.client, p.server): p for p in Pins.all()}
    rows = []
    for name in clients.detect():
        found, err = clients.servers(name)
        rows.append({"client": name, "path": str(clients.config_path(name)), "error": err, "servers": [
            {"name": s.name, "wrapped": s.wrapped, "remote": s.remote, "command": s.command,
             "held_back": sorted(pins[(name, s.name)].pending) if (name, s.name) in pins else []}
            for s in found]})
    return rows


def cmd_status(args: argparse.Namespace) -> None:
    rows = status_rows()
    if args.json_out:
        print(json.dumps(rows, indent=2))
        return
    if not rows:
        print("\n  No MCP apps found (Claude Desktop, VS Code, Windsurf).\n")
        return
    print()
    for row in rows:
        print(f"  {clients.label(row['client'])}  ({row['path']})")
        if row["error"]:
            print(f"    ! {row['error']}")
        if not row["servers"] and not row["error"]:
            print("    no MCP servers configured")
        for s in row["servers"]:
            mark = "✔ protected" if s["wrapped"] else ("– remote (not covered)" if s["remote"] else "✘ not protected")
            print(f"    {s['name']:<20} {mark}")
            for tool in s["held_back"]:
                print(f"      ⚠ holding back tool '{tool}' — review with: leash mcp trust {s['name']}")
        print()
    if any(not s["wrapped"] and not s["remote"] for r in rows for s in r["servers"]):
        print("  Protect the unprotected ones with:  leash mcp wrap\n")


def cmd_trust(args: argparse.Namespace) -> None:
    from leash.mcp.pins import Pins

    matches = [p for p in Pins.all() if p.server == args.server and (not args.client or p.client == args.client)]
    pending = [(p, n, e) for p in matches for n, e in p.pending.items() if not args.tool or n in args.tool]
    if not pending:
        known = sorted({p.server for p in Pins.all()})
        print(f"  Nothing to review for '{args.server}'."
              + (f" Servers Leash knows: {', '.join(known)}" if known else ""))
        return
    print(f"\n  Tools Leash is holding back from '{args.server}':\n")
    for p, name, entry in pending:
        old = p.tools.get(name, {}).get("description")
        print(f"  • {name}  ({clients.label(p.client)}) — {entry.get('why', '')}")
        if old is not None:
            print(f"      before: {old[:400]}")
        print(f"      now:    {entry.get('description', '')[:800]}\n")
    print("  Only trust these if the descriptions look like plain descriptions of what the tool does.")
    print("  Text that gives the AI orders, mentions secret files or asks it to hide things is a red flag.")
    if not args.yes:
        if not sys.stdin.isatty():
            print("  ✘ Run this in a terminal to confirm, or pass --yes.", file=sys.stderr)
            sys.exit(2)
        try:
            if input("\n  Trust them? [y/N] ").strip().lower() not in ("y", "yes"):
                print("  Nothing changed.")
                return
        except EOFError:
            return
    for p in matches:
        p.trust([n for pp, n, _ in pending if pp is p])
    print(f"\n  ✔ Trusted {len(pending)} tool(s). Restart the app (or its MCP server) to see them.\n")
