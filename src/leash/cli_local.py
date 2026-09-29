"""Local (serverless) CLI commands: hooks, presets, local audit, policy tests.

Nothing here imports httpx or talks to a Leash server.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from leash import paths

HOST_CHOICES = ("claude-code", "copilot", "cursor", "codex")


class OrderedChecks(argparse.Action):
    """Collect ``-a ACTION [-r RESOURCE ...]`` groups in command-line order,
    so each resource belongs to the action before it.  Also keeps the plain
    ``args.action`` / ``args.resource`` lists for the server commands."""

    def __call__(self, parser, namespace, values, option_string=None):
        checks = getattr(namespace, "checks", None) or []
        if self.dest == "action":
            checks.append([values, []])
        elif not checks:
            parser.error("--resource must follow an --action")
        else:
            checks[-1][1].append(values)
        namespace.checks = checks
        items = list(getattr(namespace, self.dest, None) or [])
        items.append(values)
        setattr(namespace, self.dest, items)


# ── setup ──────────────────────────────────────────────────────────────────

def _ensure_policies() -> list[str]:
    """Seed ~/.leash/policies on first use and make sure the coding-agent
    preset is present.  Returns human-readable notes."""
    notes = []
    target = paths.policies_dir()
    if not target.exists():
        paths.seed_policies(target)
        notes.append(f"Created {target} with the bundled presets")
    elif paths.install_preset("coding_agent", target):
        notes.append(f"Added the coding-agent preset to {target}")
    return notes


def cmd_install(args: argparse.Namespace) -> None:
    from leash.hooks import install as inst

    scope = "project" if args.project is not None else "user"
    project_dir = Path(args.project) if args.project else None
    host_list = args.hosts or inst.detect_hosts()
    if not host_list:
        print("  No supported agents found. Name one explicitly:", ", ".join(HOST_CHOICES))
        sys.exit(1)

    if not args.dry_run:
        for note in _ensure_policies():
            print(f"  • {note}")

    failed = False
    for host in host_list:
        try:
            r = inst.install(host, scope, project_dir=project_dir, command=args.hook_command, dry_run=args.dry_run)
        except (OSError, ValueError) as exc:
            print(f"  ✘ {host}: {exc}", file=sys.stderr)
            failed = True
            continue
        verb = {"installed": "Installed", "updated": "Updated", "unchanged": "Already installed"}[r.action]
        prefix = "Would write" if args.dry_run and r.content else verb
        print(f"  ✔ {host}: {prefix} → {r.target.path}")
        if r.backup:
            print(f"      backup: {r.backup}")
        if args.dry_run and r.content:
            print("      " + r.content.rstrip().replace("\n", "\n      "))
        for note in r.notes:
            print(f"      note: {note}")

    if not args.dry_run and not failed:
        print("\n  Leash is now checking every tool call. Try it:")
        print("    leash policy test --local --agent claude-code -a shell.exec -r 'rm -rf ~'")
        print("    leash audit tail")
    sys.exit(1 if failed else 0)


def cmd_uninstall(args: argparse.Namespace) -> None:
    from leash.hooks import install as inst

    scope = "project" if args.project is not None else "user"
    project_dir = Path(args.project) if args.project else None
    host_list = args.hosts or list(HOST_CHOICES)
    for host in host_list:
        try:
            r = inst.uninstall(host, scope, project_dir=project_dir, dry_run=args.dry_run)
        except (OSError, ValueError) as exc:
            print(f"  ✘ {host}: {exc}", file=sys.stderr)
            continue
        if r.action == "removed":
            print(f"  ✔ {host}: {'Would remove' if args.dry_run else 'Removed'} from {r.target.path}")
            if r.backup:
                print(f"      backup: {r.backup}")
        elif args.hosts:
            print(f"  – {host}: not installed ({r.target.path})")


def cmd_hosts(args: argparse.Namespace) -> None:
    from leash.hooks import install as inst

    rows = inst.status(Path(args.project) if args.project else None)
    if args.json_out:
        print(json.dumps(rows, indent=2))
        return
    print(f"\n  {'AGENT':<12} {'DETECTED':<9} {'USER':<6} {'PROJECT':<8} ")
    print(f"  {'─' * 40}")
    by_host: dict[str, dict] = {}
    for row in rows:
        by_host.setdefault(row["host"], {"detected": row["detected"]})[row["scope"]] = row
    for host, info in by_host.items():
        def mark(scope: str) -> str:
            r = info[scope]
            return "error" if r["error"] else ("✔" if r["installed"] else "–")
        print(f"  {host:<12} {'yes' if info['detected'] else 'no':<9} {mark('user'):<6} {mark('project'):<8}")
    print("\n  Install with: leash install [agent ...]   (add --project to commit hooks to this repo)\n")


# ── presets ────────────────────────────────────────────────────────────────

def cmd_init_preset(args: argparse.Namespace) -> None:
    if args.list_presets:
        for name in paths.preset_names():
            print(f"  {name.replace('_', '-')}")
        return
    target = paths.policies_dir()
    if not target.exists():
        paths.seed_policies(target, presets=["default"])
    try:
        dest = paths.install_preset(args.preset, target, force=args.force)
    except FileNotFoundError as exc:
        print(f"  ✘ {exc}", file=sys.stderr)
        sys.exit(1)
    if dest is None:
        print(f"  Preset '{args.preset}' already exists in {target} (use --force to overwrite)")
    else:
        print(f"  ✔ Wrote {dest}")


# ── local audit ────────────────────────────────────────────────────────────

_ICONS = {"allow": "✔", "deny": "✘", "ask": "?"}


def _print_entry(e: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(e))
        return
    decision = str(e.get("decision", ""))
    icon = _ICONS.get(decision.replace("observe_", ""), "·")
    where = f"  [{e['policy']}/{e['rule']}]" if e.get("policy") else ""
    print(f"  {e.get('ts', '')[:19]}  {icon} {decision:<13} {e.get('agent', ''):<12} {str(e.get('request', ''))[:80]}{where}")
    if decision != "allow" and e.get("reason"):
        print(f"      {e['reason']}")


def cmd_audit_tail(args: argparse.Namespace) -> None:
    from leash import auditlog

    log = paths.audit_log_file()
    if not log.exists() and not args.follow:
        print(f"  No local audit log yet ({log}). It is created on the first hook decision.")
        return
    for e in auditlog.tail(args.lines):
        _print_entry(e, args.json_out)
    if not args.follow:
        return
    seen = sum(1 for _ in auditlog.read()) if log.exists() else 0
    try:
        while True:
            time.sleep(0.5)
            if not log.exists():
                continue
            entries = list(auditlog.read())
            for e in entries[seen:]:
                _print_entry(e, args.json_out)
            seen = len(entries)
    except KeyboardInterrupt:
        pass


def cmd_audit_verify(args: argparse.Namespace) -> None:
    from leash import auditlog

    ok, count, problem = auditlog.verify()
    if ok:
        print(f"  ✔ Audit chain intact: {count} entries ({paths.audit_log_file()})")
    else:
        print(f"  ✘ Audit chain broken after {count} valid entries: {problem}", file=sys.stderr)
        sys.exit(1)


# ── policy test (local) ────────────────────────────────────────────────────

_TEST_TOOLS = {
    "shell.exec": ("bash", "command"),
    "file.read": ("read", "file_path"),
    "file.write": ("write", "file_path"),
    "file.delete": ("delete", "file_path"),
    "file.search": ("grep", "path"),
    "web.fetch": ("web_fetch", "url"),
    "web.search": ("web_search", "query"),
    "agent.spawn": ("task", "subagent_type"),
}


def _test_call(host: str, action: str, resource: str | None):
    """Build the tool call a hook would see, so shell splitting and path
    resolution apply exactly as they do for real tool calls."""
    import os

    from leash.hooks.actions import ToolCall

    cwd = os.getcwd()
    if action in _TEST_TOOLS:
        tool, key = _TEST_TOOLS[action]
        return ToolCall(host, tool, {key: resource or ""}, cwd=cwd)
    if action.startswith("mcp.") and action.count(".") >= 2:
        _, server, tool = action.split(".", 2)
        return ToolCall(host, f"mcp__{server}__{tool}", {}, cwd=cwd)
    return None


def cmd_policy_test_local(args: argparse.Namespace) -> None:
    import yaml

    from leash.engine import PolicyDirectory, compile_policy, evaluate_policies, sort_policies
    from leash.hooks.hosts import Verdict
    from leash.hooks.runner import evaluate_call

    policies = PolicyDirectory(paths.policies_dir()).policies
    if args.policy_file:
        path = Path(args.policy_file)
        candidate = compile_policy(yaml.safe_load(path.read_text(encoding="utf-8")) or {}, str(path))
        policies = sort_policies([p for p in policies if p.name != candidate.name] + [candidate])
    agent = args.agent
    host = next((h for h in HOST_CHOICES if agent.startswith(h)), "claude-code")

    print(f"\n  Local policy check  (agent: {agent}, policies: {paths.policies_dir()})")
    print(f"  {'─' * 60}")
    blocked = False
    for action, resources in getattr(args, "checks", None) or [(a, []) for a in args.action]:
        for resource in resources or [None]:
            call = _test_call(host, action, resource)
            if call is not None:
                v, _ = evaluate_call(call, policies, agent=agent)
            else:
                d = evaluate_policies(policies, agent, action, resource, {}, agent_name=agent, normalize=False)
                v = Verdict(d.decision, d.reason, d.matched_policy, d.matched_rule)
            label = f"{action} {resource}" if resource else action
            via = f"  via {v.policy}/{v.rule}" if v.policy else ""
            print(f"  {_ICONS.get(v.decision, '·')} {label[:48]:48s} → {v.decision:5s}{via}")
            if v.decision != "allow":
                blocked = True
                print(f"      {v.reason}")
    print()
    if args.strict and blocked:
        sys.exit(1)
