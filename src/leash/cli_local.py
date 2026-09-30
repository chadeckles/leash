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

HOST_CHOICES = ("claude-code", "copilot", "cursor", "codex", "openclaw")
HOST_LABELS = {
    "claude-code": "Claude Code", "copilot": "Copilot CLI", "cursor": "Cursor",
    "codex": "Codex", "openclaw": "OpenClaw",
}


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

def _ensure_policies(hosts: list[str] | None = None) -> list[str]:
    """Seed ~/.leash/policies on first use and make sure the presets the
    hooked agents need are present.  Returns human-readable notes."""
    notes = []
    target = paths.policies_dir()
    if not target.exists():
        paths.seed_policies(target)
        notes.append(f"Created {target} with the bundled presets")
    elif paths.install_preset("coding_agent", target):
        notes.append(f"Added the coding-agent preset to {target}")
    else:
        notes += _upgrade_preset(target, "coding_agent")
    if "openclaw" in (hosts or []):
        notes += _ensure_openclaw_preset(target) or _upgrade_preset(target, "openclaw")
    return notes


def _upgrade_preset(target: Path, name: str) -> list[str]:
    """Replace a bundled preset copied before rules had ``group:`` tags (so
    `leash settings` would have no effect), keeping the old file as a backup."""
    import shutil

    import yaml

    dest = target / f"{name}.yaml"
    try:
        doc = yaml.safe_load(dest.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return []
    rules = doc.get("rules") if isinstance(doc, dict) else None
    if not isinstance(rules, list) or any(isinstance(r, dict) and "group" in r for r in rules):
        return []
    backup = paths.leash_home() / "backups" / f"{name}-{int(time.time())}.yaml"
    backup.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(dest), backup)
    paths.install_preset(name, target)
    return [f"Updated {dest.name} to the latest rules (your old copy: {backup})"]


def _ensure_openclaw_preset(target: Path) -> list[str]:
    """Install openclaw.yaml, replacing the pre-0.7 server preset (which used
    raw OpenClaw tool names and denied everything else)."""
    import shutil

    import yaml

    dest = target / "openclaw.yaml"
    if dest.exists():
        try:
            doc = yaml.safe_load(dest.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            doc = {}
        if doc.get("name") != "openclaw-policy":
            return []
        backup = paths.leash_home() / "backups" / f"openclaw-policy-{int(time.time())}.yaml"
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(dest), backup)
        paths.install_preset("openclaw", target)
        return [f"Replaced the old OpenClaw server policy with the hook preset (old file: {backup})"]
    paths.install_preset("openclaw", target)
    return [f"Added the OpenClaw preset to {target}"]


def cmd_install(args: argparse.Namespace) -> None:
    from leash.hooks import install as inst

    scope = "project" if args.project is not None else "user"
    project_dir = Path(args.project) if args.project else None
    host_list = args.hosts or inst.detect_hosts()
    if not host_list:
        print("  No supported agents found. Name one explicitly:", ", ".join(HOST_CHOICES))
        sys.exit(1)

    done, failed = _install_hosts(host_list, args, scope=scope, project_dir=project_dir,
                                  command=args.hook_command, dry_run=args.dry_run)
    if not args.dry_run and done:
        names = _names(done)
        print(f"\n  Leash is on: every tool call from {names} is now checked before it runs.")
        print("\n  Next steps:")
        print(f"    1. Restart {names} (sessions that are already open keep their old settings).")
        print("    2. Check that everything is healthy:   leash doctor")
        print(f"    3. See a block without an agent:       leash policy test --local --agent {done[0]} -a shell.exec -r 'rm -rf ~'")
        print("    4. Watch what your agent does:          leash audit tail -f")
        print("\n  When Leash blocks something, run `leash explain` to see why and how to allow it.")
    sys.exit(1 if failed else 0)


def _names(hosts: list[str]) -> str:
    labels = [HOST_LABELS.get(h, h) for h in hosts]
    return labels[0] if len(labels) == 1 else ", ".join(labels[:-1]) + " and " + labels[-1]


def _install_hosts(host_list: list[str], args: argparse.Namespace, *, scope: str = "user",
                   project_dir: Path | None = None, command: str | None = None,
                   dry_run: bool = False) -> tuple[list[str], bool]:
    """Install hooks for each host, printing one line per host.  Returns the
    hosts that are active and whether any failed."""
    from leash.hooks import install as inst

    if not dry_run:
        for note in _ensure_policies(host_list):
            print(f"  • {note}")

    failed = False
    done: list[str] = []
    for host in host_list:
        try:
            r = inst.install(host, scope, project_dir=project_dir, command=command,
                             dry_run=dry_run, confirm=_install_confirm(args))
        except (OSError, ValueError) as exc:
            print(f"  ✘ {host}: {exc}", file=sys.stderr)
            failed = True
            continue
        if r.action == "partial":
            print(f"  ! {host}: plugin written to {r.target.path}, but not active yet")
            failed = True
        else:
            verb = {"installed": "Installed", "updated": "Updated", "unchanged": "Already installed"}[r.action]
            prefix = "Would write" if dry_run and r.content else verb
            print(f"  ✔ {host}: {prefix} → {r.target.path}")
            done.append(host)
        if r.backup:
            print(f"      backup: {r.backup}")
        if dry_run and r.content:
            print("      " + r.content.rstrip().replace("\n", "\n      "))
        for note in r.notes:
            print(f"      note: {note}")
    return done, failed


def _install_confirm(args: argparse.Namespace):
    if getattr(args, "yes", False):
        return lambda _question: True
    if not sys.stdin.isatty():
        return None

    def ask(question: str) -> bool:
        print("\n      " + question.replace("\n", "\n      "))
        try:
            return input("      [y/N] ").strip().lower() in ("y", "yes")
        except EOFError:
            return False
    return ask


def cmd_uninstall(args: argparse.Namespace) -> None:
    from leash.hooks import install as inst

    scope = "project" if args.project is not None else "user"
    project_dir = Path(args.project) if args.project else None
    host_list = args.hosts or [h for h in HOST_CHOICES if not (scope == "project" and h == "openclaw")]
    removed = False
    for host in host_list:
        try:
            r = inst.uninstall(host, scope, project_dir=project_dir, dry_run=args.dry_run)
        except (OSError, ValueError) as exc:
            print(f"  ✘ {host}: {exc}", file=sys.stderr)
            continue
        if r.action == "removed":
            removed = True
            print(f"  ✔ {host}: {'Would remove' if args.dry_run else 'Removed'} from {r.target.path}")
            if r.backup:
                print(f"      backup: {r.backup}")
        elif r.action == "partial":
            print(f"  ! {host}: not fully removed", file=sys.stderr)
        elif args.hosts:
            print(f"  – {host}: not installed ({r.target.path})")
        for note in r.notes:
            print(f"      note: {note}")
    if removed and not args.dry_run:
        print("\n  Agents will no longer be checked by Leash once you restart them.")
        print(f"  Your policies and audit log are still in {paths.leash_home()}.")
        print("  To remove Leash completely, also delete that folder and run:  uv tool uninstall leash")


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
            if r.get("supported") is False:
                return "n/a"
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


def _print_entry(e: dict, as_json: bool, wide: bool = False) -> None:
    if as_json:
        print(json.dumps(e))
        return
    decision = str(e.get("decision", ""))
    icon = _ICONS.get(decision.replace("observe_", ""), "·")
    where = f"  [{e['policy']}/{e['rule']}]" if e.get("policy") else ""
    request = str(e.get("request", ""))
    if not wide and len(request) > 80:
        request = request[:79] + "…"
    print(f"  {e.get('ts', '')[:19]}  {icon} {decision:<13} {e.get('agent', ''):<12} {request}{where}")
    if decision != "allow" and e.get("reason"):
        print(f"      {e['reason']}")


def cmd_audit_tail(args: argparse.Namespace) -> None:
    from leash import auditlog

    log = paths.audit_log_file()
    if not log.exists() and not args.follow:
        print(f"  No local audit log yet ({log}). It is created on the first hook decision.")
        return
    wide = getattr(args, "wide", False)
    for e in auditlog.tail(args.lines):
        _print_entry(e, args.json_out, wide)
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
                _print_entry(e, args.json_out, wide)
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

    from leash import settings
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
                d = evaluate_policies(policies, agent, action, resource, {}, agent_name=agent, normalize=False,
                                      skip_groups=settings.disabled_groups())
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


# ── explain / allow ────────────────────────────────────────────────────────

MY_RULES_FILE = "my_rules.yaml"
MY_RULES_NAME = "my-rules"
_FLAGGED = ("deny", "ask", "observe_deny", "observe_ask")
_ASK_OUTCOME = {
    "claude-code": "Claude Code showed you a permission prompt. If you said yes it ran; if you said no it didn't.",
    "copilot": "Copilot CLI asked you to approve it. If you said yes it ran; if you said no it didn't.",
    "cursor": "Cursor asked you to approve it (for other tool types Cursor can't prompt, so it was blocked).",
    "codex": "Codex hooks can't show a prompt, so this was blocked.",
    "openclaw": "OpenClaw paused and asked you to approve it (with /approve or the approval button).",
}


def _flagged_entry(which: str) -> dict:
    """The Nth most recent blocked / approval-required audit entry."""
    from leash import auditlog

    try:
        n = 1 if which in ("", "last") else int(which)
    except ValueError:
        print(f"  ✘ Expected 'last' or a number, got '{which}'", file=sys.stderr)
        sys.exit(2)
    if not paths.audit_log_file().exists():
        print("  Nothing to explain yet: Leash hasn't checked any tool calls on this machine.")
        print("  Run `leash doctor` to make sure your agent is hooked up.")
        sys.exit(1)
    flagged = [e for e in auditlog.read() if e.get("decision") in _FLAGGED]
    if n < 1 or n > len(flagged):
        if not flagged:
            print("  Leash hasn't blocked or questioned anything yet. 🎉")
        else:
            print(f"  Only {len(flagged)} blocked/approval entries exist.")
        print("  See everything with: leash audit tail")
        sys.exit(1)
    return flagged[-n]


_VERBS = {
    "shell.exec": "run the command",
    "file.read": "read the file",
    "file.write": "write the file",
    "file.delete": "delete the file",
    "file.search": "search in",
    "web.fetch": "fetch the web page",
    "web.search": "search the web for",
    "agent.spawn": "start a sub-agent of type",
}


_PLURAL = {
    "shell.exec": "run commands",
    "file.read": "read files",
    "file.write": "write files",
    "file.delete": "delete files",
    "file.search": "search in folders",
    "web.fetch": "fetch web pages",
    "web.search": "search the web for anything",
}


def _plain(action: str, resource: str) -> str:
    """``file.read /x`` → ``read the file /x`` (falls back to the raw action)."""
    if action in _VERBS:
        return f"{_VERBS[action]} {resource}".rstrip()
    if action.startswith("mcp."):
        return f"use the MCP tool {action[4:]}"
    if action.startswith("tool."):
        return f"use its {action[5:]} tool"
    return f"{action} {resource}".rstrip()


def _split_request(request: str) -> tuple[str, str]:
    action, _, resource = request.partition(" ")
    return action, resource


def _ago(ts: str) -> str:
    from datetime import datetime, timezone

    try:
        then = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return ts
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    secs = int((datetime.now(timezone.utc) - then).total_seconds())
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if secs >= size:
            k = secs // size
            return f"{k} {unit}{'s' if k != 1 else ''} ago"
    return "just now"


def _policy_file(name: str) -> Path | None:
    import yaml

    for f in sorted(paths.policies_dir().glob("*.y*ml")):
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            continue
        if isinstance(doc, dict) and doc.get("name") == name:
            return f
    return None


def _suggest_pattern(action: str, resource: str) -> str | None:
    """A broader, still-reasonable pattern to offer for approval rules."""
    import posixpath
    from urllib.parse import urlsplit

    if not resource:
        return None
    if action.startswith("file."):
        parent = posixpath.dirname(resource)
        return f"{_glob_escape(parent)}/*" if parent and parent != "/" else None
    if action == "shell.exec":
        words = resource.split()
        return " ".join(words[:2]) + "*" if len(words) > 2 else None
    if action == "web.fetch":
        parts = urlsplit(resource)
        return f"{parts.scheme}://{parts.netloc}/*" if parts.netloc else None
    return None


def _glob_escape(text: str) -> str:
    import re

    return re.sub(r"([*?\[])", r"[\1]", text)


def _shell_quote(text: str) -> str:
    import shlex

    return shlex.quote(text)


def cmd_explain(args: argparse.Namespace) -> None:
    e = _flagged_entry(args.which)
    host = str(e.get("host") or e.get("agent") or "")
    label = HOST_LABELS.get(host, host or "the agent")
    decision = str(e.get("decision"))
    action, resource = _split_request(str(e.get("request", "")))
    call = str(e.get("call") or "")
    if call.startswith(f"{action} "):
        call = call[len(action) + 1:]
    observe = decision.startswith("observe_")
    base = decision.replace("observe_", "")

    headline = "Leash blocked this" if base == "deny" else "Leash asked for your approval"
    if observe:
        headline = f"Leash would have {'blocked' if base == 'deny' else 'asked about'} this (observe mode)"
    print(f"\n  {headline}  ·  {label}  ·  {_ago(str(e.get('ts', '')))}\n")
    if call and call != resource:
        print(f"  The agent tried to {_plain(action, call)[:300]}")
        print(f"  Leash flagged:     {resource[:300]}")
    else:
        print(f"  The agent tried to {_plain(action, resource)[:300]}")
    if e.get("cwd"):
        print(f"  In folder:         {e['cwd']}")
    print(f"  Why:               {e.get('reason') or '(no reason given)'}")
    if e.get("policy"):
        src = _policy_file(str(e["policy"]))
        where = f" in {src}" if src else ""
        print(f"  Rule:              the \"{e.get('rule')}\" rule of policy \"{e['policy']}\"{where}")

    print("\n  What happened:")
    if observe:
        print("    Leash is in observe mode (LEASH_MODE=observe), so this was only recorded — it was not blocked.")
    elif base == "deny":
        print(f"    It did not run. {label} was told it was blocked and why.")
    else:
        print(f"    {_ASK_OUTCOME.get(host, 'Your agent asked you to approve it.')}")

    print("\n  What you can do:")
    print("    • Nothing. If an agent shouldn't do this, Leash did its job.")
    which = "" if args.which in ("", "last") else f" {args.which}"
    print(f"    • Always allow exactly this for {label}:   leash allow{which}")
    pattern = _suggest_pattern(action, resource) if base == "ask" else None
    if pattern:
        print(f"    • Always allow similar ones:  leash allow{which} --pattern {_shell_quote(pattern)}")
    group = str(e.get("group") or "")
    if base == "ask" and group in ("risky", "network", "outside_workspace"):
        from leash import settings

        title = next(g.title for g in settings.GROUPS if g.id == group)
        print(f"    • Stop asking about all of these (\"{title}\"):  leash settings")
    print("    • See everything your agent did:   leash audit tail")
    if base == "deny":
        print("\n  ⚠ Leash blocks this by default because it is dangerous or exposes secrets.")
        print("    Only allow it if you are sure you understand why the agent needs it.")
    print()


def _load_my_rules(path: Path) -> dict:
    import yaml

    if path.exists():
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if isinstance(doc, dict) and isinstance(doc.get("rules"), list):
            return doc
    return {
        "name": MY_RULES_NAME,
        "description": "Your own exceptions, added with `leash allow`. Checked before the bundled policies.",
        "priority": 100,
        "mode": "enforce",
        "agents": ["*"],
        "rules": [],
    }


def _save_my_rules(path: Path, doc: dict) -> None:
    import yaml

    header = (
        "# Your own Leash exceptions, managed by `leash allow`.\n"
        "#\n"
        "# Priority 100 means these rules are checked before the bundled policies,\n"
        "# and the first matching rule wins.  You can edit or delete rules here;\n"
        "# `leash allow --undo` removes the most recent one.\n"
        "#\n"
        "# `conditions: {host: ...}` limits a rule to one agent.\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(header + yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=100), encoding="utf-8")
    tmp.replace(path)


def _confirm(prompt: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print("  ✘ `leash allow` needs you to confirm in a terminal (or pass --yes).", file=sys.stderr)
        sys.exit(2)
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except EOFError:
        return False


def cmd_allow(args: argparse.Namespace) -> None:
    from datetime import date

    from leash.hooks.actions import _CASE_INSENSITIVE_FS

    target = paths.policies_dir() / MY_RULES_FILE
    if args.undo:
        doc = _load_my_rules(target)
        if not doc["rules"]:
            print(f"  No rules to undo in {target}")
            return
        rule = doc["rules"].pop()
        removed = 1
        # Case-insensitive duplicates are added in pairs; remove the pair and
        # report the original (the first of the pair).
        while doc["rules"] and doc["rules"][-1].get("reason") == rule.get("reason") and \
                doc["rules"][-1].get("action") == rule.get("action") and \
                str(doc["rules"][-1].get("resource", "")).lower() == str(rule.get("resource", "")).lower():
            rule = doc["rules"].pop()
            removed += 1
        _save_my_rules(target, doc)
        extra = " (and its lower-case copy)" if removed > 1 else ""
        print(f"  ✔ Removed: {rule.get('action')} {rule.get('resource', '')}".rstrip() + extra)
        return

    e = _flagged_entry(args.which)
    host = str(e.get("host") or "")
    label = HOST_LABELS.get(host, host or "every agent")
    action, resource = _split_request(str(e.get("request", "")))
    if not action:
        print("  ✘ That audit entry has no action to allow.", file=sys.stderr)
        sys.exit(1)
    pattern = args.pattern if args.pattern is not None else _glob_escape(resource)

    rules = []
    for res in dict.fromkeys([pattern] + ([pattern.lower()] if _CASE_INSENSITIVE_FS and
                                          (action.startswith("file.") or action == "shell.exec") else [])):
        rule: dict = {"action": action}
        if res:
            rule["resource"] = res
        rule["effect"] = "allow"
        if host and not args.all_agents:
            rule["conditions"] = {"host": host}
        rule["reason"] = f"Allowed by you with `leash allow` on {date.today().isoformat()}"
        rules.append(rule)

    import yaml

    who = "every agent" if args.all_agents or not host else label
    what = _plain(action, pattern) if args.pattern is None else f"{_PLURAL.get(action, action)} matching {pattern}"
    print(f"\n  This lets {who} {what} without Leash stopping it.")
    print(f"\n  It adds this rule to {target}:\n")
    print("    " + yaml.safe_dump(rules[:1], sort_keys=False, width=100).rstrip().replace("\n", "\n    "))
    if len(rules) > 1:
        print("\n    (plus the same rule in lower case, because this computer's file names ignore case)")
    if str(e.get("decision", "")).endswith("deny"):
        print("\n  ⚠ Leash blocks this by default because it is dangerous or exposes secrets.")
    if args.dry_run:
        print("\n  (dry run: nothing written)\n")
        return
    if not _confirm("\n  Add it? [y/N] ", args.yes):
        print("  Nothing changed.")
        return

    doc = _load_my_rules(target)
    doc["rules"].extend(rules)
    _save_my_rules(target, doc)

    from leash import settings
    from leash.engine import PolicyDirectory, evaluate_policies

    policies = PolicyDirectory(target.parent).policies
    agent = str(e.get("agent") or host)
    ctx = {"host": host, "tool": e.get("tool", ""), "cwd": e.get("cwd", ""), "in_workspace": False}
    check = evaluate_policies(policies, agent, action, resource, ctx, agent_name=agent, normalize=False,
                              skip_groups=settings.disabled_groups())
    if check.decision == "allow":
        print(f"\n  ✔ Saved. {who[0].upper() + who[1:]} may now: {action} {resource}".rstrip())
    else:
        print(f"\n  ! Saved, but a check still says '{check.decision}' ({check.reason}). "
              f"Run `leash policy test --local` to investigate.")
    print("    Undo it any time with:  leash allow --undo\n")


# ── setup / settings ───────────────────────────────────────────────────────

_LEVEL_KEYS = {"s": "strict", "b": "balanced", "r": "relaxed"}


def _ask_level(current: str) -> str:
    from leash import settings

    print("  How careful should Leash be?\n")
    names = list(settings.LEVELS)
    for i, name in enumerate(names, 1):
        mark = "  ← current" if name == current else ""
        print(f"    {i}. {name.capitalize():<9} {settings.LEVEL_INFO[name]}{mark}")
    default = names.index(current) + 1 if current in names else 2
    while True:
        try:
            raw = input(f"\n  Choose 1-3 [{default}]: ").strip().lower()
        except EOFError:
            raw = ""
        if not raw:
            return names[default - 1]
        if raw.isdigit() and 1 <= int(raw) <= len(names):
            return names[int(raw) - 1]
        if raw in names or raw[:1] in _LEVEL_KEYS:
            return raw if raw in names else _LEVEL_KEYS[raw[:1]]
        print("  Please type 1, 2 or 3.")


def cmd_setup(args: argparse.Namespace) -> None:
    from leash import settings
    from leash.hooks import install as inst
    from leash.hooks.runner import evaluate_call, load_local_policies

    print("\n  Leash setup — a seatbelt for your AI agents\n")
    hosts = args.hosts or inst.detect_hosts()
    if not hosts:
        print("  No AI agents found on this computer yet.")
        print(f"  Leash works with: {', '.join(HOST_LABELS.values())}.")
        print("  Install one of them, then run `leash setup` again.\n")
        sys.exit(1)
    print(f"  Found: {_names(hosts)}\n")

    existed = settings.settings_file().exists()
    current = settings.load()
    level = args.level
    if level is None and sys.stdin.isatty() and not args.yes:
        level = _ask_level(current.level)
    elif level is None:
        level = current.level if existed and current.level in settings.LEVELS else settings.DEFAULT_LEVEL
    if level != current.level or not existed:
        settings.save(settings.for_level(level))
    print(f"\n  Protection level: {level.capitalize()} — {settings.LEVEL_INFO[level]}\n")

    done, failed = _install_hosts(hosts, args)
    if not done:
        print("\n  ✘ Leash couldn't hook into any agent. Run `leash doctor` for details.\n", file=sys.stderr)
        sys.exit(1)

    policies = load_local_policies()
    print()
    for host in done:
        v, _ = evaluate_call(_test_call(host, "shell.exec", "rm -rf ~"), policies, agent=host)
        if v.decision == "deny":
            print(f"  ✔ Checked: Leash blocks `rm -rf ~` for {HOST_LABELS.get(host, host)}")
        else:
            print(f"  ! {HOST_LABELS.get(host, host)}: `rm -rf ~` was '{v.decision}', not blocked. Run `leash doctor`.")
            failed = True

    names = _names(done)
    print(f"\n  You're set. Every tool call from {names} is now checked before it runs.\n")
    print(f"  1. Restart {names} so {'it picks' if len(done) == 1 else 'they pick'} up Leash.")
    print("  2. Try it: ask your agent to \"show me the contents of ~/.ssh\".")
    print("     Leash will block it. Then run `leash explain` to see why.\n")
    print("  Later:")
    print("    leash settings        turn protections on or off")
    print("    leash audit summary   what your agents did today")
    print("    leash doctor          check everything is healthy\n")
    sys.exit(1 if failed else 0)


def _print_settings(prefs) -> None:
    from leash import settings

    print(f"\n  Leash protection: {prefs.label}\n")
    for i, g in enumerate(settings.GROUPS, 1):
        on = prefs.groups.get(g.id, True)
        box = "[x]" if on else "[ ]"
        lock = "  (always on)" if g.locked else ""
        print(f"    {i}. {box} {g.title}{lock}")
        print(f"           {g.detail}")
    print()


def cmd_settings(args: argparse.Namespace) -> None:
    from leash import settings

    prefs = settings.load()
    if prefs.problem:
        print(f"  ! {prefs.problem}. Every protection is on until you save new settings.", file=sys.stderr)
    if args.level:
        prefs = settings.for_level(args.level)
        settings.save(prefs)
        print(f"  ✔ Protection level set to {prefs.label}: {settings.LEVEL_INFO[args.level]}")
        return
    if args.json_out:
        print(json.dumps({"level": prefs.level, "groups": prefs.groups, "file": str(settings.settings_file())}, indent=2))
        return
    if args.show or not sys.stdin.isatty():
        _print_settings(prefs)
        if not args.show:
            print("  (Run `leash settings` in a terminal to change these, or use --level.)\n")
        return

    changed = False
    while True:
        _print_settings(prefs)
        print("  Type a number to switch it on or off, s/b/r for Strict/Balanced/Relaxed,")
        print("  Enter to save, or q to quit without saving.")
        try:
            raw = input("\n  > ").strip().lower()
        except EOFError:
            raw = "q"
        if raw == "":
            break
        if raw in ("q", "quit"):
            print("  Nothing changed.\n")
            return
        if raw[:1] in _LEVEL_KEYS and not raw.isdigit():
            prefs = settings.for_level(_LEVEL_KEYS[raw[:1]])
            changed = True
            continue
        if not raw.isdigit() or not 1 <= int(raw) <= len(settings.GROUPS):
            print(f"  Please type a number from 1 to {len(settings.GROUPS)}, s, b, r, q or Enter.")
            continue
        g = settings.GROUPS[int(raw) - 1]
        if g.locked:
            print(f"  \"{g.title}\" can't be turned off: without it an agent could switch Leash off.")
            continue
        turning_off = prefs.groups.get(g.id, True)
        if turning_off and g.id in ("secrets", "destructive"):
            print(f"  ⚠ Turning off \"{g.title}\" lets agents {g.detail[0].lower() + g.detail[1:]}")
            try:
                if input("  Are you sure? [y/N] ").strip().lower() not in ("y", "yes"):
                    continue
            except EOFError:
                continue
        prefs.groups[g.id] = not turning_off
        prefs.level = settings.level_for(prefs.groups)
        changed = True
    if changed or prefs.problem:
        settings.save(prefs)
        print(f"  ✔ Saved ({prefs.label}). Takes effect on your agent's next tool call.\n")
    else:
        print("  Nothing changed.\n")


# ── audit summary (local) ──────────────────────────────────────────────────

def _since(value: str | None):
    import re
    from datetime import datetime, timedelta, timezone

    if not value:
        return None
    m = re.fullmatch(r"(\d+)\s*([mhd])", value.strip().lower())
    if m:
        size = {"m": "minutes", "h": "hours", "d": "days"}[m.group(2)]
        return datetime.now(timezone.utc) - timedelta(**{size: int(m.group(1))})
    try:
        then = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        print(f"  ✘ --since expects a duration like 24h or 7d, or a date like 2026-01-31, got '{value}'",
              file=sys.stderr)
        sys.exit(2)
    return then if then.tzinfo else then.replace(tzinfo=timezone.utc)


def cmd_audit_summary_local(args: argparse.Namespace) -> None:
    from collections import Counter
    from datetime import datetime, timezone

    from leash import auditlog

    log = paths.audit_log_file()
    if not log.exists():
        print(f"\n  Nothing yet: Leash hasn't checked any tool calls on this machine ({log}).")
        print("  Run `leash setup` to connect your agents.\n")
        return
    window = args.since or "24h"
    start = _since(window)
    entries = []
    for e in auditlog.read():
        try:
            ts = datetime.fromisoformat(str(e.get("ts", "")).replace("Z", "+00:00"))
        except ValueError:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if start is None or ts >= start:
            entries.append(e)

    kinds = Counter(str(e.get("decision", "")).replace("observe_", "") for e in entries)
    by_agent = Counter(HOST_LABELS.get(str(e.get("host", "")), str(e.get("agent", "?"))) for e in entries)
    flagged = [e for e in entries if e.get("decision") in _FLAGGED]
    if args.json_out:
        print(json.dumps({"since": start.isoformat() if start else None, "total": len(entries),
                          "decisions": dict(kinds), "agents": dict(by_agent),
                          "top_reasons": Counter(str(e.get("reason", "")) for e in flagged).most_common(5)},
                         indent=2))
        return

    print(f"\n  Leash activity · since {window} ago  ({log})")
    print(f"  {'─' * 60}")
    if not entries:
        print("  No tool calls in this period. Try --since 7d.\n")
        return
    agents = " · ".join(f"{name} {n}" for name, n in by_agent.most_common())
    print(f"  {len(entries)} tool calls checked   ({agents})")
    print(f"    ✔ {kinds.get('allow', 0):>5}  allowed")
    print(f"    ? {kinds.get('ask', 0):>5}  asked you first")
    print(f"    ✘ {kinds.get('deny', 0):>5}  blocked")
    if any(str(e.get("decision", "")).startswith("observe_") for e in entries):
        print("      (observe mode: some of these were only recorded, not enforced)")
    if flagged:
        print("\n  Why Leash stepped in:")
        for reason, n in Counter(str(e.get("reason", "")) for e in flagged).most_common(5):
            print(f"    {n:>4}×  {_clip(reason, 90)}")
        print("\n  Most recent:")
        for e in flagged[-5:]:
            action, resource = _split_request(str(e.get("request", "")))
            icon = _ICONS.get(str(e.get("decision", "")).replace("observe_", ""), "·")
            who = HOST_LABELS.get(str(e.get("host", "")), str(e.get("agent", "")))
            print(f"    {icon} {_ago(str(e.get('ts', ''))):<15} {who:<12} {_clip(_plain(action, resource), 70)}")
        print("\n  Details on the latest one: leash explain     Everything: leash audit tail")
    else:
        print("\n  Nothing was blocked or questioned. 🎉")
    print()


def _clip(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"
