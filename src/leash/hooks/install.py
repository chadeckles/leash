"""``leash install`` / ``leash uninstall``: wire ``leash hook`` into agent hosts.

Every operation is idempotent: Leash's own entries are recognized by their
``leash … hook <host>`` command, replaced on re-install, and removed on
uninstall, leaving the user's other hooks untouched.  Any existing file is
backed up to ``~/.leash/backups/`` before it is changed.

Scopes:

* ``user``    – this user, every project (default)
* ``project`` – committed to a repository so teammates / cloud agents get it

OpenClaw is different: it is gated by a plugin, not a hook config file, and
is always per-user (see :mod:`leash.hooks.openclaw`).
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from leash import paths
from leash.hooks.hosts import HOSTS

SCOPES = ("user", "project")
TIMEOUT_SEC = 30


@dataclass
class Target:
    host: str
    scope: str
    path: Path
    own_file: bool  # True when the whole file belongs to Leash


@dataclass
class Result:
    target: Target
    action: str  # installed | updated | unchanged | partial | removed | absent
    backup: Optional[Path] = None
    notes: List[str] = field(default_factory=list)
    content: Optional[str] = None


# ── locations ──────────────────────────────────────────────────────────────

def _home_dir(env: str, default: str) -> Path:
    return Path(os.getenv(env) or Path.home() / default).expanduser()


def _is_windows() -> bool:
    return os.name == "nt"


def target_for(host: str, scope: str = "user", project_dir: Optional[Path] = None) -> Target:
    if host not in HOSTS:
        raise ValueError(f"Unknown host '{host}'. Choose from: {', '.join(HOSTS)}")
    if scope not in SCOPES:
        raise ValueError(f"Unknown scope '{scope}'. Choose from: {', '.join(SCOPES)}")
    if host == "openclaw":
        if scope == "project":
            raise ValueError("OpenClaw is protected per user; run `leash install openclaw` without --project")
        from leash.hooks import openclaw

        return Target(host, scope, openclaw.plugin_dir(), own_file=True)
    if scope == "project":
        root = Path(project_dir or Path.cwd()).resolve()
        rel = {
            "claude-code": ".claude/settings.json",
            "copilot": ".github/hooks/leash.json",
            "cursor": ".cursor/hooks.json",
            "codex": ".codex/hooks.json",
        }[host]
        return Target(host, scope, root / rel, own_file=host == "copilot")
    path = {
        "claude-code": lambda: _home_dir("CLAUDE_CONFIG_DIR", ".claude") / "settings.json",
        "copilot": lambda: _home_dir("COPILOT_HOME", ".copilot") / "hooks" / "leash.json",
        "cursor": lambda: Path.home() / ".cursor" / "hooks.json",
        "codex": lambda: _home_dir("CODEX_HOME", ".codex") / "hooks.json",
    }[host]()
    return Target(host, scope, path, own_file=host == "copilot")


def detect_hosts() -> List[str]:
    """Hosts that appear to be installed for this user."""
    found = []
    probes = {
        "claude-code": (_home_dir("CLAUDE_CONFIG_DIR", ".claude"), "claude"),
        "copilot": (_home_dir("COPILOT_HOME", ".copilot"), "copilot"),
        "cursor": (Path.home() / ".cursor", "cursor"),
        "codex": (_home_dir("CODEX_HOME", ".codex"), "codex"),
    }
    from leash.hooks import openclaw

    probes["openclaw"] = (openclaw.state_dir(), "openclaw")
    for host, (config_dir, binary) in probes.items():
        if config_dir.exists() or shutil.which(binary):
            found.append(host)
    return found


# ── the hook command ───────────────────────────────────────────────────────

def _quote(parts: List[str]) -> str:
    return subprocess.list2cmdline(parts) if _is_windows() else shlex.join(parts)


def hook_command(host: str, scope: str = "user", override: Optional[str] = None) -> str:
    """The command a host should run.  User scope pins the absolute
    path of this installation; project scope uses ``leash`` from PATH so the
    committed file works for every contributor."""
    if override:
        return override
    if scope == "project":
        return f"leash hook {host}"
    return _quote(hook_argv(host))


def hook_argv(host: str, override: Optional[str] = None) -> List[str]:
    """The hook command as an argument list (for hosts that spawn it
    directly, like the OpenClaw plugin)."""
    if override:
        return shlex.split(override, posix=not _is_windows())
    sibling = Path(sys.executable).parent / ("leash.exe" if _is_windows() else "leash")
    exe = str(sibling) if sibling.is_file() else shutil.which("leash")
    if exe:
        return [exe, "hook", host]
    return [sys.executable, "-m", "leash", "hook", host]


def _ours(command: Any, host: str) -> bool:
    return isinstance(command, str) and re.search(
        r"leash(?:\.exe)?['\"]?\s+hook\s+(?:" + re.escape(host) + r"|auto)\b", command
    ) is not None


# ── config documents ───────────────────────────────────────────────────────

def _claude_group(cmd: str, host: str) -> Dict[str, Any]:
    handler: Dict[str, Any] = {"type": "command", "command": cmd, "timeout": TIMEOUT_SEC}
    if host == "codex":
        handler["statusMessage"] = "Leash policy check"
    return {"matcher": "*", "hooks": [handler]}


def _strip_claude_like(doc: Dict[str, Any], host: str) -> bool:
    hooks = doc.get("hooks")
    if not isinstance(hooks, dict) or not isinstance(hooks.get("PreToolUse"), list):
        return False
    changed = False
    groups = []
    for group in hooks["PreToolUse"]:
        if isinstance(group, dict) and isinstance(group.get("hooks"), list):
            kept = [h for h in group["hooks"] if not (isinstance(h, dict) and _ours(h.get("command"), host))]
            if len(kept) != len(group["hooks"]):
                changed = True
                if not kept:
                    continue
                group = {**group, "hooks": kept}
        groups.append(group)
    if changed:
        if groups:
            hooks["PreToolUse"] = groups
        else:
            del hooks["PreToolUse"]
        if not hooks:
            del doc["hooks"]
    return changed


def _strip_cursor(doc: Dict[str, Any], host: str) -> bool:
    hooks = doc.get("hooks")
    if not isinstance(hooks, dict):
        return False
    changed = False
    for event in list(hooks):
        entries = hooks[event]
        if not isinstance(entries, list):
            continue
        kept = [e for e in entries if not (isinstance(e, dict) and _ours(e.get("command"), host))]
        if len(kept) != len(entries):
            changed = True
            if kept:
                hooks[event] = kept
            else:
                del hooks[event]
    return changed


CURSOR_EVENTS = ("preToolUse", "beforeShellExecution", "beforeMCPExecution")


def _add(doc: Dict[str, Any], host: str, cmd: str) -> None:
    if host in ("claude-code", "codex"):
        doc.setdefault("hooks", {}).setdefault("PreToolUse", []).append(_claude_group(cmd, host))
    elif host == "cursor":
        doc.setdefault("version", 1)
        hooks = doc.setdefault("hooks", {})
        for event in CURSOR_EVENTS:
            hooks.setdefault(event, []).append({"command": cmd, "timeout": TIMEOUT_SEC, "failClosed": True})


def _copilot_doc(cmd: str) -> Dict[str, Any]:
    return {
        "version": 1,
        "hooks": {
            "preToolUse": [{
                "type": "command",
                "bash": cmd,
                "powershell": f"& {cmd}" if cmd.startswith(("'", '"')) else cmd,
                "timeoutSec": TIMEOUT_SEC,
            }]
        },
    }


def render(target: Target, cmd: str, existing: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if target.host == "copilot":
        return _copilot_doc(cmd)
    doc = json.loads(json.dumps(existing or {}))
    if target.own_file:
        doc = {}
    _strip(doc, target.host)
    _add(doc, target.host, cmd)
    return doc


def _strip(doc: Dict[str, Any], host: str) -> bool:
    return _strip_cursor(doc, host) if host == "cursor" else _strip_claude_like(doc, host)


def is_installed(target: Target) -> bool:
    if target.host == "openclaw":
        from leash.hooks import openclaw

        return openclaw.is_installed()
    doc = _read(target.path)
    if doc is None:
        return False
    if target.host == "copilot":
        entries = (doc.get("hooks") or {}).get("preToolUse") or []
        return any(_ours(e.get("bash") or e.get("command"), "copilot") for e in entries if isinstance(e, dict))
    return _strip(json.loads(json.dumps(doc)), target.host)


# ── file helpers ───────────────────────────────────────────────────────────

def _read(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return {}
    doc = json.loads(text)
    if not isinstance(doc, dict):
        raise ValueError(f"{path} does not contain a JSON object")
    return doc


def _backup(target: Target) -> Optional[Path]:
    if not target.path.exists():
        return None
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    dest = paths.leash_home() / "backups" / f"{target.host}-{target.scope}-{stamp}-{target.path.name}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(target.path, dest)
    return dest


def _write(path: Path, doc: Dict[str, Any], mode: int = 0o644) -> None:
    if path.is_symlink():
        # Keep dotfile-manager symlinks (stow, chezmoi): write the target.
        path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        mode = path.stat().st_mode & 0o777
    tmp = path.with_name(f".{path.name}.leash-tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(doc, indent=2) + "\n")
    os.chmod(tmp, mode)
    os.replace(tmp, path)


# ── public API ─────────────────────────────────────────────────────────────

def install(
    host: str,
    scope: str = "user",
    *,
    project_dir: Optional[Path] = None,
    command: Optional[str] = None,
    dry_run: bool = False,
) -> Result:
    target = target_for(host, scope, project_dir)
    if host == "openclaw":
        return _install_openclaw(target, command, dry_run)
    cmd = hook_command(host, scope, command)
    existing = _read(target.path)
    doc = render(target, cmd, existing)
    notes: List[str] = []
    if host == "codex":
        notes.append("Codex asks you to trust new hooks: open Codex and run /hooks to review and trust Leash.")
    if host == "cursor":
        notes.append("Cursor reloads hooks.json automatically; restart Cursor if the hook doesn't appear.")
    if scope == "project":
        notes.append("Project hooks run `leash` from PATH: every contributor (and CI/cloud agent) needs Leash installed.")

    if existing == doc:
        return Result(target, "unchanged", notes=notes)
    text = json.dumps(doc, indent=2) + "\n"
    if dry_run:
        return Result(target, "installed" if existing is None else "updated", notes=notes, content=text)
    backup = _backup(target)
    _write(target.path, doc)
    return Result(target, "installed" if existing is None else "updated", backup, notes)


def uninstall(
    host: str,
    scope: str = "user",
    *,
    project_dir: Optional[Path] = None,
    dry_run: bool = False,
) -> Result:
    target = target_for(host, scope, project_dir)
    if host == "openclaw":
        return _uninstall_openclaw(target, dry_run)
    existing = _read(target.path)
    if existing is None or not is_installed(target):
        return Result(target, "absent")
    if dry_run:
        return Result(target, "removed")
    backup = _backup(target)
    if target.own_file:
        target.path.unlink()
    else:
        _strip(existing, host)
        _write(target.path, existing)
    return Result(target, "removed", backup)


def _install_openclaw(target: Target, command: Optional[str], dry_run: bool) -> Result:
    from leash.hooks import openclaw

    argv = hook_argv("openclaw", command)
    fresh = not target.path.exists()
    files_ok = openclaw.files_current(argv)
    linked = openclaw.is_linked()
    link = openclaw.link_commands()
    manual = [f"Link it into OpenClaw: {openclaw.shell_line(c)}" for c in link]
    if files_ok and linked:
        return Result(target, "unchanged")
    action = "installed" if fresh else "updated"
    if dry_run:
        content = f"write plugin files: {', '.join(openclaw.rendered_files(argv))}\n"
        if not linked:
            content += "".join(f"run: {openclaw.shell_line(c)}\n" for c in link)
        return Result(target, action, content=content)
    if not files_ok:
        openclaw.write_files(argv)
    notes: List[str] = []
    if not linked:
        if openclaw.cli_available():
            ok, err = openclaw.run_cli(link)
            if not ok:
                notes.append(f"`openclaw plugins install` failed: {err}")
                notes += manual
                return Result(target, "partial", notes=notes)
        else:
            notes.append("The `openclaw` command isn't on PATH, so the plugin isn't linked yet.")
            notes += manual
            return Result(target, "partial", notes=notes)
    notes.append("Restart OpenClaw (or run `openclaw plugins reload leash`) so the plugin loads.")
    notes.append("When Leash asks for approval, OpenClaw pauses the tool call; approve it with /approve or the approval button.")
    return Result(target, action, notes=notes)


def _uninstall_openclaw(target: Target, dry_run: bool) -> Result:
    from leash.hooks import openclaw

    linked = openclaw.is_linked()
    if not linked and not target.path.exists():
        return Result(target, "absent")
    if dry_run:
        return Result(target, "removed")
    notes: List[str] = []
    if linked:
        ok, err = openclaw.run_cli(openclaw.unlink_commands())
        if not ok:
            notes.append(f"Couldn't unlink the plugin automatically ({err}). Run: "
                         + "; ".join(openclaw.shell_line(c) for c in openclaw.unlink_commands()))
            # Keep the files: OpenClaw still loads them and would fail closed.
            return Result(target, "partial", notes=notes)
    openclaw.remove_files()
    return Result(target, "removed", notes=notes)


def status(project_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Where Leash is (and isn't) installed."""
    rows = []
    detected = set(detect_hosts())
    for host in HOSTS:
        for scope in SCOPES:
            if host == "openclaw" and scope == "project":
                rows.append({
                    "host": host, "scope": scope, "path": "", "installed": False,
                    "detected": host in detected, "error": "", "supported": False,
                })
                continue
            target = target_for(host, scope, project_dir)
            try:
                installed = is_installed(target)
                error = ""
            except (OSError, ValueError) as exc:
                installed, error = False, str(exc)
            rows.append({
                "host": host, "scope": scope, "path": str(target.path),
                "installed": installed, "detected": host in detected, "error": error,
            })
    return rows
