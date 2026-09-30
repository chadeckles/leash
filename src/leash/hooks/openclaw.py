"""``leash install openclaw``: the Leash plugin for OpenClaw.

OpenClaw has no hook config file like Claude Code; tool calls are gated by
plugins through the typed ``before_tool_call`` hook.  Leash ships a tiny
dependency-free plugin (``openclaw_plugin/``) that pipes each tool call into
``leash hook openclaw``.  Installing it means:

1. copying the plugin to ``~/.leash/integrations/openclaw`` (under ``~/.leash``
   so the coding-agent policy's tamper rules protect it), and
2. linking it into OpenClaw with ``openclaw plugins install --link``, which
   adds the directory to ``plugins.load.paths`` in ``~/.openclaw/openclaw.json``.

OpenClaw's config is JSON5 and owned by its CLI, so Leash never edits it
directly: step 2 runs the ``openclaw`` CLI when it is on ``PATH`` and
otherwise prints the command to run.

Some OpenClaw versions (e.g. 2026.3) scan plugins at install time and refuse to
link any plugin that starts a process -- which this one must do to run
``leash hook openclaw``.  Those versions still accept a *copy* install with
OpenClaw's own ``--dangerously-force-unsafe-install`` override, into
``<state>/extensions/leash``.  Leash only does that after the user agrees.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from importlib import resources
from pathlib import Path
from typing import List, Optional, Tuple

from leash import paths

PLUGIN_ID = "leash"
PLUGIN_FILES = ("index.js", "openclaw.plugin.json", "package.json")
CONFIG_FILE = "leash.json"
CLI_TIMEOUT_SEC = 120


def state_dir() -> Path:
    if os.getenv("OPENCLAW_STATE_DIR"):
        return Path(os.environ["OPENCLAW_STATE_DIR"]).expanduser()
    profile = os.getenv("OPENCLAW_PROFILE")
    name = f".openclaw-{profile}" if profile and profile != "default" else ".openclaw"
    return Path.home() / name


def config_file() -> Path:
    if os.getenv("OPENCLAW_CONFIG_PATH"):
        return Path(os.environ["OPENCLAW_CONFIG_PATH"]).expanduser()
    return state_dir() / "openclaw.json"


def plugin_dir() -> Path:
    return paths.leash_home() / "integrations" / "openclaw"


def copied_dir() -> Path:
    """Where OpenClaw puts a copy-installed (not linked) plugin."""
    return state_dir() / "extensions" / PLUGIN_ID


def link_commands() -> List[List[str]]:
    # No --force: linking is idempotent, and OpenClaw >= 2026.6 rejects --force with --link.
    return [["openclaw", "plugins", "install", "--link", str(plugin_dir())]]


def copy_install_commands() -> List[List[str]]:
    return [["openclaw", "plugins", "install", str(plugin_dir()), "--dangerously-force-unsafe-install"]]


def scanner_blocked(error: str) -> bool:
    """True when OpenClaw's install-time code scan refused the plugin."""
    return "dangerous code patterns" in error


def enable_commands() -> List[List[str]]:
    return [["openclaw", "plugins", "enable", PLUGIN_ID]]


def unlink_commands() -> List[List[str]]:
    return [["openclaw", "plugins", "uninstall", PLUGIN_ID, "--force"]]


def rendered_files(command: List[str]) -> dict[str, str]:
    """The plugin files, with the hook command recorded in ``leash.json``."""
    pkg = resources.files("leash.hooks") / "openclaw_plugin"
    files = {name: (pkg / name).read_text(encoding="utf-8") for name in PLUGIN_FILES}
    files[CONFIG_FILE] = json.dumps({"command": command}, indent=2) + "\n"
    return files


def files_current(command: List[str], target: Optional[Path] = None) -> bool:
    target = target or plugin_dir()
    for name, text in rendered_files(command).items():
        f = target / name
        if not f.is_file() or f.read_text(encoding="utf-8") != text:
            return False
    return True


def write_files(command: List[str]) -> Path:
    target = plugin_dir()
    target.mkdir(parents=True, exist_ok=True)
    for name, text in rendered_files(command).items():
        (target / name).write_text(text, encoding="utf-8")
    return target


def remove_files() -> bool:
    target = plugin_dir()
    if not target.exists():
        return False
    shutil.rmtree(target)
    return True


def _same_path(a: str, b: Path) -> bool:
    try:
        return Path(a).expanduser().resolve() == b.resolve()
    except (OSError, RuntimeError, ValueError):
        return False


def is_linked() -> bool:
    """True when ``plugins.load.paths`` in OpenClaw's config lists the plugin
    directory.  (A copy install's record also mentions the directory as its
    ``sourcePath``, so a plain text search isn't enough.)"""
    cfg = config_file()
    try:
        text = cfg.read_text(encoding="utf-8")
    except OSError:
        return False
    target = plugin_dir()
    try:
        data = json.loads(text)
    except ValueError:
        data = None  # JSON5 (comments, trailing commas): fall back to text
    if isinstance(data, dict):
        load = (data.get("plugins") or {}).get("load") or {}
        entries = load.get("paths") if isinstance(load, dict) else None
        return isinstance(entries, list) and any(
            isinstance(e, str) and _same_path(e, target) for e in entries)
    forms = {str(target), target.as_posix()}
    try:
        forms.add("~/" + target.relative_to(Path.home()).as_posix())
    except ValueError:
        pass
    return any(form in text for form in forms)


def is_copied() -> bool:
    """True when OpenClaw's extensions folder holds Leash's own plugin copy."""
    d = copied_dir()
    try:
        manifest = json.loads((d / "openclaw.plugin.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return (isinstance(manifest, dict) and manifest.get("id") == PLUGIN_ID
            and (d / "index.js").is_file() and (d / CONFIG_FILE).is_file())


def remove_copy() -> bool:
    """Delete Leash's plugin copy from OpenClaw's extensions folder.

    ``openclaw plugins uninstall`` in 2026.3 records copy installs as linked
    paths and so leaves the copy behind, where OpenClaw keeps discovering and
    loading it.  Only a folder that is verifiably Leash's copy is removed.
    """
    if not is_copied():
        return False
    shutil.rmtree(copied_dir())
    return True


def unregister() -> Tuple[bool, str]:
    """Remove the plugin from OpenClaw (config via its CLI, then any copy)."""
    ok, err = run_cli(unlink_commands())
    if not ok and is_copied() and ("not found" in err.lower() or "not managed" in err.lower()):
        ok, err = True, ""  # a stray copy OpenClaw no longer tracks
    if ok:
        remove_copy()
    return ok, err


def is_registered() -> bool:
    """True when OpenClaw loads the plugin, linked or as a copy."""
    return is_linked() or is_copied()


def is_installed() -> bool:
    return (plugin_dir() / "index.js").is_file() and is_registered()


def cli_available() -> Optional[str]:
    return shutil.which("openclaw")


def run_cli(commands: List[List[str]]) -> Tuple[bool, str]:
    """Run ``openclaw`` CLI commands; returns (ok, combined error output)."""
    exe = cli_available()
    if not exe:
        return False, "the `openclaw` command is not on PATH"
    for cmd in commands:
        try:
            proc = subprocess.run(
                [exe, *cmd[1:]], capture_output=True, text=True, timeout=CLI_TIMEOUT_SEC,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, str(exc)
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout).strip()[-800:]
    return True, ""


def shell_line(cmd: List[str]) -> str:
    import shlex

    return shlex.join(cmd) if os.name != "nt" else subprocess.list2cmdline(cmd)
