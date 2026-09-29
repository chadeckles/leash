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


def link_commands() -> List[List[str]]:
    return [["openclaw", "plugins", "install", "--link", str(plugin_dir()), "--force"]]


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


def files_current(command: List[str]) -> bool:
    target = plugin_dir()
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


def is_linked() -> bool:
    """True when OpenClaw's config lists the plugin directory."""
    cfg = config_file()
    try:
        text = cfg.read_text(encoding="utf-8")
    except OSError:
        return False
    target = plugin_dir()
    forms = {str(target), target.as_posix()}
    try:
        forms.add("~/" + target.relative_to(Path.home()).as_posix())
    except ValueError:
        pass
    return any(form in text for form in forms)


def is_installed() -> bool:
    return (plugin_dir() / "index.js").is_file() and is_linked()


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
