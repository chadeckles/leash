"""Find MCP client configs (Claude Desktop, VS Code, Windsurf) and route their
local MCP servers through ``leash mcp run``.

Wrapping rewrites a server entry from::

    {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]}

to::

    {"command": "/path/to/leash", "args": ["mcp", "run", "--client", "claude-desktop",
     "--name", "github", "--", "npx", "-y", "@modelcontextprotocol/server-github"]}

Everything else in the entry (env, cwd, type) is kept, the file is backed up
first, and ``unwrap`` restores the original command.  Remote (URL) servers are
left alone: there is no local process to sit in front of.

Claude Code, Copilot CLI, Cursor, Codex and OpenClaw don't need this: their
Leash hooks already see every MCP tool call.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class Client:
    id: str
    label: str
    key: str  # where servers live in the config file

    @property
    def path(self) -> Path:
        return config_path(self.id)


CLIENTS = {
    "claude-desktop": Client("claude-desktop", "Claude Desktop", "mcpServers"),
    "vscode": Client("vscode", "VS Code", "servers"),
    "windsurf": Client("windsurf", "Windsurf", "mcpServers"),
}

# clientInfo.name sent in `initialize` → our client id (for `leash mcp run` without --client)
_INFO_NAMES = {"claude-ai": "claude-desktop", "claude desktop": "claude-desktop",
               "visual studio code": "vscode", "vscode": "vscode", "windsurf": "windsurf"}


def client_id_from_info(name: str) -> str:
    key = (name or "").strip().lower()
    if key in _INFO_NAMES:
        return _INFO_NAMES[key]
    return "mcp-client-" + (re.sub(r"[^a-z0-9]+", "-", key).strip("-") or "unknown")


def label(client: str) -> str:
    if client in CLIENTS:
        return CLIENTS[client].label
    return client.replace("mcp-client-", "") or "your MCP client"


def _app_support() -> Path:
    home = Path.home()
    if sys.platform == "darwin":
        return home / "Library" / "Application Support"
    if os.name == "nt":
        return Path(os.environ.get("APPDATA") or home / "AppData" / "Roaming")
    return Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config")


def config_path(client: str) -> Path:
    if client == "claude-desktop":
        return _app_support() / "Claude" / "claude_desktop_config.json"
    if client == "vscode":
        return _app_support() / "Code" / "User" / "mcp.json"
    if client == "windsurf":
        return Path.home() / ".codeium" / "windsurf" / "mcp_config.json"
    raise ValueError(f"unknown MCP client {client!r}")


def detect() -> List[str]:
    """Clients installed on this computer (their config folder exists)."""
    return [c for c in CLIENTS if config_path(c).parent.is_dir()]


# ── server entries ─────────────────────────────────────────────────────────

def is_wrapped(entry: Dict[str, Any]) -> bool:
    args = entry.get("args")
    if not isinstance(args, list) or "--" not in args:
        return False
    head = args[:args.index("--")]
    return any(head[i:i + 2] == ["mcp", "run"] for i in range(len(head) - 1))


def is_remote(entry: Dict[str, Any]) -> bool:
    return bool(entry.get("url")) or str(entry.get("type", "")).lower() in ("http", "sse", "streamable-http")


def wrap_entry(entry: Dict[str, Any], client: str, name: str, leash_argv: List[str]) -> Dict[str, Any]:
    args = [str(a) for a in entry.get("args") or []]
    new = dict(entry)
    new["command"] = leash_argv[0]
    new["args"] = [*leash_argv[1:], "mcp", "run", "--client", client, "--name", name,
                   "--", str(entry["command"]), *args]
    return new


def unwrap_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    args = list(entry.get("args") or [])
    cut = args.index("--")
    new = dict(entry)
    new["command"], new["args"] = args[cut + 1], args[cut + 2:]
    if not new["args"]:
        new.pop("args")
    return new


def leash_argv() -> List[str]:
    """How the client should start Leash: the absolute executable of this install."""
    from leash.hooks.install import hook_argv

    return hook_argv("x")[:-2]


@dataclass
class Server:
    name: str
    wrapped: bool
    remote: bool
    command: str


@dataclass
class Change:
    client: str
    path: Path
    changed: List[str] = field(default_factory=list)
    skipped: List[Tuple[str, str]] = field(default_factory=list)
    backup: Optional[Path] = None
    error: str = ""
    manual: Dict[str, Any] = field(default_factory=dict)  # entries to paste by hand (config has comments)


def _strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas, leaving strings alone."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("//", i):
            i = text.find("\n", i) if "\n" in text[i:] else n
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
        else:
            out.append(c)
            i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def _load(client: str) -> Tuple[Optional[Dict[str, Any]], str, bool]:
    """Return (config, error, has_comments)."""
    from leash.hooks.install import _read

    path = config_path(client)
    try:
        return _read(path), "", False
    except OSError as exc:
        return None, f"couldn't read {path} ({exc})", False
    except ValueError as exc:
        try:
            doc = json.loads(_strip_jsonc(path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            doc = None
        if isinstance(doc, dict):
            return doc, "", True
        return None, f"couldn't read {path} ({exc})", False


def servers(client: str) -> Tuple[List[Server], str]:
    doc, err, _ = _load(client)
    entries = (doc or {}).get(CLIENTS[client].key)
    out = []
    for name, entry in (entries or {}).items() if isinstance(entries, dict) else ():
        if isinstance(entry, dict):
            wrapped = is_wrapped(entry)
            cmd = unwrap_entry(entry)["command"] if wrapped else entry.get("command", "")
            out.append(Server(name, wrapped, is_remote(entry), str(cmd or entry.get("url", ""))))
    return out, err


def _rewrite(client: str, wrap: bool, only: Optional[List[str]], dry_run: bool) -> Change:
    from leash.hooks.install import Target, _backup, _write

    path = config_path(client)
    change = Change(client, path)
    doc, change.error, has_comments = _load(client)
    if doc is None:
        return change
    entries = doc.get(CLIENTS[client].key)
    if not isinstance(entries, dict):
        return change
    argv = leash_argv() if wrap else []
    for name, entry in entries.items():
        if not isinstance(entry, dict) or (only and name not in only):
            continue
        if wrap:
            if is_wrapped(entry):
                continue
            if is_remote(entry) or not entry.get("command"):
                change.skipped.append((name, "remote server — Leash can only wrap servers that run on this computer"))
                continue
            entries[name] = wrap_entry(entry, client, name, argv)
        else:
            if not is_wrapped(entry):
                continue
            entries[name] = unwrap_entry(entry)
        change.changed.append(name)
    if change.changed and has_comments:
        # Rewriting would drop the user's comments, so show the edit instead.
        change.manual = {name: entries[name] for name in change.changed}
    elif change.changed and not dry_run:
        change.backup = _backup(Target(f"mcp-{client}", "user", path, False))
        _write(path, doc)
    return change


def wrap(client: str, only: Optional[List[str]] = None, dry_run: bool = False) -> Change:
    return _rewrite(client, True, only, dry_run)


def unwrap(client: str, only: Optional[List[str]] = None, dry_run: bool = False) -> Change:
    return _rewrite(client, False, only, dry_run)
