"""Map host tool calls onto Leash's normalized action model.

Every host (Claude Code, Copilot CLI, Cursor, Codex) names its tools
differently.  Policies are written once against a small vocabulary:

=========================  ======================================  ==========================
action                     resource                                example host tools
=========================  ======================================  ==========================
``shell.exec``             the command, and each sub-command       Bash, bash, Shell, exec
``file.read``              absolute, symlink-resolved path         Read, view
``file.write``             absolute, symlink-resolved path         Write, Edit, apply_patch
``file.delete``            absolute, symlink-resolved path         Delete
``file.search``            directory or file searched              Grep, Glob, rg
``web.fetch``              URL                                     WebFetch, web_fetch
``web.search``             query                                   WebSearch
``agent.spawn``            sub-agent type                          Task, Agent, task
``mcp.<server>.<tool>``    empty (arguments are in context)        mcp__github__create_pr
``tool.<name>``            empty                                   anything else
=========================  ======================================  ==========================

Each request also carries a context with ``host``, ``tool``, ``cwd``,
``session`` and, for file actions, ``in_workspace`` (true/false), so rules can
use ``conditions:``.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

SHELL_TOOLS = {
    "bash", "powershell", "shell", "run_terminal_cmd", "exec_command",
    "local_shell", "container.exec", "run_shell_command", "exec",
}
READ_TOOLS = {"read", "view", "read_file", "notebookread"}
WRITE_TOOLS = {
    "write", "edit", "multiedit", "notebookedit", "create", "str_replace_editor",
    "str_replace_based_edit_tool", "edit_file", "search_replace", "write_file",
    "replace", "write_to_file",
}
DELETE_TOOLS = {"delete", "delete_file"}
PATCH_TOOLS = {"apply_patch"}
SEARCH_TOOLS = {"grep", "glob", "rg", "ls", "list_dir", "codebase_search", "file_search", "search_file_content"}
FETCH_TOOLS = {"webfetch", "web_fetch", "fetch"}
WEB_SEARCH_TOOLS = {"websearch", "web_search"}
AGENT_TOOLS = {"task", "agent", "spawn_agent"}

_PATH_KEYS = ("file_path", "path", "notebook_path", "target_file", "filePath", "absolute_path", "file")
_PATCH_HEADER = re.compile(r"^\*\*\* (Add|Update|Delete) File: (.+)$|^\*\*\* Move to: (.+)$", re.M)
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_WRAPPERS = {"sudo", "env", "command", "exec", "nohup", "time", "nice", "doas", "builtin"}


@dataclass
class ToolCall:
    """A host-agnostic view of one pending tool call."""

    host: str
    tool: str
    args: Any
    cwd: str = ""
    session: str = ""
    workspace_roots: Sequence[str] = ()
    mcp_server: Optional[str] = None


@dataclass
class ActionRequest:
    action: str
    resource: str = ""
    context: Dict[str, Any] = field(default_factory=dict)

    def describe(self) -> str:
        return f"{self.action} {self.resource}".strip()


def _as_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip().startswith("{"):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except ValueError:
            return {}
    return {}


def resolve_path(path: str, cwd: str = "") -> str:
    """Absolute, ``~``-expanded, symlink-resolved path with ``/`` separators."""
    if not path:
        return ""
    path = os.path.expanduser(str(path))
    if not os.path.isabs(path):
        path = os.path.join(cwd or os.getcwd(), path)
    return os.path.realpath(path).replace("\\", "/")


def _within(path: str, roots: Iterable[str]) -> bool:
    for root in roots:
        if not root:
            continue
        root = root.rstrip("/") or "/"
        if root == "/" or path == root or path.startswith(root + "/"):
            return True
    return False


# ── shell ──────────────────────────────────────────────────────────────────

def shell_command_text(args: Mapping[str, Any]) -> str:
    cmd = args.get("command", args.get("cmd", ""))
    if isinstance(cmd, (list, tuple)):
        parts = [str(p) for p in cmd]
        # ["bash", "-lc", "<script>"] → "<script>"
        if len(parts) >= 3 and os.path.basename(parts[0]) in ("bash", "sh", "zsh") and parts[1] in ("-c", "-lc"):
            return parts[-1]
        return shlex.join(parts)
    return str(cmd or "")


def _match_paren(text: str, open_idx: int) -> int:
    depth = 0
    for j in range(open_idx, len(text)):
        if text[j] == "(":
            depth += 1
        elif text[j] == ")":
            depth -= 1
            if depth == 0:
                return j
    return len(text)


def split_shell(command: str) -> List[str]:
    """Split a command line into simple commands.

    Splits on unquoted ``;``, ``&``, ``|`` (so also ``&&``/``||``) and
    newlines, and extracts ``$( … )``, ``<( … )``/``>( … )`` and backtick
    substitutions as extra
    segments.  A best-effort lexer for policy matching, not a shell parser.
    """
    segments: List[str] = []
    buf: List[str] = []
    quote: Optional[str] = None
    i, n = 0, len(command)

    def flush() -> None:
        seg = "".join(buf).strip()
        if seg:
            segments.append(seg)
        buf.clear()

    while i < n:
        c = command[i]
        if quote == "'":
            if c == "'":
                quote = None
            buf.append(c)
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            buf.append(command[i:i + 2])
            i += 2
            continue
        if command.startswith(("$(", "<(", ">("), i):
            end = _match_paren(command, i + 1)
            segments.extend(split_shell(command[i + 2:end]))
            buf.append(command[i:end + 1])
            i = end + 1
            continue
        if c == "`":
            end = command.find("`", i + 1)
            end = n if end == -1 else end
            segments.extend(split_shell(command[i + 1:end]))
            buf.append(command[i:end + 1])
            i = end + 1
            continue
        if quote == '"':
            if c == '"':
                quote = None
            buf.append(c)
        elif c in ("'", '"'):
            quote = c
            buf.append(c)
        elif c in ";|&\n":
            flush()
        else:
            buf.append(c)
        i += 1
    flush()
    return segments


_KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "}", "(", ")"}
_CASE_INSENSITIVE_FS = sys.platform in ("darwin", "win32")


def _strip_wrappers(segment: str) -> str:
    """``FOO=1 sudo -E rm -rf /`` → ``rm -rf /``."""
    try:
        words = shlex.split(segment, posix=True)
    except ValueError:
        return segment
    i = 0
    while i < len(words):
        if _ENV_ASSIGN.match(words[i]):
            i += 1
        elif os.path.basename(words[i]) in _WRAPPERS:
            i += 1
            while i < len(words) and words[i].startswith("-"):
                i += 1
        else:
            break
    if i == 0 or i >= len(words):
        return segment
    return " ".join(words[i:])


def _home_to_tilde(word: str) -> str:
    home = os.path.expanduser("~").rstrip("/")
    word = word.replace("${HOME}", "$HOME")
    if home and (word == home or word.startswith(home + "/")):
        return "~" + word[len(home):]
    return word


def _canonical_command(segment: str) -> str:
    """Reduce a simple command to what actually runs, for matching:
    ``( \\/bin/rm -rf "$HOME" )`` / ``then sudo rm -rf ~`` → ``rm -rf ~``.

    Unquotes words, drops grouping characters and shell keywords, strips
    ``sudo``/``env``/``VAR=`` wrappers, reduces the command word to its
    basename, and writes the home directory as ``~``.
    """
    try:
        words = shlex.split(segment, posix=True)
    except ValueError:
        words = segment.split()
    if words:
        words[0] = words[0].lstrip("({!")
        last = words[-1]
        # Drop a closing `)`/`}` of a group, but not of `${HOME}` or `$(x)`.
        while last and last[-1] in ")}" and last.count(last[-1]) > last.count("({"[")}".index(last[-1])]):
            last = last[:-1]
        words[-1] = last
    words = [w for w in words if w]
    while words and words[0] in _KEYWORDS:
        words = words[1:]
    i = 0
    while i < len(words):
        if _ENV_ASSIGN.match(words[i]):
            i += 1
        elif os.path.basename(words[i].lstrip("\\")) in _WRAPPERS:
            i += 1
            while i < len(words) and words[i].startswith("-"):
                i += 1
        elif words[i] in _KEYWORDS:
            i += 1
        else:
            break
    words = words[i:]
    if not words:
        return ""
    words[0] = os.path.basename(words[0].lstrip("\\")) or words[0]
    return " ".join(_home_to_tilde(w) for w in words)


def _collapse(text: str) -> str:
    return " ".join(text.split())


def shell_requests(command: str, context: Dict[str, Any]) -> List[ActionRequest]:
    """One request for the whole command line, plus several forms of each
    sub-command (as written, without wrappers, and canonicalized)."""
    full = command.strip()
    variants = [full]
    for seg in split_shell(full):
        variants.append(_collapse(seg))
        variants.append(_collapse(_strip_wrappers(seg)))
        variants.append(_canonical_command(seg))
    if _CASE_INSENSITIVE_FS:
        # `RM -RF /` and `cat ~/.SSH/id_rsa` work on case-insensitive filesystems
        variants += [v.lower() for v in variants]
    seen, out = set(), []
    for v in variants:
        if v and v not in seen:
            seen.add(v)
            out.append(ActionRequest("shell.exec", v, dict(context)))
    return out or [ActionRequest("shell.exec", "", dict(context))]


# ── patches ────────────────────────────────────────────────────────────────

def patch_paths(patch: str) -> List[Tuple[str, str]]:
    """``[(action, path)]`` for every file an ``apply_patch`` envelope touches."""
    found = []
    for m in _PATCH_HEADER.finditer(patch or ""):
        kind, path, moved = m.group(1), m.group(2), m.group(3)
        if moved:
            found.append(("file.write", moved.strip()))
        else:
            found.append(("file.delete" if kind == "Delete" else "file.write", path.strip()))
    return found


# ── main entry point ───────────────────────────────────────────────────────

def _first_str(args: Mapping[str, Any], keys: Sequence[str]) -> str:
    for k in keys:
        v = args.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


def _mcp_parts(call: ToolCall) -> Optional[Tuple[str, str]]:
    name = call.tool
    if name.startswith("mcp__"):
        parts = name.split("__", 2)
        if len(parts) == 3:
            return parts[1], parts[2]
    if name.startswith("MCP:"):
        return call.mcp_server or "", name[4:]
    if call.mcp_server:
        return call.mcp_server, name
    return None


def _scalar_args(args: Mapping[str, Any]) -> Dict[str, Any]:
    return {f"arg.{k}": v for k, v in args.items() if isinstance(v, (str, int, float, bool))}


def requests_for(call: ToolCall) -> List[ActionRequest]:
    """Translate a :class:`ToolCall` into one or more :class:`ActionRequest`."""
    args = _as_dict(call.args)
    tool_key = call.tool.lower()
    roots = [resolve_path(r) for r in (call.workspace_roots or ()) if r]
    if call.cwd:
        roots.append(resolve_path(call.cwd))
    if os.getenv("CLAUDE_PROJECT_DIR"):
        roots.append(resolve_path(os.environ["CLAUDE_PROJECT_DIR"]))

    base = {"host": call.host, "tool": call.tool, "cwd": call.cwd, "session": call.session}

    def file_reqs(action: str, raw_path: str) -> List[ActionRequest]:
        path = resolve_path(raw_path, call.cwd)
        ctx = {**base, "in_workspace": bool(path) and _within(path, roots)}
        reqs = [ActionRequest(action, path, ctx)]
        if _CASE_INSENSITIVE_FS and path.lower() != path:
            # ~/.SSH/id_rsa is ~/.ssh/id_rsa on APFS/NTFS; also check the
            # lower-cased path so lower-case rules can't be sidestepped.
            reqs.append(ActionRequest(action, path.lower(), dict(ctx)))
        return reqs

    mcp = _mcp_parts(call)
    if mcp:
        server, tool = mcp
        action = f"mcp.{server}.{tool}" if server else f"mcp.{tool}"
        return [ActionRequest(action, "", {**base, "mcp_server": server, "mcp_tool": tool, **_scalar_args(args)})]

    if tool_key in SHELL_TOOLS:
        return shell_requests(shell_command_text(args), base)

    if tool_key in PATCH_TOOLS:
        patch = args.get("input") or args.get("patch") or shell_command_text(args)
        if not args and isinstance(call.args, str):
            patch = call.args
        paths = patch_paths(str(patch))
        if not paths:
            return [ActionRequest("file.write", "", {**base, "in_workspace": False})]
        return [r for action, p in paths for r in file_reqs(action, p)]

    if tool_key in ("str_replace_editor", "str_replace_based_edit_tool") and args.get("command") == "view":
        return file_reqs("file.read", _first_str(args, _PATH_KEYS))
    if tool_key in READ_TOOLS:
        return file_reqs("file.read", _first_str(args, _PATH_KEYS))
    if tool_key in WRITE_TOOLS:
        return file_reqs("file.write", _first_str(args, _PATH_KEYS))
    if tool_key in DELETE_TOOLS:
        return file_reqs("file.delete", _first_str(args, _PATH_KEYS))
    if tool_key in SEARCH_TOOLS:
        target = _first_str(args, ("path", "dir_path", "target_directory", "directory")) or call.cwd
        return file_reqs("file.search", target)
    if tool_key in FETCH_TOOLS:
        return [ActionRequest("web.fetch", _first_str(args, ("url", "uri")), base)]
    if tool_key in WEB_SEARCH_TOOLS:
        return [ActionRequest("web.search", _first_str(args, ("query", "q")), base)]
    if tool_key in AGENT_TOOLS:
        kind = _first_str(args, ("subagent_type", "agent_type", "agent", "name")) or "default"
        return [ActionRequest("agent.spawn", kind, base)]

    return [ActionRequest(f"tool.{call.tool}", "", {**base, **_scalar_args(args)})]
