"""Per-host payload parsing and decision rendering.

Each adapter turns the host's pre-tool-use JSON into a :class:`ToolCall` and
renders Leash's verdict in the format that host expects.  A Leash *allow*
never auto-approves: it defers to the host's own permission flow, so Leash
can only make an agent stricter.

References (checked Sept 2026):

* Claude Code  – ``PreToolUse`` → ``hookSpecificOutput.permissionDecision``
* Copilot CLI  – ``preToolUse`` → ``permissionDecision`` (camelCase input)
* Cursor       – ``preToolUse`` / ``beforeShellExecution`` /
  ``beforeMCPExecution`` / ``beforeReadFile`` → ``permission``
* Codex        – ``PreToolUse`` → ``hookSpecificOutput.permissionDecision``
  (``ask`` is not supported, so it is rendered as deny)
* OpenClaw     – plugin ``before_tool_call`` (via the bundled Leash plugin,
  which pipes ``{tool_name, tool_input, cwd}`` in and maps
  ``{decision, reason}`` to ``block`` / ``requireApproval``)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

from leash.hooks.actions import ToolCall

HOSTS = ("claude-code", "copilot", "cursor", "codex", "openclaw")

#: Returned by ``parse`` for tool calls another hook event covers.
DEFER = "defer"


@dataclass
class Verdict:
    decision: str  # allow | deny | ask
    reason: str = ""
    policy: Optional[str] = None
    rule: Optional[str] = None
    request: str = ""

    def message(self) -> str:
        where = f" [{self.policy}/{self.rule}]" if self.policy else ""
        prefix = "Leash requires approval" if self.decision == "ask" else "Blocked by Leash"
        what = f" — {self.request[:200]}" if self.request else ""
        return f"{prefix}: {self.reason}{where}{what}. {EXPLAIN_HINT}"


EXPLAIN_HINT = "(The user can run `leash explain` in a terminal for details and options.)"


Rendered = Tuple[Optional[Dict[str, Any]], int]


def detect_host(payload: Mapping[str, Any]) -> str:
    """Guess the host from its payload (for plugins shared across hosts)."""
    if payload.get("hook_event_name") == "before_tool_call":
        return "openclaw"
    if "cursor_version" in payload or "conversation_id" in payload:
        return "cursor"
    if "toolName" in payload or "toolArgs" in payload:
        return "copilot"
    if "turn_id" in payload:
        return "codex"
    if "transcript_path" in payload or "tool_use_id" in payload or "permission_mode" in payload:
        return "claude-code"
    if isinstance(payload.get("timestamp"), str):
        return "copilot"
    return "claude-code"


# ── Claude Code / Codex (same wire format) ────────────────────────────────

def _parse_claude_like(host: str, payload: Mapping[str, Any]):
    event = payload.get("hook_event_name")
    if event and event != "PreToolUse":
        return None
    server = payload.get("mcp_server")
    return ToolCall(
        host=host,
        tool=str(payload.get("tool_name") or ""),
        args=payload.get("tool_input") or {},
        cwd=str(payload.get("cwd") or ""),
        session=str(payload.get("session_id") or ""),
        mcp_server=server.get("name") if isinstance(server, Mapping) else None,
    )


def _render_claude(verdict: Verdict, payload: Mapping[str, Any]) -> Rendered:
    if verdict.decision == "allow":
        return None, 0
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": verdict.decision,
            "permissionDecisionReason": verdict.message(),
        }
    }, 0


def _render_codex(verdict: Verdict, payload: Mapping[str, Any]) -> Rendered:
    if verdict.decision == "allow":
        return None, 0
    msg = verdict.message()
    if verdict.decision == "ask":
        msg += " (Codex hooks can't prompt, so this is blocked; approve it by editing your Leash policy)"
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": msg,
        }
    }, 0


# ── Copilot CLI ────────────────────────────────────────────────────────────

def _parse_copilot(payload: Mapping[str, Any]):
    event = payload.get("hook_event_name") or payload.get("hookEventName")
    if event and event not in ("PreToolUse", "preToolUse"):
        return None
    if "toolName" in payload or "toolArgs" in payload:
        return ToolCall(
            host="copilot",
            tool=str(payload.get("toolName") or ""),
            args=payload.get("toolArgs") or {},
            cwd=str(payload.get("cwd") or ""),
            session=str(payload.get("sessionId") or ""),
        )
    return ToolCall(
        host="copilot",
        tool=str(payload.get("tool_name") or ""),
        args=payload.get("tool_input") or {},
        cwd=str(payload.get("cwd") or ""),
        session=str(payload.get("session_id") or ""),
    )


def _render_copilot(verdict: Verdict, payload: Mapping[str, Any]) -> Rendered:
    if verdict.decision == "allow":
        return None, 0
    out: Dict[str, Any] = {
        "permissionDecision": verdict.decision,
        "permissionDecisionReason": verdict.message(),
    }
    if payload.get("hook_event_name") == "PreToolUse":
        out["hookSpecificOutput"] = {"hookEventName": "PreToolUse", **out}
    return out, 0


# ── Cursor ─────────────────────────────────────────────────────────────────

def _parse_cursor(payload: Mapping[str, Any]):
    event = payload.get("hook_event_name") or "preToolUse"
    base = dict(
        host="cursor",
        cwd=str(payload.get("cwd") or ""),
        session=str(payload.get("conversation_id") or ""),
        workspace_roots=tuple(payload.get("workspace_roots") or ()),
    )
    if not base["cwd"] and base["workspace_roots"]:
        base["cwd"] = str(base["workspace_roots"][0])
    if event == "preToolUse":
        tool = str(payload.get("tool_name") or "")
        # Shell and MCP calls are evaluated by beforeShellExecution /
        # beforeMCPExecution, which (unlike preToolUse) can prompt the user.
        if tool == "Shell" or tool.startswith("MCP:"):
            return DEFER
        return ToolCall(tool=tool, args=payload.get("tool_input") or {}, **base)
    if event == "beforeShellExecution":
        return ToolCall(tool="Shell", args={"command": payload.get("command") or ""}, **base)
    if event == "beforeMCPExecution":
        return ToolCall(
            tool=str(payload.get("tool_name") or ""),
            args=payload.get("tool_input") or {},
            mcp_server=str(payload.get("mcp_server_name") or "unknown"),
            **base,
        )
    if event == "beforeReadFile":
        return ToolCall(tool="Read", args={"file_path": payload.get("file_path") or ""}, **base)
    return None


def _render_cursor(verdict: Verdict, payload: Mapping[str, Any]) -> Rendered:
    event = payload.get("hook_event_name") or "preToolUse"
    if verdict.decision == "allow":
        return {"permission": "allow"}, 0
    decision, msg = verdict.decision, verdict.message()
    if decision == "ask" and event not in ("beforeShellExecution", "beforeMCPExecution"):
        decision = "deny"
        msg += " (Cursor can't prompt for this tool, so it is blocked)"
    return {"permission": decision, "user_message": msg, "agent_message": msg}, 0


# ── OpenClaw (via the Leash plugin's before_tool_call handler) ────────────

def _parse_openclaw(payload: Mapping[str, Any]):
    event = payload.get("hook_event_name")
    if event and event != "before_tool_call":
        return None
    tool = str(payload.get("tool_name") or "")
    # Code Mode's outer `exec` runs JavaScript, not a shell command.
    if payload.get("tool_kind") == "code_mode_exec":
        tool = "code_mode_exec"
    return ToolCall(
        host="openclaw",
        tool=tool,
        args=payload.get("tool_input") or {},
        cwd=str(payload.get("cwd") or ""),
        session=str(payload.get("session_id") or ""),
    )


def _render_openclaw(verdict: Verdict, payload: Mapping[str, Any]) -> Rendered:
    out: Dict[str, Any] = {"decision": verdict.decision}
    if verdict.decision != "allow":
        out["reason"] = verdict.message()
    return out, 0


# ── registry ───────────────────────────────────────────────────────────────

def parse(host: str, payload: Mapping[str, Any]):
    if host == "claude-code":
        return _parse_claude_like("claude-code", payload)
    if host == "codex":
        return _parse_claude_like("codex", payload)
    if host == "copilot":
        return _parse_copilot(payload)
    if host == "cursor":
        return _parse_cursor(payload)
    if host == "openclaw":
        return _parse_openclaw(payload)
    raise ValueError(f"Unknown host '{host}'. Choose from: {', '.join(HOSTS)}")


def render(host: str, verdict: Verdict, payload: Mapping[str, Any]) -> Rendered:
    return {
        "claude-code": _render_claude,
        "codex": _render_codex,
        "copilot": _render_copilot,
        "cursor": _render_cursor,
        "openclaw": _render_openclaw,
    }[host](verdict, payload)


def passthrough(host: str, payload: Mapping[str, Any]) -> Rendered:
    """Output for events Leash doesn't evaluate (no opinion)."""
    if host == "cursor":
        return {"permission": "allow"}, 0
    if host == "openclaw":
        return {"decision": "allow"}, 0
    return None, 0
