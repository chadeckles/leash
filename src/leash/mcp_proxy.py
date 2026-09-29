"""Leash MCP Proxy – authorization sidecar for any MCP server.

Sits between an MCP client and an upstream MCP server, intercepting every
``tools/call`` request through Leash's policy engine before forwarding it.

Architecture::

    MCP Client (Claude, Cursor, etc.)
        │  stdio / SSE
        ▼
    Leash MCP Proxy
        │  authorize ──▶ Leash server ──▶ allow/deny
        │  audit     ──▶ Leash server ──▶ signed log
        ▼  forward
    Upstream MCP Server (your tools)

Usage::

    # Start the proxy (wraps an upstream MCP server command):
    python -m leash.mcp_proxy \
        --leash-url http://localhost:8000 \
        --agent-name "my-mcp-agent" \
        -- npx -y @modelcontextprotocol/server-filesystem /data

    # Or in claude_desktop_config.json / cursor MCP settings:
    {
      "mcpServers": {
        "guarded-fs": {
          "command": "python",
          "args": [
            "-m", "leash.mcp_proxy",
            "--leash-url", "http://localhost:8000",
            "--agent-name", "fs-agent",
            "--", "npx", "-y",
            "@modelcontextprotocol/server-filesystem", "/data"
          ]
        }
      }
    }

Maps to OWASP ASI:
- ASI02 (Tool Misuse) → per-tool authorization
- ASI03 (Identity & Privilege) → scoped agent identity + JWT
- ASI09 (Human-Agent Trust) → signed audit trail
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from leash.client import LeashAgent

logger = logging.getLogger("leash.mcp_proxy")

# Argument names that commonly carry a resource a tool acts on.  Every one
# present is authorized as a ``resource`` so policy ``resource:`` globs apply
# (e.g. both ``source`` and ``destination`` of a move must be allowed).
_RESOURCE_ARG_KEYS = (
    "path", "paths", "file_path", "filepath", "filename", "file",
    "uri", "url", "directory", "dir", "source", "destination",
)


def _extract_resources(tool_args: Any) -> List[str]:
    if not isinstance(tool_args, dict):
        return []
    found: List[str] = []
    for key in _RESOURCE_ARG_KEYS:
        value = tool_args.get(key)
        values = value if isinstance(value, list) else [value]
        for v in values:
            if isinstance(v, str) and v and v not in found:
                found.append(v)
    return found


def _args_to_context(tool_args: Any) -> Dict[str, Any]:
    """Expose scalar tool arguments to policy conditions as ``arg.<name>``.

    Arguments are model-controlled, so they are namespaced to avoid being
    confused with trusted context keys (e.g. ``user_role``).
    """
    if not isinstance(tool_args, dict):
        return {}
    return {
        f"arg.{k}": v for k, v in tool_args.items()
        if isinstance(v, (str, int, float, bool))
    }


def _default_token_file(agent_name: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in agent_name)
    return Path.home() / ".leash" / f"mcp_{safe}.json"


class MCPProxy:
    """Proxies JSON-RPC messages between an MCP client (stdin/stdout) and an
    upstream MCP server (subprocess), injecting Leash authorization on
    ``tools/call`` requests.
    """

    def __init__(
        self,
        upstream_cmd: List[str],
        leash_url: str = "http://localhost:8000",
        agent_name: str = "mcp-proxy",
        on_deny: str = "error",
        auto_discover: bool = True,
        on_tool_change: str = "block",
    ):
        self.upstream_cmd = upstream_cmd
        self.leash_url = leash_url
        self.agent_name = agent_name
        self.on_deny = on_deny
        self.auto_discover = auto_discover
        self.on_tool_change = on_tool_change

        self._agent: Optional[LeashAgent] = None
        self._upstream: Optional[subprocess.Popen] = None
        self._discovered_tools: Dict[str, Any] = {}
        self._tool_hashes: Dict[str, str] = {}  # tool_name → SHA-256 of description
        self._tools_seen: bool = False  # True after first tools/list response
        # Tools whose description/schema changed mid-session (possible rug-pull)
        self._quarantined: set[str] = set()

    def start(self) -> None:
        """Start the upstream MCP server and begin proxying."""
        # Connect to Leash
        self._agent = LeashAgent(
            self.leash_url,
            name=self.agent_name,
            token_file=_default_token_file(self.agent_name),
        )
        self._agent.connect()
        logger.info("Connected to Leash as %s", self._agent.agent_id)

        # Start upstream MCP server as a subprocess
        self._upstream = subprocess.Popen(
            self.upstream_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            bufsize=0,
        )
        logger.info("Started upstream: %s", " ".join(self.upstream_cmd))

        # Read from upstream stdout in a background thread and forward to
        # our stdout (the MCP client).  We intercept responses to
        # tools/list to learn available tools.
        upstream_reader = threading.Thread(
            target=self._read_upstream, daemon=True
        )
        upstream_reader.start()

        # Main loop: read from stdin (MCP client) and proxy to upstream
        self._read_client()

    def _read_client(self) -> None:
        """Read JSON-RPC messages from the MCP client (our stdin)."""
        buffer = ""
        for line in sys.stdin:
            buffer += line
            # MCP stdio uses newline-delimited JSON
            if line.strip() == "":
                continue
            try:
                msg = json.loads(buffer.strip())
                buffer = ""
            except json.JSONDecodeError:
                continue

            handled = self._handle_client_message(msg)
            if not handled:
                # Forward unmodified to upstream
                self._send_upstream(msg)

    def _read_upstream(self) -> None:
        """Read JSON-RPC messages from the upstream MCP server (subprocess stdout)."""
        assert self._upstream and self._upstream.stdout
        for line in self._upstream.stdout:
            decoded = line.decode("utf-8", errors="replace")
            if not decoded.strip():
                continue

            try:
                msg = json.loads(decoded.strip())
            except json.JSONDecodeError:
                # Forward raw line as-is
                sys.stdout.write(decoded)
                sys.stdout.flush()
                continue

            # Intercept tools/list responses to learn available tools
            if self._is_tools_list_response(msg):
                self._on_tools_discovered(msg)

            # Forward to client
            sys.stdout.write(json.dumps(msg) + "\n")
            sys.stdout.flush()

    def _handle_client_message(self, msg: dict) -> bool:
        """Intercept tools/call requests for authorization.

        Returns True if the message was handled (either forwarded or denied),
        False if it should be forwarded as-is.
        """
        method = msg.get("method")
        if method != "tools/call":
            return False

        # Extract tool name and arguments
        params = msg.get("params", {})
        tool_name = params.get("name", "unknown")
        tool_args = params.get("arguments", {})
        msg_id = msg.get("id")

        assert self._agent is not None

        if tool_name in self._quarantined and self.on_tool_change == "block":
            logger.warning("BLOCKED: %s — tool definition changed mid-session (ASI04)", tool_name)
            self._send_client_error(
                msg_id,
                f"Leash blocked '{tool_name}': tool description/schema changed "
                f"mid-session (possible tool poisoning). Restart the session to re-trust it.",
            )
            return True

        # Authorize with Leash — once per resource argument; all must be
        # allowed.  The server records every decision (including resource +
        # argument context) in the audit trail, so no separate /audit call
        # is needed here.
        context = _args_to_context(tool_args) or None
        try:
            auth: Dict[str, Any] = {"decision": "deny"}
            for resource in _extract_resources(tool_args) or [""]:
                auth = self._agent.authorize(tool_name, resource=resource, context=context)
                if auth.get("decision", "deny") != "allow":
                    break
        except Exception as exc:
            logger.error("Leash authorization failed: %s", exc)
            # Fail-closed: deny if Leash is unreachable
            self._send_client_error(
                msg_id,
                f"Authorization service unavailable: {exc}",
            )
            return True

        decision = auth.get("decision", "deny")

        if decision != "allow":
            reason = auth.get("reason", "denied by policy")
            logger.warning("DENIED: %s → %s", tool_name, reason)
            self._send_client_error(
                msg_id,
                f"Leash denied '{tool_name}': {reason}",
            )
            return True

        logger.info("ALLOWED: %s", tool_name)
        self._send_upstream(msg)
        return True

    def _is_tools_list_response(self, msg: dict) -> bool:
        """Check if a message is a response to tools/list."""
        result = msg.get("result")
        if not isinstance(result, dict):
            return False
        tools = result.get("tools")
        return isinstance(tools, list)

    def _on_tools_discovered(self, msg: dict) -> None:
        """Called when we see a tools/list response from upstream.

        On the first call, records SHA-256 hashes of each tool's description.
        On subsequent calls, compares hashes to detect tool poisoning —
        a rug-pull attack where an MCP server changes tool descriptions
        mid-session to hijack agent behaviour (OWASP ASI04).
        """
        tools = msg.get("result", {}).get("tools", [])
        changed_tools: list[str] = []

        for t in tools:
            name = t.get("name", "")
            if not name:
                continue

            # Compute a stable hash of the tool's description + schema
            desc = t.get("description", "")
            schema = json.dumps(t.get("inputSchema", {}), sort_keys=True)
            h = hashlib.sha256(f"{desc}|{schema}".encode()).hexdigest()

            if self._tools_seen:
                # Compare with previously recorded hash
                old_hash = self._tool_hashes.get(name)
                if old_hash and old_hash != h:
                    changed_tools.append(name)
                    self._quarantined.add(name)
                    logger.warning(
                        "TOOL POISONING DETECTED: '%s' description/schema changed "
                        "mid-session (ASI04). old=%s new=%s",
                        name, old_hash[:12], h[:12],
                    )

            self._tool_hashes[name] = h
            self._discovered_tools[name] = t
            # Register in the LeashAgent's tool map for discover()
            if self._agent:
                self._agent._tools[name] = lambda: None  # placeholder

        if changed_tools:
            logger.warning(
                "⚠ %d tool(s) changed mid-session: %s — possible rug-pull attack",
                len(changed_tools), ", ".join(changed_tools),
            )
            # Audit the poisoning detection
            if self._agent:
                try:
                    self._agent.audit(
                        "leash.tool_poisoning_detected", "deny",
                        inputs={"changed_tools": changed_tools},
                    )
                except Exception:
                    pass

        if not self._tools_seen:
            logger.info(
                "Discovered %d tools from upstream: %s",
                len(tools),
                ", ".join(self._discovered_tools.keys()),
            )
            logger.info(
                "Tool description hashes recorded for poisoning detection (ASI04)",
            )

        self._tools_seen = True

        # Auto-create a starter policy if requested (only on first discovery)
        if self.auto_discover and self._agent and self._discovered_tools:
            try:
                self._agent.discover(
                    default_effect="deny",
                    policy_name=f"mcp-{self.agent_name}",
                    policy_priority=10,
                )
            except Exception as exc:
                logger.warning("Auto-discovery policy creation failed: %s", exc)

    def _send_upstream(self, msg: dict) -> None:
        """Send a JSON-RPC message to the upstream MCP server."""
        if self._upstream and self._upstream.stdin:
            data = json.dumps(msg) + "\n"
            self._upstream.stdin.write(data.encode("utf-8"))
            self._upstream.stdin.flush()

    def _send_client_error(self, msg_id: Any, message: str) -> None:
        """Send a JSON-RPC error response back to the MCP client."""
        error_response = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {
                "code": -32600,
                "message": message,
            },
        }
        sys.stdout.write(json.dumps(error_response) + "\n")
        sys.stdout.flush()

    def stop(self) -> None:
        """Shut down the upstream process and Leash connection."""
        if self._upstream:
            self._upstream.terminate()
            self._upstream.wait(timeout=5)
        if self._agent:
            self._agent.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="leash-mcp-proxy",
        description="Leash authorization proxy for MCP servers",
    )
    parser.add_argument(
        "--leash-url",
        default="http://localhost:8000",
        help="Leash server URL (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--agent-name",
        default="mcp-proxy",
        help="Agent name for Leash registration",
    )
    parser.add_argument(
        "--on-deny",
        choices=["error", "empty"],
        default="error",
        help="Behaviour on deny: return error or empty result",
    )
    parser.add_argument(
        "--on-tool-change",
        choices=["block", "warn"],
        default="block",
        help="When a tool's description/schema changes mid-session: block further "
             "calls to it (default) or only warn",
    )
    parser.add_argument(
        "--no-auto-discover",
        action="store_true",
        help="Don't auto-create a policy from discovered tools",
    )
    parser.add_argument(
        "upstream_cmd",
        nargs=argparse.REMAINDER,
        help="Upstream MCP server command (after --)",
    )

    args = parser.parse_args()

    # Strip leading '--' from upstream command
    upstream = args.upstream_cmd
    if upstream and upstream[0] == "--":
        upstream = upstream[1:]

    if not upstream:
        parser.error("No upstream MCP server command provided. Use: -- <command>")

    logging.basicConfig(
        level=logging.INFO,
        format="[leash-mcp] %(levelname)s %(message)s",
        stream=sys.stderr,  # Logs go to stderr; stdout is for MCP JSON-RPC
    )

    proxy = MCPProxy(
        upstream_cmd=upstream,
        leash_url=args.leash_url,
        agent_name=args.agent_name,
        on_deny=args.on_deny,
        auto_discover=not args.no_auto_discover,
        on_tool_change=args.on_tool_change,
    )

    try:
        proxy.start()
    except KeyboardInterrupt:
        pass
    finally:
        proxy.stop()


if __name__ == "__main__":
    main()
