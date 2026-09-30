"""``leash mcp run``: a stdio MCP proxy that checks tool calls locally.

The MCP client starts this process instead of the MCP server; it starts the
real server as a child and passes JSON-RPC messages through, except:

* ``tools/list`` results are filtered through :mod:`leash.mcp.pins`;
* ``tools/call`` requests are checked against your Leash policies, exactly
  like a hook would check them (action ``mcp.<server>.<tool>``).  Allowed
  calls go through; blocked ones get an error result the AI can read; calls
  that need approval are shown to you as an MCP elicitation prompt when the
  client supports it, and refused otherwise.

No server, port or token is involved, and decisions go to the same audit log
as the hooks (``host: "mcp"``).
"""

from __future__ import annotations

import itertools
import json
import os
import subprocess
import sys
import threading
import time
from typing import IO, Any, Dict, List, Optional

from leash.hooks.actions import ToolCall
from leash.hooks.hosts import Verdict
from leash.mcp import clients
from leash.mcp.pins import Pins

APPROVAL_TIMEOUT = 300


class Proxy:
    def __init__(self, cmd: List[str], client: Optional[str] = None, name: Optional[str] = None,
                 stdin: Optional[IO[bytes]] = None, stdout: Optional[IO[bytes]] = None,
                 stderr: Optional[IO[str]] = None):
        self.cmd = cmd
        self.client = client or ""
        self.name = name or os.path.basename(cmd[0]).split(".")[0] or "server"
        self.stdin = stdin or sys.stdin.buffer
        self.stdout = stdout or sys.stdout.buffer
        self.stderr = stderr or sys.stderr
        self.observe = os.getenv("LEASH_MODE", "").lower() == "observe"
        self.session = ""
        self.can_prompt = False
        self._out_lock = threading.Lock()
        self._in_lock = threading.Lock()
        self._list_ids: set = set()
        self._withheld: Dict[str, str] = {}
        self._waiting: Dict[str, Dict[str, Any]] = {}
        self._ids = itertools.count(1)
        self._proc: Optional[subprocess.Popen] = None

    # ── plumbing ───────────────────────────────────────────────────────────

    def run(self) -> int:
        try:
            self._proc = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                          stderr=None, bufsize=0)
        except OSError as exc:
            self.note(f"couldn't start the MCP server {self.cmd[0]!r}: {exc}")
            return 127
        upstream = threading.Thread(target=self._read_upstream, daemon=True)
        upstream.start()
        client = threading.Thread(target=self._read_client, daemon=True)
        client.start()
        while upstream.is_alive() and client.is_alive():
            upstream.join(0.2)
        if not client.is_alive():  # client went away: let the server finish, then stop it
            self._close_upstream()
            upstream.join(10)
        return self._stop()

    def _close_upstream(self) -> None:
        try:
            if self._proc and self._proc.stdin:
                self._proc.stdin.close()
        except OSError:
            pass

    def _stop(self) -> int:
        proc = self._proc
        if proc is None:
            return 0
        try:
            return proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                return proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
                return proc.wait()

    def note(self, text: str) -> None:
        try:
            self.stderr.write(f"[leash] {text}\n")
            self.stderr.flush()
        except (OSError, ValueError):
            pass

    def _send(self, stream: IO[bytes], lock: threading.Lock, msg: Any) -> None:
        data = (json.dumps(msg, separators=(",", ":")) + "\n").encode()
        with lock:
            try:
                stream.write(data)
                stream.flush()
            except (OSError, ValueError):
                pass

    def to_client(self, msg: Any) -> None:
        self._send(self.stdout, self._out_lock, msg)

    def to_server(self, msg: Any) -> None:
        assert self._proc and self._proc.stdin
        self._send(self._proc.stdin, self._in_lock, msg)

    def _messages(self, stream: IO[bytes]):
        for line in iter(stream.readline, b""):
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                yield line
                continue
            for m in (msg if isinstance(msg, list) else [msg]):
                yield m

    def _read_client(self) -> None:
        for msg in self._messages(self.stdin):
            if isinstance(msg, bytes):
                with self._in_lock:
                    self._proc.stdin.write(msg)  # type: ignore[union-attr]
                continue
            try:
                self.from_client(msg)
            except Exception as exc:  # noqa: BLE001 — never let one message kill the session
                self.note(f"error handling a message from the client: {exc}")
                if isinstance(msg, dict) and msg.get("method") == "tools/call" and "id" in msg:
                    self._refuse(msg["id"], f"Leash couldn't check this call ({exc}), so it was blocked.")

    def _read_upstream(self) -> None:
        assert self._proc and self._proc.stdout
        for msg in self._messages(self._proc.stdout):
            if isinstance(msg, bytes):
                with self._out_lock:
                    self.stdout.write(msg)
                    self.stdout.flush()
                continue
            if isinstance(msg, dict) and msg.get("id") in self._list_ids and "method" not in msg:
                self._list_ids.discard(msg.get("id"))
                msg = self._filter_tools(msg)
            self.to_client(msg)

    # ── client → server ───────────────────────────────────────────────────

    def from_client(self, msg: Any) -> None:
        if not isinstance(msg, dict):
            return self.to_server(msg)
        method = msg.get("method")
        if method is None and str(msg.get("id", "")) in self._waiting:
            waiter = self._waiting[str(msg["id"])]
            waiter["reply"] = msg
            waiter["event"].set()
            return None
        if method == "initialize":
            params = msg.get("params") or {}
            info = params.get("clientInfo") or {}
            self.client = self.client or clients.client_id_from_info(str(info.get("name", "")))
            self.can_prompt = isinstance((params.get("capabilities") or {}).get("elicitation"), dict)
            self.session = f"mcp-{self.client}-{os.getppid()}"
        elif method == "tools/list" and "id" in msg:
            self._list_ids.add(msg["id"])
        elif method == "tools/call" and "id" in msg:
            return self._check(msg)
        return self.to_server(msg)

    def _check(self, msg: Dict[str, Any]) -> None:
        from leash.hooks import runner

        started = time.perf_counter()
        params = msg.get("params") or {}
        tool = str(params.get("name") or "")
        args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        self.client = self.client or "mcp-client-unknown"
        call = ToolCall("mcp", tool, args, cwd=os.getcwd(), session=self.session or f"mcp-{self.client}",
                        mcp_server=self.name)

        # Also check saved pins: a client may call a tool it listed in an earlier session.
        withheld = self._withheld.get(tool) or (Pins.load(self.client, self.name).pending.get(tool) or {}).get("why")
        if withheld:
            verdict = Verdict("deny", f"Leash is holding back the {self.name} tool '{tool}' because {withheld}. "
                                      f"Run `leash mcp trust {self.name}` to review it.")
            observations: List[Dict[str, Any]] = []
        else:
            verdict, observations = runner.decide(call, agent=self.client)

        extra = {"mcp_client": self.client, "mcp_server": self.name}
        if verdict.decision == "allow" or self.observe:
            runner._audit("mcp", call, verdict, observations, self.observe, started, self.stderr,
                          agent=self.client, extra=extra)
            return self.to_server(msg)
        if verdict.decision == "ask" and self.can_prompt:
            threading.Thread(target=self._ask, args=(msg, call, verdict, observations, started, extra),
                             daemon=True).start()
            return None
        if verdict.decision == "ask":
            verdict = Verdict("ask", f"{verdict.reason}. {clients.label(self.client)} can't show Leash's approval "
                                     f"prompt, so this was blocked. To allow it, run `leash allow` in a terminal "
                                     f"and try again.", verdict.policy, verdict.rule, verdict.request, verdict.group)
        runner._audit("mcp", call, verdict, observations, False, started, self.stderr,
                      agent=self.client, extra=extra)
        self._refuse(msg["id"], verdict.reason)
        return None

    def _ask(self, msg, call, verdict, observations, started, extra) -> None:
        from leash.hooks import runner

        key = f"leash-approval-{next(self._ids)}"
        waiter: Dict[str, Any] = {"event": threading.Event(), "reply": None}
        self._waiting[key] = waiter
        self.to_client({"jsonrpc": "2.0", "id": key, "method": "elicitation/create", "params": {
            "message": f"Leash: allow the {self.name} tool '{call.tool}'?\n\n{verdict.reason}",
            "requestedSchema": {"type": "object", "required": ["approve"], "properties": {
                "approve": {"type": "boolean", "title": "Allow this call",
                            "description": "Yes runs the tool once. No blocks it."}}},
        }})
        answered = waiter["event"].wait(APPROVAL_TIMEOUT)
        self._waiting.pop(key, None)
        result = (waiter["reply"] or {}).get("result") or {}
        approved = answered and result.get("action") == "accept" and (result.get("content") or {}).get("approve") is True
        runner._audit("mcp", call, verdict, observations, False, started, self.stderr,
                      agent=self.client, extra={**extra, "approved": bool(approved)})
        if approved:
            self.to_server(msg)
        else:
            self._refuse(msg["id"], f"You didn't approve this in Leash's prompt. ({verdict.reason})")

    def _refuse(self, msg_id: Any, reason: str) -> None:
        text = f"Blocked by Leash: {reason}"
        if "leash explain" not in text and "leash mcp trust" not in text:
            text += " Run `leash explain` in a terminal for details."
        self.to_client({"jsonrpc": "2.0", "id": msg_id,
                        "result": {"content": [{"type": "text", "text": text}], "isError": True}})

    # ── server → client ───────────────────────────────────────────────────

    def _filter_tools(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        result = msg.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            return msg
        pins = Pins.load(self.client or "mcp-client-unknown", self.name)
        visible, withheld = pins.review([t for t in result["tools"] if isinstance(t, dict)])
        for name, why in withheld.items():
            if name not in self._withheld:
                self.note(f"holding back {self.name} tool '{name}': {why}. Run `leash mcp trust {self.name}`.")
                self._audit_withheld(name, why)
        self._withheld = withheld
        return {**msg, "result": {**result, "tools": visible}}

    def _audit_withheld(self, tool: str, why: str) -> None:
        from leash import auditlog

        try:
            auditlog.append({
                "host": "mcp", "agent": self.client, "session": self.session, "cwd": os.getcwd(),
                "tool": tool, "request": f"mcp.{self.name}.{tool}", "decision": "deny",
                "reason": f"Tool held back because {why}. Run `leash mcp trust {self.name}` to review it.",
                "group": "tamper", "mcp_client": self.client, "mcp_server": self.name, "mcp_withheld": True,
            })
        except OSError:
            pass


def run(cmd: List[str], client: Optional[str] = None, name: Optional[str] = None) -> int:
    return Proxy(cmd, client=client, name=name).run()
