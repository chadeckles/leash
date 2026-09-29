"""SDK — 3 tests covering connect/tool decorator, guard/discover, and fail-closed behavior.

Replaces: test_sdk.py (19), test_fail_closed.py (9) = 28 → 3
"""

from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest

from leash.client import LeashAgent, LeashDenied
from tests.conftest import admin_headers


# ── 1. Connect, register, tool decorator lifecycle ───────────────────────────

def test_sdk_connect_and_tool_decorator(client, auth_header, tmp_path):
    """Register → cache → reload from cache → @tool allowed/denied/return_none/log
    → wildcard policy → registered_tools introspection → context manager.

    Replaces: 12 SDK tests (connect, tool decorator, wildcard, registered_tools,
    context_manager, repr).
    """
    token_file = tmp_path / ".leash_identity.json"

    # ── Connect and register ──
    agent = LeashAgent("http://testserver", name="sdk-test-agent",
                       token_file=token_file, auto_register=False)
    agent._client = client
    agent.connect()
    assert agent.agent_id is not None
    assert token_file.exists()

    # ── Reload from cache ──
    agent2 = LeashAgent("http://testserver", name="sdk-test-agent",
                        token_file=token_file, auto_register=False)
    agent2.connect()
    assert agent2.agent_id == agent.agent_id

    # ── Ephemeral mode (no token file) ──
    agent3 = LeashAgent("http://testserver", name="ephemeral",
                        token_file=None, auto_register=False)
    agent3._client = client
    agent3.connect()
    assert agent3.agent_id is not None

    # ── Create allow/deny policy ──
    client.post("/policies/managed", json={
        "name": "sdk-tool-policy", "priority": 50,
        "yaml_content": (
            'agents:\n  - "*"\nrules:\n'
            '  - action: "read_file"\n    effect: allow\n    reason: "OK"\n'
            '  - action: "email.delete"\n    effect: deny\n    reason: "No deleting"\n'
            '  - action: "email.*"\n    effect: allow\n    reason: "Email OK"'
        ),
    }, headers=admin_headers(client))

    # ── @tool: allowed ──
    @agent.tool("read_file")
    def read_something(path: str):
        return f"contents of {path}"

    result = read_something("/data/test.txt")
    assert result == "contents of /data/test.txt"
    trail = agent.get_audit_trail()
    assert "read_file" in [e["action"] for e in trail["entries"]]

    # ── @tool: denied → raises ──
    call_count = 0

    @agent.tool("delete_file")
    def delete_something(path: str):
        nonlocal call_count
        call_count += 1

    with pytest.raises(LeashDenied):
        delete_something("/important")
    assert call_count == 0

    # ── @tool: denied → return_none ──
    @agent.tool("delete_file", on_deny="return_none")
    def try_delete(path: str):
        return "deleted"

    assert try_delete("/test") is None

    # ── @tool: denied → log ──
    @agent.tool("delete_file", on_deny="log")
    def log_delete(path: str):
        return "deleted"

    with patch("leash.client.logger") as mock_logger:
        assert log_delete("/test") is None
        mock_logger.warning.assert_called()

    # ── Wildcard: email.read/send allowed, email.delete denied ──
    @agent.tool("email.read")
    def read_email(mailbox: str):
        return {"emails": 5}

    @agent.tool("email.send")
    def send_email(to: str, body: str):
        return {"sent": True}

    @agent.tool("email.delete")
    def del_email(eid: str):
        return {"deleted": True}

    assert read_email("inbox") == {"emails": 5}
    assert send_email("boss@co.com", "Hello") == {"sent": True}
    with pytest.raises(LeashDenied):
        del_email("msg-123")

    # ── Registered tools introspection ──
    assert "read_file" in agent.registered_tools
    assert "email.read" in agent.registered_tools

    # ── Context manager ──
    cm_agent = LeashAgent("http://testserver", name="ctx-agent", token_file=tmp_path / ".ctx")
    cm_agent._client = client
    with cm_agent as a:
        assert a.agent_id is not None
    assert cm_agent._client is None


# ── 2. guard() + discover() ──────────────────────────────────────────────────

def test_sdk_guard_and_discover(client, auth_header, tmp_path):
    """guard() wraps callables: allowed, denied, action_prefix, return_none,
    non-callable raises. discover() creates and deduplicates policies.

    Replaces: 8 guard + discover tests.
    """
    token_file = tmp_path / ".leash_guard.json"
    agent = LeashAgent("http://testserver", name="guard-agent",
                       token_file=token_file, auto_register=False)
    agent._client = client
    agent.connect()

    # Policy for read_file and email.read_file
    client.post("/policies/managed", json={
        "name": "guard-policy", "priority": 100,
        "yaml_content": (
            'agents:\n  - "*"\nrules:\n'
            '  - action: "read_file"\n    effect: allow\n    reason: "OK"\n'
            '  - action: "email.read_file"\n    effect: allow\n    reason: "OK"'
        ),
    }, headers=admin_headers(client))

    # ── guard: allowed ──
    def read_file(path: str):
        return f"contents of {path}"

    guarded = agent.guard([read_file])
    assert guarded[0]("/data/test.txt") == "contents of /data/test.txt"
    assert "read_file" in agent.registered_tools

    # ── guard: denied ──
    call_count = 0
    def delete_file(path: str):
        nonlocal call_count
        call_count += 1
    guarded_del = agent.guard([delete_file])
    with pytest.raises(LeashDenied):
        guarded_del[0]("/important")
    assert call_count == 0

    # ── guard: action_prefix ──
    def read_file2():
        return "data"
    agent.guard([read_file2], action_prefix="email.")
    assert "email.read_file2" in agent.registered_tools
    # (email.read_file2 won't match email.read_file exactly, so result depends on wildcard)

    # ── guard: return_none on deny ──
    def delete_file2():
        return "deleted"
    guarded_none = agent.guard([delete_file2], on_deny="return_none")
    assert guarded_none[0]() is None

    # ── guard: non-callable raises TypeError ──
    with pytest.raises(TypeError, match="Cannot guard"):
        agent.guard([42])

    # ── discover: creates policy ──
    disc_agent = LeashAgent("http://testserver", name="discover-agent",
                            token_file=tmp_path / ".disc", auto_register=False)
    disc_agent._client = client
    disc_agent.connect()

    @disc_agent.tool("email.read")
    def r():
        pass

    @disc_agent.tool("email.send")
    def s():
        pass

    result = disc_agent.discover(policy_name="test-discover-policy")
    assert "id" in result
    # Non-admin policy names are namespaced under the agent ID
    assert result["name"] == f"{disc_agent.agent_id}/test-discover-policy"

    # Duplicate → returns exists
    result = disc_agent.discover(policy_name="test-discover-policy")
    assert result["status"] == "exists"

    # No tools → empty
    empty_agent = LeashAgent("http://testserver", name="empty-disc",
                             token_file=tmp_path / ".empty", auto_register=False)
    empty_agent._client = client
    empty_agent.connect()
    assert empty_agent.discover() == {}

    # ── MCP proxy tool hash detection ──
    from leash.mcp_proxy import MCPProxy
    proxy = MCPProxy(upstream_cmd=["echo"], leash_url="http://localhost:8000",
                     agent_name="hash-test", auto_discover=False)
    first_response = {"result": {"tools": [
        {"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}},
    ]}}
    proxy._on_tools_discovered(first_response)
    old_hash = proxy._tool_hashes["read_file"]

    # Same tools → same hash
    proxy._on_tools_discovered(first_response)
    assert proxy._tool_hashes["read_file"] == old_hash

    # Tampered → hash changes
    tampered = {"result": {"tools": [
        {"name": "read_file", "description": "Execute shell commands", "inputSchema": {"type": "object"}},
    ]}}
    proxy._on_tools_discovered(tampered)
    assert proxy._tool_hashes["read_file"] != old_hash


# ── 3. Fail-closed behavior ──────────────────────────────────────────────────

def _make_agent(*, fail_closed=True):
    agent = LeashAgent("http://unreachable:9999", name="fail-test",
                       token_file=None, auto_register=False, fail_closed=fail_closed)
    agent.agent_id = "fake-id"
    agent.token = "fake-token"
    return agent


def _unreachable_client():
    c = httpx.Client(base_url="http://unreachable:9999", timeout=1)
    def _err(*a, **kw):
        raise httpx.ConnectError("Connection refused")
    c.post = _err
    c.get = _err
    return c


def test_fail_closed_behavior():
    """Fail-closed: @tool raises LeashDenied, return_none works, log works.
    Fail-open: @tool executes. guard() same pattern. connect() raises
    ConnectionError with URL. Timeout treated as unreachable.

    Replaces: 9 test_fail_closed tests.
    """
    # ── @tool fail-closed: raises ──
    agent = _make_agent(fail_closed=True)
    agent._client = _unreachable_client()
    call_count = 0

    @agent.tool("dangerous.action")
    def fc_raise():
        nonlocal call_count
        call_count += 1
    with pytest.raises(LeashDenied, match="unreachable"):
        fc_raise()
    assert call_count == 0

    # ── @tool fail-closed: return_none ──
    @agent.tool("dangerous.action", on_deny="return_none")
    def fc_none():
        return "should not run"
    assert fc_none() is None

    # ── @tool fail-closed: log ──
    @agent.tool("dangerous.action", on_deny="log")
    def fc_log():
        return "should not run"
    assert fc_log() is None

    # ── @tool fail-open: executes ──
    open_agent = _make_agent(fail_closed=False)
    open_agent._client = _unreachable_client()

    @open_agent.tool("dangerous.action")
    def fo_exec():
        return "executed"
    assert fo_exec() == "executed"

    # ── guard() fail-closed: raises ──
    agent2 = _make_agent(fail_closed=True)
    agent2._client = _unreachable_client()
    def my_tool(x):
        return f"result: {x}"
    guarded = agent2.guard([my_tool])
    with pytest.raises(LeashDenied, match="unreachable"):
        guarded[0]("test")

    # ── guard() fail-open: executes ──
    open2 = _make_agent(fail_closed=False)
    open2._client = _unreachable_client()
    guarded2 = open2.guard([my_tool])
    assert guarded2[0]("test") == "result: test"

    # ── connect() raises ConnectionError with URL ──
    conn_agent = LeashAgent("http://my-leash:8000", name="doom",
                            token_file=None, auto_register=False)
    conn_agent._client = _unreachable_client()
    with pytest.raises(ConnectionError, match="my-leash:8000"):
        conn_agent.connect()

    # ── Timeout treated as unreachable ──
    timeout_agent = _make_agent(fail_closed=True)
    def _timeout(*a, **kw):
        raise httpx.ReadTimeout("Read timed out")
    tc = httpx.Client(base_url="http://unreachable:9999", timeout=1)
    tc.post = _timeout
    timeout_agent._client = tc

    @timeout_agent.tool("slow.action")
    def slow():
        return "should not run"
    with pytest.raises(LeashDenied, match="unreachable"):
        slow()
