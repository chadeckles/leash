"""Scanner — 2 tests covering risk classification, policy coverage/generation,
and the scan API endpoints + MCP subprocess discovery.

Replaces: test_scanner.py (43) → 2
"""

from __future__ import annotations

import json
import textwrap
from unittest.mock import MagicMock, patch

import pytest
import yaml

from sdk.scanner import (
    classify_tool,
    classify_tools,
    analyze_policy_coverage,
    generate_policy,
    format_scan_table,
    MCPScanner,
)
from tests.conftest import register_agent, admin_headers


FILESYSTEM_TOOLS = [
    {"name": "read_file", "description": "Read the contents of a file from disk", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
    {"name": "write_file", "description": "Write content to a file on disk"},
    {"name": "delete_file", "description": "Permanently remove a file from disk"},
    {"name": "list_directory", "description": "List all files in a directory"},
    {"name": "get_file_info", "description": "Get metadata about a file"},
    {"name": "search_files", "description": "Search for files matching a pattern"},
    {"name": "move_file", "description": "Move a file to a new location, can overwrite existing files"},
]

DANGEROUS_TOOLS = [
    {"name": "exec_command", "description": "Execute a shell command on the system"},
    {"name": "send_email", "description": "Send an email to a recipient"},
    {"name": "delete_database", "description": "Drop a database table permanently"},
]


def test_scanner_classification_and_coverage():
    """Risk classification: high (destructive/execution/exfiltration),
    medium (write/network/filesystem), low (read-only), unknown.
    Multi-category → highest wins. Batch, input schema preserved.
    Policy coverage stats, wildcard coverage. Policy generation:
    valid YAML, high→deny, low→allow, catchall, observe mode, custom agent,
    validates clean. Table formatter. Serialization.

    Replaces: 25 scanner unit tests.
    """
    # ── Risk classification ──
    assert classify_tool("delete_file", "Permanently remove a file").risk == "high"
    assert "destructive" in classify_tool("delete_file", "Permanently remove a file").categories
    assert classify_tool("exec_command", "Execute a shell command").risk == "high"
    assert "execution" in classify_tool("exec_command", "Execute a shell command").categories
    assert classify_tool("send_email", "Send an email").risk == "high"
    assert "exfiltration" in classify_tool("send_email", "Send an email").categories

    assert classify_tool("create_note", "Create a new note").risk == "medium"
    assert classify_tool("fetch_url", "Fetch content from a URL").risk == "medium"
    assert classify_tool("list_directory", "List all files in a directory").risk == "medium"

    assert classify_tool("get_file_info", "Get metadata about a file").risk == "low"
    assert classify_tool("frobnicate", "Does something unusual").risk == "unknown"
    assert "manual review" in classify_tool("frobnicate", "Does something unusual").risk_reason.lower()

    # Multi-category: highest wins
    t = classify_tool("move_file", "Move a file, can overwrite existing")
    assert t.risk == "high"
    assert len(t.categories) >= 2

    # Name-only classification
    assert classify_tool("remove", "").risk == "high"
    # Description-only classification
    assert classify_tool("do_thing", "Execute arbitrary shell commands").risk == "high"
    # Highest risk wins
    assert classify_tool("delete_and_list", "Delete files and list directory").risk == "high"

    # Batch classification
    results = classify_tools(FILESYSTEM_TOOLS)
    assert len(results) == 7
    assert {t.name for t in results} >= {"read_file", "delete_file"}

    # Input schema preserved
    schema = {"type": "object", "properties": {"path": {"type": "string"}}}
    assert classify_tool("read_file", "Read a file", schema).input_schema == schema

    # ── Policy coverage ──
    classified = classify_tools(FILESYSTEM_TOOLS)
    scan = analyze_policy_coverage(classified)
    assert scan.tools_discovered == 7
    assert isinstance(scan.policy_coverage, float)

    # Stats add up
    classified_d = classify_tools(DANGEROUS_TOOLS)
    scan_d = analyze_policy_coverage(classified_d)
    assert scan_d.tools_discovered == 3
    assert len(scan_d.high_risk) >= 2
    assert scan_d.tools_discovered == len(scan_d.high_risk) + len(scan_d.medium_risk) + len(scan_d.low_risk) + len(scan_d.unknown_risk)

    # ── Policy generation ──
    scan.target = "test-server"
    policy_yaml = generate_policy(scan, policy_name="test-gen")
    doc = yaml.safe_load(policy_yaml)
    assert doc["name"] == "test-gen"
    assert "rules" in doc and "agents" in doc

    # High risk → deny
    scan_d.target = "test"
    doc_d = yaml.safe_load(generate_policy(scan_d))
    rules_by_action = {r["action"]: r for r in doc_d["rules"]}
    assert rules_by_action["exec_command"]["effect"] == "deny"
    assert rules_by_action["send_email"]["effect"] == "deny"

    # Low risk → allow
    low_tools = [{"name": "get_status", "description": "Get system status information"}]
    scan_low = analyze_policy_coverage(classify_tools(low_tools))
    scan_low.target = "test"
    doc_low = yaml.safe_load(generate_policy(scan_low))
    assert {r["action"]: r for r in doc_low["rules"]}["get_status"]["effect"] == "allow"

    # Catchall deny
    last_rule = doc["rules"][-1]
    assert last_rule["action"] == "*" and last_rule["effect"] == "deny"

    # Observe mode
    med_tools = [{"name": "write_file", "description": "Write a file"}, {"name": "get_info", "description": "Get info"}]
    scan_obs = analyze_policy_coverage(classify_tools(med_tools))
    scan_obs.target = "test"
    doc_obs = yaml.safe_load(generate_policy(scan_obs, include_observe=True))
    assert doc_obs.get("mode") == "observe"

    # Custom agent pattern
    scan_ca = analyze_policy_coverage(classify_tools([{"name": "ping", "description": "Ping"}]))
    scan_ca.target = "test"
    doc_ca = yaml.safe_load(generate_policy(scan_ca, agent_pattern='"fs-*"'))
    assert "fs-*" in doc_ca["agents"]

    # Generated policy passes validator
    from app.policy.validator import validate_policy_yaml
    scan.target = "test"
    errors = validate_policy_yaml(generate_policy(scan, policy_name="val-test"))
    assert [e for e in errors if "warning" not in e.lower()] == []

    # ── Table formatter ──
    scan.target = "@modelcontextprotocol/server-filesystem"
    output = format_scan_table(scan)
    assert "╔" in output and "Leash Security Surface Scan" in output
    assert "@modelcontextprotocol/server-filesystem" in output
    assert "Tools discovered: 7" in output and "Policy coverage:" in output

    # ── Serialization ──
    scan.target = "test"
    d = scan.to_dict()
    parsed = json.loads(json.dumps(d))
    assert parsed["tools_discovered"] == 7
    assert all(k in d for k in ("high_risk", "medium_risk", "low_risk", "unknown_risk", "tools"))


def test_scanner_api_and_mcp(client, db_session):
    """Scan API endpoint: classification, risk buckets, auth required,
    empty tools rejected, agent-scoped coverage, generate-policy endpoint.
    MCP discover: parses tools, handles missing command, handles no response.

    Replaces: 10 scanner API + MCP tests.
    """
    # ── POST /scan: returns classification ──
    aid, hdr = register_agent(client, "scan-api-agent")
    resp = client.post("/scan", json={"tools": FILESYSTEM_TOOLS}, headers=hdr)
    assert resp.status_code == 200
    data = resp.json()
    assert data["tools_discovered"] == 7
    assert isinstance(data["policy_coverage"], float)
    assert all(k in data for k in ("high_risk", "medium_risk", "low_risk"))

    # Risk classification: dangerous tools get high
    resp = client.post("/scan", json={"tools": DANGEROUS_TOOLS}, headers=hdr)
    high_names = {t["name"] for t in resp.json()["high_risk"]}
    assert "exec_command" in high_names and "send_email" in high_names

    # ── Auth required ──
    assert client.post("/scan", json={"tools": FILESYSTEM_TOOLS}).status_code in (401, 403)

    # ── Empty tools rejected ──
    assert client.post("/scan", json={"tools": []}, headers=hdr).status_code == 422

    # ── Agent-scoped coverage ──
    client.post("/policies/managed", json={
        "name": "scoped-scan", "priority": 10,
        "yaml_content": textwrap.dedent(f"""\
            agents: ["{aid}"]
            rules:
              - action: "read_file"
                effect: allow
                reason: "scoped"
        """),
    }, headers=admin_headers(client))
    resp = client.post("/scan", json={"tools": FILESYSTEM_TOOLS, "agent_id": aid}, headers=hdr)
    covered_names = {t["name"] for t in resp.json()["tools"] if t["has_policy_coverage"]}
    assert "read_file" in covered_names

    # ── POST /scan/generate-policy ──
    resp = client.post("/scan/generate-policy", json={
        "tools": FILESYSTEM_TOOLS,
        "policy_name": "api-generated",
        "agent_pattern": '"test-*"',
    }, headers=hdr)
    assert resp.status_code == 200
    gen = resp.json()
    assert "policy_yaml" in gen
    assert gen["tools_discovered"] == 7
    assert "api-generated" in gen["policy_yaml"]
    assert "test-*" in gen["policy_yaml"]

    # Risk counts
    resp = client.post("/scan/generate-policy", json={"tools": DANGEROUS_TOOLS}, headers=hdr)
    assert resp.json()["high_risk_count"] >= 2

    # ── MCP discover: parses tools ──
    import io
    init_resp = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {
        "protocolVersion": "2024-11-05",
        "capabilities": {"tools": {}},
        "serverInfo": {"name": "mock", "version": "1.0"},
    }}) + "\n"
    tools_resp = json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"tools": [
        {"name": "ping", "description": "Check connectivity"},
        {"name": "exec_shell", "description": "Run a shell command"},
    ]}}) + "\n"

    mock_proc = MagicMock()
    mock_proc.stdin = MagicMock()
    mock_proc.stdout = io.BytesIO(init_resp.encode() + tools_resp.encode())
    mock_proc.stderr = MagicMock()
    mock_proc.terminate = MagicMock()
    mock_proc.wait = MagicMock()
    mock_proc.kill = MagicMock()

    with patch("subprocess.Popen", return_value=mock_proc):
        tools = MCPScanner(["mock-server"], timeout=5).discover()
    assert len(tools) == 2
    assert tools[0]["name"] == "ping"

    # ── MCP: missing command ──
    with pytest.raises(RuntimeError, match="Cannot start MCP server"):
        MCPScanner(["nonexistent-binary-xyz-123"]).discover()

    # ── MCP: no response ──
    mock_proc2 = MagicMock()
    mock_proc2.stdin = MagicMock()
    mock_proc2.stdout = io.BytesIO(b"")
    mock_proc2.stderr = MagicMock()
    mock_proc2.terminate = MagicMock()
    mock_proc2.wait = MagicMock()
    mock_proc2.kill = MagicMock()

    with patch("subprocess.Popen", return_value=mock_proc2):
        with pytest.raises(RuntimeError, match="did not respond"):
            MCPScanner(["mock-server"], timeout=1).discover()
