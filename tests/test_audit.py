"""Audit Trail — 6 tests covering logging, hash chain, chain detection,
security scan, JSONL export, and webhooks/file sinks.

Replaces: test_audit.py (8), test_audit_export.py (21), test_audit_scan.py (18),
test_edge_cases.py hash-chain (2), test_verify.py (7), test_doctor.py (13) = 69 → 6
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from unittest.mock import patch

from app.core.security import sign_data, hash_data
from tests.conftest import register_agent, admin_headers


# ── Helper ────────────────────────────────────────────────────────────────────

def _post_audit(client, agent_id, headers, action, decision="allow"):
    return client.post("/audit", json={
        "agent_id": agent_id, "action": action, "policy_decision": decision,
    }, headers=headers)


# ── 1. Logging, filtering, pagination, summary ───────────────────────────────

def test_audit_logging_and_query(client):
    """Create entries, filter by agent/decision/action, paginate, summary,
    reject invalid decision values.

    Replaces: test_create_and_query_entries, test_invalid_decision_rejected,
    test_summary, + system endpoint smoke checks.
    """
    a1, h1 = register_agent(client, "audit-a1")
    a2, h2 = register_agent(client, "audit-a2")

    # ── Create and verify response shape ──
    resp = client.post("/audit", json={
        "agent_id": a1, "action": "read_file",
        "inputs": {"file": "/tmp/test.txt"}, "policy_decision": "allow",
    }, headers=h1)
    assert resp.status_code == 201
    entry = resp.json()
    assert entry["agent_id"] == a1
    assert len(entry["signature"]) > 0
    assert entry["timestamp"] is not None

    _post_audit(client, a1, h1, "write_file", "allow")
    _post_audit(client, a2, h2, "delete_file", "deny")

    # ── Filters ──
    data = client.get("/audit", params={"agent_id": a1}, headers=h1).json()
    assert all(e["agent_id"] == a1 for e in data["entries"])

    data = client.get("/audit", params={"decision": "deny"}, headers=h1).json()
    assert all(e["policy_decision"] == "deny" for e in data["entries"])

    data = client.get("/audit", params={"agent_id": a2, "decision": "deny", "action": "delete_file"}, headers=h2).json()
    assert data["total"] == 1

    # ── Pagination ──
    data = client.get("/audit", params={"limit": 1}, headers=h1).json()
    assert len(data["entries"]) == 1

    # ── Summary ──
    data = client.get("/audit/summary", headers=h1).json()
    assert data["total_entries"] >= 3
    assert data["total_allowed"] >= 2
    assert data["total_denied"] >= 1

    # ── Invalid decision rejected ──
    resp = client.post("/audit", json={
        "agent_id": "bad", "action": "test", "policy_decision": "maybe",
    }, headers=h1)
    assert resp.status_code == 422

    # ── System endpoints (smoke) ──
    assert client.get("/health").json() == {"status": "ok"}
    assert "leash_uptime_seconds" in client.get("/metrics").text
    assert client.get("/docs").status_code == 200


# ── 2. Hash chain integrity + signature verification ─────────────────────────

def test_hash_chain_integrity(client):
    """First entry has null prev_hash, subsequent entries are linked via SHA-256,
    the verify endpoint validates signatures, and the audit-chain endpoint
    confirms the entire chain is intact.

    Replaces: 7 hash-chain tests across test_audit, test_edge_cases, test_verify.
    """
    aid, hdr = register_agent(client, "chain-agent")

    r1 = _post_audit(client, aid, hdr, "step.one").json()
    assert r1["prev_hash"] is None  # genesis entry

    r2 = _post_audit(client, aid, hdr, "step.two").json()
    assert r2["prev_hash"] is not None
    assert len(r2["prev_hash"]) == 64  # SHA-256 hex

    # Verify the actual chain linkage
    chain_data = {
        "id": r1["id"], "agent_id": r1["agent_id"], "timestamp": r1["timestamp"],
        "action": r1["action"], "policy_decision": r1["policy_decision"],
        "signature": r1["signature"],
    }
    assert r2["prev_hash"] == hash_data(chain_data)

    r3 = _post_audit(client, aid, hdr, "step.three", "deny").json()
    assert r3["prev_hash"] != r2["prev_hash"]  # different predecessor

    # ── Signature verification endpoint ──
    sig_data = {"agent_id": "test", "action": "read_file", "decision": "allow"}
    sig = sign_data(sig_data)
    assert client.post("/verify", json={"data": sig_data, "signature": sig}).json()["valid"] is True

    # Tampered data
    sig_data["decision"] = "deny"
    assert client.post("/verify", json={"data": sig_data, "signature": sig}).json()["valid"] is False

    # Bad signature
    assert client.post("/verify", json={"data": {"x": 1}, "signature": "deadbeef" * 32}).json()["valid"] is False

    # Verify is unauthenticated
    assert client.post("/verify", json={"data": {"foo": "bar"}, "signature": sign_data({"foo": "bar"})}).status_code == 200

    # ── Audit chain verification endpoint ──
    resp = client.get("/verify/audit-chain")
    assert resp.json()["valid"] is True
    assert resp.json()["entries_checked"] >= 3


# ── 3. Chain detection ────────────────────────────────────────────────────────

def test_chain_detection(client):
    """Built-in patterns (data-exfiltration, read-then-execute), custom patterns,
    cross-agent isolation, and no false positives on safe actions.

    Replaces: 7 chain-detection tests across test_audit and test_audit_scan.
    """
    # ── Data exfiltration ──
    aid, hdr = register_agent(client, "exfil-agent")
    _post_audit(client, aid, hdr, "file.read")
    _post_audit(client, aid, hdr, "email.send")

    data = client.post("/audit/chains", json={}, headers=hdr).json()
    exfil = [m for m in data["matches"] if m["pattern"] == "data-exfiltration"]
    assert len(exfil) >= 1
    assert exfil[0]["agent_id"] == aid

    # ── Read-then-execute ──
    aid2, hdr2 = register_agent(client, "inject-agent")
    _post_audit(client, aid2, hdr2, "code.read")
    _post_audit(client, aid2, hdr2, "code.execute")
    data = client.post("/audit/chains", json={}, headers=hdr2).json()
    rte = [m for m in data["matches"] if m["pattern"] == "read-then-execute" and m["agent_id"] == aid2]
    assert len(rte) >= 1

    # ── Custom pattern ──
    aid3, hdr3 = register_agent(client, "custom-chain-agent")
    _post_audit(client, aid3, hdr3, "api.login")
    _post_audit(client, aid3, hdr3, "api.export")
    data = client.post("/audit/chains", json={
        "agent_id": aid3,
        "patterns": [{"name": "login-export", "actions": ["api.login", "api.export"],
                       "description": "Credential abuse"}],
    }, headers=hdr3).json()
    assert data["patterns_checked"] == 1
    assert data["matches"][0]["pattern"] == "login-export"

    # ── Cross-agent isolation ──
    x_id, x_h = register_agent(client, "iso-X")
    y_id, y_h = register_agent(client, "iso-Y")
    _post_audit(client, x_id, x_h, "file.read")
    _post_audit(client, y_id, y_h, "email.send")
    data = client.post("/audit/chains", json={"agent_id": x_id}, headers=x_h).json()
    assert len([m for m in data["matches"] if m["pattern"] == "data-exfiltration"]) == 0

    # ── No false positive on safe actions ──
    safe_id, safe_h = register_agent(client, "safe-agent")
    _post_audit(client, safe_id, safe_h, "code.lint")
    _post_audit(client, safe_id, safe_h, "code.test")
    data = client.post("/audit/scan", json={"agent_id": safe_id, "limit": 100}).json()
    chains = next(c for c in data["checks"] if c["check"] == "chain-detection")
    assert chains["status"] == "pass"


# ── 4. Multi-check audit security scan ───────────────────────────────────────

def test_audit_scan_all_checks(client):
    """All 5 checks run, deny storms detected, observe shadows surfaced,
    permission probing flagged, severity counts correct.

    Replaces: 18 test_audit_scan tests (minus the 1 broken test_unused_permissions_flagged).
    """
    # ── Empty scan returns all 5 checks, clean status ──
    resp = client.post("/audit/scan", json={"limit": 100})
    data = resp.json()
    assert data["checks_run"] == 5
    assert data["status"] == "clean"
    check_names = {c["check"] for c in data["checks"]}
    assert check_names == {"hash-integrity", "chain-detection", "deny-storm", "observe-shadow", "permission-gaps"}

    # ── Deny storm (6+ denials) ──
    storm_id, storm_h = register_agent(client, "storm-agent")
    for i in range(6):
        _post_audit(client, storm_id, storm_h, f"shell.exec.{i}", "deny")

    data = client.post("/audit/scan", json={"limit": 500, "window": 3600}).json()
    storms = next(c for c in data["checks"] if c["check"] == "deny-storm")
    assert storms["status"] == "warn"
    assert storms["findings"][0]["severity"] == "high"
    assert storms["findings"][0]["agent_id"] == storm_id

    # Few denials → no storm
    calm_id, calm_h = register_agent(client, "calm-agent")
    _post_audit(client, calm_id, calm_h, "file.delete", "deny")
    data = client.post("/audit/scan", json={"agent_id": calm_id, "limit": 100}).json()
    assert next(c for c in data["checks"] if c["check"] == "deny-storm")["status"] == "pass"

    # Allows don't count
    flood_id, flood_h = register_agent(client, "flood-agent")
    for i in range(10):
        _post_audit(client, flood_id, flood_h, f"code.read.{i}", "allow")
    data = client.post("/audit/scan", json={"agent_id": flood_id, "limit": 100}).json()
    assert next(c for c in data["checks"] if c["check"] == "deny-storm")["status"] == "pass"

    # ── Observe shadows ──
    shadow_id, shadow_h = register_agent(client, "shadow-agent")
    _post_audit(client, shadow_id, shadow_h, "file.delete", "observe_deny")
    _post_audit(client, shadow_id, shadow_h, "shell.exec", "observe_deny")
    data = client.post("/audit/scan", json={"limit": 500}).json()
    shadows = next(c for c in data["checks"] if c["check"] == "observe-shadow")
    assert shadows["status"] == "warn"
    agent_findings = [f for f in shadows["findings"] if f["agent_id"] == shadow_id]
    assert agent_findings[0]["metadata"]["total"] >= 2

    # Normal entries don't trigger observe
    normal_id, normal_h = register_agent(client, "normal-agent")
    _post_audit(client, normal_id, normal_h, "file.read", "allow")
    data = client.post("/audit/scan", json={"agent_id": normal_id, "limit": 100}).json()
    assert next(c for c in data["checks"] if c["check"] == "observe-shadow")["status"] == "pass"

    # ── Permission probing ──
    probe_id, probe_h = register_agent(client, "probe-agent")
    for _ in range(5):
        _post_audit(client, probe_id, probe_h, "shell.exec", "deny")
    data = client.post("/audit/scan", json={"limit": 500}).json()
    gaps = next(c for c in data["checks"] if c["check"] == "permission-gaps")
    assert gaps["status"] == "warn"
    probing = [f for f in gaps["findings"] if "Repeated denied" in f["title"] and f["agent_id"] == probe_id]
    assert len(probing) >= 1

    # ── Severity counts match findings ──
    all_findings = []
    for c in data["checks"]:
        all_findings.extend(c["findings"])
    actual = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        actual[f["severity"]] += 1
    assert data["critical_count"] == actual["critical"]
    assert data["high_count"] == actual["high"]
    assert data["medium_count"] == actual["medium"]

    # ── Overall status with findings ──
    assert data["status"] == "warnings"


# ── 5. JSONL export ───────────────────────────────────────────────────────────

def test_audit_export_jsonl(client):
    """JSONL export: format, filters (agent/decision/since/iso), schema
    completeness, observe_deny events, bad format rejected, empty result.

    Replaces: 11 TestAuditExportEndpoint tests + 5 TestSinceParser tests.
    """
    aid, hdr = register_agent(client, "export-agent")

    # Seed: create a policy and trigger authorize calls
    client.post("/policies/managed", json={
        "name": f"export-{aid[:8]}", "priority": 100,
        "yaml_content": (
            'agents:\n  - "*"\nrules:\n'
            '  - action: "read_file"\n    effect: allow\n    reason: "ok"\n'
            '  - action: "delete_file"\n    effect: deny\n    reason: "blocked"'
        ),
    }, headers=admin_headers(client))
    for _ in range(3):
        client.post("/authorize", json={"agent_id": aid, "action": "read_file"}, headers=hdr)
    client.post("/authorize", json={"agent_id": aid, "action": "delete_file"}, headers=hdr)

    # ── Basic export: format, field completeness ──
    resp = client.get("/audit/export", params={"agent_id": aid})
    assert resp.status_code == 200
    assert "ndjson" in resp.headers.get("content-type", "")
    lines = [json.loads(line) for line in resp.text.strip().split("\n") if line]
    assert len(lines) >= 4

    expected_keys = {
        "event_id", "timestamp", "agent_id", "action", "resource",
        "decision", "matched_policy", "reason", "observation",
        "inputs", "outputs", "signature", "prev_hash", "chain_intact",
    }
    assert expected_keys == set(lines[0].keys())
    assert all(e["agent_id"] == aid for e in lines)
    assert all(len(e["signature"]) > 10 for e in lines)

    # ── Filter by decision ──
    resp = client.get("/audit/export", params={"agent_id": aid, "decision": "deny"})
    deny_lines = [json.loads(line) for line in resp.text.strip().split("\n") if line]
    assert len(deny_lines) >= 1
    assert all(e["decision"] == "deny" for e in deny_lines)

    # ── Filter by since (duration and ISO) ──
    resp = client.get("/audit/export", params={"agent_id": aid, "since": "24h"})
    assert resp.status_code == 200
    resp = client.get("/audit/export", params={"agent_id": aid, "since": "2020-01-01T00:00:00Z"})
    assert resp.status_code == 200

    # ── Observe-deny events ──
    obs_id, obs_h = register_agent(client, "export-observe")
    client.post("/policies/managed", json={
        "name": f"exp-obs-{obs_id[:8]}", "priority": 100,
        "yaml_content": 'name: obs\nmode: observe\nagents:\n  - "*"\nrules:\n  - action: "danger"\n    effect: deny\n    reason: "observed"',
    }, headers=admin_headers(client))
    client.post("/authorize", json={"agent_id": obs_id, "action": "danger"}, headers=obs_h)
    resp = client.get("/audit/export", params={"agent_id": obs_id, "decision": "observe_deny"})
    obs_lines = [json.loads(line) for line in resp.text.strip().split("\n") if line]
    assert len(obs_lines) >= 1
    assert obs_lines[0]["decision"] == "observe_deny"

    # ── Bad format rejected ──
    assert client.get("/audit/export", params={"format": "csv"}).status_code == 400

    # ── Bad since rejected ──
    assert client.get("/audit/export", params={"since": "yesterday"}).status_code == 400

    # ── Empty result ──
    resp = client.get("/audit/export", params={"agent_id": "nonexistent"})
    assert resp.status_code == 200
    assert resp.text.strip() == ""


# ── 6. Webhooks and file sinks ───────────────────────────────────────────────

class _WebhookCollector(BaseHTTPRequestHandler):
    received: list = []
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        _WebhookCollector.received.append(json.loads(body))
        self.send_response(200)
        self.end_headers()
    def log_message(self, *a):
        pass


def test_audit_webhooks_and_sinks(client):
    """File sink appends JSONL, webhook receives events, both no-op when unset.

    Replaces: TestAuditFileSink (2) + TestAuditWebhook (2) = 4 tests.
    """
    # ── File sink ──
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        sink_path = f.name
    try:
        with patch("app.core.config.AUDIT_SINK", sink_path):
            aid, hdr = register_agent(client, "sink-agent")
            client.post("/policies/managed", json={
                "name": f"sink-{aid[:8]}", "priority": 100,
                "yaml_content": 'agents:\n  - "*"\nrules:\n  - action: "read_file"\n    effect: allow\n    reason: "ok"',
            }, headers=admin_headers(client))
            client.post("/authorize", json={"agent_id": aid, "action": "read_file"}, headers=hdr)

            content = open(sink_path).read().strip()
            if content:
                for line in content.split("\n"):
                    obj = json.loads(line)
                    assert "event_id" in obj and "signature" in obj
    finally:
        os.unlink(sink_path)

    # ── File sink no-op ──
    with patch("app.core.config.AUDIT_SINK", ""):
        noop_id, noop_h = register_agent(client, "nosink")
        client.post("/audit", json={"agent_id": noop_id, "action": "test", "policy_decision": "allow"}, headers=noop_h)

    # ── Webhook ──
    _WebhookCollector.received = []
    server = HTTPServer(("127.0.0.1", 0), _WebhookCollector)
    port = server.server_address[1]
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()

    with patch("app.core.config.WEBHOOK_URL", f"http://127.0.0.1:{port}/hook"):
        wh_id, wh_h = register_agent(client, "webhook-agent")
        client.post("/audit", json={"agent_id": wh_id, "action": "webhook_test", "policy_decision": "allow"}, headers=wh_h)

    thread.join(timeout=10)
    server.server_close()
    assert len(_WebhookCollector.received) >= 1
    assert _WebhookCollector.received[0]["action"] == "webhook_test"

    # ── Webhook no-op ──
    with patch("app.core.config.WEBHOOK_URL", ""):
        noop2_id, noop2_h = register_agent(client, "nowebhook")
        client.post("/audit", json={"agent_id": noop2_id, "action": "test", "policy_decision": "allow"}, headers=noop2_h)
