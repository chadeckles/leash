"""Policy Engine — 10 tests covering authorization, CRUD, wildcards, rate limits,
ABAC, observe mode, dry-run, OWASP tags, and resource traversal.

Replaces: test_policy.py (31), test_observe_mode.py (16), test_edge_cases.py (4) = 51 → 10
"""

from __future__ import annotations

from tests.conftest import register_agent, admin_headers

SAMPLE_YAML = """
agents:
  - "*"
rules:
  - action: "read_file"
    effect: allow
    reason: "Agents may read"
  - action: "delete_file"
    effect: deny
    reason: "No deletions"
""".strip()


# ── 1. Core authorization: allow / deny / default-deny ────────────────────────

def test_authorize_allow_deny_default(client):
    """Allow, deny, and unknown actions each produce the correct decision,
    signature, and matched-policy metadata.

    Replaces: test_authorize_allow_deny_unknown, test_authorize_auto_logs_to_audit,
    test_authorize_missing_fields.
    """
    aid, hdr = register_agent(client, "authz-agent")
    client.post("/policies/managed", json={
        "name": "basic-authz", "priority": 50,
        "yaml_content": (
            'agents:\n  - "*"\nrules:\n'
            '  - action: "read_file"\n    effect: allow\n    reason: "May read"\n'
            '  - action: "delete_file"\n    effect: deny\n    reason: "No deletes"'
        ),
    }, headers=admin_headers(client))

    # ── Allow ──
    data = client.post("/authorize", json={"agent_id": aid, "action": "read_file"}, headers=hdr).json()
    assert data["decision"] == "allow"
    assert len(data["signature"]) > 0
    assert data["matched_policy"] is not None

    # ── Deny ──
    data = client.post("/authorize", json={"agent_id": aid, "action": "delete_file"}, headers=hdr).json()
    assert data["decision"] == "deny"
    assert "no deletes" in data["reason"].lower()

    # ── Unknown action → default deny ──
    data = client.post("/authorize", json={"agent_id": aid, "action": "unknown_op"}, headers=hdr).json()
    assert data["decision"] == "deny"

    # ── Auto-audit: the actions above should appear in the audit trail ──
    audit = client.get("/audit", params={"agent_id": aid}).json()
    actions = [e["action"] for e in audit["entries"]]
    assert "read_file" in actions
    assert "delete_file" in actions

    # ── Missing fields → 422 ──
    assert client.post("/authorize", json={"agent_id": aid}, headers=hdr).status_code == 422


# ── 2. Identity enforcement ───────────────────────────────────────────────────

def test_authorize_identity_enforcement(client):
    """Agent A cannot authorize or view permissions on behalf of Agent B.

    Replaces: test_authorize_identity_enforcement, test_effective_permissions_identity_enforcement.
    """
    aid_a, hdr_a = register_agent(client, "agent-a")
    aid_b, hdr_b = register_agent(client, "agent-b")

    assert client.post("/authorize", json={"agent_id": aid_b, "action": "read_file"}, headers=hdr_a).status_code == 403
    assert client.get(f"/agents/{aid_b}/permissions", headers=hdr_a).status_code == 403


# ── 3. CRUD lifecycle ─────────────────────────────────────────────────────────

def test_policy_crud_lifecycle(client, auth_header):
    """Create → duplicate rejected → read → list sorted/filtered → update
    → deactivate (ignored by engine) → delete → 404 on all verbs.

    Replaces: test_crud_lifecycle, test_list_policies_sorted_and_filtered,
    test_not_found, test_db_policy_used_in_authorize, test_db_policy_overrides_yaml,
    test_inactive_policy_ignored.
    """
    # ── Create ──
    resp = client.post("/policies/managed", json={
        "name": "crud-policy", "priority": 50, "yaml_content": SAMPLE_YAML,
    }, headers=auth_header)
    assert resp.status_code == 201
    pid = resp.json()["id"]
    assert resp.json()["active"] is True

    # ── Duplicate name → 409 ──
    assert client.post("/policies/managed", json={
        "name": "crud-policy", "yaml_content": SAMPLE_YAML,
    }, headers=auth_header).status_code == 409

    # ── Read ──
    assert client.get(f"/policies/managed/{pid}", headers=auth_header).json()["name"] == "crud-policy"

    # ── List: sorted by priority desc, active-only filter works ──
    client.post("/policies/managed", json={"name": "crud-hi", "yaml_content": SAMPLE_YAML, "priority": 100}, headers=auth_header)
    client.post("/policies/managed", json={"name": "crud-off", "yaml_content": SAMPLE_YAML, "active": False}, headers=auth_header)
    data = client.get("/policies/managed", headers=auth_header).json()
    priorities = [p["priority"] for p in data["policies"]]
    assert priorities == sorted(priorities, reverse=True)
    data = client.get("/policies/managed", params={"active_only": True}, headers=auth_header).json()
    assert all(p["active"] for p in data["policies"])

    # ── DB policy used in authorization ──
    aid, hdr = register_agent(client, "db-authz-agent")
    client.post("/policies/managed", json={
        "name": "db-search", "priority": 100,
        "yaml_content": 'agents:\n  - "*"\nrules:\n  - action: "web_search"\n    effect: allow\n    reason: "DB policy permits searching"',
    }, headers=admin_headers(client))
    data = client.post("/authorize", json={"agent_id": aid, "action": "web_search"}, headers=hdr).json()
    assert data["decision"] == "allow"
    assert "DB policy" in data["reason"]

    # ── Inactive policy ignored by engine ──
    aid2, hdr2 = register_agent(client, "inactive-agent")
    client.post("/policies/managed", json={
        "name": "moon-policy", "priority": 100, "active": False,
        "yaml_content": 'agents:\n  - "*"\nrules:\n  - action: "export_data"\n    effect: allow\n    reason: "Go"',
    }, headers=admin_headers(client))
    assert client.post("/authorize", json={"agent_id": aid2, "action": "export_data"}, headers=hdr2).json()["decision"] == "deny"

    # ── Update ──
    data = client.patch(f"/policies/managed/{pid}", json={"priority": 99, "active": False}, headers=auth_header).json()
    assert data["priority"] == 99 and data["active"] is False

    # ── Delete ──
    assert client.delete(f"/policies/managed/{pid}", headers=auth_header).status_code == 204
    assert client.get(f"/policies/managed/{pid}", headers=auth_header).status_code == 404

    # ── Not-found on all verbs ──
    assert client.patch("/policies/managed/99999", json={"priority": 1}, headers=auth_header).status_code == 404
    assert client.delete("/policies/managed/99999", headers=auth_header).status_code == 404


# ── 4. Wildcard / glob matching ───────────────────────────────────────────────

def test_wildcard_and_glob_matching(client):
    """email.* matches email.read/send, doesn't match calendar.read,
    specific deny overrides wildcard allow, multi-level file.read.* works,
    resource glob /data/* matches, and dry-run respects wildcards.

    Replaces: 7 wildcard tests + test_dry_run_with_wildcards.
    """
    aid, hdr = register_agent(client, "wc-agent")

    # ── email.* with explicit deny on email.delete ──
    client.post("/policies/managed", json={
        "name": "email-mixed", "priority": 100,
        "yaml_content": (
            'agents:\n  - "*"\nrules:\n'
            '  - action: "email.delete"\n    effect: deny\n    reason: "No deleting email"\n'
            '  - action: "email.*"\n    effect: allow\n    reason: "Email OK"\n'
            '  - action: "file.read.*"\n    effect: allow\n    reason: "Read any file type"\n'
            '  - action: "access_file"\n    resource: "/data/*"\n    effect: allow\n    reason: "Data dir only"'
        ),
    }, headers=admin_headers(client))

    # Matches
    assert client.post("/authorize", json={"agent_id": aid, "action": "email.read"}, headers=hdr).json()["decision"] == "allow"
    assert client.post("/authorize", json={"agent_id": aid, "action": "email.send"}, headers=hdr).json()["decision"] == "allow"
    # Specific deny beats wildcard allow
    assert client.post("/authorize", json={"agent_id": aid, "action": "email.delete"}, headers=hdr).json()["decision"] == "deny"
    # Doesn't over-match
    assert client.post("/authorize", json={"agent_id": aid, "action": "calendar.read"}, headers=hdr).json()["decision"] == "deny"
    # Multi-level wildcard
    assert client.post("/authorize", json={"agent_id": aid, "action": "file.read.csv"}, headers=hdr).json()["decision"] == "allow"
    assert client.post("/authorize", json={"agent_id": aid, "action": "file.write.csv"}, headers=hdr).json()["decision"] == "deny"
    # Resource glob
    assert client.post("/authorize", json={"agent_id": aid, "action": "access_file", "resource": "/data/report.txt"}, headers=hdr).json()["decision"] == "allow"
    assert client.post("/authorize", json={"agent_id": aid, "action": "access_file", "resource": "/secrets/pw.txt"}, headers=hdr).json()["decision"] == "deny"

    # ── Dry-run with wildcards ──
    candidate = 'name: wc-dr\npriority: 100\nagents: ["*"]\nrules:\n  - action: "email.*"\n    effect: allow\n    reason: "All email"'
    data = client.post("/policies/dry-run", json={
        "policy_yaml": candidate, "agent_id": "dr-agent",
        "actions": [{"action": "email.read"}, {"action": "calendar.read"}],
    }, headers=hdr).json()
    results = {r["action"]: r for r in data["results"]}
    assert results["email.read"]["decision"] == "allow"


# ── 5. Rate limiting ──────────────────────────────────────────────────────────

def test_rate_limiting(client):
    """Within limit → allowed, exceeded → denied with OWASP tag,
    different agents have independent counters.

    Replaces: 3 rate-limit tests.
    """
    aid_a, hdr_a = register_agent(client, "rate-A")
    aid_b, hdr_b = register_agent(client, "rate-B")
    client.post("/policies/managed", json={
        "name": "rate-policy", "priority": 100,
        "yaml_content": (
            'agents:\n  - "*"\nrules:\n'
            '  - action: "limited.call"\n    effect: allow\n'
            '    reason: "Max 2"\n    rate_limit:\n      max_calls: 2\n      window: 3600'
        ),
    }, headers=admin_headers(client))

    # Agent A: first call allowed
    assert client.post("/authorize", json={"agent_id": aid_a, "action": "limited.call"}, headers=hdr_a).json()["decision"] == "allow"

    # Post-execution /audit entries (e.g. from the SDK decorator) don't consume quota
    for _ in range(2):
        client.post("/audit", json={"agent_id": aid_a, "action": "limited.call", "policy_decision": "allow"}, headers=hdr_a)
    assert client.post("/authorize", json={"agent_id": aid_a, "action": "limited.call"}, headers=hdr_a).json()["decision"] == "allow"

    # Third authorization exceeds max_calls=2
    data = client.post("/authorize", json={"agent_id": aid_a, "action": "limited.call"}, headers=hdr_a).json()
    assert data["decision"] == "deny"
    assert "Rate limit exceeded" in data["reason"]
    assert "LLM10" in (data.get("owasp") or [])

    # Agent B is independent — still allowed
    assert client.post("/authorize", json={"agent_id": aid_b, "action": "limited.call"}, headers=hdr_b).json()["decision"] == "allow"


# ── 6. ABAC conditions ────────────────────────────────────────────────────────

def test_abac_conditions(client):
    """Conditions: match → allow, mismatch → skip (deny), no context → skip,
    multiple conditions all must match, glob values work.

    Replaces: 5 ABAC tests.
    """
    aid, hdr = register_agent(client, "abac-agent")
    client.post("/policies/managed", json={
        "name": "abac-policy", "priority": 100,
        "yaml_content": (
            'agents:\n  - "*"\nrules:\n'
            '  - action: "db.query"\n    effect: allow\n    reason: "Analysts only"\n'
            '    conditions:\n      user_role: "analyst"\n'
            '  - action: "db.write"\n    effect: allow\n    reason: "Admin eng only"\n'
            '    conditions:\n      user_role: "admin"\n      department: "eng-*"'
        ),
    }, headers=admin_headers(client))

    # Match
    assert client.post("/authorize", json={"agent_id": aid, "action": "db.query", "context": {"user_role": "analyst"}}, headers=hdr).json()["decision"] == "allow"
    # Mismatch
    assert client.post("/authorize", json={"agent_id": aid, "action": "db.query", "context": {"user_role": "admin"}}, headers=hdr).json()["decision"] == "deny"
    # No context
    assert client.post("/authorize", json={"agent_id": aid, "action": "db.query"}, headers=hdr).json()["decision"] == "deny"
    # Multi-condition: both match
    assert client.post("/authorize", json={"agent_id": aid, "action": "db.write", "context": {"user_role": "admin", "department": "eng-platform"}}, headers=hdr).json()["decision"] == "allow"
    # Multi-condition: one mismatch
    assert client.post("/authorize", json={"agent_id": aid, "action": "db.write", "context": {"user_role": "admin", "department": "sales"}}, headers=hdr).json()["decision"] == "deny"


# ── 7. Observe mode full cycle ────────────────────────────────────────────────

def test_observe_mode_full_cycle(client):
    """Observe-mode deny → returns allow + observation, audit logged as observe_deny,
    effective permissions show mode. Enforce mode and no-mode both deny for real.

    Replaces: 16 observe-mode tests.
    """
    aid, hdr = register_agent(client, "observe-agent")
    OBSERVE_YAML = (
        f'name: obs-policy\nmode: observe\npriority: 100\nagents:\n  - "{aid}"\nrules:\n'
        '  - action: "delete_file"\n    effect: deny\n    reason: "Destructive"\n'
        '  - action: "read_file"\n    effect: allow\n    reason: "OK"'
    )
    client.post("/policies/managed", json={
        "name": "obs-test", "priority": 100, "yaml_content": OBSERVE_YAML,
    }, headers=admin_headers(client))

    # ── Observe-mode deny returns allow + observation ──
    data = client.post("/authorize", json={"agent_id": aid, "action": "delete_file"}, headers=hdr).json()
    assert data["decision"] == "allow"
    assert data["observation"] is not None
    assert "OBSERVE" in data["observation"]
    assert "observe mode" in data["reason"].lower()
    assert len(data["signature"]) > 0

    # ── Observe-mode allow has no observation ──
    data = client.post("/authorize", json={"agent_id": aid, "action": "read_file"}, headers=hdr).json()
    assert data["decision"] == "allow"
    assert data["observation"] is None

    # ── Audit logged as observe_deny ──
    audit = client.get("/audit", params={"agent_id": aid, "action": "delete_file"}, headers=hdr).json()
    assert audit["total"] >= 1
    entry = audit["entries"][0]
    assert entry["policy_decision"] == "observe_deny"
    assert "observation" in entry["outputs"]
    assert "OBSERVE" in entry["outputs"]["observation"]

    # ── Effective permissions surface mode ──
    perms = client.get(f"/agents/{aid}/permissions", headers=hdr).json()
    observe_rules = [p for p in perms["permissions"] if p["mode"] == "observe"]
    assert len(observe_rules) >= 2
    assert perms["observed_rules"] >= 2

    # ── Enforce mode denies for real ──
    aid2, hdr2 = register_agent(client, "enforce-agent")
    client.post("/policies/managed", json={
        "name": "enf-test", "priority": 200,
        "yaml_content": f'name: enf\nmode: enforce\npriority: 200\nagents:\n  - "{aid2}"\nrules:\n  - action: "delete_file"\n    effect: deny\n    reason: "Blocked"',
    }, headers=admin_headers(client))
    data = client.post("/authorize", json={"agent_id": aid2, "action": "delete_file"}, headers=hdr2).json()
    assert data["decision"] == "deny"
    assert data["observation"] is None

    # ── No-mode defaults to enforce ──
    aid3, hdr3 = register_agent(client, "nomode-agent")
    client.post("/policies/managed", json={
        "name": "nomode-test", "priority": 200,
        "yaml_content": f'name: nm\npriority: 200\nagents:\n  - "{aid3}"\nrules:\n  - action: "delete_file"\n    effect: deny\n    reason: "Blocked"',
    }, headers=admin_headers(client))
    assert client.post("/authorize", json={"agent_id": aid3, "action": "delete_file"}, headers=hdr3).json()["decision"] == "deny"


# ── 8. Dry-run ─────────────────────────────────────────────────────────────────

def test_dry_run(client, auth_header):
    """Dry-run evaluates a candidate policy without persisting it.
    Handles OWASP tags, conditions, and empty YAML gracefully.

    Replaces: test_dry_run, test_dry_run_with_owasp_and_conditions.
    """
    candidate = """
name: dr-candidate
priority: 100
agents: ["*"]
rules:
  - action: "web_search"
    effect: allow
    reason: "Searching OK"
  - action: "db.query"
    effect: allow
    reason: "Analysts only"
    conditions:
      user_role: "analyst"
    owasp: ["LLM06"]
  - action: "read_file"
    effect: deny
    reason: "Candidate denies reads"
"""
    data = client.post("/policies/dry-run", json={
        "policy_yaml": candidate, "agent_id": "dr-agent",
        "actions": [
            {"action": "web_search"},
            {"action": "read_file"},
            {"action": "write_file"},
            {"action": "db.query", "context": {"user_role": "analyst"}},
        ],
    }, headers=auth_header).json()
    results = {r["action"]: r for r in data["results"]}
    assert results["web_search"]["decision"] == "allow"
    assert results["read_file"]["decision"] == "deny"
    assert results["write_file"]["decision"] == "deny"
    assert results["db.query"]["decision"] == "allow"
    assert "LLM06" in results["db.query"]["owasp"]

    # Empty YAML
    data = client.post("/policies/dry-run", json={
        "policy_yaml": "", "agent_id": "x", "actions": [{"action": "read_file"}],
    }, headers=auth_header).json()
    assert "Invalid or empty" in data["summary"]


# ── 9. OWASP tags ─────────────────────────────────────────────────────────────

def test_owasp_tags(client):
    """Rule-level and policy-level OWASP tags propagate to authorize response.

    Replaces: test_owasp_tags_in_response, test_owasp_tags_from_policy_level.
    """
    aid, hdr = register_agent(client, "owasp-agent")

    # Rule-level
    client.post("/policies/managed", json={
        "name": "owasp-rule", "priority": 100,
        "yaml_content": (
            'agents:\n  - "*"\nrules:\n'
            '  - action: "tagged.action"\n    effect: allow\n    reason: "Tagged"\n'
            '    owasp: ["LLM06", "LLM10"]'
        ),
    }, headers=admin_headers(client))
    data = client.post("/authorize", json={"agent_id": aid, "action": "tagged.action"}, headers=hdr).json()
    assert "LLM06" in data["owasp"] and "LLM10" in data["owasp"]

    # Policy-level
    aid2, hdr2 = register_agent(client, "owasp-plvl")
    client.post("/policies/managed", json={
        "name": "owasp-plvl", "priority": 100,
        "yaml_content": (
            'agents:\n  - "*"\nowasp: ["LLM06"]\nrules:\n'
            '  - action: "plvl.action"\n    effect: allow\n    reason: "Policy tags"'
        ),
    }, headers=admin_headers(client))
    data = client.post("/authorize", json={"agent_id": aid2, "action": "plvl.action"}, headers=hdr2).json()
    assert data["owasp"] == ["LLM06"]


# ── 10. Resource traversal ────────────────────────────────────────────────────

def test_resource_traversal_blocked(client):
    """Path traversal (../ and %2e%2e) is normalized before matching.

    Replaces: test_resource_traversal_blocked.
    """
    aid, hdr = register_agent(client, "traversal-agent")
    client.post("/policies/managed", json={
        "name": "traversal-test", "priority": 100,
        "yaml_content": (
            'agents:\n  - "*"\nrules:\n'
            '  - action: "access_file"\n    resource: "/data/*"\n    effect: allow\n    reason: "Data only"'
        ),
    }, headers=admin_headers(client))

    assert client.post("/authorize", json={"agent_id": aid, "action": "access_file", "resource": "/data/../../etc/passwd"}, headers=hdr).json()["decision"] == "deny"
    assert client.post("/authorize", json={"agent_id": aid, "action": "access_file", "resource": "/data/%2e%2e/etc/passwd"}, headers=hdr).json()["decision"] == "deny"
    assert client.post("/authorize", json={"agent_id": aid, "action": "access_file", "resource": "/data/report.csv"}, headers=hdr).json()["decision"] == "allow"
