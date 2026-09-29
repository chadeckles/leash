"""Validation & Metrics — 2 tests covering the policy validator, metrics engine,
and YAML error handling through the API.

Replaces: test_validator_metrics.py (22), test_yaml_errors.py (9) = 31 → 2
"""

from __future__ import annotations

import textwrap
import threading
from pathlib import Path

from leash.engine.validator import validate_policy, validate_policy_yaml
from leash.server.core.metrics import _Metrics
from tests.conftest import register_agent


def test_policy_validator_and_metrics():
    """Validator: valid minimal/full, missing fields, empty rules, invalid effect,
    unknown keys, bad rate_limit, missing reason warning, YAML parse error, empty YAML,
    mode validation. Metrics: counters, labels, histograms, render, thread safety.

    Replaces: 16 TestPolicyValidator + 6 TestMetrics + 5 TestObserveModeValidator = 27 tests.
    """
    # ── Valid minimal ──
    assert validate_policy({"name": "t", "agents": ["*"], "rules": [{"action": "r", "effect": "allow", "reason": "ok"}]}) == []

    # ── Valid full ──
    assert validate_policy({
        "name": "full", "description": "A policy", "priority": 50,
        "agents": ["a1", "*research*"],
        "rules": [
            {"action": "email.send", "effect": "allow", "reason": "ok",
             "resource": "/outbox/*", "rate_limit": {"max_calls": 10, "window": 3600}, "owasp": ["ASI02"]},
            {"action": "*", "effect": "deny", "reason": "Catch-all"},
        ],
    }) == []

    # ── Missing required fields ──
    assert any("missing required field 'name'" in e for e in validate_policy({"agents": ["*"], "rules": [{"action": "x", "effect": "allow"}]}))
    assert any("missing required field 'rules'" in e for e in validate_policy({"name": "t", "agents": ["*"]}))
    assert any("missing 'agents'" in e for e in validate_policy({"name": "t", "rules": [{"action": "x", "effect": "allow"}]}))
    assert any("missing required field 'action'" in e for e in validate_policy({"name": "t", "agents": ["*"], "rules": [{"effect": "allow"}]}))

    # ── Empty rules ──
    assert any("'rules' is empty" in e for e in validate_policy({"name": "t", "agents": ["*"], "rules": []}))

    # ── Invalid effect ──
    assert any("'effect' must be 'allow', 'deny' or 'ask'" in e for e in
               validate_policy({"name": "t", "agents": ["*"], "rules": [{"action": "x", "effect": "maybe"}]}))

    # ── Unknown keys ──
    assert any("unknown top-level key 'flavor'" in e for e in
               validate_policy({"name": "t", "agents": ["*"], "rules": [{"action": "x", "effect": "allow"}], "flavor": "chocolate"}))
    assert any("unknown key 'color'" in e for e in
               validate_policy({"name": "t", "agents": ["*"], "rules": [{"action": "x", "effect": "allow", "color": "red"}]}))

    # ── Negative priority ──
    assert any("priority" in e and ">= 0" in e for e in
               validate_policy({"name": "t", "priority": -1, "agents": ["*"], "rules": [{"action": "x", "effect": "allow"}]}))

    # ── Bad rate limit ──
    errs = validate_policy({"name": "t", "agents": ["*"], "rules": [{"action": "x", "effect": "allow", "rate_limit": {"max_calls": "ten"}}]})
    assert any("max_calls must be int" in e for e in errs)
    assert any("missing 'window'" in e for e in errs)

    # ── Missing reason warning ──
    assert any("missing 'reason'" in e for e in
               validate_policy({"name": "t", "agents": ["*"], "rules": [{"action": "x", "effect": "allow"}]}))

    # ── YAML string: parse error, empty, roundtrip ──
    assert any("YAML parse error" in e for e in validate_policy_yaml("{{invalid yaml: ["))
    assert any("empty YAML" in e for e in validate_policy_yaml(""))
    assert validate_policy_yaml(textwrap.dedent("name: my-policy\nagents: ['*']\nrules:\n  - action: read\n    effect: allow\n    reason: test\n")) == []

    # ── Mode validation: observe/enforce valid, bad mode rejected ──
    base = {"name": "t", "agents": ["*"], "rules": [{"action": "x", "effect": "deny", "reason": "no"}]}
    assert validate_policy({**base, "mode": "observe"}) == []
    assert validate_policy({**base, "mode": "enforce"}) == []
    assert validate_policy(base) == []  # no mode is fine
    assert any("mode" in e and "observe" in e for e in validate_policy({**base, "mode": "shadow"}))
    assert any("mode" in e for e in validate_policy({**base, "mode": 42}))

    # ── Shipped policy files all valid ──
    from leash.server.core.config import POLICIES_DIR
    policy_dir = Path(POLICIES_DIR)
    for yf in list(policy_dir.glob("*.yaml")) + list(policy_dir.glob("*.yml")):
        real_errors = [i for i in validate_policy_yaml(yf.read_text()) if "recommended" not in i.lower()]
        assert not real_errors, f"{yf.name} has errors: {real_errors}"

    # ── Metrics engine ──
    m = _Metrics()
    m.inc("test_counter")
    assert m.get("test_counter") == 1
    m.inc("test_counter", 5)
    assert m.get("test_counter") == 6

    # Labels
    m.inc("requests", labels={"method": "GET", "status": "200"})
    m.inc("requests", labels={"method": "GET", "status": "200"})
    m.inc("requests", labels={"method": "POST", "status": "201"})
    assert m.get("requests", labels={"method": "GET", "status": "200"}) == 2

    # Histogram
    m.observe("latency", 0.1)
    m.observe("latency", 0.2)
    m.observe("latency", 0.3)
    rendered = m.render()
    assert "leash_latency_sum 0.6" in rendered
    assert "leash_latency_count 3" in rendered

    # Render format
    m.inc("authorize_total", labels={"decision": "allow"})
    rendered = m.render()
    assert "# HELP leash_authorize_total" in rendered
    assert "# TYPE leash_authorize_total counter" in rendered
    assert "leash_uptime_seconds" in rendered

    # Thread safety
    m2 = _Metrics()
    def _inc():
        for _ in range(1000):
            m2.inc("concurrent")
    threads = [threading.Thread(target=_inc) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert m2.get("concurrent") == 4000


def test_yaml_error_api_responses(client, auth_header):
    """API endpoints return clear 422 errors for invalid YAML: unparseable,
    missing fields, invalid effect, unknown keys, empty, and update path.
    Corrupt DB policy doesn't crash authorize.

    Replaces: 9 test_yaml_errors.py tests.
    """
    # ── Unparseable ──
    resp = client.post("/policies/managed", json={"name": "broken", "yaml_content": "{{not: valid: yaml: ["}, headers=auth_header)
    assert resp.status_code == 422
    assert any("YAML parse error" in e for e in resp.json()["detail"]["errors"])

    # ── Missing rules ──
    resp = client.post("/policies/managed", json={"name": "no-rules", "yaml_content": "agents:\n  - '*'\n"}, headers=auth_header)
    assert resp.status_code == 422
    assert any("missing required field 'rules'" in e for e in resp.json()["detail"]["errors"])

    # ── Invalid effect ──
    resp = client.post("/policies/managed", json={
        "name": "bad-eff",
        "yaml_content": "name: bad-eff\nagents:\n  - '*'\nrules:\n  - action: test\n    effect: maybe\n",
    }, headers=auth_header)
    assert resp.status_code == 422
    assert any("'effect' must be 'allow', 'deny' or 'ask'" in e for e in resp.json()["detail"]["errors"])

    # ── Unknown keys ──
    resp = client.post("/policies/managed", json={
        "name": "extra",
        "yaml_content": "name: extra\nagents:\n  - '*'\nflavor: chocolate\nrules:\n  - action: test\n    effect: allow\n    reason: ok\n",
    }, headers=auth_header)
    assert resp.status_code == 422
    assert any("unknown top-level key 'flavor'" in e for e in resp.json()["detail"]["errors"])

    # ── Empty YAML ──
    resp = client.post("/policies/managed", json={"name": "empty", "yaml_content": ""}, headers=auth_header)
    assert resp.status_code == 422

    # ── Valid YAML accepted ──
    resp = client.post("/policies/managed", json={
        "name": "valid-yaml-test",
        "yaml_content": "name: valid-yaml-test\nagents:\n  - '*'\nrules:\n  - action: test\n    effect: allow\n    reason: Valid\n",
    }, headers=auth_header)
    assert resp.status_code == 201
    pid = resp.json()["id"]

    # ── Update rejects bad YAML ──
    resp = client.patch(f"/policies/managed/{pid}", json={"yaml_content": "{{broken: yaml: ["}, headers=auth_header)
    assert resp.status_code == 422

    # ── Update accepts valid YAML ──
    resp = client.patch(f"/policies/managed/{pid}", json={
        "yaml_content": "name: valid-yaml-test\nagents:\n  - '*'\nrules:\n  - action: test.v2\n    effect: deny\n    reason: updated\n",
    }, headers=auth_header)
    assert resp.status_code == 200

    # ── Corrupt DB policy doesn't crash authorize ──
    aid, hdr = register_agent(client, "corrupt-agent")
    from leash.server.core.database import get_db
    from leash.server.models.policy import Policy
    db = next(get_db())
    corrupt = Policy(name="corrupt-policy", priority=100, yaml_content="{{not valid", active=True)
    db.add(corrupt)
    db.commit()

    resp = client.post("/authorize", json={"agent_id": aid, "action": "anything"}, headers=hdr)
    assert resp.status_code == 200
    assert resp.json()["decision"] in ("allow", "deny")

    db.delete(corrupt)
    db.commit()
