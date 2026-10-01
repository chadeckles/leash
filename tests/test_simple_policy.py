"""The simple `tool: allow|deny` policy format, its catalog, and `leash scan openclaw`."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from app.policy.simple import expand, lint, render
from app.policy.validator import validate_policy, validate_policy_yaml
from tests.conftest import register_agent

ROOT = Path(__file__).resolve().parent.parent
OPENCLAW_YAML = ROOT / "app" / "policies" / "openclaw.yaml"


def _authorize(client, aid, hdr, action):
    return client.post("/authorize", json={"agent_id": aid, "action": action}, headers=hdr).json()


def test_shipped_openclaw_policy_is_simple_and_valid():
    doc = yaml.safe_load(OPENCLAW_YAML.read_text())
    assert set(doc) == {"agent", "tools", "everything_else"}
    assert doc["tools"]["exec"] == "deny" and doc["tools"]["read"] == "allow"
    assert validate_policy(doc, "openclaw.yaml") == []


def test_expand_produces_full_rules():
    full = expand({"agent": "openclaw", "tools": {"read": "allow", "exec": "Deny ", "cron": "allow"}})
    assert full["name"] == "openclaw-policy"
    assert full["agents"] == ["*openclaw*"]
    rules = {r["action"]: r for r in full["rules"]}
    assert rules["exec"]["effect"] == "deny"
    assert rules["exec"]["reason"] == "exec is blocked — it could run any shell command on your computer"
    assert rules["exec"]["owasp"]
    assert rules["cron"]["rate_limit"] == {"max_calls": 20, "window": 3600}
    assert full["rules"][-1]["action"] == "*" and full["rules"][-1]["effect"] == "deny"


def test_expand_keeps_advanced_rules_first_and_ids_verbatim():
    aid = "12345678-1234-1234-1234-123456789abc"
    full = expand({
        "agent": aid, "tools": {"write": "deny"}, "mode": "observe",
        "rules": [{"action": "write", "resource": "notes/*", "effect": "allow"}],
    })
    assert full["agents"] == [aid]
    assert full["mode"] == "observe"
    assert [r["action"] for r in full["rules"]] == ["write", "write", "*"]
    assert full["rules"][0]["resource"] == "notes/*"


def test_lint_catches_beginner_mistakes():
    assert any("did you mean 'exec'" in e for e in lint({"agent": "openclaw", "tools": {"exce": "deny"}}))
    assert any("use allow or deny" in e for e in lint({"agent": "openclaw", "tools": {"exec": False}}))
    assert any("use allow or deny" in e for e in lint({"agent": "openclaw", "tools": {"exec": "block"}}))
    assert any("agent:" in e for e in lint({"tools": {"exec": "deny"}}))
    assert validate_policy_yaml("agent: openclaw\ntools:\n  exec: no\n")
    # Unknown, non-typo tools are fine (OpenClaw adds tools over time)
    assert lint({"agent": "openclaw", "tools": {"brand_new_tool": "deny"}}) == []


def test_engine_enforces_simple_policy(client):
    aid, hdr = register_agent(client, "openclaw-agent")
    allowed = _authorize(client, aid, hdr, "read")
    assert allowed["decision"] == "allow"
    assert allowed["reason"] == "read is allowed — it can read files in its workspace"
    denied = _authorize(client, aid, hdr, "exec")
    assert denied["decision"] == "deny"
    assert denied["matched_policy"] == "openclaw-policy"
    assert "any shell command" in denied["reason"]
    assert _authorize(client, aid, hdr, "unlisted_tool")["decision"] == "deny"


def test_non_admin_cannot_grant_itself_tools_via_simple_format(client):
    aid, hdr = register_agent(client, "simple-escalation")

    def create(name, body):
        return client.post("/policies/managed", json={"name": name, "priority": 100, "yaml_content": body},
                           headers=hdr)

    assert create("grant", f"agent: {aid}\ntools:\n  exec: allow\n").status_code == 403
    assert create("open", f"agent: {aid}\ntools:\n  exec: deny\neverything_else: allow\n").status_code == 403
    assert _authorize(client, aid, hdr, "exec")["decision"] == "deny"

    assert create("tighten", f"agent: {aid}\ntools:\n  web_search: deny\n").status_code == 201
    assert _authorize(client, aid, hdr, "web_search")["decision"] == "deny"


def test_render_round_trips():
    text = render("openclaw", {"read": "allow", "exec": "deny"}, header="# hi")
    doc = yaml.safe_load(text)
    assert doc == {"agent": "openclaw", "tools": {"read": "allow", "exec": "deny"}, "everything_else": "deny"}
    assert "run any shell command" in text


def test_scan_openclaw_reflects_policy_edits(tmp_path, capsys):
    from sdk.scan_openclaw import scan_openclaw

    policy = OPENCLAW_YAML.read_text().replace("exec: deny", "exec: allow", 1)
    (tmp_path / "openclaw.yaml").write_text(policy)
    out_file = tmp_path / "generated.yaml"

    assert scan_openclaw(fmt="json", save_policy=str(out_file), policies_dir=str(tmp_path)) == 0
    tools = {t["tool"]: t for t in json.loads(capsys.readouterr().out)["tools"]}
    assert tools["exec"]["effect"] == "allow" and tools["exec"]["risk"] == "high"
    assert tools["browser"]["effect"] == "deny"
    assert yaml.safe_load(out_file.read_text())["tools"]["exec"] == "allow"
    assert validate_policy_yaml(out_file.read_text()) == []

    scan_openclaw(policies_dir=str(tmp_path))
    assert "⚠ high risk and allowed" in capsys.readouterr().out


def test_scan_openclaw_accepts_flags_after_subcommand(tmp_path, capsys, monkeypatch):
    import sys

    import pytest

    from sdk import cli

    out_file = tmp_path / "saved.yaml"
    monkeypatch.setattr(sys, "argv", ["leash", "scan", "openclaw", "--save-policy", str(out_file)])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0
    assert "exec: deny" in out_file.read_text()
