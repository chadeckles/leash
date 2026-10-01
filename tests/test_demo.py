"""Tests for the `leash demo` walkthrough and `leash audit verify`."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def test_leash_demo_runs_offline_end_to_end():
    env = {**os.environ, "NO_COLOR": "1"}
    for var in ("DATABASE_URL", "KEYS_DIR", "POLICIES_DIR"):
        env.pop(var, None)
    proc = subprocess.run(
        [sys.executable, "-m", "sdk.cli", "demo"],
        cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=120, check=False,
    )
    out = proc.stdout
    assert proc.returncode == 0, out + proc.stderr
    assert out.count("✔ ALLOW") == 3
    assert out.count("✘ DENY") == 3
    assert "✔ VALID" in out and "✘ BROKEN" in out
    assert "exec is blocked — it could run any shell command" in out


def test_audit_verify_reports_valid_chain(client, monkeypatch, capsys):
    from sdk import cli
    from tests.conftest import register_agent

    aid, hdr = register_agent(client, "verify-cli-agent")
    client.post("/authorize", json={"agent_id": aid, "action": "anything"}, headers=hdr)
    monkeypatch.setattr(cli, "_get_client", lambda base_url, token=None: client)

    cli.cmd_audit_verify(argparse.Namespace(url="http://testserver"))
    assert "✔ Audit chain VALID" in capsys.readouterr().out


def test_audit_verify_exits_nonzero_when_broken(client, monkeypatch, db_session):
    from app.models.audit import AuditEntry
    from sdk import cli
    from tests.conftest import register_agent

    aid, hdr = register_agent(client, "verify-cli-tamper")
    for action in ("read", "write", "exec"):
        client.post("/authorize", json={"agent_id": aid, "action": action}, headers=hdr)
    entries = db_session.query(AuditEntry).filter_by(agent_id=aid).order_by(AuditEntry.id).all()
    entries[1].policy_decision = "allow" if entries[1].policy_decision == "deny" else "deny"
    db_session.flush()
    monkeypatch.setattr(cli, "_get_client", lambda base_url, token=None: client)

    with pytest.raises(SystemExit) as exc:
        cli.cmd_audit_verify(argparse.Namespace(url="http://testserver"))
    assert exc.value.code == 1
