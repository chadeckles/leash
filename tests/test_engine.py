"""Pure policy engine (leash.engine), state paths, and packaging boundaries."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import textwrap
import time

import pytest

from leash import paths
from leash.engine import InMemoryRateLimiter, PolicyDirectory, PolicyEngine


def _engine(*policies, **kw):
    return PolicyEngine(policies, **kw)


def _policy(name="p", priority=0, agents=("*",), mode="enforce", rules=()):
    return {"name": name, "priority": priority, "agents": list(agents), "mode": mode, "rules": list(rules)}


def _rule(action, effect="allow", **extra):
    return {"action": action, "effect": effect, "reason": f"{effect} {action}", **extra}


def test_engine_imports_no_server_or_http_deps():
    code = textwrap.dedent("""
        import sys
        import leash, leash.engine, leash.paths
        heavy = {"fastapi", "sqlalchemy", "pydantic", "httpx", "jwt", "cryptography", "uvicorn"}
        loaded = sorted(heavy & {m.split(".")[0] for m in sys.modules})
        assert not loaded, loaded
    """)
    subprocess.run([sys.executable, "-c", code], check=True)


ENGINE = _engine(
    _policy("low", 1, rules=[_rule("email.*")]),
    _policy("high", 10, rules=[_rule("email.send", "deny")]),
    _policy("crew", 5, agents=["crewai-*"], rules=[_rule("crew.*")]),
    _policy("files", 5, rules=[_rule("file.read", resource="/data/*", conditions={"env": "prod-*"})]),
    _policy("watch", 5, mode="observe", rules=[_rule("rm", "deny")]),
)

# (action, resource, context, agent_name, expected decision, expected matched policy)
ENGINE_CASES = [
    ("email.send", "", None, None, "deny", "high"),            # priority: highest first
    ("email.read", "", None, None, "allow", "low"),            # first match across policies
    ("shell.exec", "", None, None, "deny", None),              # default deny
    ("crew.run", "", None, "crewai-research", "allow", "crew"),  # agent name glob
    ("crew.run", "", None, "other", "deny", None),
    ("file.read", "/data/x.csv", {"env": "prod-eu"}, None, "allow", "files"),
    ("file.read", "/data/../etc/passwd", {"env": "prod-eu"}, None, "deny", None),   # traversal
    ("file.read", "/data/%2e%2e/etc/passwd", {"env": "prod-eu"}, None, "deny", None),
    ("file.read", "/data/x.csv", {"env": "dev"}, None, "deny", None),               # condition mismatch
    ("file.read", "/data/x.csv", None, None, "deny", None),                         # missing context
    ("rm", "", None, None, "allow", "watch"),                  # observe mode never blocks
]


def test_engine_cases():
    failures = []
    for action, resource, context, name, want, policy in ENGINE_CASES:
        d = ENGINE.evaluate("id-1", action, resource, context, agent_name=name)
        if (d.decision, d.matched_policy) != (want, policy):
            failures.append(f"{action} {resource} {context} {name}: want {want}/{policy}, got {d.decision}/{d.matched_policy}")
    assert not failures, "\n".join(failures)

    observed = ENGINE.evaluate("a", "rm")
    assert observed.observation and observed.audit_decision == "observe_deny"
    assert ENGINE.evaluate("a", "rm", dry_run=True).decision == "deny"


def test_rate_limit_sliding_window():
    now = [0.0]
    engine = _engine(
        _policy(rules=[_rule("api.call", rate_limit={"max_calls": 2, "window": 60})]),
        rate_limiter=InMemoryRateLimiter(clock=lambda: now[0]),
    )
    assert engine.evaluate("a", "api.call").allowed
    assert engine.evaluate("a", "api.call").allowed
    denied = engine.evaluate("a", "api.call")
    assert not denied.allowed and "Rate limit exceeded: 2/2" in denied.reason and "LLM10" in denied.owasp
    assert engine.evaluate("b", "api.call").allowed  # per-agent counters
    now[0] = 61
    assert engine.evaluate("a", "api.call").allowed
    assert "not checked in dry-run" in engine.evaluate("a", "api.call", dry_run=True).reason


def test_policy_directory_reloads_and_skips_invalid_files(tmp_path):
    (tmp_path / "p.yaml").write_text("name: p\nagents: ['*']\nrules:\n  - action: a\n    effect: allow\n    reason: r\n")
    (tmp_path / "broken.yaml").write_text("rules: [\n")
    directory = PolicyDirectory(tmp_path, check_interval=0)
    assert [p.name for p in directory.policies] == ["p"]

    time.sleep(0.01)
    (tmp_path / "q.yml").write_text("name: q\npriority: 5\nagents: ['*']\nrules: []\n")
    assert [p.name for p in directory.policies] == ["q", "p"]  # highest priority first

    engine = PolicyEngine.from_directory(tmp_path)
    assert engine.evaluate("x", "a").allowed

    # Invalid files are skipped, not fatal
    (tmp_path / "b.yaml").write_text("name: b\nagents: ['other']\nrules: ['email.send']\n")
    (tmp_path / "c.yaml").write_text("name: c\npriority: high\nagents: ['*']\nrules: []\n")
    time.sleep(0.01)
    assert [p.name for p in directory.policies] == ["q", "p"]
    assert {d["name"] for d in directory.documents} == {"q", "p"}


def test_leash_home_paths_presets_and_identities(tmp_path, monkeypatch):
    monkeypatch.setenv("LEASH_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("POLICIES_DIR", raising=False)
    monkeypatch.delenv("KEYS_DIR", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    home = tmp_path / "home"
    assert paths.policies_dir() == home / "policies"
    assert paths.keys_dir() == home / "keys"
    assert paths.database_url() == f"sqlite:///{home / 'leash.db'}"
    assert paths.agent_identity_file("my bot/1") == home / "agents" / "my_bot_1.json"

    assert "default" in paths.preset_names()
    written = paths.seed_policies()
    assert {p.name for p in written} >= {"default.yaml"}
    # Existing directories (and user edits) are never overwritten
    (home / "policies" / "default.yaml").write_text("# mine\n")
    assert paths.seed_policies() == []
    assert (home / "policies" / "default.yaml").read_text() == "# mine\n"

    secret = home / "x" / "secret.json"
    paths.write_private(secret, "{}")
    assert stat.S_IMODE(os.stat(secret).st_mode) == 0o600

    # SDK and MCP proxy identities live under LEASH_HOME; legacy files still work
    from leash import LeashAgent
    from leash.mcp_proxy import _default_token_file

    monkeypatch.setenv("LEASH_URL", "http://example.invalid:9")
    monkeypatch.chdir(tmp_path)
    agent = LeashAgent(name="bot", auto_register=False)
    assert agent.base_url == "http://example.invalid:9"
    assert agent.token_file == home / "agents" / "bot.json"
    assert LeashAgent(name="bot", token_file=None).token_file is None
    (tmp_path / ".leash_identity.json").write_text('{"name": "legacy", "agent_id": "x", "token": "t"}')
    assert LeashAgent(name="legacy").token_file.name == ".leash_identity.json"

    assert _default_token_file("fs") == home / "agents" / "mcp_fs.json"
    (home / "mcp_fs.json").write_text("{}")
    assert _default_token_file("fs") == home / "mcp_fs.json"


@pytest.fixture()
def isolated_keys(tmp_path, monkeypatch):
    from leash.server.core import security

    monkeypatch.setattr(security, "KEYS_DIR", str(tmp_path))
    monkeypatch.setattr(security, "_cached_keys", None)
    monkeypatch.setattr(security, "_cached_prev_pub", None)
    return tmp_path


def test_server_keys_ed25519_and_legacy_rsa(isolated_keys):
    from leash.server.core import security

    token = security.create_agent_token("a", "n")
    assert security.key_algorithm() == "EdDSA"
    assert security.verify_agent_token(token)["sub"] == "a"
    sig = security.sign_data({"k": 1})
    assert security.verify_signature({"k": 1}, sig)
    assert not security.verify_signature({"k": 2}, sig)
    assert not security.verify_signature({"k": 1}, "not-hex")
    assert stat.S_IMODE(os.stat(isolated_keys / "server_private.pem").st_mode) == 0o600

    # Legacy RSA keys keep working and rotate to Ed25519
    security._cached_keys = None
    priv, pub = security.generate_rsa_keypair()
    (isolated_keys / "server_private.pem").write_bytes(priv)
    (isolated_keys / "server_public.pem").write_bytes(pub)

    assert security.key_algorithm() == "RS256"
    old_token = security.create_agent_token("a", "n")
    old_sig = security.sign_data({"k": 1})
    assert security.verify_agent_token(old_token)["sub"] == "a"

    security.rotate_server_keys()
    assert security.key_algorithm() == "EdDSA"
    # Tokens and audit signatures from the RSA key stay verifiable via the previous key
    assert security.verify_agent_token(old_token)["sub"] == "a"
    assert security.verify_signature({"k": 1}, old_sig)
    assert security.verify_agent_token(security.create_agent_token("b", "n"))["sub"] == "b"
