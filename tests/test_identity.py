"""Identity & Authentication — 2 tests covering the full agent lifecycle and auth edge cases.

Replaces: test_identity.py (9 tests), test_edge_cases.py auth section (4 tests) = 13 → 2
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt

from app.core.config import JWT_ALGORITHM, JWT_ISSUER
from app.core.security import get_server_private_key, get_server_public_key


def test_agent_lifecycle(client, auth_header):
    """Full agent lifecycle: register → JWT valid → vendor metadata → get → update
    → rotate keys → list with filters → stats → last_seen_at → not-found guards.

    Replaces 9 former tests in test_identity.py.
    """
    # ── Register with vendor metadata ──
    resp = client.post("/agents", json={
        "name": "lifecycle-agent", "vendor": "openai",
        "agent_type": "coding", "tags": ["production"],
    })
    assert resp.status_code == 201
    agent = resp.json()
    aid, token = agent["agent_id"], agent["token"]
    hdr = {"Authorization": f"Bearer {token}"}

    # JWT is valid and contains correct claims
    decoded = jwt.decode(token, get_server_public_key(),
                         algorithms=[JWT_ALGORITHM], issuer=JWT_ISSUER)
    assert decoded["sub"] == aid

    # Vendor metadata persisted
    assert agent["vendor"] == "openai"
    assert agent["agent_type"] == "coding"
    assert agent["tags"] == ["production"]

    # ── Empty name rejected ──
    assert client.post("/agents", json={"name": ""}).status_code == 422

    # ── Duplicate name rejected ──
    assert client.post("/agents", json={"name": "lifecycle-agent"}).status_code == 409

    # ── Get agent ──
    data = client.get(f"/agents/{aid}", headers=hdr).json()
    assert data["name"] == "lifecycle-agent"
    assert data["last_seen_at"] is None  # never authorized yet

    # ── Update agent ──
    data = client.patch(f"/agents/{aid}",
                        json={"vendor": "anthropic", "tags": ["staging"]},
                        headers=hdr).json()
    assert data["vendor"] == "anthropic"
    assert data["tags"] == ["staging"]

    # ── Rotate keys ──
    rot = client.post(f"/agents/{aid}/rotate", headers=hdr).json()
    assert rot["new_public_key"] != agent["public_key"]
    new_token = rot["token"]
    hdr = {"Authorization": f"Bearer {new_token}"}

    # ── last_seen_at updates on authorize ──
    client.post("/authorize", json={"agent_id": aid, "action": "read_file"}, headers=hdr)
    assert client.get(f"/agents/{aid}", headers=hdr).json()["last_seen_at"] is not None

    # ── Stats (the /authorize call above already logged 1 deny entry) ──
    client.post("/audit", json={"agent_id": aid, "action": "read_file", "policy_decision": "allow"}, headers=hdr)
    client.post("/audit", json={"agent_id": aid, "action": "delete_file", "policy_decision": "deny"}, headers=hdr)
    stats = client.get(f"/agents/{aid}/stats", headers=hdr).json()
    assert stats["total_actions"] >= 2
    assert stats["allowed_actions"] >= 1
    assert stats["denied_actions"] >= 1

    # ── List agents with filters ──
    client.post("/agents", json={"name": "ant-filter", "vendor": "anthropic", "agent_type": "research", "tags": ["dev"]})
    data = client.get("/agents", headers=hdr).json()
    assert data["total"] >= 2

    data = client.get("/agents", params={"vendor": "anthropic"}, headers=hdr).json()
    assert all(a["vendor"] == "anthropic" for a in data["agents"])

    data = client.get("/agents", params={"limit": 1}, headers=hdr).json()
    assert len(data["agents"]) == 1

    # ── Not-found guards ──
    fake_hdr = auth_header  # sub='test-agent-id', never registered
    assert client.get("/agents/test-agent-id", headers=fake_hdr).status_code == 404
    assert client.post("/agents/test-agent-id/rotate", headers=fake_hdr).status_code == 404
    assert client.patch("/agents/test-agent-id", json={"vendor": "x"}, headers=fake_hdr).status_code == 404
    assert client.get("/agents/test-agent-id/stats", headers=fake_hdr).status_code == 404


def test_auth_rejects_bad_tokens(client):
    """Every flavor of bad JWT is rejected: expired, malformed, missing, wrong issuer.

    Replaces 4 former tests in test_edge_cases.py.
    """
    now = datetime.now(timezone.utc)
    key = get_server_private_key()
    payload = {"agent_id": "x", "action": "y"}

    # ── Expired token ──
    expired = jwt.encode({
        "sub": "x", "name": "x", "type": "", "iss": JWT_ISSUER,
        "iat": now - timedelta(hours=25), "exp": now - timedelta(hours=1),
    }, key, algorithm=JWT_ALGORITHM)
    assert client.post("/authorize", json=payload,
                       headers={"Authorization": f"Bearer {expired}"}).status_code == 401

    # ── Malformed token ──
    assert client.post("/authorize", json=payload,
                       headers={"Authorization": "Bearer not.a.real.jwt"}).status_code == 401

    # ── Missing auth header entirely ──
    assert client.post("/authorize", json=payload).status_code == 401

    # ── Wrong issuer ──
    wrong_iss = jwt.encode({
        "sub": "x", "name": "x", "type": "", "iss": "not-leash",
        "iat": now, "exp": now + timedelta(hours=1),
    }, key, algorithm=JWT_ALGORITHM)
    assert client.post("/authorize", json=payload,
                       headers={"Authorization": f"Bearer {wrong_iss}"}).status_code == 401


def test_server_key_rotation_graceful(client):
    """Server key rotation: existing JWTs remain valid via previous-key fallback,
    new JWTs use the new key, and audit signature verification works across rotation.
    """
    from app.core.security import (
        rotate_server_keys, verify_agent_token, sign_data,
        verify_signature, get_server_key_info, create_agent_token,
    )

    # ── 1. Create a JWT and sign data with the CURRENT key ──
    old_token = create_agent_token("rot-agent", "rotation-test", agent_type="cli")
    old_data = {"agent_id": "rot-agent", "action": "test", "decision": "allow", "reason": "test"}
    old_signature = sign_data(old_data)

    # Both verify with current key
    decoded = verify_agent_token(old_token)
    assert decoded["sub"] == "rot-agent"
    assert verify_signature(old_data, old_signature)

    # ── 2. Rotate the server keys ──
    result = rotate_server_keys()
    assert result["previous_key_archived"] is True

    # ── 3. Old JWT still works (verified via previous key fallback) ──
    decoded = verify_agent_token(old_token)
    assert decoded["sub"] == "rot-agent"

    # ── 4. Old audit signature still verifiable ──
    assert verify_signature(old_data, old_signature)

    # ── 5. New JWT uses new key and works ──
    new_token = create_agent_token("rot-agent-2", "rotation-test-2")
    decoded2 = verify_agent_token(new_token)
    assert decoded2["sub"] == "rot-agent-2"

    # ── 6. New signature uses new key and works ──
    new_data = {"agent_id": "rot-agent-2", "action": "test2", "decision": "deny", "reason": "test"}
    new_sig = sign_data(new_data)
    assert verify_signature(new_data, new_sig)

    # ── 7. Key info reports the state correctly ──
    info = get_server_key_info()
    assert info["has_previous_key"] is True
    assert info["exists"] is True

    # ── 8. Admin API endpoint works ──
    # Register a CLI admin agent so we have a valid admin token
    resp = client.post("/agents", json={"name": "key-rot-admin", "agent_type": "cli"})
    admin_token = resp.json()["token"]
    admin_hdr = {"Authorization": f"Bearer {admin_token}"}

    # Key info endpoint
    info_resp = client.get("/admin/key-info", headers=admin_hdr)
    assert info_resp.status_code == 200
    assert "age_days" in info_resp.json()

    # Server key rotation endpoint (admin-only)
    rot_resp = client.post("/admin/rotate-server-keys", headers=admin_hdr)
    assert rot_resp.status_code == 200
    assert rot_resp.json()["previous_key_archived"] is True
