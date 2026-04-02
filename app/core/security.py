"""Cryptographic utilities – key generation, JWT signing, and audit signatures."""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from app.core.config import JWT_ALGORITHM, JWT_EXPIRATION_HOURS, JWT_ISSUER, KEYS_DIR

_logger = logging.getLogger("leash.security")

# ---------------------------------------------------------------------------
# RSA key-pair helpers
# ---------------------------------------------------------------------------

def generate_rsa_keypair() -> "tuple[bytes, bytes]":
    """Return (private_pem, public_pem) for a new 2048-bit RSA key."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


# ---------------------------------------------------------------------------
# Server signing key (used for JWTs and audit signatures)
# ---------------------------------------------------------------------------

# Module-level cache: avoids disk I/O on every sign/verify call.
_cached_keys: "tuple[bytes, bytes] | None" = None
# Previous public key for graceful rotation — allows JWT verification
# during the transition window after a server key rotation.
_cached_prev_pub: "bytes | None" = None


def _ensure_server_keys() -> "tuple[bytes, bytes]":
    """Load or create the server-level RSA key-pair stored on disk.

    The result is cached in memory after the first call so that
    subsequent sign/verify operations don't hit the filesystem.

    Also loads the previous public key (``server_public.prev.pem``) if
    present — used for graceful JWT verification after a server key
    rotation.
    """
    global _cached_keys, _cached_prev_pub
    if _cached_keys is not None:
        return _cached_keys

    keys_path = Path(KEYS_DIR)
    keys_path.mkdir(parents=True, exist_ok=True)
    priv_path = keys_path / "server_private.pem"
    pub_path = keys_path / "server_public.pem"
    prev_pub_path = keys_path / "server_public.prev.pem"

    # Load previous public key if present (from a prior rotation)
    if prev_pub_path.exists():
        _cached_prev_pub = prev_pub_path.read_bytes()

    if priv_path.exists() and pub_path.exists():
        _cached_keys = (priv_path.read_bytes(), pub_path.read_bytes())
        return _cached_keys

    priv, pub = generate_rsa_keypair()
    priv_path.write_bytes(priv)
    pub_path.write_bytes(pub)
    # Restrict permissions on private key
    os.chmod(priv_path, 0o600)
    _cached_keys = (priv, pub)
    return _cached_keys


def rotate_server_keys() -> dict:
    """Rotate the server signing key-pair with graceful transition.

    Steps:
    1. Current keys are archived as ``*.prev.pem`` (one generation kept)
    2. New key-pair is generated and written to disk
    3. In-memory caches are updated

    After rotation:
    - New JWTs and audit signatures use the new key
    - Existing JWTs signed by the old key remain verifiable via the
      previous public key (graceful fallback in :func:`verify_agent_token`)
    - Old audit signatures remain verifiable via ``/verify`` (also
      checks the previous key)
    - Agents can re-register or call ``/agents/{id}/rotate`` at their
      leisure to get a JWT signed by the new key

    Returns a dict with rotation metadata.
    """
    global _cached_keys, _cached_prev_pub

    keys_path = Path(KEYS_DIR)
    keys_path.mkdir(parents=True, exist_ok=True)
    priv_path = keys_path / "server_private.pem"
    pub_path = keys_path / "server_public.pem"
    prev_priv_path = keys_path / "server_private.prev.pem"
    prev_pub_path = keys_path / "server_public.prev.pem"

    # 1. Archive current → previous
    old_pub_bytes = None
    if priv_path.exists():
        priv_path.rename(prev_priv_path)
        os.chmod(prev_priv_path, 0o600)
    if pub_path.exists():
        old_pub_bytes = pub_path.read_bytes()
        pub_path.rename(prev_pub_path)

    # 2. Generate new
    priv, pub = generate_rsa_keypair()
    priv_path.write_bytes(priv)
    pub_path.write_bytes(pub)
    os.chmod(priv_path, 0o600)

    # 3. Update caches
    _cached_prev_pub = old_pub_bytes
    _cached_keys = (priv, pub)

    _logger.info("Server signing keys rotated — previous public key archived for verification")

    return {
        "rotated_at": datetime.now(timezone.utc).isoformat(),
        "previous_key_archived": old_pub_bytes is not None,
        "note": "All new JWTs use the new key. Existing JWTs remain valid via previous-key fallback.",
    }


def get_server_private_key() -> bytes:
    priv, _ = _ensure_server_keys()
    return priv


def get_server_public_key() -> bytes:
    _, pub = _ensure_server_keys()
    return pub


def get_server_previous_public_key() -> "bytes | None":
    """Return the previous server public key, or None if no rotation has occurred."""
    _ensure_server_keys()  # ensures _cached_prev_pub is loaded
    return _cached_prev_pub


def get_server_key_info() -> dict:
    """Return metadata about the server signing keys for diagnostics."""
    keys_path = Path(KEYS_DIR)
    priv_path = keys_path / "server_private.pem"
    prev_pub_path = keys_path / "server_public.prev.pem"

    info: dict = {"keys_dir": str(keys_path), "exists": priv_path.exists()}
    if priv_path.exists():
        stat = priv_path.stat()
        created = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
        age_days = (datetime.now(timezone.utc) - created).days
        info["created"] = created.isoformat()
        info["age_days"] = age_days
        info["permissions"] = oct(stat.st_mode & 0o777)
        info["needs_rotation"] = age_days > 90
    info["has_previous_key"] = prev_pub_path.exists()
    return info


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def create_agent_token(agent_id: str, name: str, agent_type: str = "", token_version: int = 1) -> str:
    """Create a signed JWT for an agent."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": agent_id,
        "name": name,
        "type": agent_type or "",
        "tv": token_version,
        "iss": JWT_ISSUER,
        "iat": now,
        "exp": now + timedelta(hours=JWT_EXPIRATION_HOURS),
    }
    return jwt.encode(payload, get_server_private_key(), algorithm=JWT_ALGORITHM)


def verify_agent_token(token: str) -> dict:
    """Decode and verify a JWT against the current server key.

    Falls back to the **previous** server public key if the current key
    fails verification.  This enables graceful server key rotation:
    existing JWTs remain valid during the transition window.

    Raises ``jwt.PyJWTError`` if neither key can verify the token.
    """
    try:
        return jwt.decode(
            token,
            get_server_public_key(),
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
        )
    except jwt.PyJWTError:
        prev_key = get_server_previous_public_key()
        if prev_key is not None:
            # Try previous key — allows graceful transition
            return jwt.decode(
                token,
                prev_key,
                algorithms=[JWT_ALGORITHM],
                issuer=JWT_ISSUER,
            )
        raise  # no previous key, propagate the original error


def verify_signature(data: dict, signature_hex: str) -> bool:
    """Verify an RSA-SHA256 hex signature against the server's public key.

    Falls back to the previous public key if the current key fails,
    so audit entries signed before a server key rotation remain
    verifiable.

    Returns True if the signature is valid, False otherwise.
    """
    canonical = json.dumps(data, sort_keys=True, default=str).encode()
    sig_bytes = bytes.fromhex(signature_hex)

    # Try current key first
    for pub_pem in (get_server_public_key(), get_server_previous_public_key()):
        if pub_pem is None:
            continue
        public_key = serialization.load_pem_public_key(pub_pem)
        try:
            public_key.verify(  # type: ignore[union-attr]
                sig_bytes,
                canonical,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True
        except Exception:
            continue
    return False


# ---------------------------------------------------------------------------
# Audit-entry signature
# ---------------------------------------------------------------------------

def sign_data(data: dict) -> str:
    """Produce an RSA-SHA256 hex signature over the canonical JSON of *data*."""
    canonical = json.dumps(data, sort_keys=True, default=str).encode()
    private_key = serialization.load_pem_private_key(get_server_private_key(), password=None)
    signature = private_key.sign(  # type: ignore[union-attr]
        canonical,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return signature.hex()


def hash_data(data: dict) -> str:
    """Return a SHA-256 hex digest for the canonical JSON of *data*."""
    canonical = json.dumps(data, sort_keys=True, default=str).encode()
    return hashlib.sha256(canonical).hexdigest()
