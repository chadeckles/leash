"""Cryptographic utilities – key generation, JWT signing, and audit signatures."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

from leash.server.core.config import ADMIN_KEY, JWT_EXPIRATION_HOURS, JWT_ISSUER, KEYS_DIR

_logger = logging.getLogger("leash.security")

# ---------------------------------------------------------------------------
# Key-pair helpers
#
# New keys are Ed25519 (fast signing, small keys).  RSA keys created by
# Leash <= 0.3 are still loaded and used with RS256 / PKCS#1 v1.5 until the
# operator runs ``leash server rotate-keys``.
# ---------------------------------------------------------------------------

def generate_keypair() -> "tuple[bytes, bytes]":
    """Return (private_pem, public_pem) for a new Ed25519 key."""
    return _pem_pair(ed25519.Ed25519PrivateKey.generate())


def generate_rsa_keypair() -> "tuple[bytes, bytes]":
    """Return (private_pem, public_pem) for a new 2048-bit RSA key (legacy)."""
    return _pem_pair(rsa.generate_private_key(public_exponent=65537, key_size=2048))


def _pem_pair(private_key) -> "tuple[bytes, bytes]":
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
    keys_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    priv_path = keys_path / "server_private.pem"
    pub_path = keys_path / "server_public.pem"
    prev_pub_path = keys_path / "server_public.prev.pem"

    # Load previous public key if present (from a prior rotation)
    if prev_pub_path.exists():
        _cached_prev_pub = prev_pub_path.read_bytes()

    if priv_path.exists() and pub_path.exists():
        _cached_keys = (priv_path.read_bytes(), pub_path.read_bytes())
        return _cached_keys

    priv, pub = generate_keypair()
    _write_private(priv_path, priv)
    pub_path.write_bytes(pub)
    _cached_keys = (priv, pub)
    return _cached_keys


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(path, 0o600)


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
    keys_path.mkdir(mode=0o700, parents=True, exist_ok=True)
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
    priv, pub = generate_keypair()
    _write_private(priv_path, priv)
    pub_path.write_bytes(pub)

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
        info["algorithm"] = key_algorithm()
    info["has_previous_key"] = prev_pub_path.exists()
    return info


# ---------------------------------------------------------------------------
# Admin bootstrap key
# ---------------------------------------------------------------------------

ADMIN_KEY_FILENAME = "admin.key"


def get_admin_key_path() -> Path:
    return Path(KEYS_DIR) / ADMIN_KEY_FILENAME


def get_admin_key() -> str:
    """Return the admin bootstrap key, generating it on first use.

    ``LEASH_ADMIN_KEY`` takes precedence.  Otherwise the key is read from
    (or created at) ``KEYS_DIR/admin.key`` with mode 0600, so only the
    user running the server — not an arbitrary agent talking HTTP — can
    mint admin identities.
    """
    if ADMIN_KEY:
        return ADMIN_KEY
    path = get_admin_key_path()
    if path.exists():
        return path.read_text().strip()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = secrets.token_urlsafe(32)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return path.read_text().strip()
    with os.fdopen(fd, "w") as f:
        f.write(key)
    _logger.info("Generated admin bootstrap key at %s", path)
    return key


def verify_admin_key(candidate: "str | None") -> bool:
    """Constant-time comparison of *candidate* against the admin key."""
    if not candidate:
        return False
    return hmac.compare_digest(candidate.encode(), get_admin_key().encode())


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

@lru_cache(maxsize=8)
def _private_key(pem: bytes):
    return serialization.load_pem_private_key(pem, password=None)


@lru_cache(maxsize=8)
def _public_key(pem: bytes):
    return serialization.load_pem_public_key(pem)


def _jwt_algorithm(key) -> str:
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return "EdDSA"
    return "RS256"


def key_algorithm() -> str:
    """JWT algorithm of the current server key (``EdDSA`` or legacy ``RS256``)."""
    return _jwt_algorithm(_public_key(get_server_public_key()))


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
    key = _private_key(get_server_private_key())
    return jwt.encode(payload, key, algorithm=_jwt_algorithm(key))


def verify_agent_token(token: str) -> dict:
    """Decode and verify a JWT against the current server key.

    Falls back to the **previous** server public key so tokens stay valid
    during a key rotation.  Each key only accepts its own algorithm.

    Raises ``jwt.PyJWTError`` if neither key can verify the token.
    """
    error: "jwt.PyJWTError | None" = None
    for pem in (get_server_public_key(), get_server_previous_public_key()):
        if pem is None:
            continue
        key = _public_key(pem)
        try:
            return jwt.decode(token, key, algorithms=[_jwt_algorithm(key)], issuer=JWT_ISSUER)
        except jwt.PyJWTError as exc:
            error = error or exc
    raise error or jwt.InvalidTokenError("No server key available")


def _canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, default=str).encode()


def verify_signature(data: dict, signature_hex: str) -> bool:
    """Verify a hex signature over *data* with the current or previous server key.

    Accepts Ed25519 and legacy RSA-SHA256 (PKCS#1 v1.5) signatures, so audit
    entries signed before a key rotation remain verifiable.
    """
    canonical = _canonical(data)
    try:
        sig_bytes = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    for pem in (get_server_public_key(), get_server_previous_public_key()):
        if pem is None:
            continue
        key = _public_key(pem)
        try:
            if isinstance(key, ed25519.Ed25519PublicKey):
                key.verify(sig_bytes, canonical)
            else:
                key.verify(sig_bytes, canonical, padding.PKCS1v15(), hashes.SHA256())  # type: ignore[union-attr]
            return True
        except Exception:
            continue
    return False


# ---------------------------------------------------------------------------
# Audit-entry signature
# ---------------------------------------------------------------------------

def sign_data(data: dict) -> str:
    """Sign the canonical JSON of *data* with the server key; returns hex."""
    key = _private_key(get_server_private_key())
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return key.sign(_canonical(data)).hex()
    return key.sign(_canonical(data), padding.PKCS1v15(), hashes.SHA256()).hex()  # type: ignore[union-attr]


def hash_data(data: dict) -> str:
    """Return a SHA-256 hex digest for the canonical JSON of *data*."""
    canonical = json.dumps(data, sort_keys=True, default=str).encode()
    return hashlib.sha256(canonical).hexdigest()
