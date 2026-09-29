"""FastAPI dependency for JWT-based authentication."""

from __future__ import annotations

from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

import logging

from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import verify_admin_key, verify_agent_token

logger = logging.getLogger("leash.auth")

_bearer_scheme = HTTPBearer(auto_error=False)


REVOKED_DETAIL = "Token has been revoked"


def _verify_token_version(payload: dict, db: Session) -> None:
    """Check that the JWT's token_version matches the current DB value.

    This enables server-side revocation: rotating keys bumps the version
    and all previously-issued JWTs become invalid.  Tokens whose agent has
    been deleted are also rejected.  Fails **closed** (503) if the database
    cannot be consulted.
    """
    token_version = payload.get("tv")
    if token_version is None:
        return  # legacy tokens without version claim — allow (backwards compat)

    agent_id = payload.get("sub")
    if not agent_id:
        return

    try:
        from app.models.agent import Agent

        agent = db.query(Agent).filter(Agent.id == agent_id).first()
    except Exception:
        logger.exception("Token revocation check failed — denying request")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authorization backend unavailable",
        )

    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"{REVOKED_DETAIL} (agent no longer registered)",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )
    if agent.token_version is not None and token_version != agent.token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"{REVOKED_DETAIL} (key rotation occurred)",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )


def require_agent(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    db: Session = Depends(get_db),
) -> dict:
    """Validate the Bearer token and return the decoded JWT payload.

    Raises 401 if the token is missing or invalid.
    The returned dict contains at least ``sub`` (agent_id) and ``name``.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = verify_agent_token(credentials.credentials)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    _verify_token_version(payload, db)
    return payload


def optional_agent(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    db: Session = Depends(get_db),
) -> Optional[dict]:
    """Like require_agent but returns None when no token is provided.

    Use for read-only endpoints that should work without auth but can
    accept a token for richer results.
    """
    if credentials is None:
        return None
    try:
        payload = verify_agent_token(credentials.credentials)
    except Exception:
        logger.warning("Rejected invalid/expired token on optional-auth endpoint")
        return None
    try:
        _verify_token_version(payload, db)
    except HTTPException:
        logger.warning("Rejected revoked token on optional-auth endpoint")
        return None
    return payload


def enforce_identity(token: dict, agent_id: str) -> None:
    """Ensure the JWT belongs to the agent making the request.

    CLI-admin tokens (type='cli') are allowed to access any agent,
    enabling management operations like permissions inspection.
    Raises 403 if the token subject doesn't match the agent_id.
    """
    if token.get("type") == "cli":
        return  # admin bypass
    token_sub = token.get("sub")
    if not token_sub or token_sub != agent_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Token subject '{token_sub}' does not match agent_id '{agent_id}'",
        )


# Admin types allowed to manage policies when LEASH_POLICY_REQUIRE_ADMIN=true
ADMIN_TYPES = frozenset({"cli", "admin", "ops"})
_ADMIN_TYPES = ADMIN_TYPES  # backwards-compatible alias

ADMIN_KEY_HEADER = "X-Leash-Admin-Key"


def is_admin_type(agent_type: Optional[str]) -> bool:
    return (agent_type or "").lower() in ADMIN_TYPES


def is_admin(payload: Optional[dict]) -> bool:
    """True if a decoded JWT payload carries an admin-class agent type."""
    return bool(payload) and is_admin_type(payload.get("type"))


def has_admin_key(request: Request) -> bool:
    """True if the request carries a valid ``X-Leash-Admin-Key`` header."""
    return verify_admin_key(request.headers.get(ADMIN_KEY_HEADER))


def require_policy_admin(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    db: Session = Depends(get_db),
) -> dict:
    """Like require_agent but enforces admin privileges when configured.

    When LEASH_POLICY_REQUIRE_ADMIN is enabled (the default), only tokens
    with an admin-class type (cli, admin, ops) can manage policies.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = verify_agent_token(credentials.credentials)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    _verify_token_version(payload, db)

    from app.core.config import POLICY_REQUIRE_ADMIN
    if POLICY_REQUIRE_ADMIN:
        agent_type = payload.get("type", "")
        if not is_admin_type(agent_type):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Policy management requires admin privileges "
                    f"(agent_type must be one of {sorted(_ADMIN_TYPES)})"
                ),
            )

    return payload
