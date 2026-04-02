"""FastAPI dependency for JWT-based authentication."""

from __future__ import annotations

from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

import logging

from app.core.security import verify_agent_token

logger = logging.getLogger("leash.auth")

_bearer_scheme = HTTPBearer(auto_error=False)


def _verify_token_version(payload: dict) -> None:
    """Check that the JWT's token_version matches the current DB value.

    This enables server-side revocation: rotating keys bumps the version
    and all previously-issued JWTs become invalid.  Skipped for CLI
    admin tokens (they have no agent row) and when there is no DB access.
    """
    token_version = payload.get("tv")
    if token_version is None:
        return  # legacy tokens without version claim — allow (backwards compat)

    agent_id = payload.get("sub")
    if not agent_id:
        return

    try:
        from app.core.database import SessionLocal
        from app.models.agent import Agent

        db = SessionLocal()
        try:
            agent = db.query(Agent).filter(Agent.id == agent_id).first()
            if agent and agent.token_version is not None:
                if token_version != agent.token_version:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Token has been revoked (key rotation occurred)",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
        finally:
            db.close()
    except HTTPException:
        raise
    except Exception:
        pass  # fail open on DB errors — don't break auth if DB is temporarily down


def require_agent(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
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

    _verify_token_version(payload)
    return payload


def optional_agent(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
) -> Optional[dict]:
    """Like require_agent but returns None when no token is provided.

    Use for read-only endpoints that should work without auth but can
    accept a token for richer results.
    """
    if credentials is None:
        return None
    try:
        return verify_agent_token(credentials.credentials)
    except Exception:
        logger.warning("Rejected invalid/expired token on optional-auth endpoint")
        return None


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
_ADMIN_TYPES = {"cli", "admin", "ops"}


def require_policy_admin(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
) -> dict:
    """Like require_agent but enforces admin privileges when configured.

    When LEASH_POLICY_REQUIRE_ADMIN=true, only agents with an admin-class
    type (cli, admin, ops) or 'admin' in their name can manage policies.
    Permissive by default for single-user deployments.
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

    from app.core.config import POLICY_REQUIRE_ADMIN
    if POLICY_REQUIRE_ADMIN:
        agent_type = payload.get("type", "")
        if agent_type not in _ADMIN_TYPES:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Policy management requires admin privileges "
                    f"(agent_type must be one of {sorted(_ADMIN_TYPES)})"
                ),
            )

    return payload
