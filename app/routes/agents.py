"""Routes for the Agent Identity Service."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.core.auth import (
    ADMIN_KEY_HEADER,
    enforce_identity,
    has_admin_key,
    is_admin,
    is_admin_type,
    optional_agent,
    require_agent,
)
from app.core.database import get_db
from app.core.metrics import METRICS
from app.identity import service
from app.identity.schemas import (
    AgentCreateRequest,
    AgentListResponse,
    AgentResponse,
    AgentStatsResponse,
    AgentTokenResponse,
    AgentUpdateRequest,
    KeyRotationResponse,
)

router = APIRouter(prefix="/agents", tags=["Identity"])


@router.post("", response_model=AgentTokenResponse, status_code=201)
def create_agent(
    body: AgentCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    _token: Optional[dict] = Depends(optional_agent),
):
    """Register a new agent and return its signed identity token.

    Admin-type agents (``agent_type`` of cli/admin/ops) can only be
    registered by a caller holding an admin JWT or the ``X-Leash-Admin-Key``
    header.  When LEASH_REQUIRE_AUTH_REGISTER=true, the same admin
    credential is required for *every* registration.
    """
    from app.core.config import REQUIRE_AUTH_REGISTER
    admin_ok = is_admin(_token) or has_admin_key(request)
    if REQUIRE_AUTH_REGISTER and not admin_ok:
        if _token is None and ADMIN_KEY_HEADER.lower() not in request.headers:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Agent registration requires authentication (LEASH_REQUIRE_AUTH_REGISTER=true)",
                headers={"WWW-Authenticate": "Bearer"},
            )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Agent registration requires an admin JWT or the X-Leash-Admin-Key header",
        )
    if is_admin_type(body.agent_type) and not admin_ok:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Registering an admin-type agent ('{body.agent_type}') requires an admin JWT "
                f"or the {ADMIN_KEY_HEADER} header"
            ),
        )
    METRICS.inc("agents_registered_total")
    return service.create_agent(
        db,
        body.name,
        vendor=body.vendor,
        agent_type=body.agent_type,
        description=body.description,
        tags=body.tags,
    )


@router.get("", response_model=AgentListResponse)
def list_agents(
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(50, ge=1, le=200, description="Page size"),
    vendor: Optional[str] = Query(None, description="Filter by vendor (e.g. github, anthropic)"),
    agent_type: Optional[str] = Query(None, description="Filter by agent type (e.g. coding, research)"),
    tag: Optional[str] = Query(None, description="Filter by tag"),
    db: Session = Depends(get_db),
    _token: Optional[dict] = Depends(optional_agent),
):
    """List all registered agents (paginated, filterable). Auth optional."""
    return service.list_agents(
        db, offset=offset, limit=limit,
        vendor=vendor, agent_type=agent_type, tag=tag,
    )


@router.get("/{agent_id}", response_model=AgentResponse)
def get_agent(
    agent_id: str,
    db: Session = Depends(get_db),
    _token: dict = Depends(require_agent),
):
    """Retrieve agent metadata (requires valid JWT, own agent only)."""
    enforce_identity(_token, agent_id)
    agent = service.get_agent(db, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@router.patch("/{agent_id}", response_model=AgentResponse)
def update_agent(
    agent_id: str,
    body: AgentUpdateRequest,
    db: Session = Depends(get_db),
    _token: dict = Depends(require_agent),
):
    """Update agent metadata (vendor, tags, etc.). Requires valid JWT, own agent only.

    Only admins may rename an agent (names drive policy matching) or
    promote it to an admin type (cli/admin/ops).
    """
    enforce_identity(_token, agent_id)
    if body.name is not None and not is_admin(_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can rename an agent (names are used for policy matching)",
        )
    if is_admin_type(body.agent_type) and not is_admin(_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can assign an admin agent_type (cli/admin/ops)",
        )
    result = service.update_agent(db, agent_id, body)
    if result is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return result


@router.get("/{agent_id}/stats", response_model=AgentStatsResponse)
def get_agent_stats(
    agent_id: str,
    db: Session = Depends(get_db),
    _token: dict = Depends(require_agent),
):
    """Return operational stats for a single agent (requires valid JWT, own agent only)."""
    enforce_identity(_token, agent_id)
    stats = service.get_agent_stats(db, agent_id)
    if stats is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return stats


@router.delete("/{agent_id}", status_code=204)
def delete_agent(
    agent_id: str,
    db: Session = Depends(get_db),
    _token: dict = Depends(require_agent),
):
    """Delete an agent (requires valid JWT, own agent only)."""
    enforce_identity(_token, agent_id)
    found = service.delete_agent(db, agent_id)
    if not found:
        raise HTTPException(status_code=404, detail="Agent not found")
    return None


@router.post("/{agent_id}/rotate", response_model=KeyRotationResponse)
def rotate_keys(
    agent_id: str,
    db: Session = Depends(get_db),
    _token: dict = Depends(require_agent),
):
    """Rotate the agent's key-pair and issue a new token (requires valid JWT, own agent only)."""
    enforce_identity(_token, agent_id)
    result = service.rotate_keys(db, agent_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return result
