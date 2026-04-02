"""Routes for the Policy Engine."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.auth import enforce_identity, require_agent
from app.core.database import get_db
from app.core.metrics import METRICS
from app.identity.service import touch_agent
from app.policy.engine import evaluate, get_policies_for_agent, get_effective_permissions, dry_run
from app.policy.schemas import (
    AuthorizeRequest,
    AuthorizeResponse,
    DryRunRequest,
    DryRunResponse,
    EffectivePermissionsResponse,
    PolicyInfo,
)
from app.audit.service import log_authorize_decision

router = APIRouter(tags=["Policy"])


@router.post("/authorize", response_model=AuthorizeResponse)
def authorize(
    body: AuthorizeRequest,
    db: Session = Depends(get_db),
    _token: dict = Depends(require_agent),
):
    """Evaluate whether an agent is allowed to perform an action (requires valid JWT)."""
    enforce_identity(_token, body.agent_id)
    # Track agent activity
    touch_agent(db, body.agent_id)
    result = evaluate(body.agent_id, body.action, body.resource, context=body.context, db=db)
    METRICS.inc("authorize_total", labels={"decision": result.decision})
    # Auto-log to audit trail
    log_authorize_decision(db, body, result)
    return result


@router.get("/policies/{agent_id}", response_model=PolicyInfo)
def get_policies(
    agent_id: str,
    db: Session = Depends(get_db),
    _token: dict = Depends(require_agent),
):
    """Return all policies applicable to a given agent (requires valid JWT)."""
    enforce_identity(_token, agent_id)
    return get_policies_for_agent(agent_id, db=db)


@router.get("/agents/{agent_id}/permissions", response_model=EffectivePermissionsResponse)
def effective_permissions(
    agent_id: str,
    db: Session = Depends(get_db),
    _token: dict = Depends(require_agent),
):
    """Show the effective permission set for an agent.

    Returns every rule that applies to this agent, flattened across all
    matching policies in priority order.  This is a read-only visibility
    endpoint — it answers: \"what can this agent do right now?\"
    """
    enforce_identity(_token, agent_id)
    return get_effective_permissions(agent_id, db=db)


@router.post("/policies/dry-run", response_model=DryRunResponse)
def policy_dry_run(
    body: DryRunRequest,
    db: Session = Depends(get_db),
    _token: dict = Depends(require_agent),
):
    """Evaluate a candidate policy against test actions without deploying it (requires valid JWT)."""
    return dry_run(body, db=db)
