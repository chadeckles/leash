"""Routes for managed policy CRUD (inlined service logic)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.auth import require_policy_admin
from app.core.config import MAX_POLICY_PRIORITY
from app.core.database import get_db
from app.models.policy import Policy
from app.policy.engine import _load_all_policies
from app.policy.schemas import (
    PolicyCreateRequest,
    PolicyListResponse,
    PolicyResponse,
    PolicyUpdateRequest,
)
from app.policy.validator import validate_policy

import yaml as _yaml

router = APIRouter(prefix="/policies/managed", tags=["Policy Management"])


# ── Overview (unauthenticated, read-only) ────────────────────────────────────

class PolicyOverviewItem(BaseModel):
    name: str
    priority: int
    agents: List[str]
    source: str          # "yaml" or "db"
    allow_count: int
    deny_count: int
    description: Optional[str] = None


class PolicyOverviewResponse(BaseModel):
    policies: List[PolicyOverviewItem]


# Mount this at /policies/overview (outside the /policies/managed prefix)
overview_router = APIRouter(tags=["Policy Management"])


@overview_router.get("/policies/overview", response_model=PolicyOverviewResponse)
def policies_overview(db: Session = Depends(get_db)):
    """Return a lightweight summary of all active policies (YAML + managed).

    When LEASH_REQUIRE_AUTH_READ=true, this endpoint is disabled and
    returns 403.  The dashboard should use authenticated API calls instead.
    """
    from app.core.config import REQUIRE_AUTH_READ
    if REQUIRE_AUTH_READ:
        raise HTTPException(
            status_code=403,
            detail="Policy overview disabled (LEASH_REQUIRE_AUTH_READ=true) — use authenticated API",
        )

    all_policies = _load_all_policies(db)
    items = []
    for p in all_policies:
        rules = p.get("rules", [])
        allow_count = sum(1 for r in rules if r.get("effect") == "allow")
        deny_count = sum(1 for r in rules if r.get("effect") != "allow")
        agents_field = p.get("agents", ["*"])
        if isinstance(agents_field, str):
            agents_field = [agents_field]
        items.append(PolicyOverviewItem(
            name=p.get("name", "unnamed"),
            priority=p.get("priority", 0),
            agents=agents_field,
            source=p.get("_source", "yaml"),
            allow_count=allow_count,
            deny_count=deny_count,
            description=p.get("description"),
        ))
    return PolicyOverviewResponse(policies=items)


def _to_response(p: Policy) -> PolicyResponse:
    return PolicyResponse(
        id=p.id, name=p.name, description=p.description, priority=p.priority,
        yaml_content=p.yaml_content, active=p.active,
        created_at=p.created_at, updated_at=p.updated_at,
    )


@router.post("", response_model=PolicyResponse, status_code=201)
def create_policy(
    body: PolicyCreateRequest,
    db: Session = Depends(get_db),
    _token: dict = Depends(require_policy_admin),
):
    if body.priority > MAX_POLICY_PRIORITY:
        raise HTTPException(
            status_code=422,
            detail=f"Priority {body.priority} exceeds maximum allowed ({MAX_POLICY_PRIORITY})",
        )
    # Validate the YAML content before persisting.
    # In the managed-policy API, 'name' comes from the request body, not the YAML,
    # so we parse first, inject the API-level name, then validate the merged doc.
    try:
        parsed = _yaml.safe_load(body.yaml_content)
    except _yaml.YAMLError as exc:
        raise HTTPException(
            status_code=422,
            detail={"message": "Invalid policy YAML", "errors": [f"YAML parse error: {exc}"]},
        )
    if not parsed or not isinstance(parsed, dict):
        raise HTTPException(
            status_code=422,
            detail={"message": "Invalid policy YAML", "errors": ["Empty or non-mapping YAML document"]},
        )
    parsed.setdefault("name", body.name)
    yaml_errors = validate_policy(parsed)
    if yaml_errors:
        raise HTTPException(
            status_code=422,
            detail={"message": "Invalid policy YAML", "errors": yaml_errors},
        )
    existing = db.query(Policy).filter(Policy.name == body.name).first()
    if existing is not None:
        raise HTTPException(status_code=409, detail=f"Policy '{body.name}' already exists")
    policy = Policy(
        name=body.name, description=body.description, priority=body.priority,
        yaml_content=body.yaml_content, active=body.active,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return _to_response(policy)


@router.get("", response_model=PolicyListResponse)
def list_policies(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    active_only: bool = Query(False),
    db: Session = Depends(get_db),
    _token: dict = Depends(require_policy_admin),
):
    query = db.query(Policy)
    if active_only:
        query = query.filter(Policy.active.is_(True))
    total = query.count()
    policies = query.order_by(Policy.priority.desc(), Policy.name).offset(offset).limit(limit).all()
    return PolicyListResponse(policies=[_to_response(p) for p in policies], total=total)


@router.get("/{policy_id}", response_model=PolicyResponse)
def get_policy(policy_id: int, db: Session = Depends(get_db), _token: dict = Depends(require_policy_admin)):
    p = db.query(Policy).filter(Policy.id == policy_id).first()
    if p is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return _to_response(p)


@router.patch("/{policy_id}", response_model=PolicyResponse)
def update_policy(
    policy_id: int, body: PolicyUpdateRequest,
    db: Session = Depends(get_db), _token: dict = Depends(require_policy_admin),
):
    p = db.query(Policy).filter(Policy.id == policy_id).first()
    if p is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    update_data = body.model_dump(exclude_unset=True)
    if "priority" in update_data and update_data["priority"] > MAX_POLICY_PRIORITY:
        raise HTTPException(
            status_code=422,
            detail=f"Priority {update_data['priority']} exceeds maximum allowed ({MAX_POLICY_PRIORITY})",
        )
    if "yaml_content" in update_data:
        try:
            parsed = _yaml.safe_load(update_data["yaml_content"])
        except _yaml.YAMLError as exc:
            raise HTTPException(
                status_code=422,
                detail={"message": "Invalid policy YAML", "errors": [f"YAML parse error: {exc}"]},
            )
        if not parsed or not isinstance(parsed, dict):
            raise HTTPException(
                status_code=422,
                detail={"message": "Invalid policy YAML", "errors": ["Empty or non-mapping YAML document"]},
            )
        parsed.setdefault("name", p.name)
        yaml_errors = validate_policy(parsed)
        if yaml_errors:
            raise HTTPException(
                status_code=422,
                detail={"message": "Invalid policy YAML", "errors": yaml_errors},
            )
    for field, value in update_data.items():
        setattr(p, field, value)
    p.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(p)
    return _to_response(p)


@router.delete("/{policy_id}", status_code=204)
def delete_policy(policy_id: int, db: Session = Depends(get_db), _token: dict = Depends(require_policy_admin)):
    p = db.query(Policy).filter(Policy.id == policy_id).first()
    if p is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    db.delete(p)
    db.commit()
    return None
