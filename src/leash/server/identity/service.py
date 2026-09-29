"""Identity Service – agent registration, retrieval, and key rotation."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.orm import Session

from leash.server.core.security import create_agent_token, generate_rsa_keypair
from leash.server.models.agent import Agent
from leash.server.identity.schemas import (
    ActionCount,
    AgentListResponse,
    AgentStatsResponse,
    AgentSummaryResponse,
    AgentTokenResponse,
    AgentResponse,
    AgentUpdateRequest,
    KeyRotationResponse,
    RecentAction,
)


def _tags_list(agent: Agent) -> list:
    """Safely return the tags list for an agent."""
    return agent.get_tags()


def get_or_create_agent(
    db: Session,
    name: str,
    vendor: Optional[str] = None,
    agent_type: Optional[str] = None,
    description: Optional[str] = None,
    tags: Optional[List[str]] = None,
) -> tuple:
    """Return (AgentTokenResponse, created: bool).

    If an agent with this exact name already exists, rotate its keys and
    return a fresh token rather than creating a duplicate.
    """
    existing = db.query(Agent).filter(Agent.name == name).first()
    if existing is not None:
        result = rotate_keys(db, existing.id)
        return result, False
    return create_agent(db, name, vendor=vendor, agent_type=agent_type,
                        description=description, tags=tags), True


def delete_agent(db: Session, agent_id: str) -> bool:
    """Delete an agent by ID. Returns True if found and deleted."""
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if agent is None:
        return False
    db.delete(agent)
    db.commit()
    return True


def create_agent(
    db: Session,
    name: str,
    vendor: Optional[str] = None,
    agent_type: Optional[str] = None,
    description: Optional[str] = None,
    tags: Optional[List[str]] = None,
) -> AgentTokenResponse:
    """Register a new agent, generate its key-pair, and return a signed JWT."""
    # Check for duplicate name
    existing = db.query(Agent).filter(Agent.name == name).first()
    if existing:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=409,
            detail=f"Agent with name '{name}' already exists (id: {existing.id}). "
                   f"Use a different name or delete the existing agent first.",
        )

    agent_id = str(uuid.uuid4())
    private_pem, public_pem = generate_rsa_keypair()

    agent = Agent(
        id=agent_id,
        name=name,
        vendor=vendor,
        agent_type=agent_type,
        description=description,
        public_key=public_pem.decode(),
        token_version=1,
    )
    agent.set_tags(tags or [])
    db.add(agent)
    db.commit()
    db.refresh(agent)

    token = create_agent_token(agent_id, name, agent_type=agent_type or "", token_version=1)

    return AgentTokenResponse(
        agent_id=agent_id,
        name=name,
        vendor=vendor,
        agent_type=agent_type,
        tags=agent.get_tags(),
        token=token,
        public_key=public_pem.decode(),
        created_at=agent.created_at,
    )


def list_agents(
    db: Session,
    offset: int = 0,
    limit: int = 50,
    vendor: Optional[str] = None,
    agent_type: Optional[str] = None,
    tag: Optional[str] = None,
) -> AgentListResponse:
    """Return a paginated, optionally filtered list of agents."""
    query = db.query(Agent)

    if vendor:
        query = query.filter(Agent.vendor == vendor)
    if agent_type:
        query = query.filter(Agent.agent_type == agent_type)
    if tag:
        # JSON-contains search – works with SQLite's LIKE on the JSON string
        query = query.filter(Agent.tags.like(f'%"{tag}"%'))

    total = query.count()
    agents = (
        query
        .order_by(Agent.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return AgentListResponse(
        agents=[
            AgentSummaryResponse(
                agent_id=a.id,
                name=a.name,
                vendor=a.vendor,
                agent_type=a.agent_type,
                tags=_tags_list(a),
                created_at=a.created_at,
                last_seen_at=a.last_seen_at,
            )
            for a in agents
        ],
        total=total,
    )


def get_agent(db: Session, agent_id: str) -> Optional[AgentResponse]:
    """Return agent metadata (without private key)."""
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if agent is None:
        return None
    return AgentResponse(
        agent_id=agent.id,
        name=agent.name,
        vendor=agent.vendor,
        agent_type=agent.agent_type,
        description=agent.description,
        tags=_tags_list(agent),
        public_key=agent.public_key,
        created_at=agent.created_at,
        updated_at=agent.updated_at,
        last_seen_at=agent.last_seen_at,
    )


def update_agent(
    db: Session, agent_id: str, body: AgentUpdateRequest,
) -> Optional[AgentResponse]:
    """Partially update agent metadata. Returns None if not found."""
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if agent is None:
        return None

    update_data = body.model_dump(exclude_unset=True)
    # Guard: only allow updating fields explicitly declared in the update schema.
    _SAFE_UPDATE_FIELDS = {"name", "vendor", "agent_type", "description", "tags"}
    for field, value in update_data.items():
        if field not in _SAFE_UPDATE_FIELDS:
            continue
        if field == "tags":
            agent.set_tags(value)
        else:
            setattr(agent, field, value)

    agent.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(agent)
    return get_agent(db, agent_id)


def touch_agent(db: Session, agent_id: str) -> None:
    """Update last_seen_at for an agent (called on every /authorize)."""
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if agent is not None:
        agent.last_seen_at = datetime.now(timezone.utc)
        db.commit()


def rotate_keys(db: Session, agent_id: str) -> Optional[KeyRotationResponse]:
    """Generate a fresh key-pair for the agent and return a new JWT."""
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if agent is None:
        return None

    private_pem, public_pem = generate_rsa_keypair()
    agent.public_key = public_pem.decode()
    agent.token_version = (agent.token_version or 0) + 1
    agent.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(agent)

    token = create_agent_token(
        agent_id, agent.name,
        agent_type=agent.agent_type or "",
        token_version=agent.token_version or 1,
    )

    return KeyRotationResponse(
        agent_id=agent_id,
        new_public_key=public_pem.decode(),
        token=token,
        rotated_at=agent.updated_at,
    )


def get_agent_stats(
    db: Session, agent_id: str, recent_n: int = 10,
) -> Optional[AgentStatsResponse]:
    """Return operational stats for a single agent."""
    from sqlalchemy import func
    from leash.server.models.audit import AuditEntry

    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if agent is None:
        return None

    # Totals
    total = (
        db.query(func.count(AuditEntry.id))
        .filter(AuditEntry.agent_id == agent_id)
        .scalar() or 0
    )
    allowed = (
        db.query(func.count(AuditEntry.id))
        .filter(AuditEntry.agent_id == agent_id, AuditEntry.policy_decision == "allow")
        .scalar() or 0
    )
    denied = total - allowed
    deny_rate = round(denied / total, 4) if total > 0 else 0.0

    # Per-action breakdown
    breakdown_rows = (
        db.query(AuditEntry.action, AuditEntry.policy_decision, func.count(AuditEntry.id))
        .filter(AuditEntry.agent_id == agent_id)
        .group_by(AuditEntry.action, AuditEntry.policy_decision)
        .all()
    )
    action_breakdown = [
        ActionCount(action=a, decision=d, count=c)
        for a, d, c in breakdown_rows
    ]

    # Recent actions
    recent_rows = (
        db.query(AuditEntry.action, AuditEntry.policy_decision, AuditEntry.timestamp)
        .filter(AuditEntry.agent_id == agent_id)
        .order_by(AuditEntry.timestamp.desc())
        .limit(recent_n)
        .all()
    )
    recent_actions = [
        RecentAction(action=a, policy_decision=d, timestamp=t)
        for a, d, t in recent_rows
    ]

    return AgentStatsResponse(
        agent_id=agent_id,
        name=agent.name,
        total_actions=total,
        allowed_actions=allowed,
        denied_actions=denied,
        deny_rate=deny_rate,
        action_breakdown=action_breakdown,
        recent_actions=recent_actions,
        last_seen_at=agent.last_seen_at,
    )
