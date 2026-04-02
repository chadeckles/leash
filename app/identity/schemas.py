"""Pydantic schemas for the Identity Service."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


# ── Requests ──────────────────────────────────────────────────────────────────

class AgentCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=256, description="Human-readable agent name")
    vendor: Optional[str] = Field(None, max_length=128, description="Vendor / provider (e.g. github, anthropic, openai)")
    agent_type: Optional[str] = Field(None, max_length=128, description="Agent type (e.g. coding, research, ops)")
    description: Optional[str] = Field(None, description="Free-text description of the agent's purpose")
    tags: Optional[List[str]] = Field(None, description="Arbitrary labels for grouping (e.g. production, backend-team)")


class AgentUpdateRequest(BaseModel):
    """PATCH body – every field optional, only supplied fields are updated."""
    name: Optional[str] = Field(None, min_length=1, max_length=256)
    vendor: Optional[str] = Field(None, max_length=128)
    agent_type: Optional[str] = Field(None, max_length=128)
    description: Optional[str] = None
    tags: Optional[List[str]] = None


# ── Responses ─────────────────────────────────────────────────────────────────

class AgentResponse(BaseModel):
    agent_id: str
    name: str
    vendor: Optional[str] = None
    agent_type: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    public_key: str
    created_at: datetime
    updated_at: datetime
    last_seen_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class AgentSummaryResponse(BaseModel):
    """Lightweight agent info for fleet listings (no public key)."""
    agent_id: str
    name: str
    vendor: Optional[str] = None
    agent_type: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    created_at: datetime
    last_seen_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class AgentListResponse(BaseModel):
    """Paginated list of agents."""
    agents: List[AgentSummaryResponse]
    total: int


class AgentTokenResponse(BaseModel):
    agent_id: str
    name: str
    vendor: Optional[str] = None
    agent_type: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    token: str
    public_key: str
    created_at: datetime


class KeyRotationResponse(BaseModel):
    agent_id: str
    new_public_key: str
    token: str
    rotated_at: datetime


# ── Per-Agent Stats ───────────────────────────────────────────────────────────────

class ActionCount(BaseModel):
    action: str
    count: int
    decision: str


class RecentAction(BaseModel):
    action: str
    policy_decision: str
    timestamp: datetime


class AgentStatsResponse(BaseModel):
    """Operational dashboard for a single agent."""
    agent_id: str
    name: str
    total_actions: int
    allowed_actions: int
    denied_actions: int
    deny_rate: float
    action_breakdown: List[ActionCount]
    recent_actions: List[RecentAction]
    last_seen_at: Optional[datetime] = None
