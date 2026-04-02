"""Pydantic schemas for the Policy Engine."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AuthorizeRequest(BaseModel):
    agent_id: str = Field(..., description="Agent requesting authorization")
    action: str = Field(..., description="Action the agent wants to perform")
    resource: str = Field("", description="Optional resource identifier")
    context: Optional[Dict[str, Any]] = Field(
        None,
        description=(
            "Optional ABAC context — arbitrary key/value pairs that policy "
            "conditions can match against (e.g. user_role, department, "
            "time_of_day). Addresses OWASP LLM06-5: execute in user context."
        ),
    )


class AuthorizeResponse(BaseModel):
    agent_id: str
    action: str
    decision: str  # "allow" | "deny" | "observed_deny"
    reason: str
    matched_policy: Optional[str] = Field(
        None,
        description="Name of the policy that produced this decision",
    )
    matched_rule: Optional[str] = Field(
        None,
        description="The action pattern of the rule that matched (e.g. 'email.*')",
    )
    signature: str
    owasp: Optional[List[str]] = Field(
        None,
        description="OWASP LLM Top 10 categories this decision relates to",
    )
    observation: Optional[str] = Field(
        None,
        description=(
            "Present when an observe-mode policy would have denied this action. "
            "The action was allowed, but this field records what would have "
            "happened under enforcement."
        ),
    )


class PolicyInfo(BaseModel):
    agent_id: str
    policies: List[Dict]


# ── Effective Permissions ───────────────────────────────────────────────────────

class EffectivePermission(BaseModel):
    """One rule from an agent's effective permission set."""
    action: str = Field(..., description="Action pattern (e.g. 'email.*')")
    effect: str = Field(..., description="'allow' or 'deny'")
    reason: str = Field("", description="Why this rule exists")
    resource: str = Field("", description="Resource scope (blank = any)")
    policy_name: str = Field(..., description="Which policy this rule comes from")
    policy_priority: int = Field(0, description="Priority of the source policy")
    has_conditions: bool = Field(False, description="Whether the rule requires ABAC conditions")
    has_rate_limit: bool = Field(False, description="Whether the rule has a rate limit")
    mode: str = Field("enforce", description="'enforce' or 'observe' — observe-mode rules log but never block")
    owasp: Optional[List[str]] = None


class EffectivePermissionsResponse(BaseModel):
    """Complete view of what an agent can and cannot do right now."""
    agent_id: str
    permissions: List[EffectivePermission]
    total_rules: int
    allowed_actions: int = Field(..., description="Count of allow rules")
    denied_actions: int = Field(..., description="Count of deny rules")
    observed_rules: int = Field(0, description="Count of rules in observe-only mode")


# ── Dry-Run ──────────────────────────────────────────────────────────────────

class DryRunAction(BaseModel):
    action: str = Field(..., description="Action to test")
    resource: str = Field("", description="Optional resource")
    context: Optional[Dict[str, Any]] = Field(None, description="Optional ABAC context")


class DryRunRequest(BaseModel):
    policy_yaml: str = Field(..., description="Raw YAML policy content to evaluate")
    agent_id: str = Field(..., description="Agent ID to test against")
    actions: List[DryRunAction] = Field(..., description="Actions to evaluate")


class DryRunResult(BaseModel):
    action: str
    resource: str
    decision: str
    reason: str
    matched_policy: Optional[str] = None
    owasp: Optional[List[str]] = None
    observation: Optional[str] = None


class DryRunResponse(BaseModel):
    agent_id: str
    results: List[DryRunResult]
    summary: str


# ── CRUD Policy Management ───────────────────────────────────────────────────

class PolicyCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=256, description="Unique policy name")
    description: Optional[str] = Field(None, description="Human-readable description")
    priority: int = Field(0, ge=0, description="Higher priority = evaluated first")
    yaml_content: str = Field(..., description="Full YAML policy body (rules, agents, etc.)")
    active: bool = Field(True, description="Whether the policy is enforced")


class PolicyUpdateRequest(BaseModel):
    """PATCH body – only supplied fields are updated."""
    name: Optional[str] = Field(None, min_length=1, max_length=256)
    description: Optional[str] = None
    priority: Optional[int] = Field(None, ge=0)
    yaml_content: Optional[str] = None
    active: Optional[bool] = None


class PolicyResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    priority: int
    yaml_content: str
    active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class PolicyListResponse(BaseModel):
    policies: List[PolicyResponse]
    total: int
