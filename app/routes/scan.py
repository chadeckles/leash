"""Routes for the security surface scanner."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.auth import require_agent
from app.core.database import get_db

router = APIRouter(prefix="/scan", tags=["Security Scanner"])


# ── Request / Response schemas ───────────────────────────────────────────

class ToolManifest(BaseModel):
    """A single MCP tool as returned by tools/list."""
    name: str
    description: str = ""
    inputSchema: Optional[Dict[str, Any]] = None


class ScanRequest(BaseModel):
    """Request body for POST /scan."""
    tools: List[ToolManifest] = Field(..., min_length=1)
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None


class ToolRiskResponse(BaseModel):
    name: str
    description: str
    risk: str
    categories: List[str]
    risk_reason: str
    has_policy_coverage: bool
    matching_policies: List[str]


class ScanResponse(BaseModel):
    target: str
    tools_discovered: int
    policy_coverage: float
    covered_count: int
    uncovered_count: int
    high_risk: List[ToolRiskResponse]
    medium_risk: List[ToolRiskResponse]
    low_risk: List[ToolRiskResponse]
    unknown_risk: List[ToolRiskResponse]
    tools: List[ToolRiskResponse]


class GeneratePolicyRequest(BaseModel):
    """Request body for POST /scan/generate-policy."""
    tools: List[ToolManifest] = Field(..., min_length=1)
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    policy_name: str = "auto-scan-policy"
    agent_pattern: str = '"*"'


class GeneratePolicyResponse(BaseModel):
    policy_yaml: str
    tools_discovered: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int


# ── Endpoints ────────────────────────────────────────────────────────────

@router.post("", response_model=ScanResponse)
def scan_tools(
    body: ScanRequest,
    _payload: dict = Depends(require_agent),
    db: Session = Depends(get_db),
):
    """Classify a set of MCP tools by risk and check policy coverage.

    Accepts a list of tool manifests (as returned by MCP ``tools/list``)
    and returns risk classification + policy gap analysis.
    """
    from sdk.scanner import classify_tools, analyze_policy_coverage

    tool_dicts = [t.model_dump() for t in body.tools]
    classified = classify_tools(tool_dicts)
    scan = analyze_policy_coverage(
        classified,
        agent_id=body.agent_id or "",
        agent_name=body.agent_name or "",
        db=db,
    )

    def _to_response(t) -> dict:
        return {
            "name": t.name,
            "description": t.description,
            "risk": t.risk,
            "categories": t.categories,
            "risk_reason": t.risk_reason,
            "has_policy_coverage": t.has_policy_coverage,
            "matching_policies": t.matching_policies,
        }

    return ScanResponse(
        target=scan.target,
        tools_discovered=scan.tools_discovered,
        policy_coverage=round(scan.policy_coverage * 100, 1),
        covered_count=scan.covered_count,
        uncovered_count=scan.uncovered_count,
        high_risk=[_to_response(t) for t in scan.high_risk],
        medium_risk=[_to_response(t) for t in scan.medium_risk],
        low_risk=[_to_response(t) for t in scan.low_risk],
        unknown_risk=[_to_response(t) for t in scan.unknown_risk],
        tools=[_to_response(t) for t in scan.tools],
    )


@router.post("/generate-policy", response_model=GeneratePolicyResponse)
def scan_generate_policy(
    body: GeneratePolicyRequest,
    _payload: dict = Depends(require_agent),
    db: Session = Depends(get_db),
):
    """Classify tools and generate a starter YAML policy.

    Returns the generated policy YAML along with risk statistics.
    """
    from sdk.scanner import classify_tools, analyze_policy_coverage, generate_policy

    tool_dicts = [t.model_dump() for t in body.tools]
    classified = classify_tools(tool_dicts)
    scan = analyze_policy_coverage(
        classified,
        agent_id=body.agent_id or "",
        agent_name=body.agent_name or "",
        db=db,
    )
    scan.target = "API request"

    policy_yaml = generate_policy(
        scan,
        policy_name=body.policy_name,
        agent_pattern=body.agent_pattern,
    )

    return GeneratePolicyResponse(
        policy_yaml=policy_yaml,
        tools_discovered=scan.tools_discovered,
        high_risk_count=len(scan.high_risk),
        medium_risk_count=len(scan.medium_risk),
        low_risk_count=len(scan.low_risk),
    )
