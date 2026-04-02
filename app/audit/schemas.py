"""Pydantic schemas for the Audit Log Service."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AuditCreateRequest(BaseModel):
    agent_id: str
    action: str
    inputs: Optional[Dict[str, Any]] = None
    outputs: Optional[Dict[str, Any]] = None
    policy_decision: str = Field(..., pattern="^(allow|deny|observe_deny)$")


class AuditEntryResponse(BaseModel):
    id: int
    agent_id: str
    timestamp: datetime
    action: str
    inputs: Optional[Dict[str, Any]] = None
    outputs: Optional[Dict[str, Any]] = None
    policy_decision: str
    signature: str
    prev_hash: Optional[str] = Field(
        None,
        description="SHA-256 hash of the previous audit entry — forms a tamper-evident chain",
    )

    model_config = {"from_attributes": True}


class AuditExportEntry(BaseModel):
    """Flat, self-contained event for JSONL export / webhook delivery.

    Includes the cryptographic signature and hash-chain reference so that
    tamper-evidence travels with the data, not just in the database.
    """
    event_id: int
    timestamp: str = Field(..., description="ISO-8601 UTC timestamp")
    agent_id: str
    action: str
    resource: Optional[str] = None
    decision: str = Field(..., description="allow | deny | observe_deny")
    matched_policy: Optional[str] = None
    reason: Optional[str] = None
    observation: Optional[str] = None
    inputs: Optional[Dict[str, Any]] = None
    outputs: Optional[Dict[str, Any]] = None
    signature: str
    prev_hash: Optional[str] = None
    chain_intact: bool = Field(
        True,
        description="True if this entry's prev_hash matches the hash of its predecessor",
    )

class AuditListResponse(BaseModel):
    """Paginated audit log results."""
    entries: List[AuditEntryResponse]
    total: int
    offset: int
    limit: int

# ── Summary / Stats ──────────────────────────────────────────────────────────

class ActionBreakdown(BaseModel):
    action: str
    count: int
    allowed: int
    denied: int


class AgentActivity(BaseModel):
    agent_id: str
    total_actions: int
    denied_actions: int


class AuditSummaryResponse(BaseModel):
    """High-level operational stats across the entire audit log."""
    total_entries: int
    total_allowed: int
    total_denied: int
    deny_rate: float = Field(..., description="Fraction of actions denied (0.0–1.0)")
    actions: List[ActionBreakdown] = Field(..., description="Per-action breakdown")
    most_active_agents: List[AgentActivity] = Field(
        ..., description="Top agents by action count"
    )
    most_denied_agents: List[AgentActivity] = Field(
        ..., description="Top agents by denial count"
    )


# ── Chain Detection ──────────────────────────────────────────────────────────

class ChainPattern(BaseModel):
    """A suspicious multi-step action pattern to detect."""
    name: str = Field(..., description="Human-readable label for this chain")
    actions: List[str] = Field(
        ..., min_length=2,
        description="Ordered action sequence (glob patterns supported)",
    )
    description: str = ""


class ChainMatch(BaseModel):
    """A detected instance of a suspicious chain."""
    pattern: str = Field(..., description="Name of the matched pattern")
    agent_id: str
    actions: List[str] = Field(..., description="Actual actions that matched")
    timestamps: List[datetime]
    window_seconds: float = Field(
        ..., description="Time between first and last action in the chain",
    )


class ChainDetectionRequest(BaseModel):
    """Request to scan the audit log for suspicious action chains."""
    patterns: Optional[List[ChainPattern]] = Field(
        None,
        description="Custom patterns to detect. If omitted, built-in patterns are used.",
    )
    agent_id: Optional[str] = Field(
        None, description="Limit scan to a specific agent",
    )
    window: int = Field(
        3600, ge=60, le=86400,
        description="Max seconds between first and last action in a chain (default 1h)",
    )
    limit: int = Field(100, ge=1, le=500, description="Max audit entries to scan")


class ChainDetectionResponse(BaseModel):
    """Results of a chain detection scan."""
    matches: List[ChainMatch]
    patterns_checked: int
    entries_scanned: int


# ── Security Scan (multi-check) ─────────────────────────────────────────────

class ScanFinding(BaseModel):
    """A single finding from the audit security scan."""
    check: str = Field(..., description="Check that produced this finding (e.g. 'chain-detection')")
    severity: str = Field(..., pattern="^(critical|high|medium|low|info)$")
    title: str
    detail: str = ""
    agent_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class ScanCheckResult(BaseModel):
    """Result of a single scan check."""
    check: str
    title: str
    status: str = Field(..., pattern="^(pass|warn|fail)$", description="pass=clean, warn=findings, fail=critical")
    findings: List[ScanFinding] = []
    summary: str = ""


class AuditScanRequest(BaseModel):
    """Request to run a full security scan on the audit log."""
    agent_id: Optional[str] = Field(None, description="Limit scan to a specific agent")
    window: int = Field(3600, ge=60, le=86400, description="Time window in seconds for chain/storm detection")
    limit: int = Field(500, ge=1, le=5000, description="Max audit entries to scan")


class AuditScanResponse(BaseModel):
    """Full security scan report across all checks."""
    status: str = Field(..., pattern="^(clean|warnings|critical)$", description="Overall scan status")
    checks_run: int
    total_findings: int
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    entries_scanned: int
    checks: List[ScanCheckResult]
