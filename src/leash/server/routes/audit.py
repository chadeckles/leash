"""Routes for the Audit Log Service."""

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from leash.server.core.auth import enforce_identity, optional_agent, require_agent
from leash.server.core.database import get_db
from leash.server.core.metrics import METRICS
from leash.server.audit import service
from leash.server.audit.schemas import (
    AuditCreateRequest,
    AuditEntryResponse,
    AuditListResponse,
    AuditScanRequest,
    AuditScanResponse,
    AuditSummaryResponse,
    ChainDetectionRequest,
    ChainDetectionResponse,
)

router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("/summary", response_model=AuditSummaryResponse)
def audit_summary(
    db: Session = Depends(get_db),
    _token: Optional[dict] = Depends(optional_agent),
):
    """Return aggregate stats across the audit log.

    When LEASH_REQUIRE_AUTH_READ=true, a valid JWT is required.
    """
    from leash.server.core.config import REQUIRE_AUTH_READ
    if REQUIRE_AUTH_READ and _token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required (LEASH_REQUIRE_AUTH_READ=true)",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return service.get_audit_summary(db)


def _parse_since(since: str) -> datetime:
    """Parse a 'since' value — either an ISO-8601 timestamp or a duration like '24h', '7d', '30m'."""
    if not since:
        raise ValueError("empty since value")

    # Try ISO-8601 first
    try:
        return datetime.fromisoformat(since.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        pass

    # Try duration shorthand: 24h, 7d, 30m, 1h30m
    import re
    total_seconds = 0
    pattern = re.compile(r"(\d+)\s*([hHdDmM])")
    matches = pattern.findall(since)
    if not matches:
        raise ValueError(f"Cannot parse 'since' value: {since!r}")

    for value, unit in matches:
        n = int(value)
        if unit.lower() == "h":
            total_seconds += n * 3600
        elif unit.lower() == "d":
            total_seconds += n * 86400
        elif unit.lower() == "m":
            total_seconds += n * 60

    return datetime.now(timezone.utc) - timedelta(seconds=total_seconds)


@router.get("/export", response_class=PlainTextResponse)
def export_audit(
    format: str = Query("jsonl", description="Export format (only 'jsonl' supported)"),
    since: Optional[str] = Query(None, description="ISO-8601 timestamp or duration (e.g. '24h', '7d', '30m')"),
    agent_id: Optional[str] = Query(None, description="Filter by agent ID"),
    decision: Optional[str] = Query(None, description="Filter by decision (allow|deny|observe_deny)"),
    action: Optional[str] = Query(None, description="Filter by action name"),
    limit: int = Query(10000, ge=1, le=100000, description="Max entries to export"),
    db: Session = Depends(get_db),
    _token: Optional[dict] = Depends(optional_agent),
):
    """Export audit log entries as JSONL (one JSON object per line).

    Each line is a self-contained event including the cryptographic
    signature and hash-chain reference, so tamper-evidence travels
    with the data.

    When LEASH_REQUIRE_AUTH_READ=true, a valid JWT is required.
    """
    from leash.server.core.config import REQUIRE_AUTH_READ
    if REQUIRE_AUTH_READ and _token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required for audit export (LEASH_REQUIRE_AUTH_READ=true)",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if format != "jsonl":
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported format '{format}'. Only 'jsonl' is supported.",
        )

    since_dt = None
    if since:
        try:
            since_dt = _parse_since(since)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    entries = service.export_audit_entries(
        db,
        since=since_dt,
        agent_id=agent_id,
        decision=decision,
        action=action,
        limit=limit,
    )

    lines = [entry.model_dump_json() for entry in entries]
    return PlainTextResponse(
        content="\n".join(lines) + ("\n" if lines else ""),
        media_type="application/x-ndjson",
    )


@router.post("/scan", response_model=AuditScanResponse)
def audit_scan(
    body: AuditScanRequest = AuditScanRequest(),
    db: Session = Depends(get_db),
    _token: Optional[dict] = Depends(optional_agent),
):
    """Run a multi-check security scan on the audit log.

    Checks: hash-chain integrity, suspicious action chains, deny storms,
    observe-mode shadow denials, and permission gap analysis.
    Returns findings with severity levels.

    When LEASH_REQUIRE_AUTH_READ=true, a valid JWT is required.
    """
    from leash.server.core.config import REQUIRE_AUTH_READ
    if REQUIRE_AUTH_READ and _token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required (LEASH_REQUIRE_AUTH_READ=true)",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return service.run_audit_scan(db, body)


@router.post("/chains", response_model=ChainDetectionResponse)
def detect_chains(
    body: ChainDetectionRequest,
    db: Session = Depends(get_db),
    _token: Optional[dict] = Depends(optional_agent),
):
    """Scan the audit log for suspicious multi-step action chains.

    Detects patterns like read→send (data exfiltration) or list→delete
    (destructive recon). Uses built-in patterns by default, or pass custom
    patterns in the request body.

    Maps to OWASP ASI02 (Tool Misuse) and ASI09 (Human-Agent Trust).

    When LEASH_REQUIRE_AUTH_READ=true, a valid JWT is required.
    """
    from leash.server.core.config import REQUIRE_AUTH_READ
    if REQUIRE_AUTH_READ and _token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required (LEASH_REQUIRE_AUTH_READ=true)",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return service.detect_chains(db, body)


@router.post("", response_model=AuditEntryResponse, status_code=201)
def create_audit_entry(
    body: AuditCreateRequest,
    db: Session = Depends(get_db),
    _token: dict = Depends(require_agent),
):
    """Append a signed entry to the audit log (requires valid JWT)."""
    enforce_identity(_token, body.agent_id)
    METRICS.inc("audit_entries_total")
    return service.create_audit_entry(db, body)


@router.get("", response_model=AuditListResponse)
def list_audit_entries(
    agent_id: Optional[str] = Query(None, description="Filter by agent ID"),
    decision: Optional[str] = Query(None, description="Filter by decision (allow|deny)"),
    action: Optional[str] = Query(None, description="Filter by action name"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(50, ge=1, le=200, description="Page size"),
    db: Session = Depends(get_db),
    _token: Optional[dict] = Depends(optional_agent),
):
    """Retrieve audit log entries with optional filters and pagination."""
    return service.get_audit_entries(
        db, agent_id=agent_id, decision=decision, action=action,
        offset=offset, limit=limit,
    )
