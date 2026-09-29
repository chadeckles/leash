"""Routes for cryptographic verification."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from leash.server.core.database import get_db
from leash.server.core.security import hash_data, verify_signature
from leash.server.models.audit import AuditEntry

router = APIRouter(tags=["Verification"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class VerifyRequest(BaseModel):
    data: Dict[str, Any] = Field(..., description="The original data dict that was signed")
    signature: str = Field(..., description="Hex-encoded RSA-SHA256 signature to verify")


class VerifyResponse(BaseModel):
    valid: bool = Field(..., description="True if the signature matches the data")


class AuditChainResponse(BaseModel):
    """Result of a full hash-chain integrity check."""
    valid: bool = Field(..., description="True if the entire hash chain is intact")
    entries_checked: int = Field(..., description="Total entries verified")
    broken_at: Optional[int] = Field(None, description="Entry ID where the chain broke (null if valid)")
    detail: str = Field("", description="Human-readable summary")


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/verify", response_model=VerifyResponse)
def verify(body: VerifyRequest):
    """Verify an RSA-SHA256 signature against the server's public key.

    This endpoint is intentionally **unauthenticated** so that any third
    party can verify a signature produced by Leash without needing a JWT.
    """
    valid = verify_signature(body.data, body.signature)
    return VerifyResponse(valid=valid)


@router.get("/verify/audit-chain", response_model=AuditChainResponse)
def verify_audit_chain(db: Session = Depends(get_db)):
    """Verify the integrity of the entire audit hash chain.

    Walks every audit entry in order and recomputes each hash to confirm
    that no entries have been tampered with, modified, or deleted.
    This endpoint is intentionally **unauthenticated** for transparency.
    """
    entries = db.query(AuditEntry).order_by(AuditEntry.id.asc()).all()

    if not entries:
        return AuditChainResponse(
            valid=True,
            entries_checked=0,
            detail="No audit entries to verify.",
        )

    prev_computed_hash: Optional[str] = None
    for entry in entries:
        # If this isn't the first entry, verify the chain link
        if entry.prev_hash is not None and prev_computed_hash is not None:
            if entry.prev_hash != prev_computed_hash:
                return AuditChainResponse(
                    valid=False,
                    entries_checked=entries.index(entry) + 1,
                    broken_at=entry.id,
                    detail=f"Hash chain broken at entry #{entry.id} — "
                           f"expected prev_hash '{prev_computed_hash[:16]}…', "
                           f"found '{entry.prev_hash[:16]}…'",
                )

        # Compute hash of this entry for next iteration
        chain_data = {
            "id": entry.id,
            "agent_id": entry.agent_id,
            "timestamp": entry.timestamp.isoformat() if entry.timestamp else "",
            "action": entry.action,
            "policy_decision": entry.policy_decision,
            "signature": entry.signature,
        }
        prev_computed_hash = hash_data(chain_data)

    return AuditChainResponse(
        valid=True,
        entries_checked=len(entries),
        detail=f"Hash chain intact across {len(entries)} entries.",
    )
