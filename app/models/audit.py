"""SQLAlchemy model for append-only audit log entries."""

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, Text

from app.core.database import Base


class AuditEntry(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    agent_id = Column(String(64), nullable=False, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    action = Column(String(256), nullable=False)
    inputs = Column(Text, nullable=True)       # JSON string
    outputs = Column(Text, nullable=True)       # JSON string
    policy_decision = Column(String(16), nullable=False)  # "allow" | "deny"
    signature = Column(Text, nullable=False)
    prev_hash = Column(String(64), nullable=True)  # SHA-256 of previous entry – tamper-evident chain
