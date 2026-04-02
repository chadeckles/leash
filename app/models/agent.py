"""SQLAlchemy model for AI agents."""

import json as _json
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, Text

from app.core.database import Base


class Agent(Base):
    __tablename__ = "agents"

    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(256), nullable=False, unique=True)
    vendor = Column(String(128), nullable=True, index=True)   # e.g. "github", "anthropic", "openai"
    agent_type = Column(String(128), nullable=True, index=True)  # e.g. "coding", "research", "ops"
    description = Column(Text, nullable=True)
    tags = Column(Text, nullable=True)  # JSON list, e.g. '["production","backend-team"]'
    public_key = Column(Text, nullable=False)
    token_version = Column(Integer, nullable=False, default=1, server_default="1")  # bump to revoke all JWTs
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))
    last_seen_at = Column(DateTime, nullable=True)

    # ── helpers for the JSON tags column ─────────────────────────────────

    def get_tags(self) -> list:
        """Deserialise the JSON tags column."""
        if self.tags:
            return _json.loads(self.tags)
        return []

    def set_tags(self, values: list) -> None:
        """Serialise a list of strings into the JSON tags column."""
        self.tags = _json.dumps(values) if values else None
