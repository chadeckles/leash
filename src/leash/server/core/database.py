"""SQLAlchemy database engine and session helpers."""

import logging
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from leash.server.core.config import DATABASE_URL

logger = logging.getLogger("leash.db")

# SQLite-specific connection arguments
_connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    _connect_args["check_same_thread"] = False
    _db_path = DATABASE_URL.split(":///", 1)[-1]
    if _db_path and _db_path != ":memory:":
        Path(_db_path).expanduser().parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(DATABASE_URL, connect_args=_connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


# ── SQLite performance & safety pragmas ───────────────────────────────────
# WAL mode allows concurrent reads while a write is in progress, which is
# critical for a single-host Docker deployment running uvicorn with even one
# worker — the /authorize hot path reads policies while audit writes are
# happening.  busy_timeout prevents "database is locked" errors under
# moderate concurrency.  These are no-ops for PostgreSQL.

@event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_conn, connection_record):
    if not DATABASE_URL.startswith("sqlite"):
        return
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.execute("PRAGMA synchronous=NORMAL")  # safe with WAL
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""
    pass


def get_db() -> Generator:  # type: ignore[misc]
    """FastAPI dependency that yields a database session."""
    db = SessionLocal()
    try:
        yield db  # type: ignore[misc]
    finally:
        db.close()


def _auto_migrate(eng) -> None:
    """Add missing columns to existing tables.

    This is a lightweight forward-only migration that inspects the live DB
    schema and compares it against the ORM models.  Any columns present in
    the model but absent from the DB are added via ALTER TABLE.

    This avoids the "no such column" crash when upgrading to a new Leash
    version that adds columns (e.g. audit_log.prev_hash).
    """
    insp = inspect(eng)
    with eng.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if not insp.has_table(table.name):
                continue  # create_all will handle brand-new tables
            existing_cols = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name not in existing_cols:
                    col_type = col.type.compile(dialect=eng.dialect)
                    nullable = "" if col.nullable else " NOT NULL"
                    default = ""
                    if col.server_default is not None:
                        default = f" DEFAULT {col.server_default.arg}"
                    sql = f"ALTER TABLE {table.name} ADD COLUMN {col.name} {col_type}{nullable}{default}"
                    logger.info("Auto-migrating: %s", sql)
                    conn.execute(text(sql))


def init_db() -> None:
    """Create all tables (idempotent) and auto-migrate existing ones."""
    # Import models so their tables are registered with Base.metadata
    import leash.server.models.agent  # noqa: F401
    import leash.server.models.audit  # noqa: F401
    import leash.server.models.policy  # noqa: F401
    Base.metadata.create_all(bind=engine)
    _auto_migrate(engine)
