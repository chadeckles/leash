"""Shared test fixtures."""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Point keys to a temp directory so tests don't pollute the project
_tmp_keys = tempfile.mkdtemp(prefix="leash_keys_")
os.environ["KEYS_DIR"] = _tmp_keys

from app.core.database import Base, get_db  # noqa: E402
from app.main import app as fastapi_app  # noqa: E402

# Ensure all models are imported so create_all picks up every table
import app.models.agent  # noqa: E402, F401
import app.models.audit  # noqa: E402, F401
import app.models.policy  # noqa: E402, F401


@pytest.fixture(scope="session")
def db_engine():
    """Create an in-memory SQLite engine for the entire test session."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def db_session(db_engine):
    """Yield a fresh session that rolls back after each test."""
    connection = db_engine.connect()
    transaction = connection.begin()
    Session = sessionmaker(bind=connection)
    session = Session()
    yield session
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture()
def client(db_session):
    """FastAPI TestClient with the DB session overridden."""
    def _override_get_db():
        yield db_session

    fastapi_app.dependency_overrides[get_db] = _override_get_db
    with TestClient(fastapi_app) as c:
        yield c
    fastapi_app.dependency_overrides.clear()


def admin_headers(client, name=None):
    """Register an admin-type (cli) agent using the admin bootstrap key and
    return its Authorization header."""
    import uuid

    from app.core.security import get_admin_key

    name = name or f"test-admin-{uuid.uuid4().hex[:8]}"

    resp = client.post(
        "/agents",
        json={"name": name, "agent_type": "cli"},
        headers={"X-Leash-Admin-Key": get_admin_key()},
    )
    assert resp.status_code == 201, resp.text
    return {"Authorization": f"Bearer {resp.json()['token']}"}


@pytest.fixture()
def auth_header(client):
    """Return an Authorization header for a registered **admin** (cli) agent.

    Policy management requires admin privileges by default.  Use
    :func:`register_agent` for an ordinary, non-admin agent.
    """
    return admin_headers(client)


def register_agent(client, name="test-agent", **extra):
    """Register an agent via the API and return (agent_id, auth_header).

    This ensures the JWT ``sub`` matches the ``agent_id``, so identity
    enforcement passes.
    """
    resp = client.post("/agents", json={"name": name, **extra})
    data = resp.json()
    return data["agent_id"], {"Authorization": f"Bearer {data['token']}"}
