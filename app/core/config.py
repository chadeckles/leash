"""Application configuration."""

import os
from pathlib import Path

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Database
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'leash.db'}")

# Policies directory
POLICIES_DIR = os.getenv("POLICIES_DIR", str(BASE_DIR / "app" / "policies"))

# Server keys directory – generated at startup if absent
KEYS_DIR = os.getenv("KEYS_DIR", str(BASE_DIR / ".keys"))

# JWT settings
JWT_ALGORITHM = "RS256"
JWT_ISSUER = "leash-identity-service"
# 168h = 7 days.  Survives a workweek without anyone thinking about it.
# The SDK auto-refreshes on 401, so expiry is invisible to users.
# Override: JWT_EXPIRATION_HOURS=24 for high-security, =720 for set-and-forget.
JWT_EXPIRATION_HOURS = int(os.getenv("JWT_EXPIRATION_HOURS", "168"))

# Policy
MAX_POLICY_PRIORITY = int(os.getenv("MAX_POLICY_PRIORITY", "100"))

# Policy admin gate – when True, only admin/cli agents can manage policies
# Single-user default: permissive.  Set LEASH_POLICY_REQUIRE_ADMIN=1 for fleet deployments.
POLICY_REQUIRE_ADMIN = os.getenv("LEASH_POLICY_REQUIRE_ADMIN", "").lower() in ("1", "true", "yes")

# Require auth for agent registration — set to 1/true for production.
# When enabled, POST /agents requires a valid admin JWT.
REQUIRE_AUTH_REGISTER = os.getenv("LEASH_REQUIRE_AUTH_REGISTER", "").lower() in ("1", "true", "yes")

# Require auth for read-only endpoints (metrics, audit export, overview).
# Strongly recommended for any network-exposed deployment.
REQUIRE_AUTH_READ = os.getenv("LEASH_REQUIRE_AUTH_READ", "").lower() in ("1", "true", "yes")

# Demo seed endpoint – disabled by default in production
DEMO_ENABLED = os.getenv("LEASH_DEMO", "").lower() in ("1", "true", "yes")

# ── Audit export ───────────────────────────────────────────────────────────
# Webhook: POST every audit event as JSON to this URL (fire-and-forget)
WEBHOOK_URL = os.getenv("LEASH_WEBHOOK_URL", "")
# File sink: append every audit event as one JSONL line to this path
AUDIT_SINK = os.getenv("LEASH_AUDIT_SINK", "")

# CORS – default allows only localhost; set LEASH_CORS_ORIGINS for production
_raw_origins = os.getenv("LEASH_CORS_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000")
CORS_ORIGINS: list[str] = [o.strip() for o in _raw_origins.split(",") if o.strip()]

# Server
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))
