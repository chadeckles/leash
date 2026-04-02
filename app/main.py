"""Leash – AI Agent Identity, Authorization, and Audit Layer."""

import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from app.core.config import CORS_ORIGINS
from app.core.database import init_db
from app.core.metrics import METRICS
from app.routes import agents, authorize, audit, policies, scan, verify
from app.routes.policies import overview_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown hooks."""
    init_db()
    yield


app = FastAPI(
    title="Leash",
    description="AI Agent Identity, Authorization, and Audit Layer",
    version="0.2.0",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────
# Default: localhost only.  Set LEASH_CORS_ORIGINS for production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

# Mount assets for branding/images (optional — may not exist after pip install)
_assets_dir = Path(__file__).parent.parent / "assets"
if _assets_dir.is_dir():
    app.mount("/assets", StaticFiles(directory=_assets_dir), name="assets")

# Register routers – specific paths must come before wildcard paths
# overview_router (/policies/overview) must precede authorize.router (/policies/{agent_id})
# policies.router (/policies/managed) must precede authorize.router (/policies/{agent_id})
app.include_router(agents.router)
app.include_router(policies.router)
app.include_router(overview_router)
app.include_router(authorize.router)
app.include_router(audit.router)
app.include_router(scan.router)
app.include_router(verify.router)


_SKIP_METRICS = {"/metrics", "/health", "/docs", "/openapi.json", "/dashboard", "/policies/overview", "/agents", "/audit/export", "/audit/summary", "/audit/scan", "/audit/chains", "/verify/audit-chain"}


@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    """Track HTTP request counts and latency for Prometheus."""
    start = time.monotonic()
    response = await call_next(request)
    elapsed = time.monotonic() - start

    path = request.url.path
    if path not in _SKIP_METRICS:
        METRICS.inc("http_requests_total", labels={
            "method": request.method,
            "path": path,
            "status": str(response.status_code),
        })
        METRICS.observe("http_request_duration_seconds", elapsed, labels={
            "method": request.method,
            "path": path,
        })

    return response


@app.get("/health", tags=["System"])
def health():
    return {"status": "ok"}


@app.get("/admin/key-info", tags=["Admin"])
def key_info(request: Request):
    """Return server signing key metadata (age, permissions, rotation status).

    Requires admin JWT when LEASH_REQUIRE_AUTH_READ=true.
    """
    from app.core.config import REQUIRE_AUTH_READ
    if REQUIRE_AUTH_READ:
        from app.core.security import verify_agent_token
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            from fastapi.responses import JSONResponse
            return JSONResponse(status_code=401, content={"detail": "Authentication required"})
        try:
            verify_agent_token(auth_header[7:])
        except Exception:
            from fastapi.responses import JSONResponse
            return JSONResponse(status_code=401, content={"detail": "Invalid or expired token"})
    from app.core.security import get_server_key_info
    return get_server_key_info()


@app.post("/admin/rotate-server-keys", tags=["Admin"])
def admin_rotate_server_keys(request: Request):
    """Rotate the server signing key-pair (admin-only).

    Archives the current key and generates a new pair.  Existing JWTs
    remain valid via previous-key fallback.  Old audit signatures also
    remain verifiable.

    **Requires a valid admin JWT** (type=cli, admin, or ops).
    """
    from app.core.security import verify_agent_token, rotate_server_keys
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=401, content={"detail": "Admin JWT required"})
    try:
        payload = verify_agent_token(auth_header[7:])
    except Exception:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=401, content={"detail": "Invalid or expired token"})

    # Only admin types can rotate server keys
    agent_type = payload.get("type", "")
    if agent_type not in ("cli", "admin", "ops"):
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=403, content={
            "detail": "Server key rotation requires admin privileges (type must be cli, admin, or ops)"
        })

    result = rotate_server_keys()
    return result


@app.get("/metrics", tags=["System"], response_class=PlainTextResponse)
def metrics(request: Request):
    """Prometheus-compatible metrics endpoint.

    When LEASH_REQUIRE_AUTH_READ=true, requires a valid JWT in the
    Authorization header.  Otherwise open (standard Prometheus scrape).
    """
    from app.core.config import REQUIRE_AUTH_READ
    if REQUIRE_AUTH_READ:
        from app.core.security import verify_agent_token
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=401,
                content={"detail": "Authentication required (LEASH_REQUIRE_AUTH_READ=true)"},
            )
        try:
            verify_agent_token(auth_header[7:])
        except Exception:
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or expired token"},
            )
    return METRICS.render()


_DASHBOARD_HTML = Path(__file__).parent / "static" / "dashboard.html"


@app.get("/dashboard", tags=["System"], response_class=HTMLResponse)
def dashboard():
    """Serve the live web dashboard."""
    return _DASHBOARD_HTML.read_text()
