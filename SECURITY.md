# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Leash, **please report it responsibly**.

### Do NOT

- Open a public GitHub issue for security vulnerabilities
- Post vulnerability details on social media or public forums
- Exploit the vulnerability beyond what's necessary to demonstrate it

### Do

Use **GitHub's private vulnerability reporting** — click the **"Report a vulnerability"**
button on the [Security tab](https://github.com/chadeckles/leash/security) of this
repository.  This creates a private advisory visible only to the maintainers.

Include:

1. **Description** — what the vulnerability is
2. **Reproduction steps** — how to trigger it
3. **Impact** — what an attacker could do
4. **Suggested fix** — if you have one (optional)

### What to Expect

| Timeline | Action |
|----------|--------|
| **24 hours** | Acknowledgment of your report |
| **72 hours** | Initial assessment and severity classification |
| **7 days** | Fix developed (or mitigation plan shared) |
| **14 days** | Patch released and advisory published |

We will credit you in the advisory unless you prefer to remain anonymous.

## Scope

The following are in scope for security reports:

- **Authentication bypass** — accessing endpoints without valid JWT
- **Authorization bypass** — actions allowed that should be denied by policy
- **Audit tampering** — modifying or deleting audit entries without detection
- **Key exposure** — leaking private keys or tokens through logs/errors/API
- **Path traversal** — accessing resources outside allowed paths
- **Injection** — YAML injection, SQL injection, or code execution
- **Denial of service** — crashing the server or exhausting resources

The following are out of scope:

- Vulnerabilities in dependencies (report to the upstream project)
- Social engineering attacks
- Rate limiting on development/local instances

## Security Architecture

Leash is designed with security as a core principle:

- **Deny by default** — no action is allowed unless explicitly permitted by policy
- **Fail closed** — SDK blocks actions when the server is unreachable
- **RS256 JWT** — 2048-bit RSA signatures, not shared secrets
- **Token versioning** — key rotation server-side invalidates all prior JWTs
- **Server key rotation** — graceful rotation with previous-key fallback
- **Hash-chained audit** — tamper-evident append-only log
- **Key rotation** — agents can rotate keys without re-registration
- **Path traversal detection** — built into the policy engine
- **Tool poisoning detection** — MCP proxy detects description changes
- **CORS protection** — restricted origins by default
- **No private key storage** — only public keys are persisted server-side
- **SQLite WAL mode** — safe concurrent reads/writes for single-host deployments

For more details, see the [Architecture documentation](docs/docs/architecture.md).

## Single-Host Deployment Guide

Leash is designed to run on **one Docker host** as its primary deployment
model.  SQLite + WAL mode is the default and handles single-host workloads
with excellent performance — PostgreSQL is only needed if you plan to run
multiple Leash server processes pointing at the same database.

### What lives where in the container

| Path | Content | Persistence |
|------|---------|-------------|
| `/app/.keys/server_private.pem` | Server signing key (signs all JWTs + audit entries) | Docker volume `leash-keys` |
| `/app/.keys/server_public.pem` | Server public key (verifies JWTs + signatures) | Docker volume `leash-keys` |
| `/app/.keys/server_public.prev.pem` | Previous public key (after key rotation) | Docker volume `leash-keys` |
| `/app/data/leash.db` | SQLite database (agents, audit log, managed policies) | Docker volume `leash-data` |
| `/app/app/policies/` | YAML policy files (bind-mounted read-only) | Host filesystem |

### Backup strategy

```bash
# 1. Stop the container (clean SQLite snapshot)
docker compose stop leash

# 2. Copy the Docker volumes
docker run --rm -v leash-data:/data -v $(pwd)/backup:/backup alpine \
  cp /data/leash.db /backup/leash.db

docker run --rm -v leash-keys:/keys -v $(pwd)/backup:/backup alpine \
  cp -r /keys/. /backup/keys/

# 3. Restart
docker compose start leash
```

For **hot backups** (no downtime), use SQLite's backup API:

```bash
docker exec leash-server python3 -c "
import sqlite3
src = sqlite3.connect('/app/data/leash.db')
dst = sqlite3.connect('/app/data/leash-backup.db')
src.backup(dst)
dst.close(); src.close()
print('Backup complete')
"
```

### SQLite vs PostgreSQL decision

| Scenario | Recommendation |
|----------|----------------|
| Single Docker host, single Leash process | **SQLite** (default) — zero ops overhead |
| Single host, need hot backups | **SQLite** — use the backup API above |
| Multiple Leash servers sharing state | **PostgreSQL** — set `DATABASE_URL=postgresql://...` |
| Cloud-managed deployment (AWS/GCP) | **PostgreSQL** — use managed RDS/Cloud SQL |

SQLite with WAL mode (enabled automatically) handles thousands of
authorize/audit operations per second on a single host.

## Server Key Rotation

The **server signing key** is the master key that signs every JWT and every
audit entry.  It is auto-generated on first startup and persists in the
Docker volume.  It should be rotated periodically (recommended: every 90 days).

### How it works

```
Before rotation:                After rotation:
  server_private.pem (current)    server_private.prev.pem (archived)
  server_public.pem  (current)    server_public.prev.pem  (archived)
                                  server_private.pem      (NEW)
                                  server_public.pem       (NEW)
```

- **New JWTs** are signed with the new key
- **Existing JWTs** signed by the old key are still accepted (verified
  via the archived previous public key)
- **Old audit signatures** remain verifiable (verification checks both keys)
- **One generation** of previous keys is kept — sufficient for single-host ops

### Rotation procedure

#### Option A: CLI (recommended)

```bash
leash server rotate-keys
```

This calls the admin API and walks you through a confirmation prompt.

#### Option B: API

```bash
curl -X POST http://localhost:8000/admin/rotate-server-keys \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

#### Option C: Manual (container restart)

```bash
# Archive old keys manually
docker exec leash-server mv /app/.keys/server_private.pem /app/.keys/server_private.prev.pem
docker exec leash-server mv /app/.keys/server_public.pem  /app/.keys/server_public.prev.pem

# Delete the in-memory cache by restarting
docker compose restart leash
# New keys are auto-generated on startup
```

### Monitoring key age

`leash doctor` checks the server key age and warns at 90 days:

```
  ⚠ key_age: Server signing key is 95 days old — run 'leash server rotate-keys'
```

You can also check programmatically:

```bash
curl http://localhost:8000/admin/key-info
# → {"age_days": 42, "needs_rotation": false, "has_previous_key": true, ...}
```

### What happens to agents after rotation?

| Agent state | What happens | Action needed |
|-------------|-------------|---------------|
| Agent with valid JWT (not expired) | JWT verified via previous key — **still works** | None (auto-heals) |
| Agent JWT expires naturally | SDK auto-reconnects on 401 — **invisible to user** | None (automatic) |
| CLI token expires | `leash` commands auto-refresh on next use | None (automatic) |
| Force immediate refresh | `leash agents register --name <agent> --force` | Manual |
| SDK `LeashAgent` in code | Auto-reconnects on 401 → new JWT | None |
| Audit entries signed by old key | Verified via previous public key | None |

## Production Hardening Checklist

Before deploying Leash to any network-accessible environment:

| Setting | Env Var | Recommended Value | Why |
|---------|---------|-------------------|-----|
| **Require auth for registration** | `LEASH_REQUIRE_AUTH_REGISTER=true` | `true` | Prevents anonymous agent creation |
| **Require auth for read endpoints** | `LEASH_REQUIRE_AUTH_READ=true` | `true` | Protects audit export, metrics, overview |
| **Require admin for policy mgmt** | `LEASH_POLICY_REQUIRE_ADMIN=true` | `true` | Restricts policy CRUD to admin tokens |
| **JWT expiration** | `JWT_EXPIRATION_HOURS=168` | `168` (7 days) | Workweek-friendly; SDK auto-refreshes on expiry |
| **CORS origins** | `LEASH_CORS_ORIGINS=http://localhost:8000` | Your origins only | Prevents cross-origin attacks |
| **Keys directory** | `KEYS_DIR=/app/.keys` | Docker volume | Persists signing keys across restarts |
| **Disable demo mode** | `LEASH_DEMO=false` | `false` (default) | No seed data endpoint |

### Docker Compose (production-ready)

The included `docker-compose.yml` ships with all hardening flags enabled:

```bash
docker compose up -d
```

> The compose file binds to **127.0.0.1:8000** by default.  Use a reverse
> proxy (nginx, Caddy, Traefik) with TLS if exposing externally.

### Day-1 bootstrap

```bash
# 1. Start the server
docker compose up -d

# 2. Initialize your admin CLI token
leash init --name ops-admin

# 3. Verify everything is healthy
leash doctor

# 4. Register your first agent
leash agents register --name my-coding-agent --type coding

# 5. Check the dashboard
open http://localhost:8000/dashboard
```

### Operational calendar

| Frequency | Task | Command |
|-----------|------|---------|
| Daily | Check server health | `leash doctor` |
| Weekly | Export audit log for archival | `leash audit export --since=7d > audit-$(date +%F).jsonl` |
| Every 90 days | Rotate server signing keys | `leash server rotate-keys` |
| As needed | Rotate agent tokens | `leash agents register --name <agent> --force` |
| Before upgrades | Backup data volume | See backup strategy above |

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x | ✅ Current |

As Leash is pre-1.0, all users should stay on the latest release.
