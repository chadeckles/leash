# Changelog

All notable changes to Leash will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.3.0] — 2026-04-06

### Fixed
- **CLI** — `agents permissions` and `agents show` now resolve agent names correctly (no longer requires raw UUID)
- **CLI** — `status` output no longer truncates long metric lines; shows key aggregates with compact summary
- **CLI** — `audit log` icons now correctly show ✔/✘ based on the `policy_decision` field

### Changed
- **README** — clarified positioning as an API-layer policy engine; added OWASP mapping highlight and StrongDM FAQ
- **PyPI package** — removed 3.5MB banner image from sdist; README now references GitHub-hosted image (package size: 4.7MB → 1.1MB)

---

## [0.2.0] — 2026-04-02

### Added

#### Core
- **Policy engine** — deny-by-default authorization with YAML and database-managed policies
- **Identity service** — agent registration with UUID, RSA key pairs, and RS256 JWT tokens
- **Audit service** — append-only, hash-chained audit trail with RSA signatures
- **Key rotation** — rotate agent and server keys without re-registration
- **Metrics** — Prometheus-compatible `/metrics` endpoint

#### Policy Features
- Wildcard matching for agent names (`*email*`, `bot-?`) and actions (`email.*`, `file.read`)
- Resource scoping with path matching (`/data/*`, `/reports/**`)
- Path traversal detection and normalization
- ABAC conditions (key-value attribute checks on request context)
- Per-rule rate limiting (sliding window, per-agent counters)
- Policy priority system (higher number = evaluated first)
- OWASP ASI and LLM Top 10 tag annotations per rule
- Dry-run endpoint for testing candidate policies without deploying
- Policy validation (CLI + API) with clear error messages
- **Observe mode** — `mode: observe` shadows policies in production without blocking; logs `observe_deny` events

#### Built-in Policies
- `default.yaml` — catch-all deny-by-default baseline
- `demo_agent.yaml` — quickstart demo with allow/deny examples
- `email_agent.yaml` — email agent with read access and send rate limits
- `openclaw.yaml` — balanced policy for [OpenClaw](https://github.com/openclaw/openclaw) AI assistants

#### Python SDK
- `LeashAgent` class with `@tool` decorator and `guard()` for bulk wrapping
- `discover()` — auto-create policies from registered tools
- Fail-closed by default (deny when server unreachable)
- `on_deny` options: raise, return_none, log
- `LeashDenied` exception with full context
- Transparent token auto-refresh on 401 (re-registers and retries silently)
- Context manager support

#### CLI
- `leash init` — register and cache identity
- `leash start` — start the server (`--reload`, `--port`)
- `leash agents` — register, list, show, delete, permissions
- `leash policy` — list, validate, test (live + dry-run; accepts agent name or ID)
- `leash audit` — summary, log, scan (5-check security scan), export (JSONL)
- `leash scan` — discover and classify MCP server tool surfaces with risk ratings
- `leash status` — health check with metrics
- `leash dashboard` — live terminal TUI
- `leash doctor` — comprehensive deployment health-check
- `leash server rotate-keys` — rotate server signing key-pair
- Auto-initialization on first command (zero-config bootstrap)

#### MCP Proxy
- Authorization layer for Model Context Protocol servers
- Claude Desktop and Cursor integration
- Auto-discovery of MCP tools on startup
- Tool poisoning detection

#### Audit & Security Scanning
- Structured JSON audit export (`GET /audit/export`) with JSONL streaming
- Webhook delivery (`LEASH_WEBHOOK_URL`) and JSONL file sink (`LEASH_AUDIT_SINK`)
- 5-check security scan: hash-chain integrity, suspicious chains, deny storms, observe shadows, permission gaps
- Severity classification: critical, high, medium, low, info

#### Infrastructure
- FastAPI server with SQLite backend (WAL mode, busy_timeout, foreign keys enforced)
- Docker support with security hardening (localhost-only, restart policy, auth flags)
- GitHub Actions CI (Python 3.11/3.12/3.13, ruff, pytest)
- `make quickstart` — zero-to-working-demo in 60 seconds
- 26 tests across 6 test files

#### Documentation
- Getting Started guide (pip, source, Docker)
- Write Your First Policy tutorial (scan-first workflow)
- OpenClaw Integration Guide
- MCP Proxy setup guide (Claude Desktop, Cursor)
- SDK reference, CLI reference, architecture overview

### Security
- RS256 JWT with 2048-bit RSA keys (7-day default expiry)
- Hash-chained audit trail (SHA-256) with RSA-signed entries
- Server key rotation with graceful previous-key fallback
- Token version revocation (key rotation invalidates old JWTs)
- Private key permissions enforced (0600)
- Path traversal detection and normalization in resource matching
- CORS middleware with localhost-only defaults (`LEASH_CORS_ORIGINS`)
- Authenticated registration and read gates (`LEASH_REQUIRE_AUTH_*`)
- Tool poisoning detection in MCP proxy
- Fail-closed SDK behavior when server is unreachable
