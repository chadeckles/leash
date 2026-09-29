# Changelog

All notable changes to Leash will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

> Work toward the next PyPI release (0.7) lands on the `next` branch. Nothing below is published yet. Phase status is tracked in [docs/docs/roadmap.md](docs/docs/roadmap.md).

### Beginner path & OpenClaw (Phase 2.5)
- **`leash install openclaw`** installs a small, dependency-free OpenClaw plugin (`~/.leash/integrations/openclaw`) and links it with `openclaw plugins install --link`. Leash never edits `openclaw.json` directly.
  - The plugin sends every `before_tool_call` to `leash hook openclaw`. Deny → blocked with the reason; ask → OpenClaw's approval prompt (`/approve`, allow once or deny); allow → OpenClaw's own settings apply.
  - Fail-closed if `leash` is missing, errors, or takes longer than 10 s.
  - Without the `openclaw` CLI on PATH, install is reported as partial and prints the manual link command; `leash doctor` warns until it's linked. `leash uninstall openclaw` unlinks and removes it.
- **`leash explain [N]`** explains the Nth most recent deny/ask in plain English: what the agent tried, the matching rule and file, what the agent did with it, and what you can do.
- **`leash allow [N]`** adds an exception to `~/.leash/policies/my_rules.yaml` (priority 100), limited to the agent that was flagged unless `--all-agents`. `--pattern` allows a glob, `--dry-run` previews, `--undo` removes the last rule. It needs an interactive terminal unless `--yes`, and the coding-agent preset denies agents from running it.
- Block messages now end with a hint to run `leash explain`. `leash install` prints numbered next steps; `leash uninstall` says what's left in `~/.leash` and how to remove it all.
- `leash audit tail -w/--wide` shows long commands and paths in full; truncation is marked with `…`. Audit entries include the full tool call (`call`) when the flagged request is a sub-command.
- `leash doctor` fails if a covering policy denies routine work (`ls`) for a hooked agent, and warns about an unlinked OpenClaw plugin.
- New docs: [Start Here](docs/docs/start-here.md), a first-15-minutes tutorial with a glossary; the OpenClaw guide is rewritten around the plugin.
- **Behaviour change: `openclaw` preset rewritten.** It now uses the hook vocabulary (`shell.exec`, `file.*`, `tool.<name>`), applies to `openclaw*` agents, and has no catch-all deny; unmatched calls fall through to `coding-agent`. It denies edits to OpenClaw's config and plugins and reads of its channel credentials, and asks before `tool.gateway`, `tool.nodes`, `tool.cron` and plugin/config commands. `leash install openclaw` backs up the old preset to `~/.leash/backups/`. Server/SDK agents named `openclaw-agent` that relied on the old deny-by-default rules should add their own rules.
- `coding-agent` preset: applies to `openclaw*`, denies `*leash allow*`, and matches `leash uninstall` anywhere in a command.
- Test suite consolidated from 102 to 45 tests with no loss of line coverage. Hook decisions are now a YAML case table (`tests/cases/hook_decisions.yaml`, 51 cases); engine and server authorization use inline case tables. Failures list every mismatched case.
- `leash doctor` no longer fails on a missing server once hooks have been used (even after `leash uninstall`); `leash allow --undo` names the original rule rather than its lower-case copy.

### Coding-agent hooks (Phase 2)
- **`leash install`**: one command hooks Leash into **Claude Code, GitHub Copilot CLI, Cursor and Codex**, with no server, registration or token.
  - It detects installed agents and merges into their existing hook config, backing it up to `~/.leash/backups/` first.
  - Re-running it is a no-op. `leash uninstall` removes only Leash's entries.
  - `--project` writes repo-level config you can commit. `leash hosts` shows what's hooked where.
- **`leash hook <agent>`**: the hook the agents call before every tool use. It maps the agent's payload to a common action model (`shell.exec`, `file.read/write/delete/search`, `web.fetch`, `agent.spawn`, `mcp.<server>.<tool>`, `tool.<name>`) and evaluates `~/.leash/policies` in-process.
  - Latency is under 100 ms, including Python start-up.
  - Shell commands are checked as a whole and as each sub-command, with `sudo`/`env` wrappers removed. File paths are resolved (including symlinks), and file actions get an `in_workspace` condition.
  - A Leash "allow" never bypasses the agent's own permission prompts.
  - Fail-closed on internal errors (exit 2). `LEASH_FAIL_OPEN=1` and `LEASH_MODE=observe` are available for rollout.
- **`coding-agent` preset**:
  - Blocks destructive commands, credential reads, and edits to Leash or the agent's own hook settings.
  - Asks before `sudo`, force-push, `git reset --hard`, publishing, infrastructure changes, `.env` reads, and writes outside the workspace.
  - Allows everything else.
  - Installed by `leash install` or `leash init --preset coding-agent`; `leash init --list-presets` shows all presets.
- **New `ask` effect** for human-in-the-loop approval. Claude Code and Copilot CLI prompt the user; Cursor prompts for shell and MCP calls. Codex and the server's `/authorize` treat it as deny (the server returns "Requires human approval: …").
- **Local audit log** at `~/.leash/audit/audit.jsonl` (0600). It is SHA-256 hash-chained and written under a file lock. New commands: `leash audit tail [-n] [-f] [--json]` and `leash audit verify`.
- **`leash policy test --local`** evaluates the local policy exactly the way the hooks do. Each `-r/--resource` belongs to the preceding `-a/--action`. `--strict` exits 1 for CI.
- **`leash doctor`** reports hooked agents, policy coverage per agent, and the local audit chain. A missing server is informational when hooks are installed.
- Engine additions:
  - `evaluate(..., normalize=False)` matches shell commands and URLs verbatim.
  - `FileRateLimiter` keeps `rate_limit` rules working across hook processes.
  - `PolicyDirectory.policies` is now sorted highest priority first.

### Packaging & install (Phase 1)
- **One package, one install command.** Code now lives in a single `leash` package (`src/leash/`). Install the server and CLI with `uv tool install 'leash[server]'` (or `pipx`/`pip`) and run `leash start`. The `./leash` wrapper, `requirements.txt` and `make install` are gone. Development uses `uv sync --all-extras`.
- **Small core install.** `pip install leash` pulls in only PyYAML and httpx (SDK, CLI, MCP proxy, policy engine). The FastAPI/SQLAlchemy/crypto stack moved to the `[server]` extra. The wheel shrank from ~1.1 MB to ~150 KB.
- **State lives in `~/.leash`** (override with `LEASH_HOME`): `policies/`, `keys/`, `leash.db`, `token.json`, `agents/`. Previously the DB, keys and policies were written next to the code, which put them inside `site-packages` for wheel installs. `POLICIES_DIR`, `KEYS_DIR` and `DATABASE_URL` still override individual locations.
- **Bundled presets.** The `default`, `demo_agent`, `email_agent` and `openclaw` policies ship as package data and are copied to `~/.leash/policies/` on first start (an existing directory is never touched).
- **SDK defaults.** `LeashAgent()` reads `$LEASH_URL` when no URL is given and caches its identity in `~/.leash/agents/<name>.json` instead of `./.leash_identity.json` (a legacy file with the same agent name is still used). The MCP proxy identity moved to `~/.leash/agents/mcp_<name>.json`. New `leash-mcp-proxy` console script and `leash --version`.
- **Docker.** The image is built with uv and keeps all state in one `/data` volume (`LEASH_HOME=/data`).

### Engine
- **`leash.engine`**: the policy engine is now a pure library with no web or database imports, usable in-process: `PolicyEngine.from_directory("~/.leash/policies").evaluate(...)`. The server, CLI and scanner all use it.
- **Faster hot path.** Policies are compiled once and cached (YAML re-scanned at most once per second, DB policies re-parsed only when they change), and glob patterns are compiled and cached.
- **In-memory rate limits.** `rate_limit` rules use a sliding-window counter instead of `COUNT(*)` over the audit table. Limits count `/authorize` decisions only, which fixes the SDK decorator's post-execution `/audit` entry being double-counted. Counters are per server process and reset on restart.
- **Ed25519.** New server keys and agent key pairs are Ed25519, and JWTs use `EdDSA`. Agent registration no longer generates a throwaway 2048-bit RSA key (the test suite went from ~27s to ~1s). Existing RSA keys keep working (RS256) until `leash server rotate-keys`, which switches to Ed25519 and keeps the old key for verifying earlier tokens and audit signatures.


### Security
- **Privilege escalation fixed**: any registered agent could create a managed policy granting itself `allow *`. `LEASH_POLICY_REQUIRE_ADMIN` now defaults to **on**. Non-admin agents may only create *self-restricting* policies (deny-only, enforce mode, scoped to their own `agent_id`), which keeps `LeashAgent.discover()` and MCP auto-discovery working.
- **Self-declared admin fixed**: registering or PATCHing an agent with `agent_type` `cli`/`admin`/`ops` now requires an admin JWT or the new `X-Leash-Admin-Key` header. The key comes from `LEASH_ADMIN_KEY` or is auto-generated at `KEYS_DIR/admin.key` (0600). `LEASH_REQUIRE_AUTH_REGISTER=true` now requires that same admin credential, as its documentation already stated.
- **Policy name squatting/shadowing fixed**: policies created by non-admins are stored as `<agent_id>/<name>`, so they can't override a YAML policy or pre-claim another agent's `discover()` name.
- **Agent impersonation via name fixed**: policy `agents:` entries that look like agent IDs now match only the real `agent_id`, never a name. Agent names shaped like UUIDs are rejected (422), and non-admins can no longer rename themselves.
- **Revocation is enforced**: tokens for deleted agents are rejected. The token-version check now fails closed (503) on DB errors, applies to policy-admin and optional-auth endpoints, and uses the request's DB session.
- **SDK no longer bypasses revocation**: on a *revoked* token the SDK raises the new `LeashRevoked` instead of silently re-registering. Expired tokens still auto-refresh. Identity files are written with mode 0600.
- **MCP proxy**: tool arguments are now evaluated. Every resource-like argument (`path`, `source`, `destination`, `paths[]`, …) is authorized, and the call is denied if any resource is denied, and scalar args are exposed as `arg.<name>` context. Previously `resource:` rules never applied to MCP calls. Tools whose description or schema changes mid-session are now **blocked** (`--on-tool-change block|warn`). The proxy identity is stored in `~/.leash/mcp_<name>.json` instead of the current directory.

- `leash start` binds to `127.0.0.1` by default (was `0.0.0.0`). Pass `--host 0.0.0.0` to expose it on the network.
- The keys directory is created with mode 0700; private keys and cached tokens are created 0600 (never briefly world-readable).
### Changed
- Removed the duplicate audit entry the MCP proxy wrote after every `/authorize`. `/authorize` audit entries now also record `context` when no `resource` is given.
- The CLI sends the admin key when auto-registering its `cli` identity.

### Upgrade notes
- **Imports:** `from sdk import LeashAgent` → `from leash import LeashAgent`; `app.main:app` → `leash.server.main:app`; `python -m sdk.mcp_proxy` → `leash-mcp-proxy`. There are no compatibility shims.
- **State:** to keep an existing deployment's data, either point `LEASH_HOME`/`DATABASE_URL`/`KEYS_DIR`/`POLICIES_DIR` at the old locations, or move `leash.db`, `.keys/*` and your policies into `~/.leash/{leash.db,keys/,policies/}`. Docker users: the volumes changed to a single `leash-data:/data`.
- **Rate limits** are no longer seeded from historical audit entries; counters start empty after upgrade or restart.
- Any `cli`/`admin`/`ops` tokens issued by earlier versions may have been self-minted. Rotate server keys (`leash server rotate-keys`) and re-run `leash init` with the admin key.
- `discover()` results for non-admin agents now carry namespaced names (`<agent_id>/<name>`).
- If you relied on non-admin agents creating allow policies, create them with an admin token instead. Setting `LEASH_POLICY_REQUIRE_ADMIN=false` restores the old, unsafe behavior.

---

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
