# Roadmap

Leash is moving from a per-workstation server toward a local, hooks-first
guardrail that installs in a couple of commands and can optionally join a team
server. Each phase is merged into the `next` branch and released to PyPI
together as **v0.7**.

| Phase | Theme | Status |
|---|---|---|
| 0 | Security hardening | ✅ Done ([#1](https://github.com/chadeckles/leash/pull/1), merged to `main`) |
| 1 | Packaging & pure engine | ✅ Done ([#2](https://github.com/chadeckles/leash/pull/2), into `next`) |
| 2 | Hooks-first: `leash hook` / `leash install <host>` | 🚧 In progress |
| 3 | MCP SDK proxy & gateway external-authz | ⏳ Planned |
| 4 | Team mode: signed bundles, OIDC, audit ingest | ⏳ Planned |

## Phase 0 — Security hardening ✅
- Policy writes are admin-only by default, and admin tokens come from a local admin key.
- Checks for revoked tokens fail closed, and names that look like UUIDs are rejected.
- Policy names from non-admin agents are namespaced.
- The MCP proxy checks every resource a tool call touches.

## Phase 1 — Packaging & pure engine ✅
- A single `leash` package (`src/leash/`) built with hatchling and locked with uv.
- The core install needs only PyYAML and httpx; the server stack is the `leash[server]` extra.
- All state lives under `LEASH_HOME` (default `~/.leash`), and presets ship as package data that is copied in on first start.
- `leash.engine` is a pure library (stdlib + PyYAML):
  - It compiles and caches policies and hot-reloads the policy directory.
  - Invalid policy files are skipped, not fatal.
  - Rate limiting uses an in-memory sliding window.
- New keys are Ed25519; existing RSA keys are still accepted.
- `leash start` binds to 127.0.0.1 by default.
- The Docker image and CI are built on uv.

*Deviations from the original plan:*
- State lives in `~/.leash`, matching `~/.claude`, `~/.copilot` and `~/.codex`, instead of platformdirs.
- There is no `[mcp]` extra yet; the proxy has no extra dependencies until Phase 3.

## Phase 2 — Hooks-first (v0.5 scope)
- `leash hook <host>` reads the host's pre-tool-use JSON on stdin and maps it to a common action model (`shell.exec`, `file.write`, `mcp.call`, …). It evaluates the local policy with no server needed and writes the decision in the format the host expects.
- `leash install` / `uninstall <host>` are idempotent and back up existing config.
- `leash init --preset`, and a local hash-chained audit log with `leash audit tail`.
- A new `ask` effect for human-in-the-loop approval on hosts that support it.

## Phase 3 — MCP & gateways
- Rebuild the proxy on the official MCP SDK (stdio + Streamable HTTP) and use tool annotations to judge risk.
- Add an external-authz endpoint for MCP gateways.

## Phase 4 — Team mode (v0.7+)
- Signed, versioned policy bundles (pulled, cached, and enforced offline).
- OIDC login, audit ingest, and OTel GenAI export.
- Postgres with Alembic migrations.
