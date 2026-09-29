# Roadmap

Leash is moving from a per-workstation server to a local, hooks-first
guardrail that installs in a couple of commands. It stays a small, focused
open-source tool: one YAML policy, enforced locally, with a tamper-evident
audit log, and no hosted service. Each phase is merged into the `next` branch,
and all of them ship to PyPI together as **v0.7**.

| Phase | Theme | Status |
|---|---|---|
| 0 | Security hardening | ✅ Done ([#1](https://github.com/chadeckles/leash/pull/1), merged to `main`) |
| 1 | Packaging & pure engine | ✅ Done ([#2](https://github.com/chadeckles/leash/pull/2), into `next`) |
| 2 | Hooks-first: `leash hook` / `leash install <host>` | ✅ Done (PR into `next`) |
| 3 | Local MCP proxy (no server needed) | ⏳ Planned |
| 4 | v0.7 release: docs, polish, PyPI | ⏳ Planned |

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

## Phase 2 — Hooks-first ✅
- `leash hook <host>` reads the host's pre-tool-use JSON on stdin and maps it to a common action model (`shell.exec`, `file.write`, `mcp.<server>.<tool>`, …). It evaluates the local policy with no server needed and writes the decision in the format the host expects.
- `leash install` / `uninstall <host>` are idempotent and back up existing config. There are two scopes: user (default) and `--project`, which writes hook config you can commit to the repo.
- `leash init --preset`, and a local hash-chained audit log with `leash audit tail`.
- A new `ask` effect for human-in-the-loop approval on hosts that support it.
- A `coding-agent` preset, `leash policy test --local`, `leash hosts`, and hook checks in `leash doctor`.

*Deviations from the original plan:* Managed/MDM installs and plugin marketplaces were dropped to keep Leash small (see [Out of scope](#out-of-scope)).

## Phase 3 — Local MCP proxy
Claude Code, Copilot CLI, Cursor and Codex already route MCP tool calls through
their hooks, so Phase 2 covers MCP for those hosts. The proxy is only for MCP
clients that have no hooks.
- The proxy runs locally as a stdio wrapper around the MCP server command (nothing is hosted). It evaluates with the same local engine and audit log as `leash hook`, so it needs no server, token or registration.
- Tool calls use the same `mcp.<server>.<tool>` actions as hooks, so one policy covers both.
- `leash mcp wrap` rewrites an MCP client config entry to run through the proxy.

## Phase 4 — v0.7 release
- Docs pass, migration notes from v0.3, and the PyPI release.

## Out of scope
To keep Leash small, these are not planned:
- Managed/MDM fleet installs.
- Hosted team server, OIDC and signed policy bundles.
- MCP gateway integrations and a Streamable-HTTP proxy.
- Plugin marketplaces.

`leash[server]` (API, dashboard, Python SDK) stays available for people who
already use it, but setup doesn't require it.
