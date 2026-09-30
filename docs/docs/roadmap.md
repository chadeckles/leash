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
| 2.5 | Beginner path: OpenClaw plugin, `leash explain` / `allow`, Start Here | ✅ Done (PR into `next`) |
| 2.6 | First-run experience: `leash setup`, protection levels, `leash settings`, `audit summary`, SIEM docs | ✅ Done (PR into `next`) |
| 3 | Local MCP proxy, tool pinning, session taint, production protection | ✅ Done (PR into `next`) |
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

## Phase 2.5 — Beginner path ✅
An end-to-end test as a first-time user (a student trying Claude Code and
OpenClaw) showed the gaps between "installed" and "confident":
- `leash install openclaw` adds a fail-closed OpenClaw plugin (`before_tool_call`); `ask` becomes OpenClaw's `/approve`. The OpenClaw preset now uses the hook vocabulary.
- `leash explain` says in plain English why something was flagged and what you can do; `leash allow` adds an exception to `my_rules.yaml` (with `--pattern`, `--undo`). Agents can't run it.
- Every block message points to `leash explain`; install/uninstall print next steps and what's left behind.
- [Start Here](start-here.md): a first-15-minutes tutorial with a glossary.

## Phase 2.6 — First-run experience ✅
Aimed at the same first-time user: no YAML and no CLI expertise needed.
- `leash setup` finds your agents, asks for a protection level (Strict / Balanced / Relaxed), connects them and checks that `rm -rf ~` is blocked.
- `leash settings` is a terminal checklist of protection groups (secrets, destructive commands, risky actions, outside the project, network). Protecting Leash itself can't be switched off; changes apply on the next tool call.
- Bundled rules carry a `group:` tag; your own rules always apply. Older copies of the bundled presets are updated automatically, with a backup.
- `leash audit summary` gives a plain-English overview of the local log. The audit record format is documented as stable, with [Splunk, Elastic and Vector examples](logs-and-siem.md) instead of a Leash dashboard.

*Deliberately not built:* a local web UI. The terminal checklist and existing SIEM tools cover the need without a new service to run.

## Phase 3 — MCP and prompt-injection protection ✅
Claude Code, Copilot CLI, Cursor and Codex already route MCP tool calls through
their hooks. The proxy covers apps that have none.
- `leash mcp run` is a local stdio wrapper around the MCP server command. Nothing is hosted; it uses the same rules, levels and audit log as `leash hook`, and tool calls use the same `mcp.<server>.<tool>` actions.
- `leash mcp wrap` rewrites Claude Desktop, VS Code and Windsurf configs to go through it, with a backup; `leash setup` offers it and `leash uninstall` reverses it.
- Tool pinning: descriptions are fingerprinted on first use; changed tools, or tools with hidden instructions, are held back until `leash mcp trust`.
- `ask` rules prompt through the app (MCP elicitation) where supported; otherwise they're refused with a `leash allow` hint.
- Session taint: after an agent reads web pages, GitHub issues or MCP results, the new `untrusted` group asks before it pushes, posts or sends anything.
- New `production` group blocks `DROP`/`TRUNCATE`, database resets, `terraform destroy` and cloud delete commands, including through MCP database tools.

*Deliberately not built:* sandboxing (use a dev container, VM or NVIDIA OpenShell alongside Leash), remote MCP gateways, and LLM-based content scanning.

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
