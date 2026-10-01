<p align="center">
  <img src="https://raw.githubusercontent.com/chadeckles/leash/main/assets/leash.png" alt="Leash – Keep your AI agents on a leash" width="700">
</p>

<p align="center">
  <a href="https://pypi.org/project/leash/"><img src="https://img.shields.io/pypi/v/leash?color=blue" alt="PyPI"></a>
  <a href="https://github.com/chadeckles/leash/actions/workflows/tests.yml"><img src="https://github.com/chadeckles/leash/actions/workflows/tests.yml/badge.svg" alt="Tests"></a>
  <a href="https://github.com/chadeckles/leash/actions/workflows/docker.yml"><img src="https://github.com/chadeckles/leash/actions/workflows/docker.yml/badge.svg" alt="Docker"></a>
  <a href="https://github.com/chadeckles/leash/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11%2B-blue.svg" alt="Python 3.11+"></a>
</p>

# Leash

**Keep your AI agents on a leash.**

You wouldn't let a dog roam the neighborhood unsupervised, so why let an AI agent read your files, send emails, and call APIs _without_ guardrails? Leash is an API-layer policy engine that sits between your agent and the outside world — no containers, no sidecars, just authorization. You write simple YAML rules that say what's allowed. Everything else is denied. Every decision from allow or deny activities is logged in a cryptographically signed, hash-chained audit trail that's tamper-evident by design.

One `pip install`, one policy file, and your agent is on a leash.

## 🌟 Highlights

- 🐕 **Deny by default** — nothing happens unless your policy says so
- 📜 **YAML rules** — human-readable, version-controllable, git-diffable, hot-reloaded
- 🔗 **Tamper-evident audit trail** — every decision is RSA-signed and SHA-256 hash-chained; edits and deletions are detectable
- 👀 **Observe mode** — shadow new rules in production before enforcing
- 🔍 **Security scanner** — discover an MCP server's tools, classify risk, generate policies
- 🔒 **Hardened by default** — admin-only policy management, admin-key-gated admin agents, fail-closed revocation
- 🧩 **Framework-agnostic** — Python SDK, MCP proxy, OpenClaw plugin, or plain REST
- 🧠 **[OpenClaw ready](docs/docs/openclaw-guide.md)** — a `before_tool_call` plugin plus a built-in policy for the popular open-source AI assistant
- 🛡️ **OWASP mapped** — rules and audit checks reference [OWASP ASI](https://owasp.org/www-project-agentic-security-initiative/) and [LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) threat IDs
- ⚡ **Pure Python** — `pip install leash`. No Go, no Rust, no sidecar containers

## ⚙️ How It Works

Before your agent runs a tool, it asks Leash *"can I do this?"*:

```
 Agent / MCP client / OpenClaw
            │  POST /authorize  {agent_id, action, resource, context}  + JWT
            ▼
 ┌─────────────────────── Leash server ───────────────────────┐
 │  Identity (RS256 JWT)  →  Policy engine (YAML + managed)   │
 │                              │                             │
 │                              ▼                             │
 │            Audit log (signed, hash-chained, SQLite)        │
 └──────────────────────────────┬─────────────────────────────┘
            ▼
     allow → tool runs          deny → tool never runs
```

1. **Identity** — each agent registers once and gets a UUID and a signed JWT.
2. **Policy** — the engine matches the agent's *name* against policy `agents:` patterns, then the first matching rule by priority decides. No match → deny.
3. **Audit** — every decision (allow, deny, observe-deny) is signed and linked to the previous entry's hash, so tampering breaks the chain.

If Leash is unreachable, the SDK, MCP proxy, and OpenClaw plugin all **fail closed**.

## ⬇️ Install and see it work (60 seconds)

```bash
git clone https://github.com/chadeckles/leash.git && cd leash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .           # makes the `leash` command available
leash demo                 # 3 allows, 3 denies, audit log, tamper detection
```

`leash demo` needs no server, config, or API keys. It starts a throwaway Leash in a temp directory, sends six real tool calls from an "OpenClaw" agent, shows each decision and reason, prints the hash-chained audit log, then edits one entry and shows the chain verification catch it. Add `--step` to pause between parts (great for presenting) or `--keep` to leave it running and open the dashboard.

Requires Python 3.11+ (macOS ships with 3.9 — run `brew install python@3.12` first if needed). `pip install leash` also works, but the PyPI release can lag behind `main`.

## 🚀 Quickstart Workflow

```bash
# 1. Start the server (terminal 1)
leash start                      # http://localhost:8000  (--port, --reload)

# 2. Register an agent (terminal 2) — the name is what policies match on
leash agents register --name openclaw-agent

# 3. See what it may do, then test real decisions
leash agents permissions openclaw-agent
leash policy test --agent openclaw-agent -a read -a web_search -a exec

# 4. Inspect the evidence
leash audit log                  # ✔/✘ per decision
leash audit scan                 # integrity, suspicious chains, deny storms, gaps
leash dashboard                  # live terminal UI (web UI: /dashboard)
```

The first CLI command auto-registers a `cli-admin` identity using the server's admin key (`.keys/admin.key`, or `LEASH_ADMIN_KEY`) and caches it in `~/.leash/token.json`. Agent identities are saved to `~/.leash/<name>.json` with `0600` permissions.

> 💡 **Deny by default.** Anything no policy allows is denied. That's the point — nothing runs unless your rules say so.

## 🔌 Integrations

### Python SDK

For agents written in Python (LangChain, CrewAI, custom code):

```python
from sdk import LeashAgent

agent = LeashAgent("http://localhost:8000", name="my-agent")

@agent.tool("email.read")
def read_inbox(mailbox: str):
    return gmail.read(mailbox)

with agent:
    read_inbox("user@example.com")   # Leash checks permission first
```

Wrap many tools at once with `guard()` — works with plain callables and LangChain tools:

```python
guarded = agent.guard([read_inbox, send_email, summarize, search])
```

A denied call never runs (`LeashDenied` by default; see `on_deny`). If the server is unreachable, the SDK denies. Expired tokens refresh automatically; revoked tokens raise `LeashRevoked`. See the [SDK Reference](docs/docs/sdk-reference.md).

### MCP Proxy (Claude Desktop, Cursor, etc.)

[MCP](https://modelcontextprotocol.io) has no built-in authorization. The proxy sits between the client and any MCP server — no server changes:

```bash
python -m sdk.mcp_proxy \
    --agent-name "fs-agent" \
    -- npx -y @modelcontextprotocol/server-filesystem /data
```

Every `tools/call` is authorized. Resource-like arguments (`path`, `source`, `destination`, `paths[]`, …) are each checked against `resource:` rules, scalar arguments are available to conditions as `arg.<name>`, and tools whose description or schema changes mid-session are blocked (tool-poisoning defense). See the [MCP Proxy Guide](docs/docs/mcp-proxy-guide.md).

### OpenClaw

[OpenClaw](https://github.com/openclaw/openclaw) can run shell commands, browse the web, and edit files. The [`leash-gate`](integrations/openclaw/leash-gate) plugin hooks OpenClaw's `before_tool_call` so **every** tool call is authorized by Leash, and denied calls are blocked with the policy's reason:

```bash
leash start                                  # terminal 1
python3 integrations/openclaw/lab.py setup   # terminal 2: registers the agent, installs + enables the plugin, configures the gateway
openclaw gateway run                         # terminal 2
python3 integrations/openclaw/lab.py allow   # terminal 3: 3 allowed tool calls
python3 integrations/openclaw/lab.py deny    # terminal 3: 3 blocked tool calls
```

The built-in [`openclaw.yaml`](app/policies/openclaw.yaml) policy allows reads, web search, and memory, and denies `exec`, `write`, `browser`, and other high-risk tools. See the [OpenClaw Integration Guide](docs/docs/openclaw-guide.md) or the hands-on **[OpenClaw Lab](docs/docs/openclaw-lab.md)**.

### REST API

Any language — register once, then ask before each action:

```bash
RESP=$(curl -s -X POST http://localhost:8000/agents \
  -H "Content-Type: application/json" -d '{"name": "my-agent"}')
AGENT_ID=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['agent_id'])")
TOKEN=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

curl -s -X POST http://localhost:8000/authorize \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"agent_id": "'$AGENT_ID'", "action": "email.read", "resource": "inbox"}'
```

Interactive API docs live at **http://localhost:8000/docs**.

## 📜 Writing Rules

Rules live in `app/policies/*.yaml` (or `POLICIES_DIR`) and are hot-reloaded — no restart needed.

```yaml
name: email-agent
priority: 10
mode: enforce          # or "observe" to log would-be denials without blocking
agents: ["*email*"]
rules:
  - action: "email.read"
    effect: allow
    reason: "Agent may read emails"

  - action: "email.send"
    effect: allow
    reason: "Agent may send, but slowly"
    rate_limit: { max_calls: 10, window: 3600 }

  - action: "email.*"
    effect: deny
    reason: "Everything else is blocked"
```

- **`priority`** — higher is evaluated first. `default.yaml` (priority 0) is the catch-all deny; use 10+ for your policies.
- **`agents`** — wildcard patterns matched against the agent's **name**. Entries shaped like UUIDs match only that exact `agent_id`.
- **`rules`** — first match wins. Optional `resource`, `conditions` (ABAC on request `context`), `rate_limit`, and `owasp` tags.

Validate before you ship, and dry-run a candidate file against a real agent:

```bash
leash policy validate app/policies/
leash policy test --agent my-agent -a email.send -f candidate.yaml
```

**Observe first.** Deploy new policies with `mode: observe`, review `leash audit log --decision observe_deny`, then flip to `enforce`. See [Write Your First Policy](docs/docs/write-your-first-policy.md).

Policies can also be managed over the API (`/policies/managed`). By default only admin identities may create them; non-admin agents may only create self-restricting, deny-only policies scoped to themselves.

## 🔗 Tamper-Evident Audit

Every `/authorize` decision is written to the audit log with an RSA signature and the SHA-256 hash of the previous entry. Changing or deleting any entry breaks the chain for everything after it:

```bash
curl -s http://localhost:8000/verify/audit-chain
# {"valid": true, "entries_checked": 42, "detail": "Hash chain intact across 42 entries."}

leash audit verify                                 # ✔ VALID / ✘ BROKEN (exit 1)
leash audit scan                                   # 🔴 CRITICAL if the chain is broken
leash audit export --since 24h > audit.jsonl       # SIEM-friendly JSONL
```

Stream events elsewhere as they happen with `LEASH_WEBHOOK_URL` (HTTP POST) or `LEASH_AUDIT_SINK` (append-only JSONL file).

## 🔐 Security Model

| Control | Default |
|---|---|
| Policy management (`/policies/managed`) | Admin only (`LEASH_POLICY_REQUIRE_ADMIN=true`) |
| Registering `cli` / `admin` / `ops` agents | Requires admin JWT or `X-Leash-Admin-Key` |
| Admin key | `LEASH_ADMIN_KEY`, else auto-generated at `KEYS_DIR/admin.key` (0600) |
| Agent registration | Open; set `LEASH_REQUIRE_AUTH_REGISTER=true` to require admin |
| Read endpoints (metrics, overview, export) | Open; set `LEASH_REQUIRE_AUTH_READ=true` for network-exposed deployments |
| Token revocation | Deleted agents and key rotation revoke tokens; DB errors fail closed (503) |
| Identity | One JWT per agent; an agent can only authorize its *own* `agent_id` |

Rotate server keys with `leash server rotate-keys`. See [SECURITY.md](SECURITY.md) and [Architecture](docs/docs/architecture.md).

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `sqlite:///<repo>/leash.db` | Database location |
| `POLICIES_DIR` | `<repo>/app/policies` | YAML policy directory |
| `KEYS_DIR` | `<repo>/.keys` | Server keys and `admin.key` |
| `JWT_EXPIRATION_HOURS` | `168` | Agent token lifetime |
| `LEASH_ADMIN_KEY` | auto-generated | Admin bootstrap key |
| `LEASH_POLICY_REQUIRE_ADMIN` | `true` | Admin-only policy management |
| `LEASH_REQUIRE_AUTH_REGISTER` | `false` | Require admin to register agents |
| `LEASH_REQUIRE_AUTH_READ` | `false` | Require auth for read endpoints |
| `LEASH_WEBHOOK_URL` / `LEASH_AUDIT_SINK` | — | Real-time audit export |
| `LEASH_CORS_ORIGINS` | localhost:8000 | Allowed browser origins |
| `LEASH_URL` | `http://localhost:8000` | Server URL used by the CLI |

## 🔍 CLI Cheat Sheet

```bash
leash start [--port 8000] [--reload]      # run the server
leash demo [--step] [--keep]              # 60-second offline demo
leash status                              # server health + metrics
leash doctor                              # health-check your deployment

leash agents register --name my-bot       # register (token → ~/.leash/my-bot.json)
leash agents list | show | permissions | delete <name-or-id>

leash policy list                         # YAML + managed policies
leash policy validate app/policies/       # lint YAML rules
leash policy test --agent my-bot -a exec  # live decision (add -f file.yaml for dry-run)

leash audit log [--decision deny]         # recent decisions
leash audit summary                       # allow/deny stats
leash audit scan                          # integrity, chains, deny storms, shadows, gaps
leash audit verify                        # re-check the hash chain
leash audit export --since 24h            # JSONL export

leash scan -- npx -y @modelcontextprotocol/server-filesystem /data   # MCP tool risk scan
leash dashboard                           # live terminal UI
leash server rotate-keys                  # rotate server signing keys
```

Full details: [CLI Reference](docs/docs/cli-reference.md).

## 🐳 Docker

```bash
make docker-up     # build + start on 127.0.0.1:8000 (auth hardening enabled)
make docker-down   # stop + remove volumes

# Point the host CLI at the container's admin key:
export LEASH_ADMIN_KEY=$(docker exec leash-server cat /app/.keys/admin.key)
```

Images are published to [GHCR](https://ghcr.io/chadeckles/leash), multi-arch (amd64 + arm64), and signed with [cosign](https://github.com/sigstore/cosign).

## 🏗️ Project Layout

```
app/                     ← Leash server (FastAPI)
  main.py                ← app, /health, /metrics, /dashboard, /admin/*
  routes/                ← /agents, /authorize, /policies, /audit, /scan, /verify
  policies/              ← YAML rules (edit these) — default, demo, email, openclaw
  policy/                ← policy engine + validator
  audit/                 ← signed, hash-chained audit log, scans, export dispatch
  identity/              ← agent registration, JWT issuance, key rotation
  core/                  ← config, auth, crypto, database, metrics
  models/                ← SQLAlchemy models (agents, policies, audit_log)
  static/dashboard.html  ← web dashboard
sdk/
  client.py              ← Python SDK (LeashAgent, LeashDenied, LeashRevoked)
  cli.py                 ← `leash` CLI
  mcp_proxy.py           ← MCP authorization proxy
  scanner.py             ← MCP tool-surface scanner
  dashboard.py           ← terminal dashboard
  demo.py                ← `leash demo` offline walkthrough
integrations/
  openclaw/leash-gate/   ← OpenClaw before_tool_call plugin
  openclaw/lab.py        ← one-command OpenClaw setup + allow/deny lab
docs/docs/               ← guides and references (MkDocs)
scripts/                 ← helper scripts
tests/                   ← pytest suite
```

## 📖 Documentation

| Guide | |
|---|---|
| [Getting Started](docs/docs/getting-started.md) | Install and first decisions |
| [Write Your First Policy](docs/docs/write-your-first-policy.md) | Observe → scan → enforce workflow |
| [OpenClaw Integration](docs/docs/openclaw-guide.md) · [OpenClaw Lab](docs/docs/openclaw-lab.md) | Govern an OpenClaw assistant |
| [MCP Proxy Guide](docs/docs/mcp-proxy-guide.md) | Claude Desktop, Cursor, any MCP server |
| [SDK Reference](docs/docs/sdk-reference.md) · [CLI Reference](docs/docs/cli-reference.md) | API details |
| [Architecture](docs/docs/architecture.md) | How it works under the hood |

## 🧪 Development

```bash
pip install -e ".[dev]"
make test          # pytest
make lint          # ruff
make dev           # server with auto-reload
```

## ✍️ Author

Built by [Chad Eckles](https://github.com/chadeckles).

## 💭 Feedback & Contributing

Found a bug? Have an idea? [Open an issue](https://github.com/chadeckles/leash/issues) or check out the [contributing guide](CONTRIBUTING.md).

## 📄 License

Apache 2.0 — see [LICENSE](LICENSE).
