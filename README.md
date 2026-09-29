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

You wouldn't let a dog roam the neighborhood unsupervised, so why let an AI agent run commands, edit your files and browse the web _without_ guardrails? Leash checks every action your agent takes **before it runs**: routine work goes through, dangerous things (`rm -rf ~`, reading your SSH keys, `curl … | sh`) are blocked, and risky-but-legitimate things (`git push --force`, reading `.env`) ask you first. Every decision is recorded in a tamper-evident log on your machine.

```bash
uv tool install leash    # 1. install
leash install            # 2. connect it to Claude Code, Copilot CLI, Cursor, Codex or OpenClaw
leash doctor             # 3. check you're protected
```

No server, no account, nothing leaves your computer.

> 🎓 **New to AI agents or security?** Read **[Start Here: Your First 15 Minutes](docs/docs/start-here.md)** — a step-by-step walkthrough in plain English, from installing to your first blocked command and how to allow things Leash was too careful about.

## 🌟 Highlights

- 🐕 **Deny by default** — nothing happens unless your policy says so
- 📜 **YAML rules** — human-readable, version-controllable, git-diffable
- 🔗 **Tamper-evident audit trail** — hash-chained and signed; deletions are detectable
- 👀 **Observe mode** — shadow new rules in production before enforcing
- 🔍 **Security scanner** — discover an MCP server's tools, classify risk, generate policies
- 🤖 **Agent guardrails in one command** — `leash install` hooks Claude Code, Copilot CLI, Cursor, Codex and OpenClaw, with no server
- 🙋 **Ask, don't just deny** — `effect: ask` sends risky actions to the agent's approval prompt
- 💬 **Explains itself** — `leash explain` says why something was blocked; `leash allow` lets it through next time
- 🧩 **Framework-agnostic** — agent hooks, Python SDK, MCP proxy, or plain REST
- 🧠 **[OpenClaw support](docs/docs/openclaw-guide.md)** — `leash install openclaw` adds a fail-closed plugin to the popular open-source AI assistant
- 🛡️ **OWASP mapped** — rules and audit checks reference [OWASP ASI](https://owasp.org/www-project-agentic-security-initiative/) and [LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) threat IDs
- ⚡ **Small core** — `pip install leash` for SDK/CLI/engine, or `leash[server]` to run the server
- 📖 **[Full documentation](docs/docs/index.md)** — getting started, policy writing guide, SDK reference, CLI reference, architecture

## ⬇️ Installation

### AI agents (Claude Code, Copilot CLI, Cursor, Codex, OpenClaw)

```bash
uv tool install leash    # or: pipx install leash   (no uv? see Start Here)
leash install            # hooks every agent it finds; restart them afterwards
```

That's it: no server and no registration. Every shell command, file edit, web fetch and MCP call your agents make is checked against `~/.leash/policies/` before it runs. Destructive commands and credential reads are blocked, and risky actions (force-push, `sudo`, publishing) ask you first.

```bash
leash audit tail -f      # watch what your agent does
leash explain            # why was that blocked?
leash allow              # ...let it through from now on (leash allow --undo to revert)
leash uninstall          # turn it off
```

See [Start Here](docs/docs/start-here.md) for a guided walkthrough, or the [coding agents guide](docs/docs/hooks.md) for details.

### Server (Python SDK, REST API, dashboard)

```bash
uv tool install 'leash[server]'
# alternatives: pipx install 'leash[server]' or pip install 'leash[server]'
```

Or run from source:

```bash
git clone https://github.com/chadeckles/leash.git && cd leash
uv sync --all-extras
uv run leash start
```

Requires Python 3.11+ (macOS ships with 3.9 — run `brew install python@3.12` first if needed).

> 💡 **Running from source?** Use `uv sync --all-extras` and `uv run leash start`, or `make quickstart` for the demo flow. See the [getting started guide](docs/docs/getting-started.md) for details.

### Starting the Server

After installing, start the server:

```bash
leash start              # start on 127.0.0.1:8000
leash start --reload     # auto-reload for development
leash start --port 9000  # custom port
leash start --host 0.0.0.0  # expose on the network
```

Or from source: `make dev`

## 🚀 Usage

### Python SDK

For developers building agents in Python (LangChain, CrewAI, or custom code). Add a few lines to your existing agent code — no separate config file needed — and every tool call is authorized and audited.

Wrap individual functions with a decorator:

```python
from leash import LeashAgent

agent = LeashAgent(name="my-agent")

@agent.tool("email.read")
def read_inbox(mailbox: str):
    return gmail.read(mailbox)

with agent:
    read_inbox("user@example.com")   # Leash checks permission first
```

The `name` is how policies find your agent — a policy with `agents: ["*email*"]` matches any agent with "email" in its name.

Or wrap many tools at once with `guard()` — no need to decorate every function individually:

```python
# Wrap a list of existing callables in one line:
guarded = agent.guard([read_inbox, send_email, summarize, search])

# Works with LangChain tools too:
guarded = agent.guard(langchain_tools)
```

If the action is denied, the function doesn't run. If Leash is unreachable, it denies by default (fail-closed).

> 💡 **Deny by default.** These examples will be denied until you [write a policy](#-writing-rules) that allows the action. That's the point — nothing runs unless your rules say so.

### MCP Proxy (Claude Desktop, Cursor, etc.)

[MCP (Model Context Protocol)](https://modelcontextprotocol.io) is how AI tools like Claude Desktop and Cursor connect to external tool servers — but MCP has no built-in authorization. This proxy sits between the AI and the MCP server so every tool call is checked against your policies, with zero code changes to the server:

```bash
leash-mcp-proxy \
    --agent-name "fs-agent" \
    -- npx -y @modelcontextprotocol/server-filesystem /data
```

Every `tools/call` is authorized, logged, and checked for tool poisoning automatically. The proxy auto-discovers the server's tools on startup.

See the [MCP Proxy Guide](docs/docs/mcp-proxy-guide.md) for Claude Desktop config, Cursor setup, and policy examples.

### OpenClaw

[OpenClaw](https://github.com/openclaw/openclaw) is a popular open-source personal AI assistant you can message from WhatsApp, Telegram, Discord and more. It can run shell commands, browse the web and manage files — so a malicious message could try to make it do any of those.

```bash
leash install openclaw
```

This adds a small Leash plugin to OpenClaw's `before_tool_call` hook. Denied calls are blocked, `ask` pauses OpenClaw for your `/approve`, and if Leash is unavailable the call is blocked (fail-closed). OpenClaw gets the coding-agent guardrails plus extra rules that protect its config, plugins and channel credentials. See the [OpenClaw guide](docs/docs/openclaw-guide.md).

### REST API

Any language — register once, check permission before each action:

```bash
# Register an agent (returns agent_id + JWT token)
curl -s -X POST http://localhost:8000/agents \
  -H "Content-Type: application/json" \
  -d '{"name": "my-agent"}'

# Authorize an action (use the token and agent_id from above)
curl -s -X POST http://localhost:8000/authorize \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "'$AGENT_ID'", "action": "email.read"}'
```

Full interactive API docs at **http://localhost:8000/docs** once the server is running.

## 📜 Writing Rules

Rules live in `~/.leash/policies/*.yaml` by default. The server seeds bundled presets there on first start and picks up changes automatically — no restart needed.

```yaml
name: email-agent
priority: 10
agents: ["*email*"]
rules:
  - action: "email.read"
    effect: allow
    reason: "Agent may read emails"

  - action: "email.*"
    effect: deny
    reason: "Everything else is blocked"
```

**How evaluation works:**

- **`priority`** — higher number = evaluated first. The built-in `default.yaml` is priority 0 (catch-all deny). Your policies should be 10+ to take precedence.
- **`agents`** — wildcard patterns matched against the agent's name. `"*email*"` matches any agent with "email" in its name.
- **Rules** — evaluated top-to-bottom within a policy. First match wins. No match anywhere = **denied**.

**Don't guess at rules — observe first.** Deploy new policies in `mode: observe` to see what *would* be denied without actually blocking anything. Once you're confident, flip to `mode: enforce`. See [Write Your First Policy](docs/docs/write-your-first-policy.md) for the full scan-first workflow.

Rules also support rate limiting, ABAC conditions, and OWASP threat tags — see the [policy writing guide](docs/docs/write-your-first-policy.md).

## 🔍 CLI Cheat Sheet

```bash
leash install                             # hook your agents (no server)
leash hosts                               # which agents are hooked
leash audit tail -f                       # watch local hook decisions
leash explain                             # why was the last thing blocked?
leash allow                               # allow it from now on (--undo to revert)
leash policy test --local -a shell.exec -r "git push --force"
leash status                              # server health
leash agents list                         # registered agents
leash agents register --name "my-bot"     # register a new agent
leash policy validate ~/.leash/policies/  # lint your YAML rules
leash audit scan                          # security scan (integrity, storms, shadows)
leash scan -- npx -y @mcp/server-fs /data # scan an MCP server's tools
leash dashboard                           # live terminal TUI
leash doctor                              # health-check your deployment
```

## 🐳 Docker

```bash
make docker-up     # build + start on port 8000
make docker-down   # stop + remove volumes
```

Images are published to [GHCR](https://ghcr.io/chadeckles/leash), multi-arch (amd64 + arm64), and signed with [cosign](https://github.com/sigstore/cosign). The container uses `LEASH_HOME=/data` with one `leash-data:/data` volume; read the admin key with `docker exec leash-server cat /data/keys/admin.key`.

## 🏗️ Project Layout

```
src/leash/
  __init__.py     ← public SDK exports
  cli.py          ← CLI
  hooks/          ← coding-agent hook adapters + installer
  auditlog.py     ← local hash-chained audit log
  client.py       ← Python SDK (LeashAgent)
  mcp_proxy.py    ← MCP authorization proxy
  scanner.py      ← security surface scanner
  engine/         ← pure policy engine
  presets/        ← bundled starter policies
  server/         ← FastAPI server, routes, models, audit, identity
tests/            ← test suite
```

## ✍️ Author

Built by [Chad Eckles](https://github.com/chadeckles).

## 💭 Feedback & Contributing

Found a bug? Have an idea? [Open an issue](https://github.com/chadeckles/leash/issues) or check out the [contributing guide](CONTRIBUTING.md).

## 📄 License

Apache 2.0 — see [LICENSE](LICENSE).
