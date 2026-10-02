# Leash

**Keep your AI agents on a leash.**

You wouldn't let a dog roam the neighborhood unsupervised — so why let an AI agent read your files, send emails, and call APIs without guardrails? Leash is the authorization and audit layer that sits between your agent and the outside world. You write simple YAML rules that say what's allowed. Everything else is denied. Every decision is logged in a cryptographically signed, hash-chained audit trail that's tamper-evident by design.

Leash is currently **beta**. Evaluate it in a controlled environment and validate policies against real agent behavior before production enforcement.

---

## How It Works

Before your agent does anything, it asks Leash: *"Can I do this?"*

```
Your Agent ──▶ Leash ──▶ allow or deny
                  │
                  └──▶ signed, hash-chained audit log
```

- 🐕 **Deny by default.** Nothing happens unless your policy says so.
- 👀 **Observe before enforce.** Shadow new policies in production — see what *would* be denied without blocking.
- 🔗 **Every action is logged.** Hash-chained entries — deletions or tampering are detectable.
- 🔍 **Scan before you deploy.** Discover an MCP server's tools, classify risk, and generate policies automatically.
- 🪪 **Identity-bound.** Each agent has a JWT. It can only authorize its own actions.
- 🔒 **Hardened by default.** Policy management and admin identities require the admin key; revoked tokens fail closed.
- 🧩 **Framework-agnostic.** Python SDK, MCP proxy, or plain REST — works with any agent.

## Who It's For

- **Developers** building AI agents that call tools (LangChain, CrewAI, custom code)
- **Teams** deploying MCP servers with Claude Desktop, Cursor, or Windsurf
- **Security engineers** who need governance over what agents can do

## Experimental Integrations

- **[OpenClaw plugin](openclaw-guide.md)** — Technical preview of authorization through OpenClaw's `before_tool_call` hook. Validate tool names and policy behavior against your OpenClaw version before enforcement.

## Quick Links

| I want to... | Go here |
|---|---|
| Run the 60-second educational demo | [Getting Started](getting-started.md) |
| Write rules for my agent | [Write Your First Policy](write-your-first-policy.md) |
| Evaluate the experimental OpenClaw integration | [OpenClaw Integration](openclaw-guide.md) |
| Run the OpenClaw technical-preview lab | [OpenClaw Lab](openclaw-lab.md) |
| Secure my MCP tools in Claude/Cursor | [MCP Proxy Guide](mcp-proxy-guide.md) |
| Use the Python SDK in my code | [SDK Reference](sdk-reference.md) |
| Use the CLI | [CLI Reference](cli-reference.md) |
| Understand how it works | [Architecture](architecture.md) |

## Installation

```bash
git clone https://github.com/chadeckles/leash.git && cd leash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
leash demo        # 60-second offline demo: allows, denies, audit log, tamper detection
leash start       # run the real server on http://localhost:8000
```

Requires Python 3.11+. See [Getting Started](getting-started.md) for Docker and step-by-step options.
