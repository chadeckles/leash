# Leash

**Keep your AI agents on a leash.**

You wouldn't let a dog roam the neighborhood unsupervised — so why let an AI agent read your files, send emails, and call APIs without guardrails? Leash is the authorization and audit layer that sits between your agent and the outside world. You write simple YAML rules that say what's allowed. Everything else is denied. Every decision is logged in a cryptographically signed, hash-chained audit trail that's tamper-evident by design.

One install, one policy file, and your agent is on a leash.

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
- 🧩 **Framework-agnostic.** Python SDK, MCP proxy, or plain REST — works with any agent.

## Who It's For

- **Developers** building AI agents that call tools (LangChain, CrewAI, custom code)
- **Teams** deploying MCP servers with Claude Desktop, Cursor, or Windsurf
- **Security engineers** who need governance over what agents can do
- **Anyone running [OpenClaw](https://github.com/openclaw/openclaw)** who wants authorization and audit on top

## Quick Links

| I want to... | Go here |
|---|---|
| Get running in 60 seconds | [Getting Started](getting-started.md) |
| Write rules for my agent | [Write Your First Policy](write-your-first-policy.md) |
| Govern my OpenClaw assistant | [OpenClaw Integration](openclaw-guide.md) |
| Secure my MCP tools in Claude/Cursor | [MCP Proxy Guide](mcp-proxy-guide.md) |
| Use the Python SDK in my code | [SDK Reference](sdk-reference.md) |
| Use the CLI | [CLI Reference](cli-reference.md) |
| Understand how it works | [Architecture](architecture.md) |

## Installation

```bash
uv tool install 'leash[server]'
leash start
```

Or from source:

```bash
git clone https://github.com/chadeckles/leash.git && cd leash
make quickstart
```

Requires Python 3.11+. See [Getting Started](getting-started.md) for Docker and step-by-step options.
