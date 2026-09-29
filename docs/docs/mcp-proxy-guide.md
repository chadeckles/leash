# MCP Proxy Guide

Leash can sit between any MCP client (Claude Desktop, Cursor, Windsurf, etc.) and any MCP server — authorizing every tool call before it reaches your tools. **No code changes to your MCP server required.**

```
Claude Desktop / Cursor
        │
        ▼
  Leash MCP Proxy          ──▶ Leash Server (allow/deny + audit)
        │
        ▼
  Your MCP Server (filesystem, database, etc.)
```

## Why You Need This

MCP servers expose tools like `read_file`, `write_file`, `run_query` — but there's no built-in way to:

- **Restrict which tools an AI model can call**
- **Log what tools were actually called** (with cryptographic proof)
- **Rate-limit tool usage** to prevent runaway costs
- **Detect tool poisoning** (tool descriptions changing mid-session)

Leash's MCP proxy adds all of this as a transparent layer.

## Quick Setup

### 1. Start the Leash server

```bash
uv tool install 'leash[server]'
leash start
```

Or from source: `make dev`

### 2. Run your MCP server through the proxy

Instead of running your MCP server directly:

```bash
# Before (no authorization):
npx -y @modelcontextprotocol/server-filesystem /data
```

Wrap it with the Leash proxy:

```bash
# After (every tool call goes through Leash):
leash-mcp-proxy \
    --agent-name "fs-agent" \
    -- npx -y @modelcontextprotocol/server-filesystem /data
```

That's it. The proxy registers as `fs-agent` with Leash, intercepts every `tools/call`, and checks policy before forwarding.

## Claude Desktop Setup

Edit your `claude_desktop_config.json`:

=== "macOS"
    ```
    ~/Library/Application Support/Claude/claude_desktop_config.json
    ```

=== "Windows"
    ```
    %APPDATA%\Claude\claude_desktop_config.json
    ```

=== "Linux"
    ```
    ~/.config/Claude/claude_desktop_config.json
    ```

### Example: Filesystem Server

```json
{
  "mcpServers": {
    "guarded-filesystem": {
      "command": "python",
      "args": [
        "-m", "leash.mcp_proxy",
        "--leash-url", "http://localhost:8000",
        "--agent-name", "claude-fs-agent",
        "--",
        "npx", "-y",
        "@modelcontextprotocol/server-filesystem",
        "/Users/you/Documents"
      ]
    }
  }
}
```

Restart Claude Desktop. The filesystem tools now go through Leash.

### Example: Multiple MCP Servers

```json
{
  "mcpServers": {
    "guarded-filesystem": {
      "command": "python",
      "args": [
        "-m", "leash.mcp_proxy",
        "--agent-name", "claude-fs",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"
      ]
    },
    "guarded-github": {
      "command": "python",
      "args": [
        "-m", "leash.mcp_proxy",
        "--agent-name", "claude-github",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-github"
      ]
    },
    "guarded-postgres": {
      "command": "python",
      "args": [
        "-m", "leash.mcp_proxy",
        "--agent-name", "claude-postgres",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-postgres",
        "postgresql://user:pass@localhost/mydb"
      ]
    }
  }
}
```

Each server gets its own Leash agent with its own policies and audit trail.

## Cursor Setup

In Cursor, go to **Settings → MCP** and add a server. The command format is the same:

```json
{
  "mcpServers": {
    "guarded-filesystem": {
      "command": "python",
      "args": [
        "-m", "leash.mcp_proxy",
        "--agent-name", "cursor-fs",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem",
        "/path/to/your/project"
      ]
    }
  }
}
```

## Writing Policies for MCP Tools

MCP tool names become Leash action names. If your MCP server exposes a tool called `read_file`, that's the action you write rules for.

The proxy also passes the call's arguments to the policy engine:

- **Resource**: every value of `path`, `file_path`, `filepath`, `filename`, `file`, `uri`, `url`, `directory`, `dir`, `source`, `destination` (and each entry of a `paths` list) is authorized as a separate `resource`. The call is denied if any one of them is denied (so `move_file /tmp/a → /etc/passwd` can't slip through), and `resource:` globs (e.g. `/data/*`) apply. Paths are normalized server-side (`..` and `%2e%2e` traversal is resolved).
- **Conditions**: scalar arguments are exposed as `arg.<name>` context keys, e.g. `conditions: {arg.path: "/data/*"}`. They're namespaced because arguments are model-controlled and shouldn't be confused with trusted context.

### Filesystem Server Tools

The `@modelcontextprotocol/server-filesystem` server exposes:

| MCP Tool | Leash Action |
|----------|---------------|
| `read_file` | `read_file` |
| `write_file` | `write_file` |
| `list_directory` | `list_directory` |
| `create_directory` | `create_directory` |
| `move_file` | `move_file` |
| `search_files` | `search_files` |
| `get_file_info` | `get_file_info` |
| `list_allowed_directories` | `list_allowed_directories` |

### Example Policy for a Filesystem MCP Server

Create `~/.leash/policies/claude_fs.yaml`:

```yaml
name: claude-fs-policy
description: Policy for Claude Desktop filesystem access
priority: 20
agents:
  - "claude-fs*"     # matches claude-fs, claude-fs-agent, etc.

rules:
  # Allow reading and listing
  - action: "read_file"
    effect: allow
    reason: "Claude may read files"

  - action: "list_directory"
    effect: allow
    reason: "Claude may list directories"

  - action: "search_files"
    effect: allow
    reason: "Claude may search for files"

  - action: "get_file_info"
    effect: allow
    reason: "Claude may check file metadata"

  - action: "list_allowed_directories"
    effect: allow
    reason: "Claude may see which directories are available"

  # Deny all writes and modifications
  - action: "write_file"
    effect: deny
    reason: "Claude cannot write files (read-only mode)"

  - action: "create_directory"
    effect: deny
    reason: "Claude cannot create directories"

  - action: "move_file"
    effect: deny
    reason: "Claude cannot move or rename files"
```

### Example Policy for a Database MCP Server

```yaml
name: claude-postgres-policy
description: Read-only database access for Claude
priority: 20
agents:
  - "claude-postgres*"

rules:
  - action: "query"
    effect: allow
    reason: "Claude may run read queries"
    rate_limit:
      max_calls: 50
      window: 3600

  - action: "list_tables"
    effect: allow
    reason: "Claude may see table names"

  - action: "describe_table"
    effect: allow
    reason: "Claude may see table schemas"

  # Block any write operations
  - action: "execute"
    effect: deny
    reason: "Claude cannot execute arbitrary SQL"

  - action: "insert"
    effect: deny
    reason: "Claude cannot insert data"

  - action: "update"
    effect: deny
    reason: "Claude cannot update data"

  - action: "delete"
    effect: deny
    reason: "Claude cannot delete data"
```

## Auto-Discovery

When the proxy starts, it discovers the tools available on the upstream MCP server and can auto-create a Leash policy for them. Auto-discovered tools are set to **deny**, and the generated policy is scoped to the proxy's own agent. An admin reviews it and grants `allow` rules, because agents can't grant themselves permissions.

Check what was discovered:

```bash
leash policy list
leash agents permissions <agent-id>
```

To disable auto-discovery:

```bash
leash-mcp-proxy \
    --agent-name "fs-agent" \
    --no-auto-discover \
    -- npx -y @modelcontextprotocol/server-filesystem /data
```

## Tool Poisoning Detection

The proxy computes a SHA-256 hash of each tool's description when it first sees it. If a tool's description or input schema changes mid-session (a potential rug-pull or tool-poisoning attack), the proxy logs a warning, records it in the audit trail, and **blocks further calls to that tool** until the session restarts:

```
[leash-mcp] WARNING TOOL POISONING DETECTED: 'read_file' description/schema changed mid-session (ASI04)
```

Use `--on-tool-change warn` to log without blocking.

This maps to OWASP ASI02 (Tool Misuse & Exploitation).

## Proxy Options

| Flag | Default | Description |
|------|---------|-------------|
| `--leash-url` | `http://localhost:8000` | Leash server URL |
| `--agent-name` | `mcp-proxy` | Agent name for registration |
| `--on-deny` | `error` | What to return on deny: `error` or `empty` |
| `--on-tool-change` | `block` | When a tool definition changes mid-session: `block` further calls or only `warn` |
| `--no-auto-discover` | (off) | Don't auto-create a policy from discovered tools |

The proxy caches its identity at `~/.leash/agents/mcp_<agent-name>.json` (mode `0600`).

## Troubleshooting

### "Connection refused" when starting the proxy

The Leash server isn't running. Start it first:

```bash
leash start
```

### Tools work without the proxy but fail with it

Check the policy. By default, everything is denied. Look at what the agent is trying to do:

```bash
leash audit log --agent <agent-id> --limit 10
```

You'll see the denied actions. Create allow rules for the ones you want.

### Claude Desktop doesn't see the tools

1. Make sure the `claude_desktop_config.json` path is correct for your OS
2. Restart Claude Desktop completely (quit and reopen)
3. Check that `python` resolves to Python 3.11+: `python --version`
4. Check the proxy logs in Claude Desktop's developer console

### How do I see what's happening?

Open the Leash dashboard at **http://localhost:8000/dashboard** — it shows every authorize decision, registered agents, and the audit feed in real time.

Or use the CLI:

```bash
leash agents list                    # see registered MCP agents
leash agents permissions <agent-id>  # see what they can do
leash audit log --agent <agent-id>   # see what they've done
leash audit scan                     # detect suspicious patterns
```
