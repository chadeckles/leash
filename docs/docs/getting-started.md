# Getting Started

Get Leash running and see it make allow/deny decisions in under 2 minutes.

## Prerequisites

- Python 3.11+ (macOS ships with 3.9 — run `brew install python@3.12` first if needed)
- uv (recommended for source installs) or pip/pipx

!!! tip "New to AI agents?"
    Read [Start Here](start-here.md) first: it explains everything step by step, from installing uv to your first blocked command.

## AI agents: two commands

If you want guardrails for Claude Code, Copilot CLI, Cursor, Codex or OpenClaw, you don't need a server:

```bash
uv tool install leash
leash setup            # then restart your agent
leash doctor
```

See [Coding Agents (Hooks)](hooks.md) and the [OpenClaw guide](openclaw-guide.md). The options below set up the server for the Python SDK, REST API and dashboards. Hooked agents don't need it; to monitor them, see [Logs & SIEM](logs-and-siem.md).

## Option 1: Install the server + CLI (Recommended)

```bash
uv tool install 'leash[server]'
leash start
```

Alternatives: `pipx install 'leash[server]'` or `pip install 'leash[server]'`.

Server starts on http://127.0.0.1:8000. Open **http://localhost:8000/docs** for interactive API docs. Use `leash start --host 0.0.0.0` only when you need network exposure.

## Option 2: One Command (from source)

```bash
git clone https://github.com/chadeckles/leash.git
cd leash
make quickstart
```

This uses a throwaway `LEASH_HOME`, starts the server, registers a demo agent, runs allow/deny decisions against built-in policies, and shows you the audit trail. You'll see output like:

```
[3/6] Registering a demo agent...
  ✔ Agent registered: a1b2c3d4-...

[4/6] Testing policy decisions...
  ✔ ALLOW  read_file    → Demo agent may read files
  ✔ ALLOW  summarize    → Demo agent may summarize content
  ✘ DENY   delete_file  → Demo agent is not allowed to delete files
  ✘ DENY   send_email   → Default policy: no action is allowed unless explicitly permitted

[5/6] Checking the audit trail...
  ✔ 5 audit entries recorded (hash-chained and signed)
```

After it finishes, open **http://localhost:8000/dashboard** to see the live dashboard.

## Option 3: Step by Step (from source)

```bash
git clone https://github.com/chadeckles/leash.git
cd leash
uv sync --all-extras
```

Start the server:

```bash
uv run leash start --reload     # or: make dev
```

In a separate terminal, register an agent and test a decision:

```bash
# Register an agent and save the response
RESP=$(curl -s -X POST http://localhost:8000/agents \
  -H "Content-Type: application/json" \
  -d '{"name": "my-agent"}')

echo $RESP | python3 -m json.tool

# Extract the agent ID and token from the response
export AGENT_ID=$(echo $RESP | python3 -c "import sys,json; print(json.load(sys.stdin)['agent_id'])")
export TOKEN=$(echo $RESP | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Test an authorize decision
curl -s -X POST http://localhost:8000/authorize \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "'$AGENT_ID'", "action": "read_file"}' | python3 -m json.tool
```

You'll get a `"decision": "deny"` — because no policy allows `read_file` for an agent named `my-agent`. That's deny-by-default working. (The built-in `demo_agent_policy` only matches agents with "demo" in the name.)

## Option 4: Docker

```bash
make docker-up
```

Server binds to 127.0.0.1:8000 by default. The image uses `LEASH_HOME=/data` with one `leash-data:/data` volume. Stop with `make docker-down`.


## State Directory

Leash stores local state under `~/.leash` by default. Set `LEASH_HOME` to move the whole tree. Policies live in `~/.leash/policies/`, keys in `~/.leash/keys/`, the SQLite database at `~/.leash/leash.db`, CLI identity at `~/.leash/token.json`, and SDK/MCP identities under `~/.leash/agents/`. `POLICIES_DIR`, `KEYS_DIR`, and `DATABASE_URL` still override individual locations.

## The CLI

If you installed with `uv tool install 'leash[server]'`, the `leash` command is already available:

```bash
leash status        # check server health
leash agents list   # see registered agents
leash --help        # see all commands
```

From source, run CLI commands with `uv run leash ...`. Use `leash --version` to confirm the installed version.

## What's Next

**Using Leash with coding agents or OpenClaw?** You're done. Use `leash audit tail -f` to watch, `leash explain` when something is blocked, and `leash allow` to make an exception. See [Coding Agents (Hooks)](hooks.md).

**Building your own agent with the server or SDK?** Follow the **scan-first workflow** — don't guess at policies:

1. **Register your agent** — `leash agents register --name my-agent`
2. **Deploy in observe mode** — capture real actions without blocking anything
3. **Scan the audit log** — `leash audit scan` reveals what the agent actually does
4. **[Write your first policy](write-your-first-policy.md)** — based on real data, not guesses
5. **[Secure your MCP tools](mcp-proxy-guide.md)** — if you use Claude Desktop, VS Code or Windsurf
6. **[Use the Python SDK](sdk-reference.md)** — if you're building an agent in code

!!! tip "Why scan first?"
    You can't write good policy for an agent you haven't observed. Different agents use completely different action names — `file.read` vs `fs.readFile` vs just `click`. Agent-S calls `click`, not `gui.click`. If your policy uses the wrong name, it blocks nothing. Scanning first gives you the real vocabulary.
