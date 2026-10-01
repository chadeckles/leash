# OpenClaw Integration Guide

[OpenClaw](https://github.com/openclaw/openclaw) is a popular open-source personal AI assistant that can run shell commands, browse the web, read/write files, and coordinate multi-agent sessions across WhatsApp, Telegram, Slack, Discord, and more.

That's a lot of power — and by default, OpenClaw has no external authorization layer. Leash adds one.

## Why Leash + OpenClaw

OpenClaw's built-in `tools.allow` / `tools.deny` config controls which tools *exist*. Leash goes further:

| Feature | OpenClaw built-in | With Leash |
|---|---|---|
| Allow/deny tools | ✔ | ✔ |
| Rate limiting per action | ✘ | ✔ |
| Tamper-evident audit trail | ✘ | ✔ |
| Observe mode (shadow before enforce) | ✘ | ✔ |
| Cross-agent policy management | ✘ | ✔ |
| OWASP threat tagging | ✘ | ✔ |

## How It Works

OpenClaw's tool names map directly to Leash action names. The [`leash-gate`](https://github.com/chadeckles/leash/tree/main/integrations/openclaw/leash-gate) plugin registers an OpenClaw `before_tool_call` hook, so every tool call — whether the model chose it in chat or it came in over the gateway's `/tools/invoke` API — is checked against your YAML policy before it executes:

```
 OpenClaw agent / gateway
        │  before_tool_call(toolName, params)
        ▼
 leash-gate plugin ── POST /authorize {action: toolName, resource: command|path|url|query}
        │
        ▼
 Leash (allow/deny + signed, hash-chained audit entry)
        │
   allow → tool runs          deny → {block: true, blockReason: "🐕 Blocked by Leash …"}
```

If Leash is unreachable or returns an error, the plugin **blocks** the call (fail-closed).

## OpenClaw's Tool Catalog

These are the default tools OpenClaw exposes — each one becomes a Leash action. Your instance may have additional tools from installed skills or plugins; use `leash audit scan` after observe mode to discover the full set.

`leash scan openclaw` prints this catalog in plain English — what each tool *can* do, its risk, and whether your current policy allows it. It reads your local policy files and needs no server or OpenClaw install.

| Category | Tools | Risk |
|---|---|---|
| **File I/O** | `read`, `write`, `edit`, `apply_patch` | 🟡 Medium |
| **Runtime** | `exec`, `process`, `code_execution` | 🔴 High |
| **Web** | `web_search`, `web_fetch`, `x_search` | 🟡 Medium |
| **Browser** | `browser` | 🔴 High |
| **Canvas** | `canvas` | 🟡 Medium |
| **Memory** | `memory_search`, `memory_get` | 🟢 Low |
| **Sessions** | `sessions_list`, `sessions_history`, `sessions_send`, `sessions_spawn`, `session_status` | 🟡 Medium |
| **Automation** | `cron`, `gateway` | 🔴 High |
| **Devices** | `nodes` | 🔴 High |
| **Messaging** | `message` | 🟡 Medium |

## Quick Setup

### 1. Install and start Leash

```bash
git clone https://github.com/chadeckles/leash.git && cd leash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
leash start
```

A source install keeps `app/policies/openclaw.yaml` in your checkout so you can edit it (it hot-reloads). `pip install leash` also works, but the bundled policies then live inside site-packages.

Server starts on http://localhost:8000. Open http://localhost:8000/docs for the interactive API reference.

### 2. Register your OpenClaw agent

```bash
leash agents register --name openclaw-agent --vendor openclaw --type assistant
```

You'll see output like:

```
  ✔ Registered 'openclaw-agent'
  ID:     a1b2c3d4-e5f6-7890-abcd-ef1234567890
  Type:   assistant
  Vendor: openclaw

  Policies applied: default, openclaw-policy
  Effective rules:  ✔ 11 allow   ✘ 13 deny

  Token saved → ~/.leash/openclaw-agent.json
```

The agent ID and token are saved automatically. Leash policies match on the **agent name** (via wildcard patterns like `*openclaw*`), so naming is what matters here.

!!! tip "Metadata flags are optional"
    `--vendor` and `--type` help with fleet filtering later but don't affect policy matching. Avoid `--type cli`, `admin`, or `ops` — those are admin types and require the admin key.

### 3. Verify the built-in policy works

Leash ships with an OpenClaw policy at `app/policies/openclaw.yaml`. It applies to any agent with "openclaw" in its name, and it is just one `allow`/`deny` line per tool:

```yaml
agent: openclaw

tools:
  read: allow           # 🟢 can read files in its workspace
  exec: deny            # 🔴 can run any shell command on your computer
  # ... one line for each of the 22 tools

everything_else: deny   # tools not listed above
```

To change what OpenClaw may do, flip a value and save — Leash reloads it automatically. Confirm it applied:

```bash
leash policy test --agent openclaw-agent -a read -a exec
```

You should see `read → allow` and `exec → deny`. That's deny-by-default working.

The built-in policy defaults:

- ✔ **Allowed:** `read`, `web_search`, `web_fetch`, `x_search`, `memory_search`, `memory_get`, `sessions_list`, `sessions_history`, `sessions_send` (rate-limited: 30/min), `session_status`, `cron` (rate-limited: 20/hour)
- ✘ **Denied:** `exec`, `process`, `code_execution`, `write`, `edit`, `apply_patch`, `browser`, `canvas`, `gateway`, `nodes`, `sessions_spawn`

!!! warning "Messaging is denied by default"
    The `message` tool (WhatsApp, Telegram, Slack, Discord) is not explicitly listed in the built-in policy, so it falls through to the catch-all deny rule. If your OpenClaw setup relies on messaging, add an explicit allow rule — see [Example Policies](#example-policies) below.

### 4. Install the `leash-gate` plugin (recommended)

The plugin lives in this repo at `integrations/openclaw/leash-gate/`. It needs OpenClaw installed (`npm install -g openclaw@latest`, Node 24.16+) and onboarded (`openclaw onboard`).

```bash
openclaw plugins install --link ./integrations/openclaw/leash-gate --force
openclaw plugins enable leash-gate
openclaw plugins inspect leash-gate --runtime --json   # confirm the before_tool_call hook is registered
```

Restart the gateway (`openclaw gateway run`) after enabling. The plugin reads the identity saved in Step 2 (`~/.leash/openclaw-agent.json`) and talks to `http://127.0.0.1:8000` by default. To override, edit `~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "leash-gate": {
        "enabled": true,
        "config": {
          "leashUrl": "http://127.0.0.1:8000",
          "identityFile": "~/.leash/openclaw-agent.json",
          "timeoutMs": 5000
        }
      }
    }
  }
}
```

Each decision is logged by the gateway:

```
🐕 Leash ALLOW read README.md [openclaw-policy/read] — read is allowed — it can read files in its workspace
🐕 Leash DENY  exec whoami [openclaw-policy/exec] — exec is blocked — it could run any shell command on your computer
```

A denied call returns the reason to the model (and to `/tools/invoke` callers as HTTP 403 `tool_call_blocked`), so the assistant can tell the user *why* it couldn't act.

!!! note "Resource mapping"
    The plugin sends the tool name as the Leash `action` and the first of `command`, `path`, `file_path`, `url`, `query`, or `target` as the `resource`, so `resource:` rules and the audit log show exactly what was attempted (e.g. `exec whoami`).

Want to try it end-to-end in ten minutes? Follow the **[OpenClaw Lab](openclaw-lab.md)**.

### 5. Other integration options

#### REST API (any language)

Call Leash before each tool execution. The agent ID and token come from Step 2:

```bash
export AGENT_ID=$(jq -r .agent_id ~/.leash/openclaw-agent.json)
export TOKEN=$(jq -r .token ~/.leash/openclaw-agent.json)

curl -s -X POST http://localhost:8000/authorize \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "'$AGENT_ID'", "action": "exec", "resource": "whoami"}' | jq .decision
```

If the response is `"allow"`, proceed. If `"deny"`, skip the tool call.

#### Python SDK (custom Python tools)

If you expose your own Python tools to OpenClaw (for example through an MCP server or skill backend), wrap them with the SDK so they are authorized too:

```python
from sdk import LeashAgent

agent = LeashAgent("http://localhost:8000", name="openclaw-agent")

@agent.tool("web_fetch")
def fetch_page(url: str):
    import httpx
    return httpx.get(url).text

with agent:
    fetch_page("https://example.com")   # ✔ allowed by policy
```

Denied calls never run, and an unreachable server denies by default. See the [SDK Reference](sdk-reference.md). For MCP servers, the [MCP Proxy](mcp-proxy-guide.md) does this without code changes.

## The Scan-First Workflow (Recommended)

The built-in policy is a solid starting point, but the best policies are built from real data. If you want to customize beyond the defaults, don't guess — **observe first, then write policy.**

!!! tip "Why scan first?"
    Different agents use different action names. OpenClaw's tool names are well-documented, but skills and plugins can add anything. If your policy uses the wrong action name, it blocks nothing and gives you a false sense of security. Scanning shows you what the agent *actually* calls.

### 1. Deploy in observe mode

Create `app/policies/openclaw_observe.yaml`:

```yaml
name: openclaw-observe
mode: observe
priority: 25
agents:
  - "*openclaw*"

rules:
  - action: "exec"
    effect: deny
    reason: "Would deny shell execution"

  - action: "browser"
    effect: deny
    reason: "Would deny browser control"

  - action: "write"
    effect: deny
    reason: "Would deny file writes"
```

With `mode: observe`, these deny rules **log** what would be blocked but **never actually block**. Your agent keeps working while Leash records every would-be denial as `observe_deny` in the audit trail.

### 2. Let the agent run, then scan

```bash
# See what the agent actually did:
leash audit scan --agent <agent-id>

# Check observe-mode shadow denials:
leash audit log --decision observe_deny --limit 50

# Export the full action vocabulary:
leash audit export --agent <agent-id> --decision observe_deny
```

### 3. Promote to enforce

If the observe results look right — the agent isn't calling `exec` legitimately, and you're comfortable blocking it — change the policy:

```yaml
name: openclaw-enforce
mode: enforce          # ← flip from observe to enforce
priority: 25
agents:
  - "*openclaw*"

rules:
  - action: "exec"
    effect: deny
    reason: "Shell execution is blocked"
  # ... rest of your rules
```

No restart needed — Leash picks up YAML changes automatically.

For the full scan-first walkthrough, see [Write Your First Policy](write-your-first-policy.md).

## Example Policies

!!! info "How priority works"
    Policies are evaluated from **highest priority number to lowest**. The built-in `openclaw-policy` has `priority: 20`. To override it, set a higher number (e.g. `priority: 25`). Within a policy, rules are evaluated top-to-bottom — **first match wins**.

The first three examples use the simple toggle format: list the tools you want, set each to `allow` or `deny`, and `everything_else: deny` blocks the rest. Leash fills in the reasons from its tool catalog. `name` and `priority` are optional; set `priority` above 20 to override the built-in policy.

### Read-only research agent

Allow searching and reading, deny everything else:

```yaml
name: openclaw-researcher
priority: 25
agent: ["*research*", "*openclaw*"]

tools:
  read: allow
  web_search: allow
  web_fetch: allow
  memory_search: allow
  memory_get: allow

everything_else: deny
```

### Coding agent (read + write, no exec)

```yaml
name: openclaw-coder
priority: 25
agent: ["*coder*", "*coding*"]

tools:
  read: allow
  write: allow
  edit: allow
  apply_patch: allow
  web_search: allow
  exec: deny
  browser: deny

everything_else: deny
```

### Messaging agent (WhatsApp, Telegram, Slack)

If your OpenClaw setup is primarily for messaging, you'll need to explicitly allow the `message` tool (it's denied by default):

```yaml
name: openclaw-messenger
priority: 25
agent: openclaw

tools:
  message: allow
  read: allow
  web_search: allow
  memory_search: allow
  memory_get: allow

everything_else: deny
```

### Full-trust agent with rate limits

For your personal main session where you trust the agent but want audit logging and custom rate limits. Custom rate limits, resources, and conditions need the full rule format:

```yaml
name: openclaw-trusted
priority: 30
agents: ["*openclaw-main*"]
rules:
  - action: "exec"
    effect: allow
    reason: "Trusted agent may run commands"
    rate_limit:
      max_calls: 60
      window: 300

  - action: "write"
    effect: allow
    reason: "Trusted agent may write files"

  - action: "browser"
    effect: allow
    reason: "Trusted agent may use browser"
    rate_limit:
      max_calls: 20
      window: 300

  - action: "*"
    effect: allow
    reason: "Trusted agent — all actions allowed with audit logging"
```

## Verifying the Integration

After setup, use these commands to confirm everything is wired up:

```bash
# Check what your agent can do:
leash agents permissions openclaw-agent

# Test live decisions (these are recorded in the audit log):
leash policy test --agent openclaw-agent -a read -a exec

# Watch decisions in real time:
leash dashboard

# See the audit trail:
leash audit log --agent <agent-id> --limit 20

# Scan for suspicious patterns:
leash audit scan --agent <agent-id>

# Confirm the hash chain is intact:
curl -s http://localhost:8000/verify/audit-chain
```

## OpenClaw Tool Groups → Leash Actions

OpenClaw supports tool groups in its config. Here's how they map to Leash actions:

| OpenClaw Group | Leash Actions |
|---|---|
| `group:runtime` | `exec`, `process`, `code_execution` |
| `group:fs` | `read`, `write`, `edit`, `apply_patch` |
| `group:sessions` | `sessions_list`, `sessions_history`, `sessions_send`, `sessions_spawn`, `session_status` |
| `group:memory` | `memory_search`, `memory_get` |
| `group:web` | `web_search`, `web_fetch`, `x_search` |
| `group:ui` | `browser`, `canvas` |
| `group:automation` | `cron`, `gateway` |
| `group:messaging` | `message` |
| `group:nodes` | `nodes` |
