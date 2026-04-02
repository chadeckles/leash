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

OpenClaw's tools map directly to Leash action names. When you wrap OpenClaw with Leash, every tool call is checked against your YAML policy before it executes:

```
OpenClaw Agent
      │
      ▼
   Leash (allow/deny + audit log)
      │
      ▼
   Tool executes (exec, read, browser, etc.)
```

## OpenClaw's Tool Catalog

These are the default tools OpenClaw exposes — each one becomes a Leash action. Your instance may have additional tools from installed skills or plugins; use `leash audit scan` after observe mode to discover the full set.

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
pip install leash
leash start
```

Server starts on http://localhost:8000. Open http://localhost:8000/docs for the interactive API reference.

### 2. Register your OpenClaw agent

```bash
leash agents register --name "openclaw-agent"
```

You'll see output like:

```
  ✔ Registered 'openclaw-agent'
  ID:     a1b2c3d4-e5f6-7890-abcd-ef1234567890
  Type:   —
  Vendor: —

  Policies applied: openclaw-policy
  Effective rules:  ✔ 10 allow   ✘ 12 deny

  Token saved → ~/.leash/openclaw-agent.json
```

The agent ID and token are saved automatically. Leash policies match on the **agent name** (via wildcard patterns like `*openclaw*`), so naming is what matters here.

!!! tip "Optional metadata flags"
    You can add `--vendor openclaw --type assistant` for fleet management and filtering later, but these don't affect policy matching.

### 3. Verify the built-in policy works

Leash ships with an OpenClaw policy at `app/policies/openclaw.yaml`. It matches any agent with "openclaw" or "claw" in the name. Confirm it applied:

```bash
leash policy test --action read --agent "openclaw-agent"
leash policy test --action exec --agent "openclaw-agent"
```

You should see `read → allow` and `exec → deny`. That's deny-by-default working.

The built-in policy defaults:

- ✔ **Allowed:** `read`, `web_search`, `web_fetch`, `x_search`, `memory_search`, `memory_get`, `sessions_list`, `sessions_history`, `sessions_send` (rate-limited: 30/min), `session_status`, `cron` (rate-limited: 20/hour)
- ✘ **Denied:** `exec`, `process`, `code_execution`, `write`, `edit`, `apply_patch`, `browser`, `canvas`, `gateway`, `nodes`, `sessions_spawn`

!!! warning "Messaging is denied by default"
    The `message` tool (WhatsApp, Telegram, Slack, Discord) is not explicitly listed in the built-in policy, so it falls through to the catch-all deny rule. If your OpenClaw setup relies on messaging, add an explicit allow rule — see [Example Policies](#example-policies) below.

### 4. Integrate with your OpenClaw agent code

#### Option A: Python SDK

The SDK is included when you `pip install leash`. Wrap your OpenClaw tool functions so every call is authorized, executed, and audit-logged automatically:

```python
from sdk import LeashAgent

agent = LeashAgent("http://localhost:8000", name="openclaw-agent")

@agent.tool("exec")
def run_command(command: str):
    """Wraps OpenClaw's exec tool with Leash authorization."""
    import subprocess
    return subprocess.run(command, shell=True, capture_output=True, text=True)

@agent.tool("web_fetch")
def fetch_page(url: str):
    """Wraps web_fetch with Leash authorization."""
    import httpx
    return httpx.get(url).text

# Use as a context manager — connects on entry, cleans up on exit:
with agent:
    fetch_page("https://example.com")   # ✔ allowed by policy
    run_command("ls -la")                # ✘ denied — LeashDenied raised
```

The `@agent.tool` decorator handles the full cycle: authorize → execute → audit. If the action is denied, the function **never runs**. If Leash is unreachable, it **denies by default** (fail-closed).

For existing tool functions you don't want to redecorate, use `agent.guard()`:

```python
guarded = agent.guard([run_command, fetch_page])
```

See the [SDK Reference](sdk-reference.md) for the full API.

#### Option B: REST API (any language)

Call Leash before each OpenClaw tool execution. The agent ID and token come from Step 2 — they're saved in `~/.leash/openclaw-agent.json`:

```bash
# Load your agent's credentials:
export AGENT_ID=$(cat ~/.leash/openclaw-agent.json | jq -r .agent_id)
export TOKEN=$(cat ~/.leash/openclaw-agent.json | jq -r .token)

# Check permission before running 'exec':
curl -s -X POST http://localhost:8000/authorize \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "'$AGENT_ID'", "action": "exec"}' | jq .decision
```

If the response is `"allow"`, proceed. If `"deny"`, skip the tool call.

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

### Read-only research agent

Allow searching and reading, deny everything else:

```yaml
name: openclaw-researcher
priority: 25
agents: ["*research*", "*openclaw*"]
rules:
  - action: "read"
    effect: allow
    reason: "May read workspace files"
  - action: "web_search"
    effect: allow
    reason: "May search the web"
  - action: "web_fetch"
    effect: allow
    reason: "May fetch web pages"
  - action: "memory_*"
    effect: allow
    reason: "May use memory"
  - action: "*"
    effect: deny
    reason: "Everything else is blocked"
```

### Coding agent (read + write, no exec)

```yaml
name: openclaw-coder
priority: 25
agents: ["*coder*", "*coding*"]
rules:
  - action: "read"
    effect: allow
    reason: "May read files"
  - action: "write"
    effect: allow
    reason: "May write files"
  - action: "edit"
    effect: allow
    reason: "May edit files"
  - action: "apply_patch"
    effect: allow
    reason: "May apply patches"
  - action: "web_search"
    effect: allow
    reason: "May search for docs"
  - action: "exec"
    effect: deny
    reason: "No shell access"
  - action: "browser"
    effect: deny
    reason: "No browser access"
  - action: "*"
    effect: deny
    reason: "Everything else is blocked"
```

### Messaging agent (WhatsApp, Telegram, Slack)

If your OpenClaw setup is primarily for messaging, you'll need to explicitly allow the `message` tool (it's denied by default):

```yaml
name: openclaw-messenger
priority: 25
agents: ["*openclaw*"]
rules:
  - action: "message"
    effect: allow
    reason: "May send messages to connected platforms"
    rate_limit:
      max_calls: 30
      window: 60
  - action: "read"
    effect: allow
    reason: "May read files for context"
  - action: "web_search"
    effect: allow
    reason: "May search the web"
  - action: "memory_*"
    effect: allow
    reason: "May use memory"
  - action: "*"
    effect: deny
    reason: "Everything else is blocked"
```

### Full-trust agent with rate limits

For your personal main session where you trust the agent but want audit logging and rate limits:

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
# Check what your agent can do (use agent ID from step 2):
leash agents permissions <agent-id>

# Test specific actions without running anything:
leash policy test --action read --agent "openclaw-agent"
leash policy test --action exec --agent "openclaw-agent"

# Watch decisions in real time:
leash dashboard

# See the audit trail:
leash audit log --agent <agent-id> --limit 20

# Scan for suspicious patterns:
leash audit scan --agent <agent-id>
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
