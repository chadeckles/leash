# Write Your First Policy

Policies are YAML files that tell Leash what an agent is allowed to do. This guide walks you through writing one from scratch — **starting with a scan of what the agent actually does.**

## The Simple Format: flip allow / deny

For most agents, a policy is a list of tools, each set to `allow` or `deny`:

```yaml
# app/policies/my_agent.yaml
agent: my-agent          # applies to agents whose name contains "my-agent"

tools:
  read: allow
  web_search: allow
  exec: deny
  write: deny

everything_else: deny    # anything not listed (this is the default)
```

That's a complete policy. Save it in `app/policies/` and Leash picks it up immediately. For OpenClaw, Leash knows every built-in tool: run `leash scan openclaw` to see what each one can do and what your policy decides, and read [`app/policies/openclaw.yaml`](https://github.com/chadeckles/leash/blob/main/app/policies/openclaw.yaml) for a fully commented example.

Simple-format rules:

- Values must be `allow` or `deny`. `leash policy validate` catches anything else, including typos of OpenClaw tool names (*did you mean 'exec'?*).
- `agent` is a name (matched as `*name*`), a glob such as `"*bot*"`, an agent ID, or a list of these.
- Optional keys: `name` (default `<agent>-policy`), `priority` (default 20), `mode: observe`, `description`.
- Need something the toggles can't express — resources, conditions, custom rate limits? Add a `rules:` list (the full format below). Those rules are checked first, then the toggles, then `everything_else`.

Everything below describes the **full format**, which the simple format compiles into.

## The Scan-First Workflow

!!! tip "Don't guess — scan first"
    The biggest mistake when writing policies is inventing action names that don't match what the agent actually calls. Instead, follow this workflow:

```
1. REGISTER   → leash agents register --name my-agent
2. OBSERVE    → deploy policy with mode: observe
3. RUN        → let the agent do real work for a while
4. SCAN       → leash audit scan --agent <agent-id>
5. REVIEW     → leash audit export --agent <agent-id>
6. WRITE      → build policy YAML based on REAL actions from the scan
7. ENFORCE    → flip mode: observe → mode: enforce
8. VERIFY     → leash audit scan (confirm no gaps)
```

**Why this matters:** An AI agent's documentation might say it "reads files" — but the actual tool call might be `file.read`, `fs.readFile`, `read_file`, or even `click` followed by `type`. You won't know until you scan.

**Real example:** Agent-S (a GUI automation agent by Simular AI) doesn't call `browse_web` or `gui.click` — its real `@agent_action` methods are bare names: `open`, `click`, `type`, `scroll`. No namespace prefix. If you wrote a policy blocking `gui.click`, it would match nothing and protect no one.

## How Policies Work

1. Policies live in `app/policies/` as `.yaml` files
2. The server picks up changes automatically — no restart needed
3. Policies are matched to agents by **name pattern**
4. Rules are evaluated **top-to-bottom** — first match wins
5. If no rule matches, the action is **denied** (deny-by-default)

!!! danger "Action Name Integrity — The #1 Policy Mistake"
    Policy rules only work if the `action` string **exactly matches** what the agent actually sends. Agents don't use a universal naming convention. One agent calls `file.read`, another calls `read_file`, another calls just `click`. If you guess wrong, your policy matches nothing and blocks nothing — while giving you a false sense of security. **Always scan first, then write policy.**

## Step 1: Register and Observe

Before writing any rules, register your agent and deploy a catch-all observe policy:

```bash
leash agents register --name my-agent
```

Create `app/policies/my_agent_observe.yaml`:

```yaml
name: my-agent-observe
mode: observe
priority: 15
agents:
  - "my-agent"

rules:
  - action: "*"
    effect: deny
    reason: "Observing all actions — will refine after scan"
```

Now let the agent run normally. Every action is allowed (observe mode never blocks), but every action that *would* be denied is logged as `observe_deny`.

## Step 2: Scan and Discover

After the agent has run for a while:

```bash
# See what the agent actually did
leash audit scan --agent <agent-id>

# Export the raw action vocabulary
leash audit export --agent <agent-id> --pretty
```

The scan reveals:
- **Every unique action** the agent called (the real names, not guesses)
- **Deny storms** — rapid bursts of denied actions
- **Permission gaps** — actions allowed but never used (over-permissioned)
- **Observe shadows** — what would be blocked if you enforced today

## Step 3: Write Rules Based on Real Data

Now you know what the agent actually does. Create your policy:

```yaml
# app/policies/my_agent.yaml
name: my-agent-policy
description: Basic policy for my agent
priority: 10
agents:
  - "my-agent"      # exact match on agent name

rules:
  - action: "file.read"
    effect: allow
    reason: "Agent may read files"
```

That's it. An agent named `my-agent` can now `file.read`. Everything else is denied.

## Matching Agents by Name Pattern

The `agents` list supports wildcards, so you don't need to know agent IDs:

```yaml
agents:
  - "*email*"        # any agent with 'email' in its name
  - "*research*"     # any agent with 'research' in its name
  - "prod-agent-1"   # exact match
  - "*"              # all agents (use carefully!)
```

!!! tip "Name your agents well"
    When registering agents, pick descriptive names like `email-bot`, `code-assistant`, `research-agent`. The name is how policies find them.

## Action Wildcards

Actions use glob patterns — just like filenames:

```yaml
rules:
  # Exact match
  - action: "email.read"
    effect: allow
    reason: "Can read emails"

  # Wildcard: matches email.read, email.send, email.delete, etc.
  - action: "email.*"
    effect: deny
    reason: "All other email actions blocked"

  # Multi-level: matches file.read.csv, file.read.json, etc.
  - action: "file.read.*"
    effect: allow
    reason: "Can read any file type"
```

**Order matters.** Rules are checked top-to-bottom, and the first match wins. Put specific rules before wildcards:

```yaml
rules:
  # ✅ Correct: specific rule first
  - action: "email.delete"
    effect: deny
    reason: "Never allow deleting emails"

  - action: "email.*"
    effect: allow
    reason: "All other email actions are fine"
```

```yaml
rules:
  # ❌ Wrong: wildcard catches everything before the specific rule runs
  - action: "email.*"
    effect: allow
    reason: "All email actions allowed"

  - action: "email.delete"    # ← this never runs!
    effect: deny
    reason: "Never allow deleting emails"
```

## Resource Scoping

Restrict actions to specific paths or resources:

```yaml
rules:
  - action: "file.read"
    resource: "/data/*"
    effect: allow
    reason: "Can read files in /data"

  - action: "file.read"
    resource: "/etc/*"
    effect: deny
    reason: "Cannot read system config files"

  - action: "file.read"
    effect: deny
    reason: "All other paths denied"
```

When your agent authorizes, it passes the resource:

```python
agent.authorize("file.read", resource="/data/report.csv")   # → allow
agent.authorize("file.read", resource="/etc/passwd")          # → deny
```

!!! warning "Path traversal protection"
    Leash normalizes resource paths automatically. An agent trying `/data/../../etc/passwd` will be evaluated against `/etc/passwd`, not `/data/*`. You don't need to handle this yourself.

## Rate Limiting

Cap how often an action can happen:

```yaml
rules:
  - action: "email.send"
    effect: allow
    reason: "Can send emails, max 10 per hour"
    rate_limit:
      max_calls: 10
      window: 3600    # seconds
```

When the limit is hit, the action is denied with a clear message: *"Rate limit exceeded: 10/10 calls in the last 3600s window"*.

Rate limits are **per-agent** — agent A and agent B each get their own counter.

## Conditions (ABAC)

Restrict rules to specific contexts using attribute-based access control:

```yaml
rules:
  - action: "db.query"
    effect: allow
    reason: "Only analysts can query the database"
    conditions:
      user_role: "analyst"

  - action: "db.write"
    effect: allow
    reason: "Only admin engineers can write to the database"
    conditions:
      user_role: "admin"
      department: "engineering"
```

The agent passes context when authorizing:

```python
agent.authorize("db.query", context={"user_role": "analyst"})     # → allow
agent.authorize("db.query", context={"user_role": "intern"})      # → deny
agent.authorize("db.query")                                        # → deny (no context)
```

**All conditions must match.** If a rule has two conditions, both must be satisfied.

Condition values support wildcards too:

```yaml
conditions:
  department: "eng-*"    # matches eng-platform, eng-security, etc.
```

## OWASP Tags

Label rules with OWASP Agentic Security Initiative (ASI) or LLM Top 10 tags for security reporting:

```yaml
rules:
  - action: "email.send"
    effect: allow
    reason: "Rate-limited email sending"
    rate_limit:
      max_calls: 10
      window: 3600
    owasp: ["ASI02", "LLM10"]
```

Tags are returned in authorize responses and audit entries, making it easy to generate compliance reports.

## Priority

When multiple policies apply to an agent, the one with the **highest priority number** is evaluated first:

```yaml
# app/policies/default.yaml (priority: 0)
# → catch-all deny — evaluated last

# app/policies/my_agent.yaml (priority: 10)
# → agent-specific allows — evaluated first
```

The default policy ships at priority 0. Your agent-specific policies should use 10+ to take precedence.

## Observe Mode

Afraid a new policy will break something? Deploy it in **observe mode** first:

```yaml
name: new-lockdown
mode: observe    # observe | enforce (default: enforce)
priority: 15
agents:
  - "*"

rules:
  - action: "file.delete"
    effect: deny
    reason: "Block destructive file operations"

  - action: "shell.*"
    effect: deny
    reason: "No shell access"
```

Observe mode is policy-level. Individual rules still use only `effect: allow` or `effect: deny`; there is no rule-level `effect: observe`.

**What happens:**

- Leash evaluates the policy normally
- Deny decisions are logged as `observe_deny` (not `deny`)
- The agent **is never blocked** — it always gets `allow`
- The authorize response includes an `observation` field explaining what *would* have been denied

**Workflow:**

1. Deploy in `mode: observe`
2. Watch the audit log: `leash audit export --decision observe_deny --since 7d`
3. See no false positives? → Flip to `mode: enforce`
4. See unexpected denials? → Tune the rules before enforcing

This is how every serious security tool works (Falco, ModSecurity, AWS Config rules). Zero-risk onboarding.

## Testing Your Policy

Before deploying, validate and test:

```bash
# Check YAML structure
leash policy validate app/policies/my_agent.yaml

# Test a specific action against live policies
leash policy test --action file.read --agent <agent-id>

# Dry-run a candidate policy without saving it
curl -X POST http://localhost:8000/policies/dry-run \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_yaml": "name: test\nagents: [\"*\"]\nrules:\n  - action: file.read\n    effect: allow\n    reason: test",
    "agent_id": "<agent-id>",
    "actions": [{"action": "file.read"}, {"action": "file.delete"}]
  }'
```

## Real-World Examples

Leash ships with policies for common agent types in `app/policies/`. Copy and adapt them:

| File | Agent Type | What It Does |
|------|-----------|-------------|
| `openclaw.yaml` | OpenClaw assistant | Reads, web search, sessions, cron — blocks exec and browser |
| `email_agent.yaml` | Email bot | Read-only email access |
| `demo_agent.yaml` | Demo/quickstart | Read, write, summarize — blocks deletes |

```bash
# Start from an existing policy:
cp app/policies/email_agent.yaml app/policies/my_bot.yaml
# Edit it for your agent's needs, then validate:
leash policy validate app/policies/my_bot.yaml
```

### Scan-First Case Study: Agent-S

[Agent-S](https://github.com/simular-ai/Agent-S) by Simular AI is a GUI automation agent that controls desktop apps via pyautogui. Without scanning, you might write a policy with actions like `browse_web`, `gui.click`, or `edit_spreadsheet`. **All of those are wrong.** Agent-S's real `@agent_action` methods are **bare names** with no namespace prefix:

| Real Action | What It Does | Risk |
|-------------|-------------|------|
| `click` | Click UI elements | Medium |
| `type` | Type text into fields | High |
| `hotkey` | Execute keyboard shortcuts | High |
| `open` | Launch applications/files | High |
| `scroll` | Scroll content | Low |
| `drag_and_drop` | Move elements | Medium |
| `set_cell_values` | Directly modify spreadsheet cells | High |
| `call_code_agent` | Execute arbitrary Python code | Critical |

These were discovered by reading the `@agent_action` decorated methods in Agent-S's `OSWorldACI` class (`gui_agents/s3/agents/grounding.py`) — not by guessing. A policy using `gui.click` would match **nothing** because the real action is just `click`. A policy for Agent-S would use these exact bare names — allowing safe navigation, rate-limiting interaction, and **blocking** `call_code_agent` and `set_cell_values`.

!!! tip "Verify after deploying"
    After your agent runs under the new policy, confirm with `leash audit export --agent <agent-id>` that the actions being allowed/denied are the ones you expect.

Run the full simulation:

```bash
python3 scripts/simulate_agent_s.py
```

## Complete Example

Here's a production-ready policy for an agent that reads customer data and generates reports:

```yaml
name: report-generator-policy
description: >-
  Generates customer reports from the data warehouse.
  Read-only access to customer data, write access to /reports only.
priority: 20
agents:
  - "*report*"

rules:
  # Read customer data (analysts only)
  - action: "db.query"
    resource: "customers.*"
    effect: allow
    reason: "May query customer tables"
    conditions:
      user_role: "analyst"
    owasp: ["ASI03", "LLM06"]

  # Write reports to output directory
  - action: "file.write"
    resource: "/reports/*"
    effect: allow
    reason: "May write report files"
    rate_limit:
      max_calls: 20
      window: 3600
    owasp: ["ASI02", "LLM10"]

  # Explicitly deny everything dangerous
  - action: "db.write"
    effect: deny
    reason: "Cannot modify the database"

  - action: "email.*"
    effect: deny
    reason: "Cannot send emails (reports are written to disk)"

  - action: "file.delete"
    effect: deny
    reason: "Cannot delete any files"
```
