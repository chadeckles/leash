# CLI Reference

The Leash CLI hooks coding agents into local policy checks (no server), and manages agents, policies and audit logs on a Leash server. Server commands auto-register on first use.

**Local commands (no server):** [`install` / `uninstall` / `hosts` / `hook`](#coding-agent-hooks), [`init --preset`](#leash-init), [`policy test --local`](#policy-test), [`audit tail` / `audit verify`](#audit-tail-verify), [`doctor`](#leash-doctor).

## Installation

Install the CLI with the core package (`pip install leash`) or server extra (`uv tool install 'leash[server]'`):

```bash
leash --help
python -m leash --help
```

## Global Options

Every command accepts these flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--url URL` | `http://localhost:8000` | Leash server URL |
| `--token TOKEN` | — | JWT token (overrides cached token) |
| `--token-file FILE` | — | JSON file containing `{"token": "..."}` |

You can also set `LEASH_URL` as an environment variable:

```bash
export LEASH_URL=http://my-leash:8000
```

## Auto-Initialization

The CLI automatically registers a `cli-admin` agent and caches the token to `~/.leash/token.json` on first use. You don't need to run `init` unless you want a custom agent name.

Registering the CLI's admin identity requires the server's **admin key**. When the CLI runs on the same host as the server it reads the key from `KEYS_DIR/admin.key` (default `~/.leash/keys/admin.key`) automatically. Otherwise, set `LEASH_ADMIN_KEY` (for Docker: `export LEASH_ADMIN_KEY=$(docker exec leash-server cat /data/keys/admin.key)`).

---

## Coding-agent hooks

See the [coding agents guide](hooks.md) for how hooks work and the action vocabulary.

### install

```bash
leash install                          # every detected agent, user scope
leash install claude-code copilot      # specific agents
leash install --project [DIR]          # repo-level config (commit it)
leash install --dry-run                # print what would be written
```

| Flag | Description |
|------|-------------|
| `AGENT ...` | `claude-code`, `copilot`, `cursor`, `codex` (default: every agent detected on this machine) |
| `--project [DIR]` | Write repo-level config in `DIR` (default: current directory) |
| `--dry-run` | Show the resulting config without writing it |
| `--command CMD` | Override the hook command (advanced) |

Creates `~/.leash/policies/` with the bundled presets on first run, or adds the `coding-agent` preset if it's missing. Existing config is merged and backed up to `~/.leash/backups/`. Re-running is a no-op.

### uninstall

```bash
leash uninstall                        # all agents, user scope
leash uninstall cursor --project
```

Removes only Leash's hook entries (and deletes `leash.json` for Copilot).

### hosts

```bash
leash hosts            # table: detected / hooked (user) / hooked (project)
leash hosts --json
```

### hook

```bash
leash hook claude-code < payload.json
```

The command the agents run for every tool call. It reads the agent's JSON on stdin and prints the decision in that agent's format. `auto` detects the agent from the payload. Exit code 2 means Leash itself failed and the call is blocked (unless `LEASH_FAIL_OPEN=1`).

---

## leash init

Register a CLI agent with the server and cache the identity token, or install a bundled policy preset locally.

```bash
leash init
leash init --name my-admin-bot
leash init --force              # re-register even if cached

leash init --list-presets
leash init --preset coding-agent          # copy into ~/.leash/policies (no server)
leash init --preset coding-agent --force  # restore the original
```

| Flag | Default | Description |
|------|---------|-------------|
| `--name NAME` | `cli-admin` | Agent name for the CLI identity |
| `--force` | — | Re-register even if already initialized; with `--preset`, overwrite the existing file |
| `--preset NAME` | — | Install a bundled preset into the local policy directory |
| `--list-presets` | — | List bundled presets |

**Token location:** `~/.leash/token.json` (mode `0600`)

---

## leash agents

### agents register

Register a new agent and show which policies match it.

```bash
leash agents register --name my-code-bot
leash agents register --name my-code-bot --vendor openai --type coding
leash agents register -n email-bot -v anthropic -t email -d "Sends weekly reports" --tag prod --tag team-a
```

| Flag | Required | Description |
|------|----------|-------------|
| `--name, -n` | ✔ | Agent name — must match a policy pattern |
| `--vendor, -v` | — | Vendor label (e.g. `openai`, `langchain`) |
| `--type, -t` | — | Agent type (e.g. `coding`, `research`) |
| `--description, -d` | — | What this agent does |
| `--tag TAG` | — | Repeatable tag (e.g. `--tag prod --tag backend`) |
| `--force, -f` | — | Overwrite token if agent name already exists |

Output includes which policies immediately apply and how many allow/deny rules the agent has.

If an agent with that name already exists, the CLI shows a warning with the existing agent's details. Use `--force` to refresh its token, or `leash agents delete <name>` to remove and re-create it.

**Token saved to:** `~/.leash/agents/<agent-name>.json`

### agents list

```bash
leash agents list
leash agents list --vendor openai
leash agents list --type coding --limit 10
```

| Flag | Default | Description |
|------|---------|-------------|
| `--vendor` | — | Filter by vendor |
| `--type` | — | Filter by agent type |
| `--limit` | 50 | Max results |

**Example output:**

```
  NAME            ID                                    VENDOR        TYPE        LAST SEEN
  ────            ──────────────────────────────────────  ────────────  ──────────  ────────────────
  demo-agent      a1b2c3d4-e5f6-7890-abcd-ef1234567890  —             demo        2025-03-28 14:22
  email-bot       f9e8d7c6-b5a4-3210-fedc-ba0987654321  anthropic     email       2025-03-28 14:20

  2 agent(s) total
```

### agents show

```bash
leash agents show <agent-id>
```

Displays name, ID, vendor, type, tags, creation time, and last seen.

### agents deregister / delete

```bash
leash agents deregister <agent-id-or-name>
leash agents delete <agent-id-or-name>
leash agents delete my-agent --yes    # skip confirmation
```

Removes an agent. Accepts either the UUID or the exact agent name. Prompts for confirmation unless `--yes` / `-y` is passed.

| Flag | Description |
|------|-------------|
| `--yes, -y` | Skip confirmation prompt |

### agents permissions

Show every rule that applies to an agent:

```bash
leash agents permissions <agent-id>
```

**Example output:**

```
  Effective permissions for: a1b2c3d4-e5f6-7890-abcd-ef1234567890
  Rules: 5 (✔ 3 allow, ✘ 2 deny)
  ────────────────────────────────────────────────────────────────
  ✔ email.read                          ← email-agent (pri 10)
  ✔ email.send [rate-limited]           ← email-agent (pri 10)
  ✔ calendar.read                       ← email-agent (pri 10)
  ✘ file.delete                         ← email-agent (pri 10)
  ✘ admin.*                             ← default (pri 0)
```

---

## leash policy

### policy list

Show all policies from YAML files and the database:

```bash
leash policy list
leash policy list --limit 100
```

**Example output:**

```
  ── YAML Policies (from disk) ──
  • default                        pri=  0  rules= 2  agents=[*]
  • demo_agent_policy               pri= 10  rules= 4  agents=[*demo*]
  • email-agent                    pri= 10  rules= 5  agents=[*email*, *mail*]
  • openclaw-policy                pri= 20  rules=22  agents=[*openclaw*, *claw*]

  ── Managed Policies (from DB) ──
  • my-custom-policy               pri=  5  [active]  updated=2025-03-28 14:30
```

### policy validate

Check policy YAML files for errors **before deploying**:

```bash
# Single file
leash policy validate ~/.leash/policies/email_agent.yaml

# All files in a directory
leash policy validate ~/.leash/policies/

# Multiple paths
leash policy validate my-policy.yaml ~/.leash/policies/
```

**Example output:**

```
  ✔ ~/.leash/policies/default.yaml
  ✔ ~/.leash/policies/email_agent.yaml
  ✘ ~/.leash/policies/broken.yaml
    → rules[1]: missing required field 'action'
    → rules[2]: 'effect' must be 'allow', 'deny' or 'ask', got 'allow_maybe'

  2 error(s) in 3 file(s)
```

Exit code is `1` if any errors are found — useful in CI.

### policy test

Test actions against live policies or dry-run against a candidate file:

```bash
# Live check against running server
leash policy test --action email.send --action email.read --agent <agent-id>

# Dry-run against a YAML file (no side effects)
leash policy test --action file.read --action file.write -f my-policy.yaml --agent test-agent

# Local: evaluate ~/.leash/policies in-process, exactly like the hooks do
leash policy test --local -a shell.exec -r "git push --force" -r "npm test" -a file.read -r ~/.ssh/id_rsa
```

| Flag | Required | Description |
|------|----------|-------------|
| `--action, -a` | ✔ | Action to test (repeatable) |
| `--agent` | — | Agent name or ID to test as (default: `test-agent`, or `claude-code` with `--local`) |
| `--policy-file, -f` | — | YAML file for dry-run mode (with `--local`, overlays the candidate on your policies) |
| `--local` | — | No server: evaluate the local policy directory |
| `--resource, -r` | — | Resource for the preceding `--action` (repeatable; `--local`) |
| `--strict` | — | Exit 1 if any check is denied or needs approval (`--local`) |

**Example output (dry-run):**

```
  Dry-run against: ~/.leash/policies/email_agent.yaml
  Agent: test-email-bot
  ──────────────────────────────────────────────────
  ✔ email.read                         → allow  Allowed by email-agent  [ASI02]
  ✔ email.send                         → allow  Allowed by email-agent  [ASI02]
  ✘ file.delete                        → deny   No matching allow rule

  2 of 3 actions allowed
```

---

## leash audit

### audit summary

Overview of all authorize decisions:

```bash
leash audit summary
```

**Example output:**

```
  Audit Summary
  ────────────────────────────────────────
  Total actions:  47
  Allowed:        31
  Denied:         16
  Deny rate:      34.0%

  Per-action breakdown:
    email.read                           12x (✔10 ✘2)
    email.send                            8x (✔5  ✘3)
    file.write                            6x (✔0  ✘6)
```

### audit log

Browse the audit trail with filters:

```bash
leash audit log
leash audit log --agent <agent-id> --limit 50
leash audit log --decision deny
leash audit log --action email.send
```

| Flag | Default | Description |
|------|---------|-------------|
| `--agent` | — | Filter by agent ID |
| `--decision` | — | `allow`, `deny`, or `observe_deny` |
| `--action` | — | Filter by action name |
| `--limit` | 20 | Max entries |

Every entry is hash-chained — tamper with one and every subsequent entry's chain breaks.

### audit scan

Run a multi-check security scan on the audit log:

```bash
leash audit scan
leash audit scan --agent <agent-id>
leash audit scan --window 1800        # 30 min window
leash audit scan --limit 500
```

| Flag | Default | Description |
|------|---------|-------------|
| `--agent` | — | Limit scan to one agent |
| `--window` | 3600 | Time window in seconds |
| `--limit` | 500 | Max entries to scan |

**Checks performed:**

| Check | What it detects |
|-------|-----------------|
| Hash-chain integrity | Tampered or deleted audit entries |
| Suspicious action chains | Multi-step patterns like read → send (exfiltration) |
| Deny storm detection | Burst of denials from one agent (probing / prompt injection) |
| Observe-mode shadows | Actions that would be blocked if observe policies were enforced |
| Permission gap analysis | Unused allows (over-permissioned), repeated probing, wildcard overscoping |

**Example output:**

```
  Leash Audit Security Scan
  ───────────────────────────────────────────────────────
  Entries scanned: 14
  Checks run:      5
  Total findings:  3
  Breakdown:       🟠 2 high, 🟡 1 medium

  ⚠️  WARNINGS — review findings below

  ✔ Audit Log Integrity
    Hash chain intact across 14 entries

  ✔ Suspicious Action Chains
    No suspicious chains (6 patterns checked)

  ⚠ Deny Storm Detection
    1 agent(s) with denial bursts
    🟠 [HIGH] Deny storm: 5 denials  (cursor-agent (3108d3c8…))

  ✔ Observe-Mode Shadows
    No observe-mode shadow denials

  ⚠ Permission Gap Analysis
    2 gap(s) across 2 agent(s)
    🟡 [MEDIUM] 2 unused permission(s)  (cursor-agent (3108d3c8…))
    🟠 [HIGH] Repeated denied action: code.write (5×)  (cursor-agent (3108d3c8…))
```

### audit export

Export the audit log as JSONL (one JSON object per line) — ideal for piping to files, `jq`, or log collectors like Fluentd and Filebeat.

```bash
# Export last 24 hours to stdout
leash audit export --since 24h

# Export denials only, pretty-printed
leash audit export --decision deny --pretty

# Export a specific agent's events to a file
leash audit export --agent <agent-id> --since 7d > agent-events.jsonl

# Pipe to jq for analysis
leash audit export --since 1h | jq '.decision'
```

| Flag | Default | Description |
|------|---------|-------------|
| `--since` | — | Only entries after this time (ISO-8601 or duration: `24h`, `7d`, `30m`) |
| `--agent` | — | Filter by agent ID |
| `--decision` | — | `allow`, `deny`, or `observe_deny` |
| `--action` | — | Filter by action name |
| `--limit` | 10000 | Max entries |
| `--pretty` | — | Pretty-print each JSON event (not pipe-friendly) |

Each exported event includes:

- `chain_intact` — whether the hash chain is valid for this entry
- `signature` — the Ed25519 signature for new keys (legacy RSA signatures still verify)
- `observation` — for observe-mode denials, what would have been blocked

**Environment variables for automatic export:**

| Variable | Description |
|----------|-------------|
| `LEASH_WEBHOOK_URL` | POST every audit event as JSON to this URL in real time |
| `LEASH_AUDIT_SINK` | Append every audit event as JSONL to this file path |

---

### audit tail / verify

The local audit log written by coding-agent hooks (`~/.leash/audit/audit.jsonl`). No server needed.

```bash
leash audit tail              # last 20 decisions
leash audit tail -n 100 -f    # follow
leash audit tail --json       # raw JSON lines
leash audit verify            # check the hash chain (exit 1 if broken)
```

---

## leash status

Quick health check:

```bash
leash status
```

**Example output:**

```
  ✔ Leash is running at http://localhost:8000
  Metrics: 12 data points
    http_requests_total{method="POST",path="/authorize",status="200"} 31
    http_requests_total{method="POST",path="/authorize",status="403"} 16
    ...
```

---

## leash scan

Scan an MCP server's tool surface, classify risks, check policy coverage, and generate starter policies.

### Basic scan

```bash
leash scan -- npx -y @modelcontextprotocol/server-filesystem /data
```

Connects to the MCP server, discovers tools, and displays a risk report.

### Generate a starter policy

```bash
leash scan --generate-policy -- npx -y @modelcontextprotocol/server-filesystem /data
leash scan --generate-policy --save-policy my-policy.yaml -- npx -y @mcp/server-fs /data
```

| Flag | Default | Description |
|------|---------|-------------|
| `--generate-policy` | — | Output a starter YAML policy from scan results |
| `--save-policy FILE` | — | Write generated policy to a file (implies `--generate-policy`) |
| `--format` | `table` | Output format: `table` or `json` (AIBOM) |
| `--agent` | — | Agent ID to check policy coverage against |
| `--agent-name` | — | Agent name pattern to check coverage against |
| `--policy-name` | `auto-scan-policy` | Name for the generated policy |
| `--agent-pattern` | `"*"` | Agent pattern in the generated policy |
| `--timeout` | 30 | Timeout in seconds for MCP server connection |

**Generated policies use this strategy:**

- 🔴 **High risk** (delete, exec, send) → `deny`
- 🟡 **Medium risk** (write, network, filesystem read) → `deny` in `observe` mode
- 🟢 **Low risk** (get, search, info) → `allow`
- ⚪ **Unknown** → `deny` (manual review required)
- Catch-all `*` → `deny`

After generating, validate and customize:

```bash
leash policy validate my-policy.yaml
# Edit the YAML to your needs, then deploy to ~/.leash/policies/
```

---

## leash dashboard

Live terminal dashboard with auto-refresh:

```bash
leash dashboard
leash dashboard --refresh 5   # refresh every 5 seconds
```

| Flag | Default | Description |
|------|---------|-------------|
| `--refresh` | 2 | Refresh interval in seconds |

Shows real-time agent activity, authorize decisions, audit stats, and policy overview. Press `Ctrl+C` to exit.

---

## leash server

### server rotate-keys

Rotate the server signing key pair. New keys are Ed25519/EdDSA; legacy RSA/RS256 keys remain verifiable during the transition.

```bash
leash server rotate-keys
leash server rotate-keys --yes    # skip confirmation
```

| Flag | Description |
|------|-------------|
| `--yes, -y` | Skip confirmation prompt |

After rotation:

- **Existing JWTs** continue to work — the server falls back to the previous key during verification
- **New JWTs** are signed with the new key
- **Audit signatures** are verified against both current and previous keys
- Agents will silently re-register when their old token eventually expires (SDK auto-refresh)

---

## leash doctor

Health-check your deployment for common issues:

```bash
leash doctor
```

Checks:

- Which coding agents are hooked, and that a policy covers each one
- Local policy files are valid, and the local audit chain is intact
- Server reachability (informational only when hooks are installed and no server is running)
- Server key age (warns at 90+ days, suggests `leash server rotate-keys`)
- Database connectivity
- Policy loading

---

## Typical Workflow

```bash
# 1. Start Leash
leash start

# 2. Initialize CLI (auto on first command, but explicit is clearer)
leash init

# 3. Scan an MCP server to understand the attack surface
leash scan -- npx -y @modelcontextprotocol/server-filesystem /data

# 4. Generate a starter policy from the scan
leash scan --generate-policy --save-policy my-policy.yaml -- npx -y @mcp/server-fs /data

# 5. Validate and customize the generated policy
leash policy validate my-policy.yaml
# Edit to fit your needs, then: cp my-policy.yaml ~/.leash/policies/

# 6. Register an agent
leash agents register -n my-code-bot -v openai -t coding

# 7. Test what the agent can do
leash policy test -a code.read -a code.write -a code.execute --agent <agent-id>

# 8. Check the audit trail after some usage
leash audit summary
leash audit log --decision deny
leash audit export --since 24h --pretty

# 9. Scan for suspicious patterns
leash audit scan

# 10. Monitor in real-time
leash dashboard
```
