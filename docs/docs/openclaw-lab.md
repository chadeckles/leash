# OpenClaw Lab: Put an AI Agent on a Leash

A hands-on walkthrough (about 10 minutes, or 5 for a live demo). You will:

1. Run Leash and install OpenClaw with the `leash-gate` plugin
2. Trigger **3 tool calls that Leash allows** and **3 that Leash blocks**, and see the decision message for each
3. Prove the audit trail is **tamper-evident** by editing it and watching verification fail

Built for [Cyber Lab Night](https://lnkd.in/eteT72xp) — Colorado Springs, Oct 7.

```
 you (curl / chat) ──▶ OpenClaw gateway ──before_tool_call──▶ leash-gate ──▶ Leash
                                                                             │
                              allow → tool runs   deny → blocked + reason ◀──┤
                                                                             ▼
                                                      signed, hash-chained audit log
```

!!! warning "Use a personal or lab machine"
    OpenClaw is a powerful agent. Don't install it on a managed work laptop without permission. This lab never needs to allow shell access.

## Prerequisites

| Tool | Version | Check |
|---|---|---|
| Python | 3.11+ | `python3 --version` |
| Node.js | 24.16+ (or 26.1+) | `node --version` |
| git, curl, sqlite3 | any | `sqlite3 --version` |
| jq | optional, for pretty output | `jq --version` |
| An LLM API key | optional, only for the chat step | Anthropic or OpenAI |

You'll use three terminals: **T1** Leash server, **T2** OpenClaw gateway, **T3** demo commands.

## Part 1 — Start Leash (T1)

```bash
git clone https://github.com/chadeckles/leash.git && cd leash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
leash start
```

Leash is now on `http://localhost:8000`. Leave it running.

## Part 2 — Register the agent (T3)

```bash
cd leash && source .venv/bin/activate
leash agents register --name openclaw-agent --vendor openclaw --type assistant
```

```
  ✔ Registered 'openclaw-agent'
  ...
  Policies applied: default, openclaw-policy
  Effective rules:  ✔ 11 allow   ✘ 13 deny

  Token saved → ~/.leash/openclaw-agent.json
```

The name contains `openclaw`, so the built-in [`openclaw.yaml`](https://github.com/chadeckles/leash/blob/main/app/policies/openclaw.yaml) policy applies: reads, search, memory, and session tools are allowed; `exec`, `write`, `edit`, `browser`, and other high-risk tools are denied. See it with:

```bash
leash agents permissions openclaw-agent
```

## Part 3 — Install OpenClaw and the plugin (T2)

```bash
npm install -g openclaw@latest        # or: curl -fsSL https://openclaw.ai/install.sh | bash
openclaw onboard                       # local setup; add your LLM key here if you want the chat step

cd leash
openclaw plugins install --link ./integrations/openclaw/leash-gate --force
openclaw plugins enable leash-gate
openclaw plugins inspect leash-gate --runtime --json   # look for the before_tool_call hook

openclaw gateway run                   # leave running; decisions print here
```

!!! tip "npm 11.16+"
    If npm blocks install scripts, use `npm install -g openclaw@latest --allow-scripts=openclaw`.

## Part 4 — Allow and deny (T3)

Grab the gateway token and define a helper that calls OpenClaw's tool API. Every call goes through the `before_tool_call` hook, exactly as if the model had chosen the tool.

```bash
export OC_TOKEN=$(jq -r '.gateway.auth.token' ~/.openclaw/openclaw.json)   # or copy it from `openclaw onboard` output

oc() {  # usage: oc <tool> ['<json args>']
  local args="${2:-}"; [ -z "$args" ] && args='{}'
  curl -s -w '  → HTTP %{http_code}\n' http://127.0.0.1:18789/tools/invoke \
    -H "Authorization: Bearer $OC_TOKEN" -H 'Content-Type: application/json' \
    -d "{\"tool\":\"$1\",\"args\":$args}"
}

echo "Hello, Cyber Lab Night!" > ~/.openclaw/workspace/hello.txt
```

### ✔ Three actions Leash allows

```bash
oc session_status
oc sessions_list
oc read '{"path":"hello.txt"}'
```

Each returns `HTTP 200` with the tool's result, and the gateway (T2) prints:

```
🐕 Leash ALLOW session_status [openclaw-policy/session_status] — OpenClaw may check session status
🐕 Leash ALLOW sessions_list [openclaw-policy/sessions_list] — OpenClaw may list active sessions
🐕 Leash ALLOW read hello.txt [openclaw-policy/read] — OpenClaw may read files in the workspace
```

### ✘ Three actions Leash denies

```bash
oc write  '{"path":"pwned.txt","content":"owned by the agent"}'
oc edit   '{"path":"hello.txt","oldText":"Hello","newText":"Goodbye"}'
oc browser '{"action":"open","url":"https://example.com"}'
```

Each returns `HTTP 403` with Leash's reason, and the tool **never runs** (`pwned.txt` is never created):

```json
{"ok":false,"error":{"type":"tool_call_blocked","message":"🐕 Blocked by Leash [openclaw-policy/write]: File writes are blocked — uncomment the allow rule below to enable"}}
```

```
🐕 Leash DENY  write pwned.txt [openclaw-policy/write] — File writes are blocked — uncomment the allow rule below to enable
🐕 Leash DENY  edit hello.txt [openclaw-policy/edit] — File edits are blocked — uncomment to enable
🐕 Leash DENY  browser https://example.com [openclaw-policy/browser] — Browser control is blocked — high risk, enables arbitrary web actions
```

!!! note "Why not `exec` over HTTP?"
    OpenClaw's gateway already refuses `exec` (and a few other dangerous tools) on `/tools/invoke`, before plugins run. You'll see Leash block `exec` in the chat step below instead. Don't remove that built-in guard for a demo.

### Optional — ask the agent (needs an LLM key)

```bash
openclaw agent exec "Run whoami in the shell and tell me the result."
openclaw agent exec "Read hello.txt and summarize it."
```

The model tries `exec`, Leash blocks it, and the assistant explains that it was *"Blocked by Leash … Shell execution is blocked"*. The `read` goes through.

## Part 5 — The evidence (T3)

```bash
leash audit log
```

```
  ✘ 2026-10-07 18:05  299d5b8b-645  browser https://example.com
  ✘ 2026-10-07 18:05  299d5b8b-645  edit hello.txt
  ✘ 2026-10-07 18:05  299d5b8b-645  write pwned.txt
  ✔ 2026-10-07 18:04  299d5b8b-645  read hello.txt
  ✔ 2026-10-07 18:04  299d5b8b-645  sessions_list
  ✔ 2026-10-07 18:04  299d5b8b-645  session_status
```

```bash
leash audit summary                                  # allow/deny counts
leash audit export --pretty | tail -40               # full signed entries (signature, prev_hash)
curl -s http://localhost:8000/verify/audit-chain | jq
```

```json
{"valid": true, "entries_checked": 6, "broken_at": null, "detail": "Hash chain intact across 6 entries."}
```

Prefer a UI? Open **http://localhost:8000/dashboard**, or run `leash dashboard` in the terminal.

## Part 6 — Tamper with the log

Pretend you're an attacker covering your tracks: rewrite the `write` denial as an allow.

```bash
sqlite3 leash.db "UPDATE audit_log SET policy_decision='allow' WHERE action LIKE 'write%';"

curl -s http://localhost:8000/verify/audit-chain | jq
```

```json
{"valid": false, "entries_checked": 5, "broken_at": 5, "detail": "Hash chain broken at entry #5 — expected prev_hash '9fbabfca…', found '453eb77b…'"}
```

Each entry stores the hash of the one before it, so changing one entry breaks the link to the **next** one. The scanner calls it out too:

```bash
leash audit scan          # 🔴 CRITICAL — Audit Log Integrity
```

!!! note
    Tamper with an entry that has at least one entry after it (like `write` here). The newest entry has nothing linking to it yet. The signatures on each entry are another layer of protection.

## Reset

```bash
# T1: Ctrl-C, then:
rm -f leash.db leash.db-wal leash.db-shm    # fresh audit log (keeps .keys/)
leash start
leash agents register --name openclaw-agent --force   # T3
```

To remove the plugin: `openclaw plugins disable leash-gate`.

## No OpenClaw? Same demo, Leash only

If OpenClaw won't install, the Leash side of the story still works with Parts 1, 2, 5, and 6:

```bash
leash policy test --agent openclaw-agent -a read -a web_search -a session_status -a exec -a write -a browser
```

Or run the plugin logic itself with Node (no OpenClaw needed) — it prints the same `🐕 Leash ALLOW/DENY` lines:

```bash
node --experimental-strip-types integrations/openclaw/leash-gate/gate.test.ts
```

## Try it yourself

- Allow writes: in `app/policies/openclaw.yaml`, change the `write` rule to `effect: allow`, save (hot reload), and rerun `oc write ...`.
- Scope it: add `resource: "notes/*"` to the allow rule so only that folder is writable.
- Shadow it: put new rules in a policy with `mode: observe` and check `leash audit log --decision observe_deny`.

---

## Presenter notes (5–10 min lightning talk)

| Time | Beat | Show |
|---|---|---|
| 0:00 | Hook: "Your AI agent has a shell. Who said yes?" | Title slide / README |
| 0:45 | Architecture: agent → plugin → Leash → audit | Diagram at the top of this page |
| 1:30 | Policy is 10 lines of YAML | `openclaw.yaml` in the editor |
| 2:30 | 3 allows | T3 `oc` calls + T2 `ALLOW` lines |
| 3:30 | 3 denies | 403 + `Blocked by Leash` reason + T2 `DENY` lines; `ls ~/.openclaw/workspace` shows no `pwned.txt` |
| 4:30 | *(if time)* Chat: "run whoami" | Assistant explains the block |
| 5:30 | Evidence | `leash audit log`, `/verify/audit-chain` → `valid: true` |
| 6:30 | Tamper | `sqlite3 UPDATE…` → `valid: false`, `leash audit scan` → CRITICAL |
| 7:30 | Wrap-up: deny by default, observe first, signed log | Repo link / QR code |

**Before the event**

- [ ] Dry-run the whole lab on the demo laptop, offline from the venue Wi-Fi if possible
- [ ] Pre-install OpenClaw and the plugin; confirm `openclaw plugins inspect leash-gate --runtime --json` shows the hook
- [ ] Confirm the gateway token path, the `read`/`edit`/`browser` argument names, and that each tool reaches the hook (a `404` means the tool isn't enabled in your OpenClaw profile — swap in another denied tool such as `canvas`)
- [ ] Reset the audit log so the demo starts clean
- [ ] Increase terminal font size; put T2 (gateway log) where the audience can see it
- [ ] Keep the "No OpenClaw?" fallback ready in a tab
