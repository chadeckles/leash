# Start Here: Your First 15 Minutes

New to AI agents? This page takes you from nothing to a protected AI agent,
and explains every step. You don't need to know anything about security.

By the end you will have:

1. installed Leash,
2. connected it to your agent (Claude Code, Copilot CLI, Cursor, Codex or OpenClaw)
   with one command, `leash setup`,
3. watched it block something dangerous,
4. allowed something it was too careful about, and
5. learned how to make it stricter, looser, or turn it off.

You never need to edit a config file.

---

## What is Leash, in one minute?

An **AI agent** is an AI that can *do things* on your computer, not just
chat. Claude Code, for example, can run terminal commands, edit files and
browse the web for you. That's what makes agents useful. It also means that
one bad instruction, or a prompt hidden in a web page it reads, could make it
delete your files or send your passwords somewhere.

**Leash checks every action before the agent takes it.** Just before an
action runs, the agent asks Leash, and Leash answers with one of three
things:

| Answer    | What happens                                                                  | Example                                   |
| --------- | ----------------------------------------------------------------------------- | ----------------------------------------- |
| **allow** | The action goes ahead as normal (your agent's own settings still apply)       | `python hello.py`, editing your project   |
| **ask**   | Your agent stops and asks *you* first                                         | `git push --force`, reading a `.env` file |
| **deny**  | The action is blocked, and the agent is told why                              | `rm -rf ~`, reading your SSH keys         |

Leash comes with sensible rules, so you don't have to write any to get
started. Everything runs on your computer. There's no account, no server and
no data leaves your machine.

!!! tip "Words you'll see"
    See [Words you'll see](#words-youll-see) at the bottom of this page for
    plain-English definitions of *hook*, *policy*, *YAML*, *audit log* and
    the other jargon.

---

## Step 1: Install uv (once)

Leash is a Python program. The easiest way to install Python command-line
tools is **uv**, a fast installer that keeps each tool in its own sandbox so
it can't break anything else.

=== "macOS / Linux"

    ```bash
    curl -LsSf https://astral.sh/uv/install.sh | sh
    ```

=== "Windows (PowerShell)"

    ```powershell
    powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
    ```

=== "I already use pip / pipx"

    You can skip uv and use `pipx install leash` in Step 2 instead.
    (Plain `pip install leash` works too, but pipx and uv keep tools isolated.)

Close and reopen your terminal afterwards, then check that it worked:

```bash
uv --version
```

!!! note "Wait, doesn't Leash block `curl ... | sh`?"
    Yes, when an **agent** tries it, because the agent could be tricked into
    running a script from anywhere. Here **you** are choosing to run uv's
    official installer, which is fine.

## Step 2: Install Leash

```bash
uv tool install leash
```

Check it:

```bash
leash --version
```

!!! warning "`leash: command not found`?"
    uv puts tools in a folder your terminal might not know about yet. Run
    `uv tool update-shell`, then close and reopen your terminal.

## Step 3: Set up Leash

Install your agent first (for example
[Claude Code](https://docs.anthropic.com/en/docs/claude-code) or
[OpenClaw](https://github.com/openclaw/openclaw)) and run it once, so it
creates its settings folder. Then:

```bash
leash setup
```

Leash finds the agents on your computer and asks one question:

```text
  Leash setup — a seatbelt for your AI agents

  Found: Claude Code

  How careful should Leash be?

    1. Strict    Everything in Balanced, plus ask before downloading or installing anything.
    2. Balanced  Block secrets and destructive commands; ask before risky actions. Recommended.
    3. Relaxed   Only block secrets and destructive commands; don't ask before risky actions.

  Choose 1-3 [2]:
```

Press **Enter** for Balanced. (Not sure? Balanced is what most people want,
and you can change it any time with `leash settings`.) Leash then connects
to each agent and checks that it works:

```text
  • Created /Users/you/.leash/policies with the bundled presets
  ✔ claude-code: Installed → /Users/you/.claude/settings.json

  ✔ Checked: Leash blocks `rm -rf ~` for Claude Code

  You're set. Every tool call from Claude Code is now checked before it runs.

  1. Restart Claude Code so it picks up Leash.
  2. Try it: ask your agent to "show me the contents of ~/.ssh".
     Leash will block it. Then run `leash explain` to see why.
```

**What just happened?** Leash added a small entry (a *hook*) to Claude
Code's settings file that says "before any tool runs, ask `leash hook`
first". It also created `~/.leash/policies/`, the folder holding the rules,
and `~/.leash/settings.yaml`, which remembers the level you picked.
It made a backup of any file it changed.

**Restart your agent** so it picks up the new setting.

!!! info "Which agents are supported?"
    Claude Code, GitHub Copilot CLI, Cursor, Codex and OpenClaw. Run
    `leash hosts` to see which ones Leash found and which are connected.
    Installed a new agent later? Just run `leash setup` again.
    For OpenClaw, see [the OpenClaw section](#using-openclaw) below.

!!! note "Setting up in a script?"
    `leash setup --level balanced --yes` answers the questions for you.
    `leash install` is the lower-level command that only connects agents.

## Step 4: Check that it's on

```bash
leash doctor
```

```text
  ✔ hooks: Hooks installed: claude-code (user)
  ✔ policy_yaml: 5 policy file(s) valid
  ✔ policy_claude-code: claude-code is governed by: coding-agent
  ✔ protection: Protection level: Balanced (off: ask before downloading or installing)
  ℹ local_audit: No local audit entries yet
  ℹ server: No server at http://localhost:8000 (not needed for hooks)
```

Green ticks mean you're protected. The ℹ lines are just information: the
audit log fills up once your agent does something, and the server is an
optional extra for developers that you don't need.

## Step 5: See a block, safely

You can ask Leash what it *would* do without involving an agent at all:

```bash
leash policy test --local -a shell.exec -r 'rm -rf ~'
```

```text
  ✘ shell.exec rm -rf ~        → deny   via coding-agent/shell.exec
      Recursive delete of the home directory
```

`shell.exec` means "run a terminal command", and `rm -rf ~` is the command
(it would delete everything in your home folder). Try a few more:

```bash
leash policy test --local \
  -a shell.exec -r 'python hello.py' \
  -a shell.exec -r 'git push --force' \
  -a file.read  -r ~/.ssh/id_rsa
```

## Step 6: Use your agent normally

Open your agent in a project folder and ask it to do something ordinary,
such as *"create hello.py that prints hello, then run it"*. You won't notice
Leash at all. Allowed actions are silent.

Now ask it to do something it shouldn't, like *"show me the contents of
~/.ssh/id_rsa"*. The agent will say it was blocked, with a message like:

```text
Blocked by Leash: SSH private keys are off-limits to agents [coding-agent/shell.exec]
— shell.exec cat ~/.ssh/id_rsa. (The user can run `leash explain` in a terminal for details and options.)
```

For an **ask** (like reading a `.env` file), your agent shows its normal
permission prompt with Leash's reason. You decide yes or no.

## Step 7: See what your agent has been doing

For a quick overview of the last 24 hours:

```bash
leash audit summary
```

```text
  Leash activity · since 24h ago
  ────────────────────────────────────────────────────────────
  42 tool calls checked   (Claude Code 42)
    ✔    39  allowed
    ?     2  asked you first
    ✘     1  blocked

  Why Leash stepped in:
       1×  SSH private keys are off-limits to agents
       2×  .env files usually contain secrets
```

For every single call:

```bash
leash audit tail
```

```text
  2026-09-29T19:52:40  ✔ allow         claude-code  shell.exec python hello.py
  2026-09-29T19:52:41  ✘ deny          claude-code  shell.exec cat ~/.ssh/id_rsa  [coding-agent/shell.exec]
      SSH private keys are off-limits to agents
  2026-09-29T19:52:45  ? ask           claude-code  file.read /Users/you/projects/hello/.env  [coding-agent/file.*]
      .env files usually contain secrets
```

Every decision is written to `~/.leash/audit/audit.jsonl`. Use
`leash audit tail -f` to watch live while your agent works, and `-w` to
see long paths in full. `leash audit verify` checks that nobody has quietly
edited or deleted entries (see *audit log* in the glossary).

## Step 8: "Why was that blocked?" and "Let it through"

```bash
leash explain
```

```text
  Leash asked for your approval  ·  Claude Code  ·  2 minutes ago

  The agent tried to read the file /Users/you/projects/hello/.env
  In folder:         /Users/you/projects/hello
  Why:               .env files usually contain secrets
  Rule:              the "file.*" rule of policy "coding-agent" in ~/.leash/policies/coding_agent.yaml

  What happened:
    Claude Code showed you a permission prompt. If you said yes it ran; if you said no it didn't.

  What you can do:
    • Nothing. If an agent shouldn't do this, Leash did its job.
    • Always allow exactly this for Claude Code:   leash allow
    • Always allow similar ones:  leash allow --pattern '/Users/you/projects/hello/*'
    • See everything your agent did:   leash audit tail
```

If you trust your agent with that project's `.env` file, run:

```bash
leash allow
```

Leash shows you the rule it will add and asks you to confirm. The rule goes
into `~/.leash/policies/my_rules.yaml`, which is checked before everything
else. It only applies to the agent that was blocked, and only to exactly
that file. Changed your mind?

```bash
leash allow --undo
```

`leash explain 2` and `leash allow 2` work on the second most recent block,
and so on.

!!! warning "Agents can't allow themselves"
    Leash blocks agents from running `leash allow` or `leash uninstall`, and
    from editing `~/.leash` or their own hook settings. Only you can loosen
    the rules.

## Step 9: Make Leash stricter or looser

Leash asking too often? Or want it to be more careful while you try
something new? Run:

```bash
leash settings
```

```text
  Leash protection: Balanced

    1. [x] Protect Leash itself  (always on)
    2. [x] Block access to passwords and keys
    3. [x] Block destructive commands
    4. [x] Ask before risky actions
    5. [x] Ask before changing files outside the project
    6. [ ] Ask before downloading or installing

  Type a number to switch it on or off, s/b/r for Strict/Balanced/Relaxed,
  Enter to save, or q to quit without saving.
```

Type `6` and press Enter to tick "Ask before downloading or installing",
then press Enter again to save. The change applies to your agent's very next
action; no restart needed. Or switch level in one go:
`leash settings --level strict`.

"Protect Leash itself" can't be switched off: without it, an agent could
turn Leash off. And agents aren't allowed to run `leash settings` or
`leash setup` themselves.

## Step 10: Turn it off

```bash
leash uninstall            # disconnect from every agent
leash uninstall cursor     # ...or just one
```

Restart your agent afterwards. Your rules and history stay in `~/.leash`
in case you come back. To remove everything, delete that folder and run
`uv tool uninstall leash`.

---

## Using OpenClaw

[OpenClaw](https://github.com/openclaw/openclaw) is a personal AI assistant
you can message from WhatsApp, Telegram, Discord and more. Because other
people (or a sneaky message) can talk to it, guardrails matter even more.

`leash setup` connects OpenClaw automatically if it's installed. To
connect only OpenClaw, run:

```bash
leash install openclaw
```

This adds a small **Leash plugin** to OpenClaw (a plugin is an add-on
OpenClaw loads at startup). Before every tool call, the plugin asks Leash:

* **deny**: OpenClaw blocks the tool call and tells the assistant why.
* **ask**: OpenClaw pauses and asks you to approve. Reply `/approve`, or
  press the approval button in your chat app.
* **allow**: OpenClaw's own permission settings still apply.

If Leash is missing, crashes or is too slow to answer, the plugin blocks
the call. (This is called *fail-closed*: when in doubt, block.)

On top of the coding-agent rules, OpenClaw gets extra protection
(`~/.leash/policies/openclaw.yaml`):

* it can't edit OpenClaw's config or plugins, so it can't switch Leash off;
* it can't read your chat-app logins (`~/.openclaw/credentials`);
* it asks before it controls paired devices (camera, screen), schedules
  jobs that run without you (`cron`), or changes its own gateway.

Restart OpenClaw afterwards (or run `openclaw plugins reload leash`).

!!! note "If `leash install openclaw` says the plugin isn't active yet"
    Leash links the plugin using OpenClaw's own `openclaw` command. If that
    command isn't on your PATH, Leash prints the exact command to run once
    OpenClaw is installed. `leash doctor` will remind you.

---

## Common questions

**Does Leash slow my agent down?**
Hardly. Each check takes about a tenth of a second and happens on your
computer.

**Can Leash make my agent *less* safe?**
It's designed not to. Leash only adds checks. When Leash says *allow*,
your agent's normal permission settings still decide.

**What does Leash protect by default?**
At the Balanced level, Leash blocks: deleting your home folder or disk,
reading SSH keys and cloud passwords, piping downloaded scripts into a shell,
deleting databases or cloud resources, and tampering with Leash itself. It
asks first before: force-pushing, `sudo`, publishing packages, reading `.env`
files, writing or deleting files outside your project, and pushing or posting
anything after the agent has read a web page or GitHub issue. Everything else is allowed. Strict also asks before
downloads and installs; Relaxed stops asking and only blocks. `leash settings`
shows exactly what's on. You can read the full list in
`~/.leash/policies/coding_agent.yaml`, which is commented.

**Is it 100% safe?**
No tool is. Leash sees what the agent *says* it's about to do. A command
can still misbehave in ways the rules don't anticipate, for example a
script that deletes files when you run it. Leash is a strong seatbelt, not
a sandbox. For risky experiments, also use a throwaway folder, a separate
user account or a container.

**Where are my rules and how do I edit them?**
They're in `~/.leash/policies/`. `leash settings` and `leash allow` cover
most needs without editing anything. When you're ready to write your own, read
[Write Your First Policy](write-your-first-policy.md). Always check a
change with `leash policy test --local` and `leash doctor`.

**Can I try Leash without it blocking anything?**
Yes: set `LEASH_MODE=observe` in your agent's environment. Leash then only
records what it *would* have blocked (`leash audit tail`).

---

## Words you'll see

**Agent**
: An AI that can take actions (run commands, edit files, browse), not just chat.

**Tool call**
: One action an agent takes, such as "run this command" or "read this file".

**Hook**
: A setting in your agent that says "before you do X, run this program
  first and do what it says." `leash install` adds one. OpenClaw uses a
  *plugin* instead, which does the same job.

**Policy**
: A file of rules. Leash's policies live in `~/.leash/policies/*.yaml`.

**Rule**
: One line of a policy: an **action** (what kind of thing, e.g.
  `shell.exec` or `file.read`), an optional **resource** (which command or
  file) and an **effect** (`allow`, `ask` or `deny`).

**YAML**
: The simple text format policies are written in. Indentation matters,
  so use spaces, not tabs.

**Glob / pattern**
: A wildcard. `*` means "anything", so `git push*` matches every
  `git push ...` command, and `/Users/you/Desktop/*` matches every file on
  your Desktop.

**First match wins**
: Leash reads the rules from top to bottom and uses the first one that
  fits. That's why exceptions go *above* the rules they override, and why
  `my_rules.yaml` is checked first.

**Audit log**
: The history of every decision. Each entry includes a fingerprint (hash)
  of the one before it, like links in a chain, so editing or deleting an
  entry breaks the chain, and `leash audit verify` notices.

**Protection level**
: Strict, Balanced or Relaxed: which groups of Leash's built-in rules are
  switched on. Pick one in `leash setup`, change it with `leash settings`.

**Observe mode**
: Leash records what it *would* block without actually blocking. Useful
  for trying rules out.

**Fail-closed**
: If Leash itself breaks, the action is blocked rather than let through.

**MCP**
: *Model Context Protocol*, a standard way to plug extra tools (GitHub,
  databases, ...) into agents. Leash checks MCP tool calls too; they show up
  as `mcp.<server>.<tool>`. For Claude Desktop, VS Code and Windsurf,
  `leash setup` offers to protect their MCP servers; see the
  [MCP guide](mcp-proxy-guide.md).

**Prompt injection**
: Instructions hidden in something the agent reads (a web page, a GitHub
  issue, a tool description) that try to make it do something you didn't
  ask. After an agent reads outside content, Leash asks before it pushes,
  posts or sends anything.

**OWASP (LLM01, ASI03, ...)**
: A security organization that publishes lists of the most common AI
  risks. The codes in Leash's rules say which risk each rule addresses.
  They are optional background reading.
