# OpenClaw Integration Guide

[OpenClaw](https://github.com/openclaw/openclaw) is a popular open-source personal AI assistant. You can message it from WhatsApp, Telegram, Slack, Discord and more, and it can run shell commands, browse the web, read and write files, control paired devices and schedule jobs. That's a lot of power in something other people can send messages to, so a single malicious message could try to make it do any of those things.

Leash adds a check in front of every one of those tool calls.

!!! tip "New to all this?"
    [Start Here](start-here.md) walks through installing Leash from scratch in plain English.

## Setup

```bash
uv tool install leash     # or: pipx install leash
leash install openclaw
```

Then restart OpenClaw (or run `openclaw plugins reload leash`) and check:

```bash
leash doctor
```

That's the whole setup. There's no server and no agent registration.

### What `leash install openclaw` does

1. Copies a small, dependency-free plugin to `~/.leash/integrations/openclaw/`.
2. Links and enables it with OpenClaw's own CLI: `openclaw plugins install --link ~/.leash/integrations/openclaw`, then `openclaw plugins enable leash`. Leash never edits `openclaw.json` itself.
3. Installs `~/.leash/policies/openclaw.yaml`. If you had the old server-era OpenClaw preset, it's backed up to `~/.leash/backups/` first.

If the `openclaw` command isn't on your PATH, Leash still writes the plugin and prints the exact `openclaw plugins install --link …` command to run later. `leash doctor` warns you until the plugin is linked.

To remove it, run `leash uninstall openclaw`. This unlinks the plugin through the OpenClaw CLI and deletes the plugin files.

## How it works

```
message ─▶ OpenClaw ─▶ before_tool_call ─▶ Leash plugin ─▶ leash hook openclaw
                                                                  │
                         block / ask for approval / continue ◀────┘
```

The plugin registers a `before_tool_call` hook. For every tool call it runs `leash hook openclaw`, passing it the tool name, its parameters, the working directory and the session. Leash evaluates your policies locally and answers:

| Leash says | OpenClaw does |
|---|---|
| **allow** | Continues. OpenClaw's own `tools.allow` / `tools.deny` and approval settings still apply. |
| **ask** | Pauses and asks you to approve (`/approve` in chat, or the approval button in apps that support it). Only *allow once* is offered; to allow permanently, use `leash allow` (below). |
| **deny** | Blocks the call and tells the assistant why. |

**Fail-closed:** if `leash` is missing, crashes, returns something unexpected or takes longer than 10 seconds, the plugin blocks the call. OpenClaw itself also blocks calls when a `before_tool_call` hook fails.

Every decision is written to `~/.leash/audit/audit.jsonl`. Watch it live with `leash audit tail -f`.

## What's protected by default

OpenClaw's file and shell tools use the same actions as coding agents:

| OpenClaw tool | Leash action | Resource |
|---|---|---|
| `exec` | `shell.exec` | the command, and each sub-command |
| `read` | `file.read` | absolute path |
| `write`, `edit`, `apply_patch` | `file.write` | absolute path |
| `web_fetch` | `web.fetch` | URL |
| `web_search` | `web.search` | query |
| MCP tools | `mcp.<server>.<tool>` | |
| everything else (`browser`, `cron`, `nodes`, `message`, `gateway`, `sessions_spawn`, …) | `tool.<name>` | |
| Code Mode's outer `exec` (runs JavaScript) | `tool.code_mode_exec` | |

This means all of the [coding-agent guardrails](hooks.md#the-policy) apply to OpenClaw: `rm -rf ~`, reading SSH keys and cloud credentials, `curl … | sh`, and tampering with `~/.leash` are denied, while force-push, `sudo`, reading `.env` and writing outside the workspace ask first. (For OpenClaw, the workspace is `OPENCLAW_WORKSPACE_DIR` or `~/.openclaw/workspace`.)

On top of that, `~/.leash/policies/openclaw.yaml` adds:

| Rule | Effect |
|---|---|
| Edit or delete `openclaw.json` or installed plugins (`extensions/`) | **deny**, so the assistant can't switch Leash off |
| Read or touch `~/.openclaw/credentials/` (channel logins) | **deny** |
| `openclaw plugins …`, `openclaw config …`, shell access to `openclaw.json` | ask |
| Read `openclaw.json` (it can contain API keys) | ask |
| `tool.gateway` (can change config, restart or update OpenClaw) | ask |
| `tool.nodes` (camera, screen, location on paired devices) | ask |
| `tool.cron` (jobs that run without you) | ask |
| `tool.message` | allow, rate-limited to 30 per minute |

Anything not listed falls through to the coding-agent policy, which allows it.

## Everyday use

```bash
leash audit tail -f           # watch what OpenClaw does
leash explain                 # why was the last call blocked or held for approval?
leash allow                   # allow exactly that from now on (asks you to confirm)
leash allow --undo            # changed your mind
```

`leash allow` writes to `~/.leash/policies/my_rules.yaml`, which is checked before every other policy. By default the rule only applies to OpenClaw (`conditions: {host: openclaw}`). The assistant itself can't run `leash allow`: the coding-agent policy denies it, and the command requires an interactive terminal.

## Customizing

Edit `~/.leash/policies/openclaw.yaml`, or add rules to `my_rules.yaml`. Rules are checked top to bottom and the first match wins. Some examples:

```yaml
# Never let the assistant use the browser
- action: "tool.browser"
  effect: deny
  reason: "No browser automation"

# Ask before it spawns sub-agents
- action: "tool.sessions_spawn"
  effect: ask
  reason: "Sub-agents need approval"

# Deny all shell commands (a read-only assistant)
- action: "shell.exec"
  effect: deny
  reason: "This assistant may not run commands"
```

Test changes without involving OpenClaw:

```bash
leash policy test --local --agent openclaw -a tool.cron -a shell.exec -r 'ls -la'
leash doctor
```

Not sure what your assistant calls? Run it for a while with `LEASH_MODE=observe` set in OpenClaw's environment (decisions are logged, nothing is blocked), then read `leash audit tail`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `leash doctor`: *plugin files exist but aren't linked* | Run the `openclaw plugins install --link …` command it prints, then restart OpenClaw. |
| Every tool call is blocked with *"Blocked by Leash (fail-closed): …"* | The plugin can't run `leash`. Check that `leash --version` works for the user OpenClaw runs as, then re-run `leash install openclaw` (it records the full path to `leash`). |
| Nothing shows up in `leash audit tail` | Check `openclaw plugins inspect leash` (add `--runtime` on newer OpenClaw to list its hooks) and make sure OpenClaw was restarted after installing. |
| A config using `$include` isn't detected as linked | `leash doctor` searches `openclaw.json` for the plugin path. If you split your config, verify with `openclaw plugins inspect leash`. |

## Advanced: server and SDK

If you build your own agents on OpenClaw's code, or want central policy management, you can also use the [Leash server and Python SDK](sdk-reference.md). Most people don't need this. The plugin above covers OpenClaw's own tool calls with no server.
