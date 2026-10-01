# leash-gate — Leash authorization for OpenClaw

An [OpenClaw](https://github.com/openclaw/openclaw) plugin that asks [Leash](../../../README.md) before **every** tool call. It registers a `before_tool_call` hook, sends the tool name and main argument to `POST /authorize`, and blocks the call when Leash says no. Every decision lands in Leash's signed, hash-chained audit log.

```
🐕 Leash ALLOW read README.md [openclaw-policy/read] — read is allowed — it can read files in its workspace
🐕 Leash DENY  exec whoami [openclaw-policy/exec] — exec is blocked — it could run any shell command on your computer
```

## Install

Requires a running Leash server and OpenClaw (Node 24.16+). The easy way, from the repo root:

```bash
python3 integrations/openclaw/lab.py setup   # register, install, enable, configure the gateway
```

Or by hand:

```bash
leash agents register --name openclaw-agent          # writes ~/.leash/openclaw-agent.json
openclaw plugins install --link ./integrations/openclaw/leash-gate --force --accept-capabilities
openclaw plugins enable leash-gate
openclaw plugins inspect leash-gate --runtime --json # should list the before_tool_call hook
```

Restart the gateway after enabling. Use `openclaw plugins reload leash-gate` after editing the code.

## Config

All optional. Set under `plugins.entries.leash-gate.config` in `~/.openclaw/openclaw.json`:

| Key | Default | Purpose |
|---|---|---|
| `leashUrl` | `http://127.0.0.1:8000` | Leash server |
| `identityFile` | `~/.leash/openclaw-agent.json` | Identity from `leash agents register` |
| `timeoutMs` | `5000` | Per-call timeout for `/authorize` |

## Behavior

- **action** = OpenClaw tool name (`read`, `exec`, `browser`, …), matching [`app/policies/openclaw.yaml`](../../../app/policies/openclaw.yaml).
- **resource** = first string among `command`, `path`, `file_path`, `filePath`, `url`, `query`, `target` (max 512 chars).
- **context** = `{source: "openclaw", openclaw_agent, session}` for ABAC conditions.
- **deny** → `{block: true, blockReason: "🐕 Blocked by Leash [policy/rule]: reason"}`. The model sees the reason; `/tools/invoke` returns HTTP 403 `tool_call_blocked`.
- **allow** and **observe-mode** decisions let the call proceed.
- **Fail-closed**: an unreachable server, timeout, missing identity file, or non-200 response blocks the call. A 401 re-reads the identity file once (in case you re-registered).

## Test without OpenClaw

`gate.ts` has no OpenClaw imports, so you can drive it with plain Node against a live Leash:

```bash
leash agents register --name openclaw-agent
node --experimental-strip-types gate.test.ts   # LEASH_URL / LEASH_IDENTITY to override
```

Expected: 3 allowed (`read`, `web_search`, `session_status`), 3 blocked (`exec`, `write`, `browser`), and fail-closed when Leash is down.
