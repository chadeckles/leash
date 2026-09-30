# Logs & SIEM

Leash doesn't ship its own monitoring dashboard for hooked agents. Every
decision is written as one JSON line to a local file that any log shipper can
forward, so it ends up next to the rest of your logs.

```bash
leash audit summary          # quick plain-English overview (last 24h)
leash audit tail -f          # watch live
leash audit verify           # check nothing was edited or deleted
```

## Where the log is

`~/.leash/audit/audit.jsonl` (mode 0600), or `$LEASH_AUDIT_LOG` if set. The
file is append-only, one record per line.

## Record format

These fields are stable. New optional fields may be added; existing ones won't
change meaning.

| Field | Type | Meaning |
|---|---|---|
| `ts` | string | ISO 8601 UTC timestamp (milliseconds) |
| `host` | string | Agent family: `claude-code`, `copilot`, `cursor`, `codex`, `openclaw`, or `mcp` for the MCP proxy |
| `agent` | string | Agent name the policy matched on (`$LEASH_AGENT`, else `host`) |
| `session` | string | Agent session ID, when the agent provides one |
| `cwd` | string | Working directory of the call |
| `tool` | string | The agent's own tool name, e.g. `Bash`, `Read`, `shell`, `exec` |
| `request` | string | The Leash action and resource that decided, e.g. `shell.exec rm -rf ~` or `file.read /home/maya/.ssh/id_ed25519` (max 2000 chars) |
| `decision` | string | `allow`, `ask`, `deny`, or `observe_ask` / `observe_deny` in observe mode |
| `reason` | string | Plain-English reason from the matching rule |
| `policy` | string | Name of the policy that decided (e.g. `coding-agent`, `my-rules`) |
| `rule` | string | The `action` pattern of the rule that decided (e.g. `file.*`) |
| `group` | string | Protection group of the rule (`tamper`, `secrets`, `destructive`, `production`, `risky`, `untrusted`, `outside_workspace`, `network`); absent for your own rules |
| `ms` | number | Time taken to decide, in milliseconds |
| `call` | string | First action of the tool call, when it differs from `request` (optional; e.g. a multi-command shell line) |
| `observations` | array | `{request, observation}` entries from `monitor` rules that matched without deciding (optional) |
| `mcp_client` | string | MCP proxy only: the app, e.g. `claude-desktop`, `vscode` |
| `mcp_server` | string | MCP proxy only: the server's name in the app's config |
| `approved` | boolean | MCP proxy only: your answer when Leash asked through the app |
| `mcp_withheld` | boolean | MCP proxy only: `true` when a tool was hidden because its description changed or looked suspicious |
| `prev` | string | SHA-256 of the previous line |
| `hash` | string | SHA-256 of this record; `leash audit verify` checks the chain |

Example:

```json
{"agent":"claude-code","cwd":"/home/maya/project","decision":"deny","group":"secrets","hash":"beb454…","host":"claude-code","ms":59.6,"policy":"coding-agent","prev":"0000…","reason":"SSH keys are off-limits to agents","request":"file.read /home/maya/.ssh/id_ed25519","rule":"file.*","session":"s1","tool":"Read","ts":"2026-01-31T18:31:15.168+00:00"}
```

## Forwarding

Point your shipper at the file and parse each line as JSON. Replace
`/home/USER` with the real home directory.

=== "Splunk Universal Forwarder"

    `inputs.conf`:

    ```ini
    [monitor:///home/USER/.leash/audit/audit.jsonl]
    sourcetype = _json
    index = main
    ```

=== "Elastic Agent / Filebeat"

    ```yaml
    filebeat.inputs:
      - type: filestream
        id: leash-audit
        paths: ["/home/USER/.leash/audit/audit.jsonl"]
        parsers:
          - ndjson:
              target: ""
              add_error_key: true
    ```

=== "Vector"

    ```toml
    [sources.leash]
    type = "file"
    include = ["/home/USER/.leash/audit/audit.jsonl"]

    [transforms.leash_json]
    type = "remap"
    inputs = ["leash"]
    source = ". = parse_json!(.message)"

    [sinks.out]
    type = "console"          # swap for splunk_hec_logs, elasticsearch, datadog_logs, …
    inputs = ["leash_json"]
    encoding.codec = "json"
    ```

The shipper needs read access to the file; it's readable only by its owner,
so run the shipper as that user or grant access deliberately.

## Useful searches

- **Blocked calls:** `decision=deny`
- **Secret access attempts:** `group=secrets`
- **What observe mode would have stopped:** `decision=observe_*`
- **Per-agent volume:** count by `host`

Run `leash audit verify` from time to time (or in a cron job): a non-zero exit
means the local file was edited, truncated or reordered.
