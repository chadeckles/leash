# Architecture

How Leash works under the hood.

## Design Principles

1. **Deny by default** — if no policy explicitly allows an action, it's denied
2. **Fail closed** — if the server is unreachable, the SDK blocks the action
3. **Observe before enforce** — shadow new policies in production before they can break anything
4. **Append-only audit** — every decision is logged with a hash chain, making tampering detectable
5. **Export everywhere** — audit events flow to JSONL files, webhooks, and SIEM pipelines in real time
6. **Separation of concerns** — policies, identity, and audit are independent modules
7. **OWASP ASI alignment** — maps to the Agentic Security Initiative (2025) threat categories

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Your Agent Code                         │
│   @agent.tool("email.send")                                     │
│   def send(to, body): ...                                       │
└───────────────────────────┬─────────────────────────────────────┘
                            │ SDK / MCP Proxy
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Leash Server                           │
│                                                                 │
│  ┌──────────┐    ┌───────────────┐    ┌───────────────────┐    │
│  │ Identity  │    │ Policy Engine │    │   Audit Service   │    │
│  │ Service   │    │               │    │                   │    │
│  │           │    │  YAML + DB    │    │  Hash-chained     │    │
│  │  JWT/RS256│    │  policies     │    │  append-only log  │    │
│  │  key      │    │  ─────────    │    │  ───────────────  │    │
│  │  rotation │    │  Wildcards    │    │  Tamper detection │    │
│  │           │    │  ABAC         │    │  Chain scanning   │    │
│  │           │    │  Rate limits  │    │  Signatures       │    │
│  └─────┬────┘    └───────┬───────┘    └────────┬──────────┘    │
│        │                 │                      │               │
│        └─────────────────┼──────────────────────┘               │
│                          │                                      │
│                    ┌─────┴─────┐                                │
│                    │  SQLite   │                                │
│                    │  Database │                                │
│                    └───────────┘                                │
└─────────────────────────────────────────────────────────────────┘
```

## Request Flow

Here's what happens when your agent calls a `@tool`-decorated function:

### 1. SDK Intercept

The `@agent.tool` decorator intercepts the function call *before* your code runs.

### 2. Authorize (POST /authorize)

The SDK sends a request to Leash:

```json
{
  "agent_id": "a1b2c3d4-...",
  "action": "email.send",
  "resource": "",
  "context": {}
}
```

### 3. Identity Check

The server validates the JWT token:

- Token must be signed with the server's RSA key
- Token must not be expired
- Issuer must be `leash`
- The `sub` claim must match the `agent_id`

### 4. Policy Evaluation

The policy engine loads all policies (YAML files + database), sorted by priority (highest first):

```
Priority  20:  openclaw.yaml               (OpenClaw-specific rules)
Priority  10:  email_agent.yaml            (email bot rules)
Priority   0:  default.yaml                (catch-all deny)
```

For each policy, the engine checks:

1. **Agent match** — does the agent's name match any pattern in the policy's `agents` list? Uses `fnmatch` wildcards (`*email*`, `my-bot-?`).
2. **Rule match** — does the requested action match a rule's `action` field? Wildcards supported (`email.*`, `*`).
3. **Resource match** — if the rule specifies a `resource`, does the requested resource match?
4. **Conditions (ABAC)** — if the rule has `conditions`, do they all pass against the request context?
5. **Rate limit** — if the rule has a `rate_limit`, has it been exceeded?
6. **Observe mode** — if the policy has `mode: observe`, log the denial but return `allow` with an `observation` field

The **first matching rule wins**. If no rule matches anywhere, the default is **deny**.

### 5. Audit Log

Every authorize decision is automatically logged:

```
┌────────────┬──────────────┬────────────┬──────────────┬───────────┐
│ timestamp  │ agent_id     │ action     │ decision     │ prev_hash │
├────────────┼──────────────┼────────────┼──────────────┼───────────┤
│ 14:22:01   │ a1b2...      │ email.send │ allow        │ 0000...   │
│ 14:22:03   │ a1b2...      │ file.del   │ deny         │ 8f3a...   │
│ 14:22:05   │ c3d4...      │ code.read  │ allow        │ 2b7e...   │
└────────────┴──────────────┴────────────┴──────────────┴───────────┘
                                                              │
                                    Each entry's hash includes ┘
                                    the previous entry's hash
                                    (hash chain = tamper detection)
```

### 6. Response

The SDK receives the decision and either executes the function or blocks it:

```json
{
  "decision": "allow",
  "reason": "Allowed by email-agent rule email.send",
  "matched_policy": "email-agent",
  "matched_rule": "email.send",
  "signature": "a1b2c3...",
  "owasp": ["ASI02"]
}
```

---

## Module Breakdown

### Identity Service (`app/identity/`)

Handles agent registration and authentication.

| Concept | Implementation |
|---------|---------------|
| Agent identity | UUID + RSA key pair per agent |
| Authentication | JWT signed with RS256 (server key) |
| Token expiry | Configurable (default: 168 hours / 7 days) |
| Key rotation | `POST /agents/{id}/rotate` → new key pair + new JWT |
| Storage | SQLite — agent name, vendor, type, tags, public key |

**JWT claims:**

```json
{
  "sub": "agent-uuid",
  "name": "my-agent",
  "type": "coding",
  "tv": 1,
  "iss": "leash",
  "iat": 1711627200,
  "exp": 1712232000
}
```

| Claim | Description |
|-------|-------------|
| `sub` | Agent UUID |
| `name` | Agent name (for policy matching) |
| `type` | Agent type (e.g. `coding`, `cli`, `research`) |
| `tv` | Token version — checked against DB; bumped on key rotation to revoke old tokens |
| `iss` | Issuer (`leash`) |
| `iat` | Issued-at timestamp |
| `exp` | Expiration (default: 7 days from issuance) |

### Policy Engine (`app/policy/`)

Evaluates allow/deny decisions against YAML and database policies.

| Concept | Implementation |
|---------|---------------|
| Policy sources | YAML files on disk + managed policies in DB |
| Merge strategy | DB policies override YAML policies with same name |
| Priority | Higher number = evaluated first |
| Agent matching | `fnmatch` patterns (`*email*`, `bot-?`) |
| Action matching | `fnmatch` patterns (`email.*`, `file.read`) |
| Resource matching | `fnmatch` with path traversal detection |
| ABAC conditions | Key-value checks against request context |
| Rate limiting | Per-agent, per-rule, sliding window |
| Observe mode | `mode: observe` — log would-be denials, never block |
| Default | Deny (no matching rule = denied) |

**Policy evaluation order:**

```
1. Sort all policies by priority (descending)
2. For each policy:
   a. Does agent name match policy's agent patterns? → no: skip
   b. For each rule in the policy:
      i.   Does action match?     → no: skip
      ii.  Does resource match?   → no: skip
      iii. Do conditions pass?    → no: skip
      iv.  Is rate limit OK?      → no: deny (rate limited)
      v.   Return the rule's effect (allow or deny)
3. No match found → deny (default)
```

### Audit Service (`app/audit/`)

Append-only, hash-chained audit trail.

| Concept | Implementation |
|---------|---------------|
| Storage | SQLite — one row per authorize decision |
| Hash chain | Each entry includes SHA-256 of the previous entry |
| Signatures | RSA signature on entry data (server key) |
| Auto-logging | Every `/authorize` call is logged automatically |
| Chain detection | Pattern matching for suspicious multi-action sequences |
| Security scan | 5-check audit scan: integrity, chains, deny storms, observe shadows, permission gaps |
| Tamper detection | Verify hash chain integrity via `/verify/audit-chain` |
| JSONL export | `GET /audit/export` — stream events with chain integrity check per entry |
| Webhook dispatch | `LEASH_WEBHOOK_URL` — fire-and-forget POST with retry |
| File sink | `LEASH_AUDIT_SINK` — append JSONL to a file (Fluentd/Filebeat/Vector) |

**Chain detection patterns (built-in):**

| Pattern | Sequence | Risk |
|---------|----------|------|
| `recon-exfil` | list → read → network.send | Data exfiltration |
| `privesc` | config.read → admin.* | Privilege escalation |
| `prompt-inject` | prompt.* → code.execute | Injection attack |

### MCP Proxy (`sdk/mcp_proxy.py`)

Authorization layer for Model Context Protocol servers.

| Concept | Implementation |
|---------|---------------|
| Tool interception | Wraps MCP tool calls with Leash authorization |
| Auto-discovery | Registers MCP tool names as Leash actions automatically |
| Tool poisoning | Detects tool description changes between sessions |
| Action naming | MCP tool name is used directly as the Leash action (1:1, no transformation) |

### Security Scanner (`sdk/scanner.py`)

Discovery and risk classification for MCP server tool surfaces.

| Concept | Implementation |
|---------|---------------|
| Tool discovery | Connect to MCP server, send `initialize` + `tools/list`, capture manifests |
| Risk classification | 7 categories: destructive, execution, exfiltration, write, network, filesystem, read-only |
| Policy gap analysis | Cross-reference tools against loaded policies, report coverage % |
| Policy generation | `--generate-policy` outputs YAML: deny (high), observe (medium), allow (low) |
| AIBOM output | `--format json` produces machine-readable tool inventory |

---

## Data Model

### Agent (`app/models/agent.py`)

```
agents
├── id            UUID (primary key)
├── name          String (unique)
├── vendor        String (nullable)
├── agent_type    String (nullable)
├── description   Text (nullable)
├── tags          JSON (list of strings)
├── public_key    Text (RSA PEM)
├── token_version Integer (bump to revoke JWTs)
├── created_at    DateTime
├── updated_at    DateTime
└── last_seen_at  DateTime
```

### Policy (`app/models/policy.py`)

```
policies
├── id            Integer (primary key, auto)
├── name          String (unique)
├── yaml_content  Text (full YAML body)
├── priority      Integer (default: 0)
├── active        Boolean (default: true)
├── created_at    DateTime
└── updated_at    DateTime
```

### Audit Entry (`app/models/audit.py`)

```
audit_entries
├── id              Integer (primary key, auto)
├── agent_id        String (FK → agents.id)
├── timestamp       DateTime
├── action          String
├── inputs          JSON (nullable)
├── outputs         JSON (nullable)
├── policy_decision String ("allow" or "deny")
├── prev_hash       String (SHA-256 of prior entry)
└── signature       Text (RSA signature)
```

---

## Security Model

### Cryptography

| What | Algorithm | Key Size |
|------|-----------|----------|
| JWT signing | RS256 (RSA + SHA-256) | 2048-bit |
| Audit signatures | RSA-PSS + SHA-256 | 2048-bit (server key) |
| Hash chain | SHA-256 | 256-bit |

### Key Management

- **Server key pair** — generated on first startup, stored in `.keys/` directory
- **Server key rotation** — `POST /admin/rotate-server-keys` generates a new server key pair; the previous key is retained for graceful JWT/signature fallback
- **Agent key pairs** — generated on registration, public key stored in DB
- **Private key permissions** — `0600` (owner read/write only)
- **Agent key rotation** — `POST /agents/{id}/rotate` generates new key pair + JWT, bumps `token_version` to revoke old tokens
- **Token version** — server-side revocation; every JWT carries a `tv` claim checked against the agent's `token_version` column

### Path Traversal Protection

The policy engine detects path traversal attempts in resource fields:

```python
# These are blocked automatically:
"../../etc/passwd"      # traversal
"/data/../etc/shadow"   # embedded traversal
```

---

## OWASP ASI Mapping

Leash maps to the [OWASP Agentic Security Initiative](https://owasp.org/www-project-agentic-security-initiative/) (2025):

| OWASP ASI | Threat | Leash Control |
|-----------|--------|-----------------|
| ASI01 | Excessive Agency | Action allow/deny with wildcards |
| ASI02 | Tool Misuse | Per-action rules, rate limiting |
| ASI03 | Identity & Privilege | Per-agent JWT, ABAC conditions |
| ASI04 | Prompt Injection | Chain detection for inject → execute |
| ASI05 | Multi-Agent Trust | Cross-agent audit + per-agent scoping |
| ASI06 | Data Exfiltration | Chain detection for recon → exfil |
| ASI07 | Resource Abuse | Rate limiting per agent per action |
| ASI08 | Supply Chain | Tool poisoning detection (MCP proxy) |
| ASI09 | Human-Agent Trust | Signed audit trail, deny-stops-execution |

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/agents` | Register a new agent |
| `GET` | `/agents` | List all agents |
| `GET` | `/agents/{id}` | Get agent details |
| `DELETE` | `/agents/{id}` | Deregister an agent |
| `POST` | `/agents/{id}/rotate` | Rotate agent keys |
| `GET` | `/agents/{id}/permissions` | Effective permissions |
| `POST` | `/authorize` | Authorize an action |
| `POST` | `/policies/managed` | Create a managed policy |
| `GET` | `/policies/managed` | List managed policies |
| `GET` | `/policies/managed/{id}` | Get a managed policy |
| `PUT` | `/policies/managed/{id}` | Update a managed policy |
| `DELETE` | `/policies/managed/{id}` | Delete a managed policy |
| `POST` | `/policies/dry-run` | Dry-run policy evaluation |
| `GET` | `/policies/overview` | Policy overview (all sources) |
| `GET` | `/audit` | Query audit entries |
| `GET` | `/audit/summary` | Audit statistics |
| `GET` | `/audit/export` | Export audit log as JSONL |
| `POST` | `/audit/chains` | Chain detection scan |
| `POST` | `/audit/scan` | Full security scan (5 checks) |
| `POST` | `/scan` | Classify tools + check policy coverage |
| `POST` | `/scan/generate-policy` | Generate starter YAML policy |
| `POST` | `/audit` | Manual audit log entry |
| `GET` | `/verify/audit-chain` | Verify hash chain integrity |
| `GET` | `/health` | Health check |
| `GET` | `/metrics` | Prometheus metrics |
| `GET` | `/dashboard` | Web dashboard |
| `GET` | `/admin/key-info` | Server key age and rotation status |
| `POST` | `/admin/rotate-server-keys` | Rotate server signing keys (admin only) |
