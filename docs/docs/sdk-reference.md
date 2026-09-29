# SDK Reference

The Python SDK wraps the authorize → execute → audit cycle so your agent code stays clean.

## Installation

Install the SDK/CLI/engine core with `pip install leash` or `uv add leash`:

```python
from leash import LeashAgent
```

## Quick Example

```python
from leash import LeashAgent

agent = LeashAgent(name="my-agent")

@agent.tool("email.read")
def read_inbox(mailbox: str):
    return gmail.read(mailbox)

@agent.tool("email.send")
def send_reply(to: str, body: str):
    return gmail.send(to, body)

with agent:
    read_inbox("user@example.com")     # Leash checks permission first
    send_reply("boss@co.com", "Done")  # checked too
```

If the action is denied, the function **doesn't run**. If Leash is unreachable, it **denies by default** (fail-closed).

---

## LeashAgent

### Constructor

```python
LeashAgent(
    base_url=None,
    *,
    name="leash-agent",
    vendor=None,           # e.g. "openai", "anthropic"
    agent_type=None,       # e.g. "coding", "research"
    tags=None,             # e.g. ["production", "team-a"]
    token_file="<auto>",
    auto_register=True,
    fail_closed=True,
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `base_url` | `str \| None` | `$LEASH_URL` or `http://localhost:8000` | Leash server URL |
| `name` | `str` | `leash-agent` | Agent name — this is how policies match you |
| `vendor` | `str` | `None` | Optional vendor label for fleet management |
| `agent_type` | `str` | `None` | Optional type label for filtering |
| `tags` | `list[str]` | `None` | Optional tags for grouping |
| `token_file` | `str \| Path \| None` | `~/.leash/agents/<name>.json` | Where to cache the JWT. `None` = no caching. A legacy `./.leash_identity.json` is still read if it matches the agent name |
| `auto_register` | `bool` | `True` | Auto-register with Leash on first use |
| `fail_closed` | `bool` | `True` | **Deny** actions when Leash is unreachable |

!!! warning "Always use fail_closed=True in production"
    Setting `fail_closed=False` means your agent will execute actions even when Leash is down. This is useful for development but dangerous in production.

### connect()

```python
agent.connect() → LeashAgent
```

Register with Leash (or load a cached identity from disk). Called automatically if `auto_register=True`.

Raises `ConnectionError` with a clear message if the server is unreachable.

### Automatic Token Refresh

If a JWT expires (for example after server key rotation), the SDK refreshes it transparently:

1. An `authorize()` or `audit()` call returns **401** for an expired token
2. The SDK silently discards the old identity and cached token file
3. Re-registers with the server to get a fresh JWT
4. Retries the original request

If the server reports the token was revoked, the SDK raises `LeashRevoked` and does **not** re-register. An operator must re-register or rotate the agent.

### authorize()

```python
agent.authorize(
    action: str,
    resource: str = "",
    context: dict | None = None,
) → dict
```

Ask Leash for permission. Returns the full response:

```python
{
    "agent_id": "abc-123",
    "action": "email.read",
    "decision": "allow",       # or "deny"
    "reason": "Agent may read emails",
    "matched_policy": "email-agent",
    "matched_rule": "email.read",
    "signature": "a1b2c3...",
    "owasp": ["ASI02"]
}
```

### audit()

```python
agent.audit(
    action: str,
    decision: str,
    inputs: dict | None = None,
    outputs: dict | None = None,
) → dict
```

Log an action to the audit trail manually. The `@agent.tool` decorator does this automatically, but you can call it directly for custom flows.

### close()

```python
agent.close()
```

Close the underlying HTTP connection. Called automatically when used as a context manager.

---

## @agent.tool Decorator

The main way to integrate Leash into your agent:

```python
@agent.tool(
    action: str,
    *,
    resource: str = "",
    context: dict | None = None,
    on_deny: str = "raise",
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `action` | `str` | required | Action name sent to Leash |
| `resource` | `str` | `""` | Optional resource for scoped rules |
| `context` | `dict` | `None` | Optional ABAC context |
| `on_deny` | `str` | `"raise"` | What to do when denied |

### on_deny Options

| Value | Behavior |
|-------|----------|
| `"raise"` | Raises `LeashDenied` exception (default) |
| `"return_none"` | Returns `None` silently |
| `"log"` | Logs a warning and returns `None` |

### Example with All Options

```python
@agent.tool(
    "db.query",
    resource="customers.*",
    context={"user_role": "analyst"},
    on_deny="log",
)
def query_customers(sql: str):
    return db.execute(sql)
```

### What Happens Under the Hood

1. **Authorize** — asks Leash if the action is allowed
2. **Execute** — runs your function (only if allowed)
3. **Audit** — logs the result to the audit trail

If Leash is unreachable and `fail_closed=True`, the function does not execute and is treated as denied.

---

## agent.guard()

Wrap existing callables without decorators — useful for LangChain tools or any list of functions:

```python
agent.guard(
    tools: list,
    *,
    on_deny: str = "raise",
    action_prefix: str = "",
) → list
```

### Plain Functions

```python
def search(query: str): ...
def calculator(expr: str): ...
def send_email(to: str, body: str): ...

guarded = agent.guard([search, calculator, send_email])
# guarded[0]("latest news")  → checks "search" action
# guarded[1]("2+2")          → checks "calculator" action
# guarded[2]("a@b.com", "hi") → checks "send_email" action
```

The action name is taken from `func.__name__`.

### With Action Prefix

```python
guarded = agent.guard([search, calculator], action_prefix="mybot.")
# Actions become "mybot.search", "mybot.calculator"
```

### LangChain Tools

```python
from langchain.tools import Tool

tools = [
    Tool(name="search", func=search_fn, description="Search the web"),
    Tool(name="calculator", func=calc_fn, description="Do math"),
]

guarded = agent.guard(tools)
# Each tool's .name becomes the Leash action
```

---

## agent.discover()

Auto-create a Leash policy from your registered tools:

```python
agent.discover(
    *,
    default_effect: str = "deny",
    policy_name: str | None = None,
    policy_priority: int = 0,
) → dict
```

```python
@agent.tool("email.read")
def read(): ...

@agent.tool("email.send")
def send(): ...

# Creates a policy with one rule per tool (default: deny)
result = agent.discover(policy_name="email-bot-policy")
```

This is useful for bootstrapping: `discover` creates the policy skeleton, then an admin flips specific tools to `allow`.

> **Note:** agents can't grant themselves permissions. Unless the agent holds an admin token, `discover()` only succeeds with `default_effect="deny"` (the generated policy is deny-only and scoped to the agent's own ID). `default_effect="allow"` returns 403. Policy names created by non-admin agents are namespaced as `<agent_id>/<name>`.

---

## Context Manager

Use `with` for clean setup/teardown:

```python
with LeashAgent(name="my-agent") as agent:
    @agent.tool("file.read")
    def read_file(path):
        return open(path).read()

    read_file("/data/report.txt")
# Connection is closed automatically
```

---

## In-Process Policy Engine

Use `leash.engine` when you want local policy decisions without the FastAPI server or database. The engine has no FastAPI, SQLAlchemy, or HTTP imports.

```python
from leash.engine import PolicyEngine

engine = PolicyEngine.from_directory("~/.leash/policies")
decision = engine.evaluate("agent-1", "email.send", agent_name="email-bot")
if not decision.allowed:
    print(decision.reason)
```

`evaluate()` returns a `Decision` with `decision`, `reason`, `matched_policy`, `matched_rule`, `owasp`, `observation`, and `.allowed`. Policy directories are cached and re-scanned at most once per second.

## LeashDenied Exception

Raised when an action is denied (with `on_deny="raise"`):

```python
from leash import LeashDenied

try:
    delete_file("/important.txt")
except LeashDenied as e:
    print(e.action)          # "delete_file"
    print(e.reason)          # "Agent is not allowed to delete files"
    print(e.matched_policy)  # "my-agent-policy"
    print(e.matched_rule)    # "delete_file"
    print(e.response)        # full response dict
```

---

## Properties

| Property | Type | Description |
|----------|------|-------------|
| `agent.agent_id` | `str \| None` | Agent UUID (set after connect) |
| `agent.token` | `str \| None` | JWT token (set after connect) |
| `agent.registered_tools` | `list[str]` | Action names registered via `@tool` or `guard()` |
| `agent.fail_closed` | `bool` | Whether to deny when Leash is unreachable |

---

## Complete Real-World Example

An agent that reads customer data and generates reports, with proper error handling:

```python
from leash import LeashAgent, LeashDenied

agent = LeashAgent(
    name="report-generator",
    vendor="internal",
    agent_type="analytics",
    tags=["production"],
)

@agent.tool("db.query", context={"user_role": "analyst"})
def query_customers(sql: str):
    return db.execute(sql)

@agent.tool("file.write", resource="/reports/*")
def write_report(path: str, content: str):
    with open(path, "w") as f:
        f.write(content)

with agent:
    try:
        data = query_customers("SELECT * FROM customers LIMIT 100")
        write_report("/reports/daily.csv", data.to_csv())
        print("Report generated!")
    except LeashDenied as e:
        print(f"Blocked: {e.reason}")
    except ConnectionError:
        print("Cannot reach Leash — aborting")
```
