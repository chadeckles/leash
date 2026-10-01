# Contributing to Leash

Thanks for your interest in contributing! Leash is an open-source AI agent authorization layer, and we welcome contributions of all kinds — bug fixes, new features, documentation, and policy examples.

## Quick Setup

```bash
# Clone the repo
git clone https://github.com/chadeckles/leash.git
cd leash

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode (makes the 'leash' CLI command available)
pip install -e .

# Run the test suite
pytest -v

# Start the server
leash start --reload
```

## Project Structure

```
leash/
├── app/                    # FastAPI server
│   ├── main.py             # App entry point
│   ├── core/               # Config, database, auth, crypto
│   ├── identity/           # Agent registration & JWT
│   ├── policy/             # Policy engine, validator, schemas
│   ├── audit/              # Hash-chained audit trail
│   ├── routes/             # API endpoints
│   ├── models/             # SQLAlchemy models
│   └── policies/           # Built-in YAML policies
├── sdk/                    # Python SDK, CLI, MCP proxy
│   ├── client.py           # LeashAgent class
│   ├── cli.py              # CLI tool
│   ├── mcp_proxy.py        # MCP authorization proxy
│   └── dashboard.py        # Terminal TUI dashboard
├── tests/                  # pytest test suite
├── docs/                   # MkDocs documentation site
└── scripts/                # Helper scripts
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/my-feature    # or fix/my-bugfix
```

### 2. Make Your Changes

- Keep changes focused — one feature or fix per PR
- Add or update tests for any behavior changes
- Update documentation if you change user-facing behavior

### 3. Run Tests

```bash
# Full suite
pytest -v

# Single file
pytest tests/test_policy.py -v

# With coverage
pytest --cov=app --cov=sdk -v
```

All tests must pass before submitting.

### 4. Lint

```bash
# We use ruff for linting
ruff check app/ sdk/ tests/
```

### 5. Submit a PR

- Push your branch and open a Pull Request
- Fill in the PR template with a clear description
- Link any related issues
- CI will run tests automatically

## Code Style

- **Python 3.11+** — use modern syntax (type hints, `match`, `|` unions)
- **Formatting** — we use `ruff` (compatible with Black defaults)
- **Imports** — stdlib → third-party → local, separated by blank lines
- **Docstrings** — required for all public functions and classes
- **Type hints** — required for function signatures
- **Naming** — `snake_case` for functions/variables, `PascalCase` for classes

## Writing Tests

Tests live in `tests/` and use pytest with FastAPI's `TestClient`:

```python
def test_my_feature(client, token, agent_id):
    """Test that my feature does the right thing."""
    resp = client.post(
        "/authorize",
        json={"agent_id": agent_id, "action": "my.action"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["decision"] == "allow"
```

The `client`, `token`, and `agent_id` fixtures are defined in `tests/conftest.py`.

### Test Categories

| File | What It Tests |
|------|---------------|
| `test_policy.py` | Policy engine — authorization, CRUD, wildcards, ABAC, rate limits |
| `test_identity.py` | Agent registration, JWT validation, key rotation, server key rotation |
| `test_audit.py` | Audit logging, summary, chain detection |
| `test_sdk.py` | SDK client, CLI, MCP proxy |
| `test_scanner.py` | Security surface scanner, risk classification |
| `test_validation.py` | Policy validator, YAML error handling |

## Adding a Policy Example

Built-in policies live in `app/policies/`. To add a new one:

1. Create a YAML file (e.g. `app/policies/my_agent.yaml`)
2. Validate it: `python3 -m sdk.cli policy validate app/policies/my_agent.yaml`
3. Add a test in `test_policy.py` that exercises the policy
4. Document it in the appropriate docs page

See [Write Your First Policy](docs/docs/write-your-first-policy.md) for the policy schema reference.

## Reporting Bugs

- Open a GitHub issue with the `bug` label
- Include: what you expected, what happened, steps to reproduce
- Include your Python version and OS

## Suggesting Features

- Open a GitHub issue with the `enhancement` label
- Describe the use case, not just the solution
- If it's a large change, open a discussion first

## Code of Conduct

Be respectful, constructive, and inclusive. We're all here to make AI agents safer.

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.
