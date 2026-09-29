# Contributing to Leash

Thanks for your interest in contributing! Leash is an open-source AI agent authorization layer, and we welcome contributions of all kinds — bug fixes, new features, documentation, and policy examples.

## Quick Setup

```bash
# Clone the repo
git clone https://github.com/chadeckles/leash.git
cd leash

# Install all dependencies
uv sync --all-extras

# Run the test suite
uv run pytest

# Start the server
uv run leash start --reload
```

## Project Structure

```
leash/
├── src/leash/              # Python package
│   ├── __init__.py         # Public SDK exports
│   ├── __main__.py         # python -m leash
│   ├── cli.py              # CLI tool
│   ├── client.py           # LeashAgent class
│   ├── mcp_proxy.py        # MCP authorization proxy
│   ├── scanner.py          # Security surface scanner
│   ├── dashboard.py        # Terminal TUI dashboard
│   ├── paths.py            # LEASH_HOME/state paths
│   ├── engine/             # Pure policy engine and validator
│   ├── presets/            # Bundled YAML policies
│   └── server/             # FastAPI server, routes, models, audit, identity
├── tests/                  # pytest test suite
├── docs/                   # MkDocs documentation site
└── scripts/                # Helper scripts (quickstart, etc.)
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
uv run pytest

# Single file
uv run pytest tests/test_policy.py -v

# With coverage (if pytest-cov is installed)
uv run pytest --cov=src/leash -v
```

All tests must pass before submitting.

Tests are data-driven where possible. To pin down how Leash treats a tool
call (a new evasion, a preset rule, a host quirk), add a line to
`tests/cases/hook_decisions.yaml` rather than a new test function. Engine and
server authorization cases live in the `ENGINE_CASES` and `MATRIX` tables in
`tests/test_engine.py` and `tests/test_policy.py`.

### 4. Lint

```bash
# We use ruff for linting
uv run ruff check src/ tests/
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

Bundled policy presets live in `src/leash/presets/`. To add a new one:

1. Create a YAML file (e.g. `src/leash/presets/my_agent.yaml`)
2. Validate it: `uv run leash policy validate src/leash/presets/my_agent.yaml`
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
