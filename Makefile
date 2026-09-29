.PHONY: quickstart sync run dev test lint fmt build clean docker-up docker-down

# Development uses uv (https://docs.astral.sh/uv/). End users install with:
#   uv tool install 'leash[server]'

quickstart:
	@bash scripts/quickstart.sh

sync:
	uv sync --all-extras

run:
	uv run leash start

dev:
	uv run leash start --reload

test:
	uv run --all-extras pytest -v

lint:
	uv run ruff check src/ tests/

fmt:
	uv run ruff format src/ tests/

build:
	uv build

clean:
	rm -rf dist build .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down -v
