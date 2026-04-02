.PHONY: install run dev test lint fmt clean docker-up docker-down quickstart

# ---------------------------------------------------------------------------
# Local development
# ---------------------------------------------------------------------------

quickstart:
	@bash scripts/quickstart.sh

install:
	pip3 install -r requirements.txt
	@echo ""
	@echo "  To use 'leash' as a global command:"
	@echo "    sudo ln -sf \$$PWD/leash /usr/local/bin/leash"
	@echo "  Or: make install-cli"
	@echo ""

install-cli:
	pip3 install -r requirements.txt
	sudo ln -sf "$$PWD/leash" /usr/local/bin/leash
	@echo "  ✔ leash command installed. Try: leash status"

run:
	uvicorn app.main:app --host 0.0.0.0 --port 8000

dev:
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

test:
	pytest tests/ -v

lint:
	ruff check app/ tests/

fmt:
	ruff format app/ tests/

clean:
	rm -f leash.db
	rm -rf .keys
	rm -f ~/.leash/token.json
	rm -f /usr/local/bin/leash 2>/dev/null || true
	rm -rf .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down -v
