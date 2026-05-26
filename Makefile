.PHONY: lint test test-cov security docker dev clean help

# ── Linting ───────────────────────────────────────────────────────────────────
lint:
	ruff check wazuh_mcp
	mypy wazuh_mcp --ignore-missing-imports --no-error-summary

# ── Tests ─────────────────────────────────────────────────────────────────────
test:
	pytest -x -q --ignore=tests/test_roi_autonomous.py

test-cov:
	pytest --cov=wazuh_mcp --cov-report=term-missing --cov-report=html:htmlcov \
		--ignore=tests/test_roi_autonomous.py
	@echo "Coverage report: htmlcov/index.html"

# ── Security ──────────────────────────────────────────────────────────────────
security:
	bandit -r wazuh_mcp -c pyproject.toml
	pip-audit --requirement requirements.txt

# ── Docker ────────────────────────────────────────────────────────────────────
docker:
	docker compose up -d --build

docker-down:
	docker compose down

# ── Development ───────────────────────────────────────────────────────────────
dev:
	WAZUH_MCP_TRANSPORT=http python -m wazuh_mcp

dev-stdio:
	python -m wazuh_mcp

# ── Pre-commit ────────────────────────────────────────────────────────────────
hooks:
	pip install pre-commit
	pre-commit install
	@echo "Pre-commit hooks installed."

# ── Cleanup ───────────────────────────────────────────────────────────────────
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name htmlcov -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	find . -name ".coverage" -delete 2>/dev/null || true

# ── Help ──────────────────────────────────────────────────────────────────────
help:
	@echo "Available targets:"
	@echo "  lint        ruff check + mypy"
	@echo "  test        pytest (fast, stops on first failure)"
	@echo "  test-cov    pytest with HTML coverage report"
	@echo "  security    bandit SAST + pip-audit dependency scan"
	@echo "  docker      docker compose up --build"
	@echo "  docker-down docker compose down"
	@echo "  dev         run server in HTTP mode (for local development)"
	@echo "  dev-stdio   run server in stdio mode"
	@echo "  hooks       install pre-commit hooks"
	@echo "  clean       remove __pycache__, .pytest_cache, htmlcov"
