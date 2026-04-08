.PHONY: help setup install install-dev test lint typecheck clean ci

PYTHON ?= python3
VENV   := .venv

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

# ------------------------------------------------------------------
# Setup & install
# ------------------------------------------------------------------

setup: $(VENV)/bin/activate install-dev ## Full first-time setup (venv + deps + hooks)
	@# Install pre-commit hook
	@mkdir -p .git/hooks
	@cp pre-commit-hook.sh .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "\n✅  Setup complete.  Activate the venv with:  source $(VENV)/bin/activate"

$(VENV)/bin/activate:
	$(PYTHON) -m venv $(VENV)

install: $(VENV)/bin/activate ## Install project (production deps only)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install -e .

install-dev: $(VENV)/bin/activate ## Install project + dev/test deps
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install -e ".[dev]"

# ------------------------------------------------------------------
# Quality gates
# ------------------------------------------------------------------

test: ## Run the test suite
	$(VENV)/bin/python -m pytest tests/ -v

lint: ## Run ruff linter
	$(VENV)/bin/ruff check .

typecheck: ## Run mypy strict type checking
	$(VENV)/bin/mypy attack_surface_mapper.py scope_utils.py create_scope.py

ci: lint typecheck test ## Run the full CI pipeline locally (lint → typecheck → test)

# ------------------------------------------------------------------
# Housekeeping
# ------------------------------------------------------------------

clean: ## Remove build artifacts, caches, and output dirs
	rm -rf $(VENV) build/ dist/ *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name '*.pyc' -delete 2>/dev/null || true
	rm -rf recon_results/ results/
