# MCP-GuardBench: a local security lab. Nothing in this Makefile contacts an external MCP server.
#
#   make setup    create the virtualenv, install, write .env, create the database
#   make test     run the whole test suite
#   make seed     register and scan the 8 local fixtures
#   make demo     run the benchmark against the local reference fixtures
#   make report   print the latest run's report (and write it to reports/latest/)
#   make cisco-demo  also benchmark the open-source Cisco MCP Scanner (installed in its own venv)
#
# Works with GNU Make 3.81 (the version macOS ships).

SHELL := /bin/bash
.DEFAULT_GOAL := help

VENV           ?= .venv
PYTHON         ?= python3
PYTHON_VERSION ?= 3.12
PY             := $(VENV)/bin/python
GB             := $(VENV)/bin/guardbench
EXTRAS         ?= dev,dashboard
UV             := $(shell command -v uv 2>/dev/null)

ifeq ($(UV),)
  # Plain venv + pip. Check the interpreter first so the failure message is readable.
  CREATE_VENV = $(PYTHON) -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else "Python 3.12+ is required; set PYTHON=python3.12") ' && $(PYTHON) -m venv $(VENV)
  INSTALL     = $(PY) -m pip install --quiet --upgrade pip && $(PY) -m pip install --quiet -e ".[$(EXTRAS)]"
  PIP_ADD     = $(PY) -m pip install --quiet
else
  # PYTHON_VERSION selects which interpreter uv provisions (e.g. `make setup PYTHON_VERSION=3.13`
  # to matrix-test another version); it downloads one if needed, it does not need to be preinstalled.
  CREATE_VENV = $(UV) venv $(VENV) --python $(PYTHON_VERSION) --quiet
  INSTALL     = $(UV) pip install --quiet --python $(PY) -e ".[$(EXTRAS)]"
  PIP_ADD     = $(UV) pip install --quiet --python $(PY)
endif

REPORT_ADAPTERS = --adapter no-defense-baseline --adapter reference-static --adapter reference-runtime

# The Cisco MCP Scanner is a third-party control under test, not a dependency: it gets its own venv
# because its dependency set (a pinned litellm, tree-sitter grammars, ...) would clash with ours.
SCANNER_VENV          ?= .venv-scanners
CISCO_SCANNER_VERSION ?= 4.8.4
CISCO_SCANNER         := $(SCANNER_VENV)/bin/mcp-scanner
ifeq ($(UV),)
  INSTALL_CISCO = $(PYTHON) -m venv $(SCANNER_VENV) && $(SCANNER_VENV)/bin/python -m pip install --quiet \
                  "cisco-ai-mcp-scanner==$(CISCO_SCANNER_VERSION)"
else
  INSTALL_CISCO = $(UV) venv $(SCANNER_VENV) --python $(PYTHON_VERSION) --quiet && $(UV) pip install --quiet \
                  --python $(SCANNER_VENV)/bin/python "cisco-ai-mcp-scanner==$(CISCO_SCANNER_VERSION)"
endif

.PHONY: help setup env install test coverage lint format typecheck check seed demo cisco-demo report \
        serve dashboard test-postgres docker-config docker-up docker-down docker-logs docker-seed \
        docker-demo clean reset-db

help: ## Show this help
	@echo "MCP-GuardBench: local security lab (no external server is ever scanned)"
	@echo
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  make %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ---------------------------------------------------------------- setup

$(PY):
	$(CREATE_VENV)

$(VENV)/.installed: pyproject.toml | $(PY)
	$(INSTALL)
	@touch $@

install: $(VENV)/.installed ## Install (or refresh) the package and its dev/dashboard extras

.env: | $(PY)
	$(PY) scripts/bootstrap_env.py

env: .env ## Write .env from .env.example with generated local credentials (never overwrites)

setup: install .env ## Create the venv, install, write .env, create the local database
	@mkdir -p data reports
	@$(GB) init-db
	@echo
	@echo "Setup complete. Next: make test | make seed | make demo | make report"

# ---------------------------------------------------------------- quality gates

test: install ## Run the full test suite (SQLite, no network, no Docker)
	$(PY) -m pytest

coverage: install ## Tests with coverage; core packages must stay at or above 80%
	$(PY) -m pytest -q --cov=guardbench --cov-report=
	$(PY) -m coverage report --skip-covered
	$(PY) -m coverage report --fail-under=80 \
	    --include="src/guardbench/analysis/*,src/guardbench/policy/*,src/guardbench/benchmark/*,src/guardbench/domain/*,src/guardbench/runtime/*"

lint: install ## Ruff lint and format check
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .

format: install ## Apply Ruff fixes and formatting
	$(PY) -m ruff check --fix .
	$(PY) -m ruff format .

typecheck: install ## mypy (strict) over src/
	$(PY) -m mypy src

check: lint typecheck test ## Everything CI runs: lint, typecheck, tests

test-postgres: install ## Run the database tests on a real (embedded) PostgreSQL, no Docker needed
	$(PIP_ADD) "pgserver>=0.1.4"
	$(PY) scripts/test_postgres.py

# ---------------------------------------------------------------- demo

seed: install ## Create the schema and register/scan the 8 local fixtures (idempotent)
	$(GB) init-db
	$(GB) seed-demo

demo: seed ## Benchmark the 3 reference adapters on the local fixtures -> reports/demo-run/
	$(PY) scripts/run_demo.py

$(CISCO_SCANNER):
	$(INSTALL_CISCO)

cisco-demo: seed $(CISCO_SCANNER) ## Also benchmark the Cisco MCP Scanner (own venv, offline) -> reports/cisco-demo/
	GUARDBENCH_CISCO_MCP_SCANNER=$(CISCO_SCANNER) $(GB) benchmark run --project demo --cases test_cases/ \
	    $(REPORT_ADAPTERS) --adapter cisco-mcp-scanner --output reports/cisco-demo/

report: install ## Print the latest run's Markdown report; write JSON/Markdown/CSV to reports/latest/
	$(PY) scripts/generate_report.py

serve: install ## Start the REST API on the loopback interface
	$(GB) serve

dashboard: install ## Start the read-only Streamlit dashboard (start `make serve` first)
	$(GB) dashboard

# ---------------------------------------------------------------- Docker (optional)

docker-config: ## Statically validate docker-compose.yml (needs the docker CLI, not the daemon)
	docker compose config --quiet && echo "docker-compose.yml is valid"

docker-up: .env ## Build and start postgres + api + dashboard (ports bound to 127.0.0.1 only)
	docker compose up --build -d

docker-down: ## Stop the containers (the database volume is kept)
	docker compose down

docker-logs: ## Follow the container logs
	docker compose logs -f --tail=100

docker-seed: .env ## Seed the demo data inside the isolated test-runner container
	docker compose --profile tools run --rm --user "$$(id -u):$$(id -g)" test-runner seed-demo

docker-demo: docker-seed ## Run the demo benchmark inside the isolated test-runner container
	docker compose --profile tools run --rm --user "$$(id -u):$$(id -g)" test-runner \
	    benchmark run --project demo --cases test_cases/ $(REPORT_ADAPTERS) --output reports/docker-demo/

# ---------------------------------------------------------------- housekeeping

clean: ## Remove caches and build output (keeps data/, reports/ and .env)
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage dist build
	find . -name __pycache__ -type d -not -path "./$(VENV)/*" -prune -exec rm -rf {} +

reset-db: ## Delete the local SQLite database (run `make seed` afterwards)
	rm -f data/guardbench.db
