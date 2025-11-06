SHELL := /bin/bash

# Environment
PYTHON := python3
UV := uv
LOAD_DEV_DATA ?= 1
DEV_STACK_INCLUDE_FRONTEND ?= 0
DEV_STACK_INCLUDE_FLOWER ?= 0
DEV_SKIP_SMOKE ?= 0
SMOKE_MODE ?= asgi
SMOKE_TARGETS ?= core,db
SMOKE_BASE_URL ?= http://localhost:8000

DEV_STACK_ARGS :=
ifeq ($(DEV_STACK_INCLUDE_FRONTEND),1)
DEV_STACK_ARGS += --frontend
endif
ifeq ($(DEV_STACK_INCLUDE_FLOWER),1)
DEV_STACK_ARGS += --flower
endif

.PHONY: ensure-uv
ensure-uv:
	@command -v $(UV) >/dev/null 2>&1 || { \
		echo "❌ uv command not found"; \
		echo "Install uv with: curl -LsSf https://astral.sh/uv/install.sh | sh"; \
		exit 1; \
	}

.PHONY: ensure-env
ensure-env:
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "📄 Created .env from .env.example"; \
	else \
		echo "ℹ️  .env already exists; skipping copy"; \
	fi

.PHONY: help
help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# Development
.PHONY: install
install: ensure-uv ## Install dependencies with UV
	$(UV) sync

.PHONY: install-dev
install-dev: ensure-uv ## Install dependencies with dev extras
	$(UV) sync --extra dev
	$(UV) run pre-commit install

.PHONY: dev
dev: install-dev ensure-env ## Setup development environment
	@echo "🚀 Cerebro development environment bootstrap"
	@$(MAKE) db-migrate
	@if [ "$(LOAD_DEV_DATA)" != "0" ]; then \
		$(MAKE) dev-data; \
	else \
		echo "⏭️  Skipping dev sample data (LOAD_DEV_DATA=$(LOAD_DEV_DATA))"; \
	fi
	@echo "🗄️  Need databases? Run: make dev-infra"
	@echo "▶️  Launch services with: make dev-stack"

.PHONY: serve
serve: ## Start development API server
	$(UV) run uvicorn cerebro.api.main:app --reload --host 0.0.0.0 --port 8000
.PHONY: dev-infra
dev-infra: ## Start local PostgreSQL and Redis for development
	docker-compose up -d postgres redis

.PHONY: smoke-api
smoke-api: ## Run API smoke checks (set SMOKE_MODE=http for running stacks)
	CEREBRO_SMOKE_MODE=$(SMOKE_MODE) \
	CEREBRO_SMOKE_BASE_URL=$(SMOKE_BASE_URL) \
	CEREBRO_SMOKE_TARGETS=$(SMOKE_TARGETS) \
	$(UV) run python scripts/smoke_api.py

.PHONY: dev-stack
dev-stack: ## Run API, Celery, and optional services concurrently (set DEV_STACK_INCLUDE_FRONTEND=1 for frontend, DEV_STACK_INCLUDE_FLOWER=1 for Flower)
	@if [ "$(DEV_SKIP_SMOKE)" = "0" ]; then \
		CEREBRO_SMOKE_MODE=asgi \
		CEREBRO_SMOKE_TARGETS=$(SMOKE_TARGETS) \
		$(UV) run python scripts/smoke_api.py; \
	else \
		echo "⏭️  Skipping smoke checks before dev stack start"; \
	fi
	$(UV) run python scripts/dev_stack.py $(DEV_STACK_ARGS)

.PHONY: dev-stop
dev-stop: ## Gracefully stop processes launched via dev-stack
	$(UV) run python scripts/dev_teardown.py


.PHONY: worker
worker: ## Start Celery worker
	$(UV) run celery -A cerebro.tasks.celery_app worker -l info

.PHONY: beat
beat: ## Start Celery beat scheduler
	$(UV) run celery -A cerebro.tasks.celery_app beat -l info

.PHONY: flower
flower: ## Start Celery monitoring with Flower
	$(UV) run celery -A cerebro.tasks.celery_app flower --port=5555

# Database
.PHONY: db-migrate
db-migrate: ## Run database migrations
	$(UV) run alembic upgrade head

.PHONY: db-reset
db-reset: ## Reset database (WARNING: destroys all data)
	$(UV) run alembic downgrade base
	$(UV) run alembic upgrade head

.PHONY: db-migration
db-migration: ## Create new migration (make db-migration MESSAGE="description")
	$(UV) run alembic revision --autogenerate -m "$(MESSAGE)"

.PHONY: dev-data
dev-data: ## Load development sample data
	$(UV) run python scripts/setup.py

# Testing
.PHONY: test
test: ## Run all tests
	$(UV) run pytest

.PHONY: test-cov
test-cov: ## Run tests with coverage
	$(UV) run pytest --cov=cerebro --cov-report=html --cov-report=term

.PHONY: test-watch
test-watch: ## Run tests in watch mode
	$(UV) run pytest-watch

# Code Quality  
.PHONY: format
format: ## Format code with Black and isort
	$(UV) run black .
	$(UV) run isort .

.PHONY: lint
lint: ## Run linting checks
	$(UV) run flake8 src/ tests/
	$(UV) run mypy src/

.PHONY: check
check: format lint test ## Run all quality checks

.PHONY: benchmarks
benchmarks: ## Run deterministic benchmark suite and generate scorecard
	$(UV) run python scripts/run_benchmarks.py --fail-on-error

.PHONY: benchmarks-verify
benchmarks-verify: ## Validate benchmark results against regression thresholds
	$(UV) run python scripts/check_regression_tournament.py

.PHONY: telemetry-dev
telemetry-dev: ## Run API with OTLP exporter configured for development
	env \
		ENABLE_AGENT_TELEMETRY=true \
		AGENT_OTEL_ENDPOINT=$${AGENT_OTEL_ENDPOINT:-http://localhost:4318/v1/traces} \
		AGENT_OTEL_HEADERS=$${AGENT_OTEL_HEADERS:-} \
		AGENT_OTEL_TIMEOUT_SECONDS=$${AGENT_OTEL_TIMEOUT_SECONDS:-5} \
	$(UV) run uvicorn cerebro.api.main:app --reload --host 0.0.0.0 --port 8000

# CLI Commands
.PHONY: cli-org-create
cli-org-create: ## Create organization (make cli-org-create NAME="Company")
	$(UV) run python -m cerebro.cli org create --name "$(NAME)"

.PHONY: cli-collect
cli-collect: ## Collect data (make cli-collect ORG="Company" PROVIDER=github)
	$(UV) run python -m cerebro.cli collect "$(ORG)" --provider $(PROVIDER)

.PHONY: cli-findings
cli-findings: ## Generate findings (make cli-findings ORG="Company")
	$(UV) run python -m cerebro.cli findings generate --org-name "$(ORG)"

.PHONY: cli-rules
cli-rules: ## List rules
	$(UV) run python -m cerebro.cli rules list

# Docker
.PHONY: docker-build
docker-build: ## Build Docker image
	docker build -t cerebro:latest .

.PHONY: docker-up
docker-up: ## Start services with Docker Compose
	docker-compose up -d

.PHONY: docker-down
docker-down: ## Stop Docker Compose services
	docker-compose down

.PHONY: docker-logs
docker-logs: ## View Docker Compose logs
	docker-compose logs -f

.PHONY: docker-test
docker-test: ## Run tests in Docker
	docker-compose exec cerebro-api uv run pytest

# Production Deployment
.PHONY: deploy-staging
deploy-staging: ## Deploy to staging environment
	@echo "🚀 Deploying to staging..."
	kubectl apply -f k8s/staging/

.PHONY: deploy-prod
deploy-prod: ## Deploy to production environment
	@echo "🚀 Deploying to production..."
	kubectl apply -f k8s/production/

# Maintenance
.PHONY: db-backup
db-backup: ## Backup database
	@echo "📦 Creating database backup..."
	pg_dump $(DATABASE_URL) > backups/cerebro-$(shell date +%Y%m%d-%H%M%S).sql

.PHONY: db-restore
db-restore: ## Restore database (make db-restore FILE=backup.sql)
	@echo "📦 Restoring database from $(FILE)..."
	psql $(DATABASE_URL) < $(FILE)

.PHONY: clean
clean: ## Clean up temporary files
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf .coverage htmlcov/ .pytest_cache/ .mypy_cache/

.PHONY: providers-test
providers-test: ## Test provider authentication
	@echo "🔗 Testing provider authentication..."
	$(UV) run python -c "
import asyncio
from cerebro.infrastructure.provider_registry import get_provider_registry
from cerebro.core.config import settings

async def test_providers():
    registry = get_provider_registry()
    for provider_name in registry.list_providers():
        try:
            if provider_name == 'github' and settings.github_token:
                provider = registry.create_provider('github', account_id='test', org_name='test')
                result = await provider.authenticate()
                print(f'✅ GitHub: {result}')
            elif provider_name == 'aws' and settings.aws_access_key_id:
                provider = registry.create_provider('aws', account_id='test', aws_account_id='123456789012')
                result = await provider.authenticate()
                print(f'✅ AWS: {result}')
            else:
                print(f'⏩ {provider_name}: Skipped (no credentials)')
        except Exception as e:
            print(f'❌ {provider_name}: {e}')

asyncio.run(test_providers())
"

# Finding Generation
.PHONY: findings-test
findings-test: ## Test finding generation with sample data
	@echo "🔍 Testing finding generation..."
	$(UV) run python -c "
import asyncio
from cerebro.findings.producers import producer_registry
from cerebro.domain.entities import ResourceEntity, ConfigEntity
from datetime import datetime

async def test_findings():
    # Test GitHub producer
    resource = ResourceEntity(
        external_id='test/repo',
        resource_type='github.repo',
        provider='github',
        name='test-repo'
    )
    
    config = ConfigEntity(
        resource_external_id='test/repo',
        captured_at=datetime.utcnow(),
        normalized_config={
            'visibility': 'public',
            'branchProtection': {'requirePR': False},
            'archived': False
        }
    )
    
    findings = producer_registry.evaluate_resource(resource, config)
    print(f'Generated {len(findings)} findings for test resource')
    
    for finding in findings:
        print(f'  - {finding.title} (severity: {finding.severity})')

asyncio.run(test_findings())
"

.DEFAULT_GOAL := help
