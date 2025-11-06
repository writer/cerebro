# Cerebro (Writer Internal)

Cerebro is Writer's internal security data platform. It tracks cloud and SaaS configuration state, exposes a consistent API surface, and supports automated or human-in-the-loop investigations used by Writer engineering and security teams.

## Key Capabilities

- Unified access across CLI, REST, and agent interfaces backed by an append-only store
- SQL and graph-style analytics without intermediate ETL pipelines
- Agent runtimes with approval workflows, telemetry, and scoped memory
- Rule evaluation and findings pipelines driven by CEL policies
- Integration sync helpers for common SaaS and endpoint providers

## Architecture at a Glance

| Layer | Components |
| --- | --- |
| Interfaces | Typer CLI, FastAPI REST service, conversational agents |
| Core services | Rule engine (CEL), findings pipeline, analytics engine, observability hooks |
| Data tier | PostgreSQL (immutable audit tables) and Redis for coordination |

## Quickstart

### Prerequisites

- Python 3.11+ (repo pins 3.11.8 via `.python-version`)
- PostgreSQL 14+
- Redis 6+
- Optional: Anthropic and/or OpenAI API keys for agent runtimes

### Local Setup

```bash
# Install uv package manager (required for all make targets)
curl -LsSf https://astral.sh/uv/install.sh | sh

# (Optional) Align your local interpreter with repo default
pyenv install --skip-existing 3.11.8
pyenv local 3.11.8

# Bootstrap dependencies, copy .env, run migrations, and seed sample data
make dev

# Skip seed data if desired
LOAD_DEV_DATA=0 make dev

# Start Postgres + Redis locally
make dev-infra

# Launch API, Celery worker, and beat; add frontend/Flower via env flags
make dev-stack
DEV_STACK_INCLUDE_FRONTEND=1 make dev-stack
DEV_STACK_INCLUDE_FLOWER=1 make dev-stack

# Containerised alternative
make docker-up
```

Access points:

- API docs: `http://localhost:8000/docs`
- Web UI: `http://localhost:3000`
- Default credentials: `admin` / `admin123!`

### Minimal Configuration

```env
DATABASE_URL=postgresql://user:password@localhost/cerebro
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=generate-a-secure-value
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-openai-...
```

Place additional settings in `.env` or export them before launching the API.

## Interacting with Cerebro

### CLI

```bash
# List critical findings
cerebro findings list --severity critical

# Execute ad-hoc SQL
cerebro query "SELECT * FROM aws_iam_user WHERE mfa_enabled = false"

# Start an agent session
cerebro agents chat <session-id>
```

### REST API

```bash
curl "http://localhost:8000/api/v1/findings?severity=critical" \
  -H "Authorization: Bearer $TOKEN"
```

### Agent Workflows

- Create sessions using the CLI or REST endpoints under `/api/v1/agents`
- Tool execution is governed by CEL policies and optional approval tasks
- Review tasks appear in the queue when destructive actions require promotion

### Memory and Observability

- Memory entries support decay, dedupe, and configurable pruning thresholds
- Telemetry is exported through Prometheus metrics such as `cerebro_agent_memory_events_total`
- Agent tool execution metrics (`cerebro_agent_tool_*`) track success, failure, and latency

## Internal SDK

Writer ships two first-class SDKs in this repo:

- **TypeScript SDK (`sdk/ts`)** – published to internal package feeds, powering frontend integrations and automation services. Run `npm run lint` / `npm run test` inside `sdk/ts` to validate changes. Key modules include HTTP client middleware, streaming helpers, pagination utilities, and Security Center analytics bundled with evidence lifecycle primitives.
- **Python SDK (`src/cerebro_sdk`)** – the async façade consumed by backend workflows, Lambda-style tasks, and compliance tooling. Validate with `PYTHONPATH=src pytest tests/unit/sdk`. The package exports managers for auth, users, organizations, findings, integrations, agents, telemetry, and now the shared Security Center primitives.

Both SDKs expose identical Security Center evidence APIs (`EntityProfile`, `EvidenceArtifact`, lifecycle policies, summaries) so automation can reason about staleness, refresh windows, and control mappings uniformly across languages. Additional guides live under [`docs/sdk/`](docs/sdk/README.md) and the `sdk/ts/test` / `tests/unit/sdk` suites provide reference scenarios.

```python
from cerebro.core.database import async_session_factory
from cerebro_sdk import AuthSession, FindingService


async def list_high_risk_findings(org_id: str, username: str, password: str) -> None:
    async with async_session_factory() as db:
        tokens = await AuthSession(db).login(username, password)
        findings = await FindingService(db).list_findings(org_id, severity="critical")
        for item in findings:
            print(item.finding_id, item.severity)
```

Additional modules cover agent tooling analytics, review queue exports, integration sync triggers, and telemetry wiring.

## Development Workflow

```bash
# Linting, typing, and tests
make lint
make test

# Database helpers
make db-migrate
make db-reset

# Docker helpers
make docker-up
make docker-down
```

## Repository Layout

```
cerebro/
├── src/cerebro/
│   ├── agents/         # Agent runtimes, tooling, review queue, memory
│   ├── api/            # FastAPI routers and dependencies
│   ├── cli/            # Typer-based command line interface
│   ├── collectors/     # Cloud & SaaS ingestion pipelines
│   ├── core/           # Config, database utilities, shared models
│   ├── findings/       # Finding normalization and workflows
│   ├── providers/      # Provider-specific integrations
│   ├── query/          # SQL + graph query engine
│   └── rules/          # CEL rule engine and policies
├── docs/               # Extended documentation
├── tests/              # Automated test suite
└── migrations/         # Alembic revisions
```

## Documentation

- [Quickstart](docs/getting-started/QUICKSTART.md)
- [API Reference](docs/user-guide/API.md)
- [Agents Guide](docs/agents/README.md)
- [Query Engine](docs/QUERY_ENGINE.md)
- [Database Schema](docs/developer-guide/DATABASE_SCHEMA.md)
- [Development Guide](docs/DEVELOPMENT.md)
- [Deployment Guide](docs/DEPLOYMENT.md)

## Internal Use Only

This repository and its artifacts are confidential and intended solely for Writer employees and approved contractors. Do not redistribute or share outside the company. Refer to the internal handbook for deployment controls, data handling requirements, and exception processes.
