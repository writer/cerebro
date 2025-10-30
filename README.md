git clone https://github.com/WriterInternal/cerebro.git
# Cerebro

Cerebro is an open-source security data platform that tracks cloud and SaaS configuration state, exposes a consistent API surface, and supports automated or human-in-the-loop investigations.

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

- Python 3.11+
- PostgreSQL 14+
- Redis 6+
- Optional: Anthropic and/or OpenAI API keys for agent runtimes

### Local Setup

```bash
# Install uv package manager
curl -LsSf https://astral.sh/uv/install.sh | sh

git clone https://github.com/WriterInternal/cerebro.git
cd cerebro

# Start API, workers, and supporting services
make dev

# Apply database migrations
make db-migrate

# Seed sample data (optional)
make dev-data

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

## Internal SDK (Writer teams)

The repository ships with `cerebro_sdk`, an async facade layer consumed by internal automation. Facets include authentication, user and organization management, findings workflows, integration orchestration, telemetry utilities, and modular agent helpers.

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

## License

Apache 2.0 – see [LICENSE](LICENSE)

## Links

- GitHub: https://github.com/WriterInternal/cerebro
- Issues: https://github.com/WriterInternal/cerebro/issues
