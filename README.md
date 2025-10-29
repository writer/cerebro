# Cerebro – Security System of Record

Cerebro is a self-hosted security data plane that continuously captures cloud and SaaS configuration state, producing forensic-ready audit trails and powering AI-assisted investigations.

## Highlights

- **Unified access** – CLI, REST API, and agent interfaces share the same append-only store
- **Graph + SQL analytics** – run fleet-wide queries and attack-path analysis without ETL pipelines
- **Pluggable agents** – Claude and OpenAI runtimes with skill-based routing, telemetry, and audited execution
- **Adaptive memory** – scoped, decay-aware recall with dedupe, pruning, and observability controls
- **Human-in-loop guardrails** – review queue, approval workflows, and runtime-level controls for risky changes
- **Compliance automation** – continuously test controls against SOC2, ISO27001, CIS, and NIST frameworks

## Architecture Overview

| Layer | Components |
| --- | --- |
| Interfaces | Typer CLI, FastAPI REST service, conversational agents |
| Core services | Rule engine (CEL), findings pipeline, graph/SQL engine, observability hooks |
| Data tier | PostgreSQL with immutable audit tables and cryptographic integrity |

## Getting Started

### Prerequisites

- Python 3.11+
- PostgreSQL 14+
- Redis 6+
- Claude and/or OpenAI API keys (for agent runtimes)

### Install & Run

```bash
# Install uv package manager
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone and bootstrap
git clone https://github.com/WriterInternal/cerebro.git
cd cerebro

# Development workflow
make dev            # start API + background workers
make db-migrate     # apply migrations
make dev-data       # seed sample data (optional)

# Docker alternative
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

## Working with Cerebro

### CLI

```bash
# List critical findings
cerebro findings list --severity critical

# Run ad-hoc SQL
cerebro query "SELECT * FROM aws_iam_user WHERE mfa_enabled = false"

# Start an agent session
cerebro agents chat <session-id>
```

### REST API

```bash
curl "http://localhost:8000/api/v1/findings?severity=critical" \
  -H "Authorization: Bearer $TOKEN"
```

### Agents

```bash
cerebro agents create "Acme Corp" --type security_analyst
cerebro agents chat <session-id>
```

- Tool execution is guarded by CEL policies, adaptive ordering, telemetry, and optional approval workflows
- Memory snippets are injected into prompts, tool contexts, and persisted alongside conversation history
- Skill-based routing picks the right runtime (`AGENT_RUNTIME_PREFERENCES`) while tracking decisions in session context
- Destructive actions automatically surface to the review queue for human promotion via REST (`/api/v1/agents/review-tasks`)

### Memory Controls

- Embeddings (OpenAI or hashing fallback) with decay, dedupe, and Max Marginal Relevance diversification
- Configurable pruning thresholds (`AGENT_MEMORY_MAX_ENTRIES_PER_ORG`, `AGENT_MEMORY_PRUNE_PROBABILITY`, etc.)
- Observability via Prometheus counter `cerebro_agent_memory_events_total` and OTLP spans when telemetry is enabled
- Tool observability via `cerebro_agent_tool_*` metrics (success, failure, duration) and adaptive ordering from live stats
- Inspect session memory:

```bash
curl "http://localhost:8000/api/v1/agents/sessions/<session-id>/memory?limit=20" \
  -H "Authorization: Bearer $TOKEN"
```

Set `include_content=true` to retrieve full text; otherwise summaries, decay metadata, and scope labels are returned.

## Internal Cerebro SDK (Writer Only)

Security and platform engineers can build automation on top of Cerebro without re-implementing core services by installing the internal `cerebro_sdk` package that ships with this repo.

### Why It Matters

- **Batteries included** – Async facades wrap authentication, user/scope management, organization inventory, findings workflows, integration sync tasks, and telemetry helpers.
- **Guardrails by default** – Token issuance, scope checks, logging, and metrics mirror the main platform, so internal tools stay compliant with rotation, revocation, and observability policies.
- **Faster delivery** – Teams focus on their automation logic (corpsec audits, detection responders, compliance reporting) while the SDK maintains stable primitives during platform upgrades.

### Quick Example

```python
from datetime import timedelta
from cerebro.core.database import async_session_factory
from cerebro_sdk import AuthSession, FindingService, IntegrationService


async def nightly_security_job(org_id: str, username: str, password: str) -> None:
    async with async_session_factory() as db:
        auth = AuthSession(db)
        tokens = await auth.login(username, password)

        findings = FindingService(db)
        critical = await findings.list_findings(org_id, severity="critical")

        integrations = IntegrationService(db)
        stale_states = await integrations.list_states()
        if any(state.last_timestamp is None for state in stale_states):
            integrations.trigger_sync("sentinelone")

        alert_team(critical, stale_states, tokens.access_token)
```

- **CorpSec** can enumerate privileged accounts and automatically remove expired admin scopes using `UserManager` and `OrganizationManager`.
- **Detection & Response** can fetch new high-severity findings, trigger SentinelOne/Kandji catch-up runs, and record metrics without wiring Celery manually.
- **GRC** can re-run rule evaluations on demand with `FindingService.generate_for_org` and push audit-ready summaries via the telemetry helpers.

## Development Workflow

```bash
# Linting / typing / tests
make lint
make test

# Database helpers
make db-migrate
make db-reset

# Docker helpers
make docker-up
make docker-down
```

### Repository Layout

```
cerebro/
├── src/cerebro/
│   ├── agents/         # Agent runtimes, tools, memory, observability
│   │   ├── review_service.py   # Human-in-loop review queue helpers
│   │   └── tool_stats.py       # Adaptive tool ordering based on success/duration
│   ├── api/            # FastAPI routers and dependencies
│   ├── cli/            # Typer-based command line interface
│   ├── collectors/     # Cloud & SaaS configuration ingestion
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

- [Quickstart](docs/QUICKSTART.md)
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
