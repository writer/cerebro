# Cerebro SDK Overview

> Status: Internal use only

The SDK provides typed, async facades over the same services that power the Cerebro API and agents. Teams can automate configuration, findings workflows, or agent operations without re-implementing platform logic.

## Getting Started

Reference the SDK from another project via a path dependency in `pyproject.toml`:

```toml
[project]
dependencies = [
    "cerebro-sdk @ file:///path/to/cerebro",
]
```

Or install directly in a virtual environment:

```bash
uv pip install -e /path/to/cerebro
```

All facades expect an `AsyncSession`. Reuse the shared factory so jobs inherit platform connection settings:

```python
from sqlalchemy.ext.asyncio import async_sessionmaker
from cerebro.core.database import async_session_factory
from cerebro_sdk import AuthSession

Session = async_sessionmaker(async_session_factory().bind, expire_on_commit=False)

async with Session() as db:
    auth = AuthSession(db)
    tokens = await auth.login("service-account", "secret")
```

Public helpers are re-exported from `cerebro_sdk` and `cerebro_sdk.agents`. Importing from these modules also grants access to shared dataclasses and typed exceptions (`AgentNotFoundError`, `AgentInvalidStatusError`, `AgentValidationError`).

## Documentation Map

| Guide | Scope |
| --- | --- |
| [TypeScript SDK Guide](typescript.md) | Project layout, HttpClient architecture, streaming, pagination, release workflow, troubleshooting. |
| [Python SDK Guide](python.md) | Package structure, async session usage, Security Center evidence lifecycle, testing, release process. |
| [Configuration, Auth, and Agents](auth-and-agents.md) | Settings proxy, auth session, user/org managers, session and review helpers, transaction semantics. |
| [Integrations and Playbooks](integrations-and-playbooks.md) | Integration registry, tooling analytics, notifications, playbook orchestration. |
| [Schema and Migrations](migrations.md) | Synchronizing database migrations with SDK models. |

## Module Index

| Module | Purpose |
| ------ | ------- |
| `cerebro_sdk.config` | Cached access to platform settings with refresh helpers. |
| `cerebro_sdk.auth` | Authentication facades for issuing and verifying JWTs. |
| `cerebro_sdk.users`, `cerebro_sdk.organizations` | CRUD helpers for user, org, account, and resource data. |
| `cerebro_sdk.findings` | Finding lifecycle management, including regeneration. |
| `cerebro_sdk.telemetry` | Structured logging and Prometheus helpers. |
| `cerebro_sdk.integrations` | Integration state management and sync orchestration. |
| `cerebro_sdk.tasks` | Celery task introspection and orchestration. |
| `cerebro_sdk.agents.sessions` | Session creation, messaging, and SQL-backed memory analytics. |
| `cerebro_sdk.agents.review` | Review queue management, comments, and history exports. |
| `cerebro_sdk.agents.analytics` | Runtime event summaries and organization-level dashboards. |
| `cerebro_sdk.agents.tooling` | Tool invocation listings, approval flows, analytics, and policy suggestions. |
| `cerebro_sdk.agents.notifications` | Notification enqueue, delivery tracking, and ticket lifecycle. |
| `cerebro_sdk.agents.playbooks` | Opinionated orchestrations spanning sessions, notifications, and tooling. |

Each module follows consistent patterns: async methods, typed dataclass outputs, and explicit validation errors. When extending the SDK, update this index and the relevant guide so downstream teams can find the new functionality.
