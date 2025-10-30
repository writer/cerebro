# Cerebro SDK Overview

> Status: Internal use only

The Cerebro SDK exposes a typed, async-first interface for automating common platform workflows. It is organized by domain to mirror the service boundaries in the monorepo.

| Module | Purpose |
| ------ | ------- |
| `cerebro_sdk.config` | Cached access to platform settings with refresh helpers. |
| `cerebro_sdk.auth` | Authentication facades for issuing and verifying JWTs. |
| `cerebro_sdk.users` / `organizations` | CRUD helpers for user, org, account, and resource data. |
| `cerebro_sdk.findings` | Finding lifecycle management, including regeneration. |
| `cerebro_sdk.telemetry` | Logging/metrics utilities for structured instrumentation. |
| `cerebro_sdk.integrations` | Integration state management and sync orchestration. |
| `cerebro_sdk.tasks` | Celery task introspection and orchestration. |
| `cerebro_sdk.agents.sessions` | Session creation, messaging, and SQL-backed memory analytics. |
| `cerebro_sdk.agents.review` | Human-in-loop review queue management and comment/history helpers. |
| `cerebro_sdk.agents.analytics` | Runtime event summaries and organization-level dashboards. |
| `cerebro_sdk.agents.tooling` | Tool invocation listings, approval flows, and policy suggestions. |
| `cerebro_sdk.agents.notifications` | Notification enqueueing, delivery tracking, and ticket lifecycle. |
| `cerebro_sdk.agents.playbooks` | High-level orchestrations stitching sessions, notifications, and tooling. |

All modules require an `AsyncSession` from `sqlalchemy.ext.asyncio`. For scripts, prefer the existing factory in `cerebro.core.database.async_session_factory()` to inherit connection settings.

```python
from sqlalchemy.ext.asyncio import async_sessionmaker
from cerebro.core.database import async_session_factory

Session = async_sessionmaker(async_session_factory().bind, expire_on_commit=False)

async with Session() as db:
    ...
```

Sub-pages cover deeper usage patterns and code samples for major domains. Error handling is standardized via exceptions exported from `cerebro_sdk.agents` (e.g., `AgentNotFoundError`, `AgentInvalidStatusError`, `AgentValidationError`).
