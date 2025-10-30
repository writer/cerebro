# Configuration, Authentication, and Agents

This page walks through the high-level flows supported by `cerebro_sdk.config`, `auth`, `users`, `organizations`, and the agent facades. All samples assume an `AsyncSession` named `db`. For an index of other SDK modules, see the [SDK overview](README.md).

## Settings Access

```python
from cerebro_sdk import get_settings, SettingsProxy

settings = get_settings()
print(settings.environment)

proxy = SettingsProxy(refresh_interval_seconds=30)
snapshot = await proxy.snapshot()
```

`SettingsProxy` caches settings in-memory and refreshes in the background. Use `await proxy.refresh()` when you need to invalidate the cache manually (for example after applying environment overrides).

## AuthSession

```python
from cerebro_sdk import AuthSession

auth = AuthSession(db)
tokens = await auth.login("analyst", "correct horse battery staple")

payload = await auth.verify(tokens.access_token, expected_type="access")
print(payload["scopes"])
```

Refresh tokens now respect `settings.refresh_token_expire_days`; the SDK automatically requests the correct expiry when generating refresh tokens.

## User and Organization Managers

```python
from cerebro_sdk import UserManager, OrganizationManager

users = UserManager(db)
record = await users.create_user(
    username="playbook-bot",
    email="bot@example.com",
    password="temporary",
    scopes=["read:findings", "execute:playbooks"],
)

orgs = OrganizationManager(db)
orgs_list = await orgs.list_organizations(limit=10)
resources = await orgs.list_resources(account_id=orgs_list[0].org_id)
```

The managers return typed dataclasses (`UserRecord`, `OrganizationRecord`, etc.) for easier IntelliSense and validation downstream.

## Agent Modules Overview

The SDK exposes granular facades under `cerebro_sdk.agents`:

| Module | Responsibilities |
| --- | --- |
| `sessions.AgentManager` | Session creation, messaging, memory analytics. |
| `review.AgentReviewManager` | Human review workflows: status updates, comments, history. |
| `analytics.AgentAnalyticsClient` | Event listings and aggregated summaries. |
| `tooling.AgentToolingManager` | Tool invocations, approval decisions, policy suggestions. |
| `notifications.AgentNotificationManager` | Notifications, ticket creation/closure. |
| `playbooks.AgentPlaybook` | Opinionated flows combining the above. |

Shared dataclasses and error types live in `cerebro_sdk.agents.types`. Import from `cerebro_sdk.agents` to access them directly (the package re-exports its public surface).

## AgentManager Highlights

```python
from uuid import uuid4
from cerebro_sdk import AgentManager, AgentMemoryStats

agents = AgentManager(db)
session = await agents.create_session(
    org_id=org_id,
    agent_type="security_analyst",
    created_by="sdk@example.com",
    context={"finding_ids": [str(uuid4())]},
)

await agents.add_message(
    session_id=session.session_id,
    role="user",
    content={"text": "Summarize the finding blast radius."},
)

stats: AgentMemoryStats | None = await agents.get_memory_stats(
    session_id=session.session_id,
    since_hours=24,
    scope_type="finding",
)
```

### SQL-Backed Memory Analytics

`get_memory_stats` aggregates directly in SQL. Optional filters include:

| Parameter | Description |
|-----------|-------------|
| `role` | Filter by `MessageRole` (enum or string). |
| `scope_type` | Restrict memories that include a specific scope type. |
| `since_hours` | Only include entries newer than the provided window. |

The response contains role/scope histograms and the top five memories by decay score.

### Efficient Session Lookups

`sessions_for_finding` and `sessions_for_incident` now use PostgreSQL JSON containment operators to avoid loading every session in Python. Both accept `limit`/`offset` for pagination.

### Review Exports

```python
from cerebro_sdk import AgentReviewManager

review = AgentReviewManager(db)
exports = await review.export_tasks(
    org_id=org_id,
    status="pending",
    include_comments=True,
    include_history=False,
)

for bundle in exports:
    print(bundle.task.title, len(bundle.comments))
```

Each export entry bundles the task record with optional comments and history, making it simple to sync the review queue into external ticketing systems.

## Transactions, Errors, and Concurrency

All managers inherit a shared base that automatically chooses between `begin()` and `begin_nested()` depending on existing transactions. Exceptions surface as typed subclasses:

| Error | When raised |
| --- | --- |
| `AgentNotFoundError` | Referenced sessions/tasks/records do not exist. |
| `AgentInvalidStatusError` | Invalid status transition (e.g., re-delivering delivered notifications). |
| `AgentValidationError` | Provided enum/string cannot be coerced into the expected type. |

Catch these from `cerebro_sdk.agents` when integrating to provide user-facing messaging.
