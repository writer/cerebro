# Configuration, Authentication, and Agents

This page walks through the high-level flows supported by `cerebro_sdk.config`, `auth`, `users`, `organizations`, and the agent facades. All samples assume an `AsyncSession` named `db`.

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

## Transactions and Concurrency

Agent review, tooling, and notification helpers now wrap writes in transaction contexts that automatically downgrade to nested savepoints when callers already hold a session transaction. This guarantees atomic history logging without forcing upstream consumers to manage commit order.
