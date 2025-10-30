# Integrations, Tasks, and Playbooks

## Integration Service

```python
from cerebro_sdk import IntegrationService
from sqlalchemy.ext.asyncio import AsyncSession

service = IntegrationService(db)
states = await service.list_states()

await service.upsert_state(
    integration="kandji",
    scope="default",
    last_cursor="abcd1234",
    metadata={"status": "ok"},
)
```

### Pluggable Registry

The SDK now exposes `IntegrationTaskRegistry`. Default entries (`kandji`, `sentinelone`) are registered automatically.

```python
from cerebro_sdk.integrations import IntegrationTaskRegistry

IntegrationTaskRegistry.register("custom", my_celery_task)

service = IntegrationService(db)
task_id = service.trigger_sync("custom", foo="bar")

# cleanup (optional)
IntegrationTaskRegistry.unregister("custom")
```

All registry lookups are case-insensitive. Attempting to trigger an unknown integration raises `ValueError`.

### Issue Event Summaries

`summarize_issue_events` groups events into time buckets. Pass `window` and `bucket` `timedelta` values to control retention and resolution.

## Task Manager Recap

```python
from cerebro_sdk import TaskManager

tasks = TaskManager()
submission = tasks.enqueue("cerebro.tasks.integration.sync_kandji")
status = tasks.get_status(submission.task_id)

if status.failed:
    tasks.revoke(submission.task_id, terminate=True)
```

The manager returns typed `TaskSubmission` and `TaskStatus` records and uses Celery control APIs under the hood.

## Agent Playbooks

```python
from cerebro_sdk import AgentPlaybook

playbook = AgentPlaybook(db)
session = await playbook.start_incident_playbook(
    org_id=org_id,
    created_by="incident-bot",
    incident_id=incident_id,
    finding_ids=[finding_id],
)

await playbook.schedule_notifications(
    task_id=review_task_id,
    channels=["slack", "pagerduty"],
)
```

Playbooks compose the agent manager, notification manager, and tooling helpers to offer turnkey flows for incidents and finding triage.

### Notifications & Tickets

`AgentNotificationManager` now uses transaction-safe writes and returns rich dataclasses:

```python
from cerebro_sdk import AgentNotificationManager

notifications = AgentNotificationManager(db)
record = await notifications.enqueue_notification(
    org_id=org_id,
    task_id=task_id,
    channel="slack",
    payload={"severity": "critical"},
)

await notifications.mark_delivered(record.notification_id)
ticket = await notifications.create_ticket(
    org_id=org_id,
    task_id=task_id,
    system="jira",
    summary="Containment review",
)
```

### Tooling and Approvals

`AgentToolingManager` surfaces tool invocation history and approval decisions. All updates run inside nested-aware transactions to avoid partial writes when callers already manage transactions.
