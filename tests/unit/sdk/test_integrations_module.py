from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.models import IntegrationSyncIssueEvent
from cerebro.tasks import integration_tasks
from cerebro_sdk.integrations import IntegrationService, IntegrationTaskRegistry

UTC = UTC


@pytest.mark.asyncio
async def test_integration_service_states(test_db: AsyncSession):
    service = IntegrationService(test_db)

    record = await service.upsert_state(
        integration="kandji",
        scope="default",
        last_cursor="cursor",
        metadata={"status": "ok"},
    )
    assert record.metadata["status"] == "ok"

    states = await service.list_states()
    assert any(state.integration == "kandji" for state in states)


@pytest.mark.asyncio
async def test_integration_service_issue_events(test_db: AsyncSession):
    now = datetime.now(UTC)
    event = IntegrationSyncIssueEvent(
        integration="kandji",
        scope="default",
        issue_type="stale",
        severity="warning",
        message="Stale cursor",
        observed_at=now,
        issue_metadata={"age": 3600},
    )
    test_db.add(event)
    await test_db.commit()

    service = IntegrationService(test_db)
    events = await service.list_issue_events(integration="kandji")
    assert events and events[0].message == "Stale cursor"

    summary = await service.summarize_issue_events(
        integration="kandji",
        window=timedelta(hours=8),
        bucket=timedelta(hours=1),
    )
    assert summary


def test_integration_service_trigger_sync(monkeypatch: pytest.MonkeyPatch):
    mock_result = MagicMock()
    mock_result.id = "task-123"
    apply_mock = MagicMock(return_value=mock_result)
    monkeypatch.setattr(integration_tasks.sync_kandji, "apply_async", apply_mock)

    service = IntegrationService(MagicMock())
    task_id = service.trigger_sync("kandji")

    assert task_id == "task-123"
    apply_mock.assert_called_once()


def test_integration_task_registry_registration(monkeypatch: pytest.MonkeyPatch):
    mock_result = MagicMock(id="task-789")
    mock_task = MagicMock()
    mock_task.apply_async.return_value = mock_result

    IntegrationTaskRegistry.register("custom", mock_task)
    try:
        service = IntegrationService(MagicMock())
        task_id = service.trigger_sync("custom", foo="bar")
        assert task_id == "task-789"
        mock_task.apply_async.assert_called_once_with(kwargs={"foo": "bar"})
    finally:
        IntegrationTaskRegistry.unregister("custom")
