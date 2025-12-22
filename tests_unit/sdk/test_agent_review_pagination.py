import pytest

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

from cerebro_sdk.agents.review import AgentReviewManager
from cerebro_sdk.pagination import PageRequest


class StubSession:
    def __init__(self, rows):
        self._rows = rows

    async def scalars(self, _stmt):
        return self._rows


def build_task(created_at: datetime):
    task_id = uuid4()
    return SimpleNamespace(
        id=task_id,
        session_id=uuid4(),
        org_id=uuid4(),
        status=SimpleNamespace(value="pending"),
        title="Task",
        summary=None,
        payload={},
        promotion_target=None,
        priority=None,
        due_at=None,
        escalated_to=None,
        notification_channel=None,
        ticket_reference=None,
        created_by="tester",
        created_at=created_at,
        resolved_by=None,
        resolved_at=None,
        resolution_notes=None,
        assigned_to=None,
    )


@pytest.mark.asyncio
async def test_list_tasks_page_returns_cursor():
    now = datetime.now(timezone.utc)
    tasks = [build_task(now - timedelta(minutes=idx)) for idx in range(3)]

    stub_session = StubSession(tasks)
    manager = AgentReviewManager(stub_session)
    page = await manager.list_tasks_page(org_id=uuid4(), page=PageRequest(limit=2))

    assert len(page.items) == 2
    assert page.next_cursor is not None


@pytest.mark.asyncio
async def test_list_tasks_page_without_more_results():
    now = datetime.now(timezone.utc)
    tasks = [build_task(now)]
    stub_session = StubSession(tasks)
    manager = AgentReviewManager(stub_session)
    page = await manager.list_tasks_page(org_id=uuid4(), page=PageRequest(limit=5))

    assert len(page.items) == 1
    assert page.next_cursor is None
