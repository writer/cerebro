import pytest

from datetime import datetime, timezone, timedelta
from uuid import uuid4
from unittest.mock import AsyncMock

from sqlalchemy.ext.asyncio import AsyncSession

from cerebro_sdk.agents.review import AgentReviewManager
from cerebro_sdk.agents.types import (
    AgentReviewQueueSummary,
    AgentReviewStatusAggregate,
    AgentReviewPendingSummary,
    AgentReviewPriorityBucket,
)


pytestmark = pytest.mark.asyncio


async def test_summarize_queue_returns_structured_summary(monkeypatch):
    fake_db = AsyncMock(spec=AsyncSession)
    manager = AgentReviewManager(fake_db)
    org_id = uuid4()
    now = datetime.now(timezone.utc)

    service_payload = {
        "generated_at": now,
        "status_counts": [
            {
                "status": "pending",
                "count": 5,
                "unassigned": 2,
                "overdue": 1,
                "oldest_created": now - timedelta(hours=4),
                "newest_created": now - timedelta(minutes=5),
            }
        ],
        "pending": {
            "total": 5,
            "unassigned": 2,
            "overdue": 1,
            "next_due": now + timedelta(hours=6),
            "oldest_created": now - timedelta(hours=10),
        },
        "priority_breakdown": [
            {"priority": "high", "count": 3},
            {"priority": "medium", "count": 2},
        ],
    }

    summarize_mock = AsyncMock(return_value=service_payload)
    monkeypatch.setattr(
        "cerebro_sdk.agents.review.AgentReviewService.summarize_queue",
        summarize_mock,
    )

    summary = await manager.summarize_queue(org_id=org_id, now=now)

    assert isinstance(summary, AgentReviewQueueSummary)
    assert summary.generated_at == now
    assert summary.status_counts == [
        AgentReviewStatusAggregate(
            status="pending",
            count=5,
            unassigned=2,
            overdue=1,
            oldest_created=service_payload["status_counts"][0]["oldest_created"],
            newest_created=service_payload["status_counts"][0]["newest_created"],
        )
    ]
    assert summary.pending == AgentReviewPendingSummary(
        total=5,
        unassigned=2,
        overdue=1,
        next_due=service_payload["pending"]["next_due"],
        oldest_created=service_payload["pending"]["oldest_created"],
    )
    assert summary.priority_breakdown == [
        AgentReviewPriorityBucket(priority="high", count=3),
        AgentReviewPriorityBucket(priority="medium", count=2),
    ]

    summarize_mock.assert_awaited_once_with(org_id=org_id, now=now, db_session=fake_db)


async def test_summarize_queue_handles_missing_payload(monkeypatch):
    fake_db = AsyncMock(spec=AsyncSession)
    manager = AgentReviewManager(fake_db)
    org_id = uuid4()

    summarize_mock = AsyncMock(return_value=None)
    monkeypatch.setattr(
        "cerebro_sdk.agents.review.AgentReviewService.summarize_queue",
        summarize_mock,
    )

    summary = await manager.summarize_queue(org_id=org_id)

    assert isinstance(summary, AgentReviewQueueSummary)
    assert isinstance(summary.generated_at, datetime)
    assert summary.status_counts == []
    assert summary.pending == AgentReviewPendingSummary(
        total=0,
        unassigned=0,
        overdue=0,
        next_due=None,
        oldest_created=None,
    )
    assert summary.priority_breakdown == []

    summarize_mock.assert_awaited_once_with(org_id=org_id, now=None, db_session=fake_db)
