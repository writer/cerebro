from datetime import datetime, timedelta, timezone

import pytest

from cerebro.analytics.datasets import DatasetBuilder
from cerebro.agents.models import (
    AgentReviewTask,
    AgentRuntimeEvent,
    AgentSession,
    AgentType,
    ReviewTaskStatus,
)
from cerebro.core.models import FrontendObservationEvent


@pytest.mark.asyncio
async def test_dataset_builder_combines_streams(test_db, test_org):
    session = AgentSession(
        org_id=test_org.org_id,
        agent_type=AgentType.SECURITY_ANALYST,
        created_by="unit-test",
        title="Benchmark Session",
        context={},
    )
    test_db.add(session)
    await test_db.commit()
    await test_db.refresh(session)

    base_time = datetime(2024, 10, 22, 12, 0, tzinfo=timezone.utc)

    runtime_event = AgentRuntimeEvent(
        org_id=test_org.org_id,
        session_id=session.id,
        event_type="tool_invocation",
        payload={"tool": "query.list_exposed_iam_users", "outcome": "SUCCESS"},
        created_at=base_time,
    )

    frontend_event = FrontendObservationEvent(
        org_id=test_org.org_id,
        user_id=None,
        agent_session_id=session.id,
        event_type="runtime_analytics_submit",
        component="RuntimeAnalyticsPanel",
        context_data={"sessionId": str(session.id)},
        event_metadata={"source": "unit-test"},
        occurred_at=base_time + timedelta(minutes=1),
        created_at=base_time + timedelta(minutes=1, seconds=5),
    )

    review_task = AgentReviewTask(
        org_id=test_org.org_id,
        session_id=session.id,
        message_id=None,
        tool_invocation_id=None,
        title="Containment Approval",
        summary="Approve containment actions",
        payload={"action": "containment"},
        priority="high",
        status=ReviewTaskStatus.APPROVED,
        created_by="autonomy",
        created_at=base_time + timedelta(minutes=2),
        resolved_at=base_time + timedelta(minutes=3),
        resolution_notes="Approved",
    )

    test_db.add_all([runtime_event, frontend_event, review_task])
    await test_db.commit()

    builder = DatasetBuilder(test_db)
    records = await builder.build(test_org.org_id)

    assert [record.source for record in records] == ["runtime", "frontend", "review"]

    runtime_record = records[0]
    assert runtime_record.labels["outcome"] == "SUCCESS"

    frontend_record = records[1]
    assert frontend_record.payload["component"] == "RuntimeAnalyticsPanel"

    review_record = records[2]
    assert review_record.labels["status"] == ReviewTaskStatus.APPROVED.value
