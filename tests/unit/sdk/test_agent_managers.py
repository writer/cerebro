from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import fakeredis.aioredis as fakeredis
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from cerebro.agents.models import (
    AgentReviewTask,
    AgentSession,
    AgentType,
    ApprovalStatus,
    NotificationStatus,
    TicketStatus,
    ToolInvocation,
    ToolInvocationStatus,
)
from cerebro.agents.models import (
    Base as AgentBase,
)
from cerebro.core.database import Base as CoreBase
from cerebro.core.models import Organization
from cerebro_sdk.agents.notifications import AgentNotificationManager
from cerebro_sdk.agents.playbooks import AgentPlaybook
from cerebro_sdk.agents.tooling import AgentToolingManager

UTC = UTC


@pytest_asyncio.fixture()
async def db_session() -> AsyncSession:
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(CoreBase.metadata.create_all)
        await conn.run_sync(AgentBase.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest_asyncio.fixture()
async def redis_client():
    client = fakeredis.FakeRedis()
    await client.flushall()
    try:
        yield client
    finally:
        await client.aclose()


async def _create_org_and_session(
    session: AsyncSession,
) -> tuple[Organization, AgentSession]:
    org = Organization(org_id=uuid4(), name="SDK Org")
    session.add(org)
    agent_session = AgentSession(
        org_id=org.org_id,
        agent_type=AgentType.INCIDENT_RESPONDER,
        created_by="analyst@example.com",
        context={},
    )
    session.add(agent_session)
    await session.commit()
    return org, agent_session


@pytest.mark.asyncio()
async def test_agent_tooling_manager_lists_updates_and_handles_approvals(
    db_session: AsyncSession,
    redis_client,
) -> None:
    org, agent_session = await _create_org_and_session(db_session)
    manager = AgentToolingManager(db_session)

    async def cache_listener(record):
        await redis_client.hset(
            f"tool:{record.invocation_id}",
            mapping={
                "status": record.status,
                "tool": record.tool_name,
            },
        )

    manager.register_listener(cache_listener)

    first = await manager.create_invocation(
        session_id=agent_session.session_id,
        tool_name="inventory-scan",
        input_data={"scope": "critical"},
    )
    second = await manager.create_invocation(
        session_id=agent_session.session_id,
        tool_name="quarantine",
        status=ToolInvocationStatus.RUNNING,
        input_data={},
    )

    page = await manager.list_invocations(session_id=agent_session.session_id, limit=1)
    assert len(page) == 1
    assert page[0].tool_name == second.tool_name

    assert await manager.list_invocations(org_id=org.org_id, status="bogus") == []

    updated = await manager.update_invocation_result(
        invocation_id=first.invocation_id,
        status=ToolInvocationStatus.SUCCESS,
        output_data={"ok": True},
    )
    assert updated.status == ToolInvocationStatus.SUCCESS.value
    assert updated.completed_at is not None

    from cerebro.agents.models import ToolApproval

    invocation_row = await db_session.get(ToolInvocation, first.invocation_id)
    assert invocation_row is not None
    tool_approval = ToolApproval(
        org_id=org.org_id,
        tool_invocation_id=first.invocation_id,
        requested_by="analyst@example.com",
        reason="requires review",
        risk_assessment={"impact": "high"},
        tool_invocation=invocation_row,
    )
    db_session.add(tool_approval)
    await db_session.commit()

    approval_record = await manager.update_approval_status(
        approval_id=tool_approval.id,
        status=ApprovalStatus.APPROVED,
        decided_by="approver@example.com",
        decision_reason="safe",
    )
    assert approval_record is not None
    assert approval_record.status == ApprovalStatus.APPROVED.value

    refreshed = await manager.get_invocation(first.invocation_id)
    assert refreshed is not None
    assert refreshed.status == ToolInvocationStatus.SUCCESS.value

    missing = await manager.update_approval_status(
        approval_id=uuid4(),
        status=ApprovalStatus.REJECTED,
        decided_by="ghost",
    )
    assert missing is None

    key = f"tool:{first.invocation_id}"
    cached_status = await redis_client.hget(key, "status")
    assert cached_status.decode() == ToolInvocationStatus.SUCCESS.value
    cached_tool = await redis_client.hget(key, "tool")
    assert cached_tool.decode() == "inventory-scan"

    manager.unregister_listener(cache_listener)

    summary = await manager.summarize_invocations(org_id=org.org_id)
    assert any(row.count >= 1 for row in summary)


@pytest.mark.asyncio()
async def test_agent_notification_manager_lifecycle(
    db_session: AsyncSession,
    redis_client,
) -> None:
    org, agent_session = await _create_org_and_session(db_session)

    review_task = AgentReviewTask(
        org_id=org.org_id,
        session_id=agent_session.session_id,
        title="Review findings",
        payload={},
        created_by="system",
    )
    db_session.add(review_task)
    await db_session.commit()

    manager = AgentNotificationManager(db_session)

    created = await manager.enqueue_notification(
        org_id=org.org_id,
        task_id=review_task.id,
        channel="slack",
        payload={"severity": "high"},
    )
    assert created.status == NotificationStatus.PENDING.value

    queue_key = f"notifications:{org.org_id}"
    await redis_client.rpush(queue_key, str(created.notification_id))

    pending = await manager.list_notifications(org_id=org.org_id, status="pending")
    assert len(pending) == 1

    delivered = await manager.mark_delivered(created.notification_id)
    assert delivered is not None
    assert delivered.status == NotificationStatus.DELIVERED.value
    assert delivered.delivered_at is not None

    assert await manager.list_notifications(org_id=org.org_id, status="n/a") == []

    ticket = await manager.create_ticket(
        org_id=org.org_id,
        task_id=review_task.id,
        system="jira",
        summary="Investigate incident",
        metadata={"priority": "P1"},
    )
    assert ticket.status == TicketStatus.OPEN.value

    await redis_client.hset(
        f"ticket:{ticket.ticket_id}",
        mapping={"status": ticket.status, "system": ticket.system},
    )

    tickets = await manager.list_tickets(task_id=review_task.id)
    assert len(tickets) == 1

    closed = await manager.close_ticket(
        ticket_id=ticket.ticket_id,
        external_id="JIRA-123",
    )
    assert closed is not None
    assert closed.status == TicketStatus.CLOSED.value
    assert closed.details.get("summary") == "Investigate incident"

    missing_close = await manager.close_ticket(ticket_id=uuid4())
    assert missing_close is None


@pytest.mark.asyncio()
async def test_agent_playbook_scenarios(
    db_session: AsyncSession,
    redis_client,
) -> None:
    org, agent_session = await _create_org_and_session(db_session)

    review_task = AgentReviewTask(
        org_id=org.org_id,
        session_id=agent_session.session_id,
        title="Escalation needed",
        payload={},
        created_by="bot",
    )
    db_session.add(review_task)
    await db_session.commit()

    playbook = AgentPlaybook(db_session)

    notifications = await playbook.schedule_notifications(
        task_id=review_task.id,
        channels=["slack", "email"],
    )
    assert len(notifications) == 2
    assert {record.channel for record in notifications} == {"slack", "email"}

    digest_key = f"task:{review_task.id}:notifications"
    for record in notifications:
        await redis_client.rpush(digest_key, record.channel)

    stored_channels = [
        value.decode() for value in await redis_client.lrange(digest_key, 0, -1)
    ]
    assert stored_channels == ["slack", "email"]

    fallback_notifications = await playbook.schedule_notifications(
        task_id=uuid4(),
        channels=["pagerduty"],
    )
    assert fallback_notifications == []

    ticket = await playbook.escalate_to_ticket(
        task_id=review_task.id,
        system="pagerduty",
        summary="Create incident",
        metadata={"impact": "sev1"},
    )
    assert ticket is not None
    assert ticket.status == TicketStatus.OPEN.value

    ticket_key = f"ticket:{ticket.ticket_id}"
    await redis_client.hset(ticket_key, mapping={"status": ticket.status})
    cached_ticket_status = await redis_client.hget(ticket_key, "status")
    assert cached_ticket_status.decode() == TicketStatus.OPEN.value

    suggestion = await playbook.record_policy_suggestion(
        org_id=org.org_id,
        tool_name="disable_user",
        cel_expression="input.is_admin",
        details={"source": "playbook"},
    )
    assert suggestion.support_count == 1
    assert suggestion.reject_count == 0

    updated = await playbook.record_policy_suggestion(
        org_id=org.org_id,
        tool_name="disable_user",
        cel_expression="input.is_admin",
        support_delta=2,
        reject_delta=1,
        details={"last_updated": datetime.now(UTC).isoformat()},
    )
    assert updated.suggestion_id == suggestion.suggestion_id
    assert updated.support_count == 3
    assert updated.reject_count == 1
