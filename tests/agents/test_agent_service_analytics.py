import pytest
from datetime import datetime, timezone
from uuid import UUID

from cerebro.agents.analytics_service import AgentAnalyticsService
from cerebro.agents.models import AgentSession, AgentType
from cerebro.agents.service import AgentSessionService
from cerebro.core.database import async_session_factory
from cerebro.core.models import Organization


@pytest.mark.asyncio
async def test_get_session_analytics_filters_by_event_type():
    async with async_session_factory() as db_session:
        org = Organization(name="Analytics Org", created_at=datetime.now(timezone.utc))
        db_session.add(org)
        await db_session.commit()
        await db_session.refresh(org)

        session = AgentSession(
            org_id=org.org_id,
            agent_type=AgentType.SECURITY_ANALYST,
            created_by="analytics@example.com",
            title="Analytics Session",
            context={}
        )
        db_session.add(session)
        await db_session.commit()
        await db_session.refresh(session)

    original_probability = AgentAnalyticsService._RETENTION_PROBABILITY
    AgentAnalyticsService._RETENTION_PROBABILITY = 0.0
    try:
        await AgentAnalyticsService.record_event(
            org_id=org.org_id,
            session_id=session.id,
            event_type="memory_recall",
            payload={"memory_count": 3},
        )
        await AgentAnalyticsService.record_event(
            org_id=org.org_id,
            session_id=session.id,
            event_type="tool_execution",
            payload={"tool": "findings_list"},
        )
    finally:
        AgentAnalyticsService._RETENTION_PROBABILITY = original_probability

    service = AgentSessionService()
    filtered = await service.get_session_analytics(
        session_id=session.id,
        org_id=org.org_id,
        limit=10,
        event_type="tool_execution",
    )

    assert len(filtered) == 1
    assert filtered[0]["event_type"] == "tool_execution"


@pytest.mark.asyncio
async def test_get_session_analytics_paginates_with_cursor():
    async with async_session_factory() as db_session:
        org = Organization(name="Analytics Org", created_at=datetime.now(timezone.utc))
        db_session.add(org)
        await db_session.commit()
        await db_session.refresh(org)

        session = AgentSession(
            org_id=org.org_id,
            agent_type=AgentType.SECURITY_ANALYST,
            created_by="analytics@example.com",
            title="Analytics Session",
            context={}
        )
        db_session.add(session)
        await db_session.commit()
        await db_session.refresh(session)

    original_probability = AgentAnalyticsService._RETENTION_PROBABILITY
    AgentAnalyticsService._RETENTION_PROBABILITY = 0.0
    try:
        await AgentAnalyticsService.record_event(
            org_id=org.org_id,
            session_id=session.id,
            event_type="memory_recall",
            payload={"memory_count": 3},
        )
        await AgentAnalyticsService.record_event(
            org_id=org.org_id,
            session_id=session.id,
            event_type="tool_execution",
            payload={"tool": "findings_list"},
        )
    finally:
        AgentAnalyticsService._RETENTION_PROBABILITY = original_probability

    service = AgentSessionService()

    first_page = await service.get_session_analytics(
        session_id=session.id,
        org_id=org.org_id,
        limit=1,
    )
    assert len(first_page) == 1

    cursor_iso = first_page[-1]["created_at"]
    cursor = datetime.fromisoformat(cursor_iso)
    cursor_id = UUID(first_page[-1]["id"])
    second_page = await service.get_session_analytics(
        session_id=session.id,
        org_id=org.org_id,
        limit=10,
        before=cursor,
        before_id=cursor_id,
    )

    assert len(second_page) >= 1
    first_page_ids = {event["id"] for event in first_page}
    for event in second_page:
        event_ts = datetime.fromisoformat(event["created_at"])
        event_id = UUID(event["id"])
        if event_ts == cursor:
            assert event_id < cursor_id
        else:
            assert event_ts < cursor
        assert event["id"] not in first_page_ids
