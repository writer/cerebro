import pytest
from datetime import datetime, timezone

from cerebro.agents.models import AgentMessage, AgentSession, AgentType, MessageRole
from cerebro.agents.service import AgentSessionService
from cerebro.core.database import async_session_factory
from cerebro.core.models import Organization


@pytest.mark.asyncio
async def test_get_session_with_messages_returns_tool_invocations_and_metrics():
    async with async_session_factory() as db_session:
        org = Organization(
            name="Session API Org",
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(org)
        await db_session.commit()
        await db_session.refresh(org)

        session = AgentSession(
            org_id=org.org_id,
            agent_type=AgentType.SECURITY_ANALYST,
            created_by="session@example.com",
            title="Session With Messages",
            context={"provider_scope": ["aws"]},
        )
        db_session.add(session)
        await db_session.commit()
        await db_session.refresh(session)

        message = AgentMessage(
            session_id=session.id,
            role=MessageRole.USER,
            content="Show me the latest findings",
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(message)
        await db_session.commit()

    service = AgentSessionService()
    result = await service.get_session_with_messages(session.id, org.org_id)

    assert result is not None
    assert result["session"]["status"] == "active"
    assert result["messages"][0]["content"] == message.content
    assert isinstance(result["tool_invocations"], list)
    assert "metrics" in result
