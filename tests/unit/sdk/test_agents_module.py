from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro_sdk.agents import AgentManager


@pytest.mark.asyncio
async def test_agent_manager_create_and_list_sessions(test_db: AsyncSession, test_org):
    manager = AgentManager(test_db)

    record = await manager.create_session(
        org_id=test_org.org_id,
        agent_type="security_analyst",
        created_by="analyst@example.com",
        context={"finding_ids": [str(uuid4())]},
        title="Investigate incident",
    )

    assert record.agent_type == "security_analyst"
    assert record.is_active is True

    sessions, total = await manager.list_sessions(org_id=test_org.org_id)
    assert total == 1
    assert sessions[0].title == "Investigate incident"


@pytest.mark.asyncio
async def test_agent_manager_messages_flow(test_db: AsyncSession, test_org):
    manager = AgentManager(test_db)
    session = await manager.create_session(
        org_id=test_org.org_id,
        agent_type="security_analyst",
        created_by="analyst@example.com",
        context={},
    )

    message = await manager.add_message(
        session_id=session.session_id,
        role="user",
        content={"text": "Summarize findings"},
    )
    assert message.role == "user"

    messages = await manager.list_messages(session_id=session.session_id)
    assert len(messages) == 1
    assert messages[0].content["text"] == "Summarize findings"

    deleted = await manager.delete_message(message.message_id)
    assert deleted is True

    messages_after = await manager.list_messages(session_id=session.session_id)
    assert messages_after == []
