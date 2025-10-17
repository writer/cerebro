import pytest
from datetime import datetime, timezone

from cerebro.agents.memory_store import AgentMemoryStore
from cerebro.agents.models import AgentSession, AgentType, MessageRole
from cerebro.agents.service import AgentSessionService
from cerebro.core.database import async_session_factory
from cerebro.core.models import Organization


@pytest.mark.asyncio
async def test_get_session_memory_returns_entries():
    AgentMemoryStore._instance = None

    async with async_session_factory() as db_session:
        org = Organization(
            name="Memory Service Org",
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(org)
        await db_session.commit()
        await db_session.refresh(org)

        session = AgentSession(
            org_id=org.org_id,
            agent_type=AgentType.SECURITY_ANALYST,
            created_by="memory@example.com",
            title="Service Memory Session",
            context={"provider_scope": ["aws"]},
        )
        db_session.add(session)
        await db_session.commit()
        await db_session.refresh(session)

    store = await AgentMemoryStore.shared()
    await store.add_message(
        session=session,
        role=MessageRole.ASSISTANT,
        content="Remediation summary for MFA rollout across privileged accounts.",
    )

    service = AgentSessionService()
    results = await service.get_session_memory(session.id, org.org_id)

    assert results is not None
    assert len(results) == 1
    entry = results[0]
    assert entry["summary"]
    assert entry["decay_score"] > 0
    assert entry["scope_labels"]

    AgentMemoryStore._instance = None
