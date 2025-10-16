import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import select, update

from cerebro.agents.memory_store import AgentMemoryStore
from cerebro.agents.models import AgentMemoryEntry, AgentSession, AgentType, MessageRole
from cerebro.core.database import async_session_factory
from cerebro.core.models import Organization


@pytest.fixture(autouse=True)
def reset_memory_store():
    AgentMemoryStore._instance = None
    yield
    AgentMemoryStore._instance = None


@pytest.fixture
async def org_for_memory():
    async with async_session_factory() as session:
        org = Organization(
            org_id=uuid4(),
            name="Memory Test Org",
            created_at=datetime.now(timezone.utc),
        )
        session.add(org)
        await session.commit()
        await session.refresh(org)
        yield org
        await session.delete(org)
        await session.commit()


@pytest.fixture
async def memory_session(org_for_memory):
    async with async_session_factory() as session:
        agent_session = AgentSession(
            org_id=org_for_memory.org_id,
            agent_type=AgentType.SECURITY_ANALYST,
            created_by="memory-test@example.com",
            title="Memory Store Session",
            context={"provider_scope": ["aws"], "finding_ids": []},
        )
        session.add(agent_session)
        await session.commit()
        await session.refresh(agent_session)
        yield agent_session
        await session.delete(agent_session)
        await session.commit()


@pytest.mark.asyncio
async def test_memory_store_prioritizes_recent_entries(memory_session):
    store = await AgentMemoryStore.shared()

    await store.add_message(
        session=memory_session,
        role=MessageRole.USER,
        content="Investigate Okta MFA coverage for privileged roles.",
    )
    await store.add_message(
        session=memory_session,
        role=MessageRole.ASSISTANT,
        content="Okta tenant shows 8 administrators without MFA. Recommend enforcing policies immediately.",
    )

    async with async_session_factory() as db_session:
        result = await db_session.execute(
            select(AgentMemoryEntry)
            .where(AgentMemoryEntry.session_id == memory_session.id)
            .order_by(AgentMemoryEntry.created_at.asc())
        )
        entries = result.scalars().all()
        assert len(entries) == 2

        older_entry, newer_entry = entries

        antiquated_time = (older_entry.created_at or datetime.now(timezone.utc)) - timedelta(days=10)
        await db_session.execute(
            update(AgentMemoryEntry)
            .where(AgentMemoryEntry.id == older_entry.id)
            .values(
                created_at=antiquated_time,
                last_accessed_at=antiquated_time,
                decay_score=0.2,
            )
        )
        await db_session.commit()

        previous_decay = newer_entry.decay_score or 1.0
        baseline_last_accessed = newer_entry.last_accessed_at or datetime.min.replace(tzinfo=timezone.utc)

    snippets = await store.retrieve_relevant(
        session=memory_session,
        query="Okta administrators MFA",
        limit=5,
    )

    assert snippets, "Expected memory retrieval to return entries"
    assert "administrators" in snippets[0].lower()

    async with async_session_factory() as db_session:
        updated_entry = await db_session.get(AgentMemoryEntry, newer_entry.id)
        assert updated_entry is not None
        assert updated_entry.decay_score > previous_decay
        assert updated_entry.last_accessed_at is not None
        assert updated_entry.last_accessed_at > baseline_last_accessed
