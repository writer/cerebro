import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import func, select, update

from cerebro.agents.memory_store import AgentMemoryStore
from cerebro.agents.models import AgentMemoryEntry, AgentSession, AgentType, MessageRole
from cerebro.core.config import settings
from cerebro.core.database import async_session_factory
from cerebro.core.models import Organization


@pytest.fixture(autouse=True)
def reset_memory_store():
    AgentMemoryStore._instance = None
    previous_probability = settings.agent_memory_prune_probability
    settings.agent_memory_prune_probability = 0.0
    try:
        yield
    finally:
        AgentMemoryStore._instance = None
        settings.agent_memory_prune_probability = previous_probability


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
    assert "administrators" in snippets[0]["snippet"].lower()
    assert snippets[0]["id"]
    assert snippets[0]["metadata"] is not None

    async with async_session_factory() as db_session:
        updated_entry = await db_session.get(AgentMemoryEntry, newer_entry.id)
        assert updated_entry is not None
        assert updated_entry.decay_score > previous_decay
        assert updated_entry.last_accessed_at is not None
        assert updated_entry.last_accessed_at > baseline_last_accessed


@pytest.mark.asyncio
async def test_memory_store_deduplicates_recent_content(memory_session):
    store = await AgentMemoryStore.shared()

    message = "Repeated identity alert requires escalation"
    await store.add_message(
        session=memory_session,
        role=MessageRole.USER,
        content=message,
    )
    await store.add_message(
        session=memory_session,
        role=MessageRole.ASSISTANT,
        content=message,
    )

    async with async_session_factory() as db_session:
        total = await db_session.scalar(
            select(func.count(AgentMemoryEntry.id)).where(
                AgentMemoryEntry.org_id == memory_session.org_id
            )
        )
        assert total == 1

        entry = (
            await db_session.execute(
                select(AgentMemoryEntry).where(
                    AgentMemoryEntry.org_id == memory_session.org_id
                )
            )
        ).scalar_one()

        metadata = entry.extra_metadata or {}
        assert metadata.get("occurrence_count") == 2
        assert entry.content_hash is not None
        assert entry.token_count >= 1


@pytest.mark.asyncio
async def test_memory_store_prefers_session_scoped_results(memory_session):
    previous_boost = settings.agent_memory_session_scope_boost
    AgentMemoryStore._instance = None
    settings.agent_memory_session_scope_boost = 2.5
    store = await AgentMemoryStore.shared()

    secondary_session = None
    try:
        await store.add_message(
            session=memory_session,
            role=MessageRole.ASSISTANT,
            content="Primary session recommendation: enable Okta MFA for admins.",
        )

        async with async_session_factory() as db_session:
            secondary_session = AgentSession(
                org_id=memory_session.org_id,
                agent_type=AgentType.SECURITY_ANALYST,
                created_by="secondary@example.com",
                title="Secondary Session",
                context={"provider_scope": ["azure"], "finding_ids": []},
            )
            db_session.add(secondary_session)
            await db_session.commit()
            await db_session.refresh(secondary_session)

        await store.add_message(
            session=secondary_session,
            role=MessageRole.ASSISTANT,
            content="Secondary insight: Azure AD administrators missing MFA.",
        )

        snippets = await store.retrieve_relevant(
            session=memory_session,
            query="MFA administrators",
            limit=2,
        )

        assert snippets
        assert "Primary session recommendation" in snippets[0]["snippet"]
    finally:
        if secondary_session is not None:
            async with async_session_factory() as db_session:
                await db_session.delete(secondary_session)
                await db_session.commit()
        settings.agent_memory_session_scope_boost = previous_boost
        AgentMemoryStore._instance = None


@pytest.mark.asyncio
async def test_memory_store_prunes_when_limits_exceeded(memory_session):
    previous_session_limit = settings.agent_memory_max_entries_per_session
    previous_org_limit = settings.agent_memory_max_entries_per_org
    previous_batch_size = settings.agent_memory_prune_batch_size
    previous_min_decay = settings.agent_memory_prune_min_decay
    previous_probability = settings.agent_memory_prune_probability

    settings.agent_memory_max_entries_per_session = 2
    settings.agent_memory_max_entries_per_org = 3
    settings.agent_memory_prune_batch_size = 10
    settings.agent_memory_prune_min_decay = 1.0
    settings.agent_memory_prune_probability = 1.0
    AgentMemoryStore._instance = None

    try:
        store = await AgentMemoryStore.shared()

        for idx in range(3):
            await store.add_message(
                session=memory_session,
                role=MessageRole.ASSISTANT,
                content=f"Session memo {idx}: review administrator MFA posture.",
            )

        async with async_session_factory() as db_session:
            session_count = await db_session.scalar(
                select(func.count(AgentMemoryEntry.id)).where(
                    AgentMemoryEntry.session_id == memory_session.id
                )
            )
            org_count = await db_session.scalar(
                select(func.count(AgentMemoryEntry.id)).where(
                    AgentMemoryEntry.org_id == memory_session.org_id
                )
            )

        assert session_count == 2
        assert org_count <= 3
    finally:
        settings.agent_memory_max_entries_per_session = previous_session_limit
        settings.agent_memory_max_entries_per_org = previous_org_limit
        settings.agent_memory_prune_batch_size = previous_batch_size
        settings.agent_memory_prune_min_decay = previous_min_decay
        settings.agent_memory_prune_probability = previous_probability
        AgentMemoryStore._instance = None
