import pytest

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from cerebro.core.database import Base
from cerebro.core.models import Organization
from cerebro.integrations.serval_service import ServalIntegrationRepository


pytestmark = pytest.mark.asyncio


async def test_serval_integration_repository_roundtrip():
    # Validate encryption, persistence, and retrieval via the repository.
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with session_factory() as session:
        org = Organization(name="Acme Corp")
        session.add(org)
        await session.commit()
        await session.refresh(org)

        repo = ServalIntegrationRepository(session)

        settings = await repo.upsert(
            org_id=org.org_id,
            api_base_url="https://api.serval.test",
            team_id="team-1",
            client_id="client-id",
            client_secret="client-secret",
            default_created_by_user_id="user-creator",
            default_status_id="status-open",
            default_priority_id="priority-default",
            status_map={"open": "status-open", "closed": "status-closed"},
            priority_map={"default": "priority-default"},
        )

        assert settings.org_id == org.org_id
        assert settings.client_id == "client-id"
        assert settings.client_secret == "client-secret"
        assert settings.status_map["closed"] == "status-closed"
        assert settings.status_reverse_map["status-closed"] == "closed"

        fetched = await repo.get(org.org_id)
        assert fetched is not None
        assert fetched.team_id == "team-1"
        assert fetched.priority_reverse_map["priority-default"] == "default"

        await repo.delete(org.org_id)
        assert await repo.get(org.org_id) is None

    await engine.dispose()
