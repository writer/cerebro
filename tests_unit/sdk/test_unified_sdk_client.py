from unittest.mock import AsyncMock

import pytest

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from cerebro_sdk.client import UnifiedCerebroSDK


pytestmark = pytest.mark.asyncio


async def test_unified_sdk_caches_facades():
    session = AsyncMock(spec=AsyncSession)
    sdk = UnifiedCerebroSDK(session)

    assert sdk.users is sdk.users
    assert sdk.agents is sdk.agents
    assert sdk.analytics is sdk.analytics

    agents = sdk.agents
    assert agents.manager._db is session
    assert agents.review._db is session
    assert agents.tooling._repo._db is session


async def test_unified_sdk_context_yields_bound_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with UnifiedCerebroSDK.from_session_factory(session_factory) as sdk:
        assert isinstance(sdk.session, AsyncSession)

    await engine.dispose()
