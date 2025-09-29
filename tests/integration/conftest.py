"""Test configuration for integration tests without API dependencies."""

import pytest
import asyncio
import os
from typing import AsyncGenerator, Generator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from cerebro.agents.models import Base as AgentBase


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Setup test environment variables."""
    os.environ['ENVIRONMENT'] = 'test'
    yield
    # Cleanup after tests
    os.environ.pop('ENVIRONMENT', None)


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def agent_db() -> AsyncGenerator[AsyncSession, None]:
    """Create test database session with only agent tables."""
    # Use in-memory SQLite for tests
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        echo=False,
    )
    
    # Create only agent tables
    async with engine.begin() as conn:
        await conn.run_sync(AgentBase.metadata.create_all)
    
    # Create session
    async_session = async_sessionmaker(engine, expire_on_commit=False)
    
    async with async_session() as session:
        yield session
    
    await engine.dispose()
