"""Test configuration and fixtures."""

import pytest
import asyncio
from typing import AsyncGenerator, Generator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from cerebro.core.database import Base
from cerebro.core.models import Organization, Account
from cerebro.core.user_models import User
from cerebro.core.user_service import UserService


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def test_db() -> AsyncGenerator[AsyncSession, None]:
    """Create test database session."""
    # Use in-memory SQLite for tests
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        echo=False,
    )
    
    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Create session
    async_session = async_sessionmaker(engine, expire_on_commit=False)
    
    async with async_session() as session:
        yield session
    
    await engine.dispose()


@pytest.fixture
async def test_org(test_db: AsyncSession) -> Organization:
    """Create test organization."""
    org = Organization(name="Test Organization")
    test_db.add(org)
    await test_db.commit()
    await test_db.refresh(org)
    return org


@pytest.fixture
async def test_github_account(test_db: AsyncSession, test_org: Organization) -> Account:
    """Create test GitHub account."""
    account = Account(
        org_id=test_org.org_id,
        provider="github",
        external_id="test-org",
        display_name="Test GitHub Organization"
    )
    test_db.add(account)
    await test_db.commit()
    await test_db.refresh(account)
    return account


@pytest.fixture
async def test_aws_account(test_db: AsyncSession, test_org: Organization) -> Account:
    """Create test AWS account."""
    account = Account(
        org_id=test_org.org_id,
        provider="aws",
        external_id="123456789012",
        display_name="Test AWS Account"
    )
    test_db.add(account)
    await test_db.commit()
    await test_db.refresh(account)
    return account


@pytest.fixture
async def test_user(test_db: AsyncSession) -> User:
    """Create test user."""
    user_service = UserService(test_db)
    await user_service.create_default_scopes()
    
    user = await user_service.create_user(
        username="testuser",
        email="test@example.com",
        password="testpass123",
        scopes=["read:findings", "read:rules"]
    )
    return user


@pytest.fixture
async def test_admin_user(test_db: AsyncSession) -> User:
    """Create test admin user."""
    user_service = UserService(test_db)
    await user_service.create_default_scopes()
    
    admin = await user_service.create_admin_user(
        username="testadmin",
        email="admin@example.com", 
        password="admin123"
    )
    return admin
