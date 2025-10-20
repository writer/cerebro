"""Test configuration and fixtures."""

import pytest
import asyncio
import os
from typing import AsyncGenerator, Generator

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./cerebro_test.db?cache=shared&uri=true")
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from cerebro.core.database import Base, get_db
from cerebro.core.models import Organization, Account
from cerebro.core.user_models import User
from cerebro.core.user_service import UserService, pwd_context
from fastapi.testclient import TestClient
from cerebro.api.main import app
from cerebro.core.security.key_store import JWTKeyStore
from cerebro.core.security.jwt import JWTService
from cerebro.metrics.jwt_metrics import jwt_metrics


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Setup test environment variables."""
    os.environ['ENVIRONMENT'] = 'test'
    pwd_context.update(schemes=["pbkdf2_sha256"], deprecated="auto")
    os.environ.setdefault("ENABLE_AGENT_TELEMETRY", "true")
    os.environ.setdefault("AGENT_OTEL_ENDPOINT", "http://localhost:4318/v1/traces")
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
def client(test_db: AsyncSession):
    """Create test client with in-memory database override."""

    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield test_db

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.pop(get_db, None)


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
    user.org_id = await test_db.scalar(select(Organization.org_id).limit(1))
    await test_db.commit()
    return user


@pytest.fixture
async def jwt_service(test_db: AsyncSession) -> JWTService:
    """Provide a JWT service instance for tests."""

    key_store = JWTKeyStore(test_db, metrics=jwt_metrics)
    await key_store.rotate_keys_if_needed()
    return JWTService(key_store, metrics=jwt_metrics)


@pytest.fixture
async def test_admin_user(test_db: AsyncSession) -> User:
    """Create test admin user."""
    user_service = UserService(test_db)
    await user_service.create_default_scopes()
    
    admin = await user_service.create_admin_user(
        username="testadmin",
        email="admin@example.com",
        password="admin-test-pass"
    )
    admin.org_id = await test_db.scalar(select(Organization.org_id).limit(1))
    await test_db.commit()
    return admin


@pytest.fixture
async def test_token(test_db: AsyncSession, test_user: User, jwt_service: JWTService):
    """Create test JWT token."""

    user_service = UserService(test_db)
    scopes = await user_service.get_user_scopes(test_user.user_id)
    org_id = test_user.org_id or await test_db.scalar(select(Organization.org_id).limit(1))

    return await jwt_service.create_token(
        username=test_user.username,
        scopes=scopes,
        org_id=org_id,
    )


@pytest.fixture
async def admin_token(test_db: AsyncSession, test_admin_user: User, jwt_service: JWTService):
    """Create admin JWT token."""

    user_service = UserService(test_db)
    scopes = await user_service.get_user_scopes(test_admin_user.user_id)
    org_id = test_admin_user.org_id or await test_db.scalar(select(Organization.org_id).limit(1))

    return await jwt_service.create_token(
        username=test_admin_user.username,
        scopes=scopes,
        org_id=org_id,
    )
