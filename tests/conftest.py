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
from cerebro.agents.models import Base as AgentsBase
from cerebro.core.models import Organization, Account, Principal, Resource, Rule, Policy
from cerebro.core.user_models import User
from cerebro.core import user_service as user_service_module
from cerebro.core.user_service import UserService, pwd_context
import httpx
from cerebro.api.main import app
from cerebro.core.security.key_store import JWTKeyStore
from cerebro.core.security.jwt import JWTService
from cerebro.metrics.jwt_metrics import jwt_metrics


class _TestPwdContext:
    """Simplified password context for test environment."""

    def hash(self, password: str) -> str:
        return f"hashed::{password}"

    def verify(self, password: str, hashed: str) -> bool:
        return hashed == self.hash(password)


user_service_module.pwd_context = _TestPwdContext()
pwd_context = user_service_module.pwd_context


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Setup test environment variables."""
    os.environ['ENVIRONMENT'] = 'test'
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
        await conn.run_sync(AgentsBase.metadata.create_all)
    
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

    transport = httpx.ASGITransport(app=app)

    async def _request(method: str, url: str, **kwargs):
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.request(method, url, **kwargs)
            return response

    class _ClientProxy:
        def __init__(self):
            self._transport = transport

        def request(self, method: str, url: str, **kwargs):
            return asyncio.get_event_loop().run_until_complete(_request(method, url, **kwargs))

        def get(self, url: str, **kwargs):
            return self.request("GET", url, **kwargs)

        def post(self, url: str, **kwargs):
            return self.request("POST", url, **kwargs)

        def put(self, url: str, **kwargs):
            return self.request("PUT", url, **kwargs)

        def delete(self, url: str, **kwargs):
            return self.request("DELETE", url, **kwargs)

    try:
        yield _ClientProxy()
    finally:
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
async def test_policy(test_db: AsyncSession, test_org: Organization) -> Policy:
    policy = Policy(org_id=test_org.org_id, name="Default Policy")
    test_db.add(policy)
    await test_db.commit()
    await test_db.refresh(policy)
    return policy


@pytest.fixture
async def test_user(test_db: AsyncSession) -> User:
    """Create test user."""
    user_service = UserService(test_db)
    await user_service.create_default_scopes()
    
    user = await user_service.create_user(
        username="testuser",
        email="test@example.com",
        password="testpass123",
        scopes=["read:findings", "read:rules", "write:findings"]
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
async def test_principal(test_db: AsyncSession, test_github_account: Account) -> Principal:
    principal = Principal(
        account_id=test_github_account.account_id,
        provider="github",
        principal_type="user",
        external_id="user-1",
        email="user@example.com",
        display_name="User 1",
        is_human=True,
    )
    test_db.add(principal)
    await test_db.commit()
    await test_db.refresh(principal)
    return principal


@pytest.fixture
async def test_resource(test_db: AsyncSession, test_github_account: Account) -> Resource:
    resource = Resource(
        account_id=test_github_account.account_id,
        provider="github",
        resource_type="repo",
        external_id="repo-1",
        name="Repo 1",
    )
    test_db.add(resource)
    await test_db.commit()
    await test_db.refresh(resource)
    return resource


@pytest.fixture
async def test_rule(test_db: AsyncSession, test_policy: Policy) -> Rule:
    rule = Rule(
        policy_id=test_policy.policy_id,
        name="Fixture Rule",
        description="Ensures repo is private",
        provider=["github"],
        resource_types=["repo"],
        expression_lang="cel",
        expression="resource.visibility == 'private'",
        severity="medium",
    )
    test_db.add(rule)
    await test_db.commit()
    await test_db.refresh(rule)
    return rule


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
