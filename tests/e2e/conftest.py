"""E2E tests (in-process).

This suite runs against the FastAPI app via `httpx.ASGITransport` and a local
SQLite database, so it can run in CI without a separately-running server.
"""

import asyncio
import os
from datetime import datetime, timezone
from typing import AsyncGenerator, Generator
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from cerebro.agents.models import AgentSession, Base as AgentsBase
from cerebro.api.main import app
from cerebro.core.database import Base, get_db
from cerebro.core.models import Account, Finding, Organization, Rule
from cerebro.core.user_service import UserService
from cerebro.core import user_service as user_service_module


os.environ.setdefault("ENVIRONMENT", "test")


class _TestPwdContext:
    def hash(self, password: str) -> str:
        return f"hashed::{password}"

    def verify(self, password: str, hashed: str) -> bool:
        return hashed == self.hash(password)


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def engine():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        echo=False,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(AgentsBase.metadata.create_all)

    yield engine
    await engine.dispose()


@pytest_asyncio.fixture(scope="session")
async def session_factory(engine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _override_app_db(session_factory: async_sessionmaker[AsyncSession]):
    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides.pop(get_db, None)


@pytest_asyncio.fixture(scope="session", autouse=True)
async def seed_database(session_factory: async_sessionmaker[AsyncSession]):
    user_service_module.pwd_context = _TestPwdContext()

    # NOTE: avoid purely-numeric UUID hex values on SQLite when using PG UUID types,
    # since SQLite may coerce them into integers (e.g. ...0001 -> 1).
    org_id = UUID(os.getenv("E2E_TEST_ORG_ID", "00000000-0000-0000-0000-00000000000a"))
    username = os.getenv("E2E_TEST_USER", "test@example.com")
    password = os.getenv("E2E_TEST_PASSWORD", "testpassword123")

    async with session_factory() as session:
        org = await session.get(Organization, org_id)
        if not org:
            org = Organization(org_id=org_id, name="E2E Test Org")
            session.add(org)

        # Minimal account + rule so we can seed findings.
        account = await session.scalar(
            select(Account).where(Account.org_id == org_id, Account.provider == "aws")
        )
        if not account:
            account = Account(
                org_id=org_id,
                provider="aws",
                external_id="e2e-account",
                display_name="E2E Account",
            )
            session.add(account)
            await session.flush()

        rule = await session.scalar(select(Rule).where(Rule.name == "E2E Rule"))
        if not rule:
            rule = Rule(
                policy_id=None,
                name="E2E Rule",
                description="E2E rule seed",
                provider=["aws"],
                resource_types=None,
                expression_lang="cel",
                expression="true",
                severity="high",
                cwe=None,
                cis=None,
                nist_800_53=None,
                mitre_attack=None,
                version=1,
                is_active=True,
            )
            session.add(rule)
            await session.flush()

        now = datetime.now(timezone.utc)
        existing = await session.scalar(select(Finding).where(Finding.title == "E2E Finding"))
        if not existing:
            session.add(
                Finding(
                    org_id=org_id,
                    account_id=account.account_id,
                    provider="aws",
                    rule_id=rule.rule_id,
                    rule_version=1,
                    resource_id=None,
                    principal_id=None,
                    first_seen=now,
                    last_seen=now,
                    status="open",
                    severity="critical",
                    fingerprint=f"e2e-fp-{uuid4()}",
                    title="E2E Finding",
                    summary="seed",
                    evidence=None,
                )
            )

        # Seed user with scopes.
        user_service = UserService(session)
        try:
            user = await user_service.create_user(
                username=username,
                email=username,
                password=password,
                is_admin=True,
                scopes=[
                    "read:findings",
                    "write:findings",
                    "read:rules",
                    "write:rules",
                ],
            )
        except ValueError:
            user = await user_service.get_user_by_username(username)
            if user is not None:
                await user_service.add_user_scopes(
                    user.user_id,
                    [
                        "read:findings",
                        "write:findings",
                        "read:rules",
                        "write:rules",
                    ],
                )

        await session.commit()


@pytest_asyncio.fixture
async def api_client() -> AsyncGenerator[httpx.AsyncClient, None]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
        follow_redirects=True,
    ) as client:
        yield client


@pytest_asyncio.fixture
async def auth_client(api_client: httpx.AsyncClient) -> AsyncGenerator[httpx.AsyncClient, None]:
    username = os.getenv("E2E_TEST_USER", "test@example.com")
    password = os.getenv("E2E_TEST_PASSWORD", "testpassword123")

    login_response = await api_client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": password},
    )
    if login_response.status_code == 200:
        tokens = login_response.json()
        api_client.headers["Authorization"] = f"Bearer {tokens['access_token']}"
    yield api_client


class TestDataFactory:
    def __init__(self, client: httpx.AsyncClient, org_id: UUID, session_factory: async_sessionmaker[AsyncSession]):
        self.client = client
        self.org_id = org_id
        self._session_factory = session_factory
        self._created_findings: list[UUID] = []
        self._created_sessions: list[UUID] = []

    async def create_finding(
        self,
        *,
        title: str = "E2E Finding (created)",
        severity: str = "high",
        provider: str = "aws",
    ) -> UUID:
        async with self._session_factory() as session:
            account = await session.scalar(
                select(Account).where(Account.org_id == self.org_id, Account.provider == provider)
            )
            if not account:
                account = Account(
                    org_id=self.org_id,
                    provider=provider,
                    external_id=f"e2e-{provider}-account",
                    display_name=f"E2E {provider} Account",
                )
                session.add(account)
                await session.flush()

            rule = await session.scalar(select(Rule).where(Rule.name == "E2E Rule"))
            if not rule:
                rule = Rule(
                    policy_id=None,
                    name="E2E Rule",
                    description="E2E rule seed",
                    provider=[provider],
                    resource_types=None,
                    expression_lang="cel",
                    expression="true",
                    severity=severity,
                    cwe=None,
                    cis=None,
                    nist_800_53=None,
                    mitre_attack=None,
                    version=1,
                    is_active=True,
                )
                session.add(rule)
                await session.flush()

            now = datetime.now(timezone.utc)
            finding = Finding(
                org_id=self.org_id,
                account_id=account.account_id,
                provider=provider,
                rule_id=rule.rule_id,
                rule_version=1,
                resource_id=None,
                principal_id=None,
                first_seen=now,
                last_seen=now,
                status="open",
                severity=severity,
                fingerprint=f"e2e-fp-{uuid4()}",
                title=title,
                summary="e2e",
                evidence=None,
            )
            session.add(finding)
            await session.commit()
            self._created_findings.append(finding.finding_id)
            return finding.finding_id

    async def create_agent_session(self, *, agent_type: str = "security_analyst", context: dict | None = None) -> UUID:
        response = await self.client.post(
            "/api/v1/agents/sessions",
            json={"agent_type": agent_type, "context": context or {}},
        )
        if response.status_code not in (200, 201):
            return UUID(int=0)
        payload = response.json()
        session_id = UUID(payload["session_id"])
        self._created_sessions.append(session_id)
        return session_id

    async def cleanup(self) -> None:
        async with self._session_factory() as session:
            for session_id in self._created_sessions:
                agent_session = await session.get(AgentSession, session_id)
                if agent_session:
                    await session.delete(agent_session)
            for finding_id in self._created_findings:
                finding = await session.get(Finding, finding_id)
                if finding:
                    await session.delete(finding)
            await session.commit()


@pytest_asyncio.fixture
async def test_org_id() -> UUID:
    return UUID(os.getenv("E2E_TEST_ORG_ID", "00000000-0000-0000-0000-00000000000a"))


@pytest_asyncio.fixture
async def data_factory(
    auth_client: httpx.AsyncClient,
    test_org_id: UUID,
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncGenerator[TestDataFactory, None]:
    factory = TestDataFactory(auth_client, test_org_id, session_factory)
    yield factory
    await factory.cleanup()


def pytest_configure(config):
    config.addinivalue_line("markers", "e2e: end-to-end tests (in-process ASGI)")
    config.addinivalue_line("markers", "e2e_slow: slow e2e tests")
    config.addinivalue_line("markers", "e2e_agent: agent-focused e2e tests")
