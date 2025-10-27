import asyncio
import shutil
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from testcontainers.postgres import PostgresContainer

import cerebro.tasks.analytics_tasks as analytics_tasks
from cerebro.analytics.time_series import SecurityMetricSnapshot
from cerebro.core.database import Base
from cerebro.core.models import (
    Account,
    Finding,
    IamEdge,
    Organization,
    Principal,
    Resource,
    Rule,
)


if shutil.which("docker") is None:  # pragma: no cover - environment dependent
    pytest.skip("Docker is required for Postgres-backed integration tests", allow_module_level=True)


@pytest.fixture
def postgres_container():
    with PostgresContainer("postgres:15-alpine") as container:
        yield container


@pytest.fixture
async def pg_engine(postgres_container):
    sync_url = make_url(postgres_container.get_connection_url())
    async_url = sync_url.set(drivername="postgresql+asyncpg")

    connection_str = async_url.render_as_string(hide_password=False)
    engine = create_async_engine(connection_str, future=True)

    for attempt in range(10):
        try:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            break
        except Exception:
            if attempt == 9:
                raise
            await asyncio.sleep(1)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    try:
        yield engine
    finally:
        await engine.dispose()


@pytest.fixture
async def pg_session_factory(pg_engine):
    factory = async_sessionmaker(pg_engine, expire_on_commit=False, class_=AsyncSession)
    yield factory


@pytest.mark.integration
@pytest.mark.asyncio
async def test_collect_metrics_round_trip_with_postgres(pg_session_factory, monkeypatch):
    session_maker = pg_session_factory

    async with session_maker() as session:
        org = Organization(name="Integration Org")
        session.add(org)
        await session.flush()

        account = Account(
            org_id=org.org_id,
            provider="github",
            external_id="acct-1",
            display_name="GitHub Account",
        )
        session.add(account)
        await session.flush()

        principal = Principal(
            account_id=account.account_id,
            provider="github",
            principal_type="user",
            external_id="user-1",
            email="analyst@example.com",
            display_name="Analyst",
            is_human=True,
        )
        session.add(principal)
        await session.flush()

        resource = Resource(
            account_id=account.account_id,
            provider="github",
            resource_type="repository",
            external_id="repo-1",
            name="security-repo",
        )
        session.add(resource)
        await session.flush()

        rule = Rule(
            name="Enforce MFA",
            provider=["github"],
            resource_types=["repository"],
            expression_lang="cel",
            expression="true",
            severity="critical",
            cis=["CIS.1"],
            nist_800_53=["AC-1"],
            version=1,
            is_active=True,
        )
        session.add(rule)
        await session.flush()

        now = datetime.now(timezone.utc)

        finding_open = Finding(
            org_id=org.org_id,
            account_id=account.account_id,
            provider="github",
            rule_id=rule.rule_id,
            rule_version=1,
            resource_id=resource.resource_id,
            principal_id=principal.principal_id,
            first_seen=now - timedelta(days=10),
            last_seen=now,
            status="open",
            severity="critical",
            fingerprint="critical-repo-public",
            title="Repository publicly accessible",
            summary="Open finding for risk scoring",
        )
        session.add(finding_open)

        finding_fixed = Finding(
            org_id=org.org_id,
            account_id=account.account_id,
            provider="github",
            rule_id=rule.rule_id,
            rule_version=1,
            resource_id=resource.resource_id,
            principal_id=principal.principal_id,
            first_seen=now - timedelta(days=5),
            last_seen=now - timedelta(days=1),
            status="fixed",
            severity="high",
            fingerprint="critical-repo-public-fixed",
            title="Repository access restricted",
            summary="Resolved finding for MTTR calculation",
        )
        session.add(finding_fixed)

        edge = IamEdge(
            account_id=account.account_id,
            provider="github",
            principal_id=principal.principal_id,
            resource_id=resource.resource_id,
            permission="repo:admin",
            effective_at=now - timedelta(days=120),
            expires_at=None,
            is_admin=True,
        )
        session.add(edge)

        await session.commit()

        org_id = org.org_id

    monkeypatch.setattr(analytics_tasks, "async_session_factory", session_maker)

    result = await analytics_tasks._collect_security_metrics_for_org(org_id)

    assert result["org_id"] == str(org_id)
    assert result["snapshots_created"], "Snapshots should be captured"
    assert result["risk_score"] >= 0

    async with session_maker() as verification_session:
        snapshots = (
            await verification_session.scalars(
                select(SecurityMetricSnapshot).where(
                    SecurityMetricSnapshot.org_id == org_id
                )
            )
        ).all()

    assert snapshots, "SecurityMetricSnapshot records should exist"
