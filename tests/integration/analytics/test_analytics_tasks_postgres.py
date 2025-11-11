import asyncio
import shutil
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from testcontainers.postgres import PostgresContainer

import cerebro.tasks.analytics_tasks as analytics_tasks

# Ensure agent analytics tables are registered before creating the schema.
from cerebro.agents import models as agent_models  # noqa: F401
from cerebro.analytics.dashboard_analytics import DashboardAnalytics
from cerebro.analytics.time_series import (
    MetricType,
    SecurityMetricSnapshot,
    TimeSeriesCollector,
)
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
    try:
        with PostgresContainer("postgres:15-alpine") as container:
            yield container
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"Postgres container unavailable: {exc}")


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
        await conn.run_sync(agent_models.Base.metadata.create_all)

    try:
        yield engine
    finally:
        await engine.dispose()


@pytest.fixture
async def pg_session_factory(pg_engine):
    factory = async_sessionmaker(pg_engine, expire_on_commit=False, class_=AsyncSession)
    yield factory


async def _seed_sample_org(session: AsyncSession) -> UUID:
    """Create a rich, multi-provider fixture that exercises analytics SQL paths."""

    org = Organization(name="Integration Org")
    session.add(org)
    await session.flush()

    providers = (
        ("github", "acct-1", "GitHub Account"),
        ("aws", "acct-aws", "AWS Production"),
        ("gcp", "acct-gcp", "GCP Security"),
    )

    accounts: dict[str, Account] = {}
    for provider, external_id, display_name in providers:
        account = Account(
            org_id=org.org_id,
            provider=provider,
            external_id=external_id,
            display_name=display_name,
        )
        session.add(account)
        await session.flush()
        accounts[provider] = account

    primary_principal = Principal(
        account_id=accounts["github"].account_id,
        provider="github",
        principal_type="user",
        external_id="user-1",
        email="analyst@example.com",
        display_name="Analyst",
        is_human=True,
    )
    session.add(primary_principal)
    await session.flush()

    cloud_engineer = Principal(
        account_id=accounts["aws"].account_id,
        provider="aws",
        principal_type="user",
        external_id="user-2",
        email="cloud@example.com",
        display_name="Cloud Engineer",
        is_human=True,
    )
    session.add(cloud_engineer)
    await session.flush()

    service_principal = Principal(
        account_id=accounts["gcp"].account_id,
        provider="gcp",
        principal_type="service_account",
        external_id="svc-1",
        email=None,
        display_name="CI Pipeline",
        is_human=False,
    )
    session.add(service_principal)
    await session.flush()

    resources = []
    for provider, account in accounts.items():
        resource = Resource(
            account_id=account.account_id,
            provider=provider,
            resource_type="repository" if provider == "github" else "bucket",
            external_id=f"{provider}-resource",
            name=f"{provider}-asset",
        )
        session.add(resource)
        await session.flush()
        resources.append(resource)

    now = datetime.now(timezone.utc)

    mfa_rule = Rule(
        name="Enforce MFA",
        provider=["github", "aws"],
        resource_types=["repository", "iam_user"],
        expression_lang="cel",
        expression="true",
        severity="critical",
        cis=["CIS.1"],
        nist_800_53=["AC-1"],
        version=1,
        is_active=True,
    )
    encryption_rule = Rule(
        name="Require Encryption",
        provider=["aws"],
        resource_types=["bucket"],
        expression_lang="cel",
        expression="resource.encrypted == true",
        severity="high",
        cis=["CIS.2"],
        nist_800_53=["SC-13"],
        version=1,
        is_active=True,
    )
    iam_rule = Rule(
        name="Limit Admin Grants",
        provider=["gcp", "github", "aws"],
        resource_types=["iam_user"],
        expression_lang="cel",
        expression="!principal.is_admin",
        severity="medium",
        cis=["CIS.3"],
        nist_800_53=["AC-2"],
        version=1,
        is_active=True,
    )
    session.add_all([mfa_rule, encryption_rule, iam_rule])
    await session.flush()

    github_resource = resources[0]
    aws_resource = resources[1]
    gcp_resource = resources[2]

    findings = [
        Finding(
            org_id=org.org_id,
            account_id=github_resource.account_id,
            provider="github",
            rule_id=mfa_rule.rule_id,
            rule_version=1,
            resource_id=github_resource.resource_id,
            principal_id=primary_principal.principal_id,
            first_seen=now - timedelta(days=15),
            last_seen=now,
            status="open",
            severity="critical",
            fingerprint="critical-repo-public",
            title="Repository publicly accessible",
            summary="Open GitHub finding",
        ),
        Finding(
            org_id=org.org_id,
            account_id=github_resource.account_id,
            provider="github",
            rule_id=mfa_rule.rule_id,
            rule_version=1,
            resource_id=github_resource.resource_id,
            principal_id=primary_principal.principal_id,
            first_seen=now - timedelta(days=5),
            last_seen=now - timedelta(days=1),
            status="fixed",
            severity="high",
            fingerprint="critical-repo-public-fixed",
            title="Repository access restricted",
            summary="Resolved GitHub finding",
        ),
        Finding(
            org_id=org.org_id,
            account_id=aws_resource.account_id,
            provider="aws",
            rule_id=encryption_rule.rule_id,
            rule_version=1,
            resource_id=aws_resource.resource_id,
            principal_id=cloud_engineer.principal_id,
            first_seen=now - timedelta(days=20),
            last_seen=now - timedelta(days=2),
            status="open",
            severity="high",
            fingerprint="s3-bucket-unencrypted",
            title="S3 bucket missing encryption",
            summary="AWS bucket requires encryption",
        ),
        Finding(
            org_id=org.org_id,
            account_id=gcp_resource.account_id,
            provider="gcp",
            rule_id=iam_rule.rule_id,
            rule_version=1,
            resource_id=gcp_resource.resource_id,
            principal_id=primary_principal.principal_id,
            first_seen=now - timedelta(days=40),
            last_seen=now - timedelta(days=3),
            status="open",
            severity="medium",
            fingerprint="gcp-admin-excess",
            title="GCP admin permissions excessive",
            summary="Excessive cross-cloud admin grants",
        ),
    ]
    session.add_all(findings)

    # Multi-provider IAM edges to trigger identity analytics
    edges: list[IamEdge] = []
    for index in range(12):
        edges.append(
            IamEdge(
                account_id=github_resource.account_id,
                provider="github",
                principal_id=primary_principal.principal_id,
                resource_id=github_resource.resource_id,
                permission=f"repo:perm:{index}",
                effective_at=now - timedelta(days=30 + index),
                expires_at=None,
                is_admin=index % 5 == 0,
            )
        )

    # Cross-provider admin access
    edges.extend(
        [
            IamEdge(
                account_id=aws_resource.account_id,
                provider="aws",
                principal_id=primary_principal.principal_id,
                resource_id=aws_resource.resource_id,
                permission="iam:AdministratorAccess",
                effective_at=now - timedelta(days=200),
                expires_at=None,
                is_admin=True,
            ),
            IamEdge(
                account_id=gcp_resource.account_id,
                provider="gcp",
                principal_id=primary_principal.principal_id,
                resource_id=gcp_resource.resource_id,
                permission="roles/owner",
                effective_at=now - timedelta(days=210),
                expires_at=None,
                is_admin=True,
            ),
        ]
    )

    # Additional engineer edges
    edges.extend(
        [
            IamEdge(
                account_id=aws_resource.account_id,
                provider="aws",
                principal_id=cloud_engineer.principal_id,
                resource_id=aws_resource.resource_id,
                permission="s3:ListBucket",
                effective_at=now - timedelta(days=12),
                expires_at=None,
                is_admin=False,
            ),
            IamEdge(
                account_id=aws_resource.account_id,
                provider="aws",
                principal_id=cloud_engineer.principal_id,
                resource_id=aws_resource.resource_id,
                permission="iam:CreateUser",
                effective_at=now - timedelta(days=60),
                expires_at=None,
                is_admin=True,
            ),
        ]
    )

    session.add_all(edges)

    await session.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS assessment_results (
                assessment_result_id UUID PRIMARY KEY,
                org_id UUID NOT NULL,
                rule_id UUID NOT NULL,
                status TEXT NOT NULL
            )
            """
        )
    )

    session.add_all(
        [
            Finding(
                org_id=org.org_id,
                account_id=aws_resource.account_id,
                provider="aws",
                rule_id=encryption_rule.rule_id,
                rule_version=1,
                resource_id=aws_resource.resource_id,
                principal_id=cloud_engineer.principal_id,
                first_seen=now - timedelta(days=2),
                last_seen=now - timedelta(days=1),
                status="fixed",
                severity="high",
                fingerprint="s3-bucket-remediated",
                title="S3 bucket encrypted",
                summary="Encryption enabled",
            )
        ]
    )

    await session.execute(
        text(
            """
            INSERT INTO assessment_results (assessment_result_id, org_id, rule_id, status)
            VALUES (:assessment_result_id, :org_id, :rule_id, :status)
            """
        ),
        {
            "assessment_result_id": str(uuid4()),
            "org_id": org.org_id,
            "rule_id": mfa_rule.rule_id,
            "status": "passed",
        },
    )

    await session.execute(
        text(
            """
            INSERT INTO assessment_results (assessment_result_id, org_id, rule_id, status)
            VALUES (:assessment_result_id, :org_id, :rule_id, :status)
            """
        ),
        {
            "assessment_result_id": str(uuid4()),
            "org_id": org.org_id,
            "rule_id": encryption_rule.rule_id,
            "status": "failed",
        },
    )

    await session.execute(
        text(
            """
            INSERT INTO assessment_results (assessment_result_id, org_id, rule_id, status)
            VALUES (:assessment_result_id, :org_id, :rule_id, :status)
            """
        ),
        {
            "assessment_result_id": str(uuid4()),
            "org_id": org.org_id,
            "rule_id": iam_rule.rule_id,
            "status": "passed",
        },
    )

    await session.commit()
    return org.org_id


@pytest.mark.integration
@pytest.mark.asyncio
async def test_collect_metrics_round_trip_with_postgres(pg_session_factory, monkeypatch):
    session_maker = pg_session_factory

    async with session_maker() as session:
        org_id = await _seed_sample_org(session)

    monkeypatch.setattr(analytics_tasks, "async_session_factory", session_maker)

    result = await analytics_tasks._collect_security_metrics_for_org(org_id)

    assert result["org_id"] == str(org_id)
    assert result["snapshots_created"], "Snapshots should be captured"
    assert result["risk_score"] >= 0

    async with session_maker() as verification_session:
        collector = TimeSeriesCollector(verification_session)
        mttr = await collector._calculate_mttr(org_id)
        sla_breaches = await collector._count_sla_breaches(org_id)

        snapshots = (
            await verification_session.scalars(
                select(SecurityMetricSnapshot).where(
                    SecurityMetricSnapshot.org_id == org_id
                )
            )
        ).all()

        metric_snapshots = await collector.collect_finding_metrics(org_id)

    assert snapshots, "SecurityMetricSnapshot records should exist"
    snapshot_types = {snapshot.metric_type for snapshot in snapshots}
    assert MetricType.OVERALL_RISK_SCORE.value in snapshot_types
    assert MetricType.COMPLIANCE_SCORE.value in snapshot_types

    assert mttr == pytest.approx(60.0)
    assert sla_breaches == 3

    collected_types = {snap.metric_type for snap in metric_snapshots}
    assert MetricType.FINDING_SEVERITY_DISTRIBUTION.value in collected_types
    severity_snapshot = next(
        snap for snap in metric_snapshots if snap.metric_type == MetricType.FINDING_SEVERITY_DISTRIBUTION.value
    )
    assert severity_snapshot.metadata["distribution"]["critical"] >= 1


@pytest.mark.integration
@pytest.mark.asyncio
async def test_dashboard_analytics_generates_postgres_payload(pg_session_factory, monkeypatch):
    async with pg_session_factory() as session:
        org_id = await _seed_sample_org(session)

    monkeypatch.setattr(analytics_tasks, "async_session_factory", pg_session_factory)

    await analytics_tasks._collect_security_metrics_for_org(org_id)

    async with pg_session_factory() as session:
        analytics = DashboardAnalytics(session)

        payload = await analytics.generate_comprehensive_dashboard(org_id)

        executive = payload["executive_summary"]
        assert executive["org_id"] == str(org_id)
        assert executive["total_assets"] == 3
        assert executive["total_identities"] == 2
        assert executive["progress_indicators"]["findings_burned_down_30d"] >= 0

        metrics = payload["security_metrics"]
        assert metrics["findings"]["total"] >= 4
        assert metrics["findings"]["critical"] >= 1
        assert metrics["findings"]["open"] >= 3
        assert metrics["sla_performance"]["breaches"] >= 3
        assert metrics["provider_breakdown"]

        heatmap = payload["risk_heatmap"]
        assert "github" in heatmap["heatmap_data"]
        assert heatmap["high_risk_areas"]

        compliance = payload["compliance_status"]
        assert "CIS" in compliance

        identity = payload["identity_analytics"]
        assert identity["summary"]["cross_provider_identities"] >= 1
        assert "aws" in identity["provider_breakdown"]
        assert any(
            anomaly["type"] == "excessive_cross_provider_admin"
            for anomaly in identity["privilege_anomalies"]
        )
        assert identity["drilldown_identities"], "Drill-down identities should be populated"
        assert identity["remediation_queue"], "Remediation queue should surface actions"
        first_action = identity["remediation_queue"][0]
        assert first_action["action_id"], "Remediation actions should include persistent IDs"
        assert first_action["status"] in {"pending", "accepted", "completed"}
        assert isinstance(first_action["notes"], list)
        assert identity["generated_at"], "Identity analytics should include generated_at"

        compliance_trends = payload.get("compliance_trends")
        assert compliance_trends is not None
        assert compliance_trends["overall"], "Overall compliance trend should not be empty"

        metadata = payload["metadata"]
        assert metadata["generated_at"]
        assert metadata["component_timings"]["total"] >= 0
        assert metadata["cache_ttl_seconds"] == 60

        timings = analytics.last_generation_timings
        assert {
            "security_metrics",
            "executive_summary",
            "identity_analytics",
            "risk_heatmap",
            "compliance_status",
            "compliance_trends",
            "total",
        }.issubset(timings.keys())
