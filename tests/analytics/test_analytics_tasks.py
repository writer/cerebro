import sqlite3
from datetime import UTC, datetime
from uuid import UUID

import pytest
from sqlalchemy import select

import cerebro.tasks.analytics_tasks as analytics_tasks
from cerebro.analytics.risk_scoring import OrganizationRiskScore, RiskSeverity
from cerebro.analytics.time_series import (
    MetricSnapshot,
    MetricType,
    SecurityMetricSnapshot,
    TimeSeriesCollector,
)

sqlite3.register_adapter(UUID, lambda value: str(value))


class _SessionContext:
    """Async context manager binding to an existing session."""

    def __init__(self, session):
        self._session = session

    async def __aenter__(self):
        return self._session

    async def __aexit__(self, exc_type, exc, tb):
        # Snapshot commits happen inside the task; no special cleanup required.
        return False


@pytest.mark.asyncio
async def test_collect_security_metrics_for_org_records_snapshots(
    monkeypatch,
    test_db,
    test_org,
):
    """Ensure the analytics task persists snapshots for the organization."""

    now = datetime.now(UTC)

    monkeypatch.setattr(
        analytics_tasks,
        "async_session_factory",
        lambda: _SessionContext(test_db),
    )

    async def _fake_mttr(self, org_id):
        return 0.0

    monkeypatch.setattr(TimeSeriesCollector, "_calculate_mttr", _fake_mttr)

    sample_snapshots = [
        MetricSnapshot(
            timestamp=now,
            metric_type="finding_count",
            value=5.0,
            metadata={"category": "findings"},
        )
    ]

    async def _fake_collect(self, org_id):
        return sample_snapshots

    monkeypatch.setattr(TimeSeriesCollector, "collect_finding_metrics", _fake_collect)

    fake_risk_score = OrganizationRiskScore(
        org_id=test_org.org_id,
        overall_score=12.5,
        risk_level=RiskSeverity.LOW,
        calculation_date=now,
        vulnerability_score=4.0,
        identity_score=3.0,
        access_control_score=2.0,
        compliance_score=1.0,
        operational_score=2.5,
        risk_factors=[],
        score_trend="stable",
        trend_confidence=0.5,
        top_risks=["Sample risk"],
        quick_wins=["Enable MFA"],
        strategic_initiatives=["Implement IAM least privilege"],
    )

    async def _fake_risk(self, org_id):
        return fake_risk_score

    monkeypatch.setattr(
        analytics_tasks.RiskScoringEngine,
        "calculate_organization_risk_score",
        _fake_risk,
    )

    async def _fake_compliance_score(self, org_id):
        return 95.0

    async def _fake_framework(self, org_id):
        return {
            "CIS": {
                "total_controls": 10,
                "compliant_controls": 9,
                "compliance_percentage": 90.0,
                "status": "partial",
            }
        }

    monkeypatch.setattr(
        analytics_tasks.DashboardRepository,
        "calculate_compliance_score",
        _fake_compliance_score,
    )
    monkeypatch.setattr(
        analytics_tasks.DashboardRepository,
        "get_compliance_by_framework",
        _fake_framework,
    )

    result = await analytics_tasks._collect_security_metrics_for_org(test_org.org_id)

    assert result["org_id"] == str(test_org.org_id)
    assert result[
        "snapshots_created"
    ], "Expected security metric snapshots to be stored"

    snapshot_stmt = select(SecurityMetricSnapshot).where(
        SecurityMetricSnapshot.org_id == test_org.org_id
    )
    snapshots = (await test_db.scalars(snapshot_stmt)).all()

    assert snapshots, "Snapshots should be persisted in the database"
    assert any(
        snapshot.metric_type == "overall_risk_score" for snapshot in snapshots
    ), "Overall risk score snapshot missing"
    assert any(
        snapshot.metric_type == MetricType.COMPLIANCE_SCORE.value
        for snapshot in snapshots
    ), "Compliance score snapshot missing"


class _FakeScalarResult:
    def __init__(self, items):
        self._items = items

    def __iter__(self):
        return iter(self._items)


class _FakeSession:
    def __init__(self, items):
        self._items = items

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def scalars(self, stmt):  # pragma: no cover - matches AsyncSession API
        return _FakeScalarResult(self._items)


@pytest.mark.asyncio
async def test_collect_all_orgs_retries_transient_failure(monkeypatch, test_org):
    org_ids = [test_org.org_id]

    monkeypatch.setattr(
        analytics_tasks,
        "async_session_factory",
        lambda: _FakeSession(org_ids),
    )

    attempts = []

    async def _flaky_collect(org_id):
        attempts.append(org_id)
        if len(attempts) == 1:
            raise RuntimeError("transient error")
        return {
            "org_id": str(org_id),
            "snapshots_created": ["snap"],
            "risk_score": 10.0,
        }

    monkeypatch.setattr(
        analytics_tasks,
        "_collect_security_metrics_for_org",
        _flaky_collect,
    )

    sleep_calls = []

    async def _no_sleep(delay):
        sleep_calls.append(delay)

    monkeypatch.setattr(analytics_tasks.asyncio, "sleep", _no_sleep)

    updates = []

    def _update(state, meta):
        updates.append((state, meta))

    result = await analytics_tasks._collect_security_metrics_for_all_orgs(
        max_attempts=2,
        update_state_cb=_update,
    )

    assert attempts.count(test_org.org_id) == 2
    assert sleep_calls == [1.0]
    assert any(state == "RETRY" for state, _ in updates)
    assert result["processed"] == 1
    assert result["results"][0]["snapshots_created"] == ["snap"]


@pytest.mark.asyncio
async def test_collect_all_orgs_records_failure_after_retries(monkeypatch, test_org):
    org_ids = [test_org.org_id]

    monkeypatch.setattr(
        analytics_tasks,
        "async_session_factory",
        lambda: _FakeSession(org_ids),
    )

    async def _always_fail(org_id):
        raise RuntimeError("persistent failure")

    monkeypatch.setattr(
        analytics_tasks,
        "_collect_security_metrics_for_org",
        _always_fail,
    )

    async def _no_sleep(delay):
        return None

    monkeypatch.setattr(analytics_tasks.asyncio, "sleep", _no_sleep)

    updates = []

    def _update(state, meta):
        updates.append((state, meta))

    result = await analytics_tasks._collect_security_metrics_for_all_orgs(
        max_attempts=2,
        update_state_cb=_update,
    )

    assert any(state == "FAILURE" for state, _ in updates)
    assert result["processed"] == 1
    assert "error" in result["results"][0]
