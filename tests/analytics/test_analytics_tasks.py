import sqlite3
from datetime import datetime, timezone
from uuid import UUID

import pytest
from sqlalchemy import select

import cerebro.tasks.analytics_tasks as analytics_tasks
from cerebro.analytics.time_series import MetricSnapshot, SecurityMetricSnapshot, TimeSeriesCollector
from cerebro.analytics.risk_scoring import OrganizationRiskScore, RiskSeverity

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

    now = datetime.now(timezone.utc)

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

    async def _fake_risk(self, org_id):  # noqa: D401
        return fake_risk_score

    monkeypatch.setattr(
        analytics_tasks.RiskScoringEngine,
        "calculate_organization_risk_score",
        _fake_risk,
    )

    result = await analytics_tasks._collect_security_metrics_for_org(test_org.org_id)

    assert result["org_id"] == str(test_org.org_id)
    assert result["snapshots_created"], "Expected security metric snapshots to be stored"

    snapshot_stmt = select(SecurityMetricSnapshot).where(
        SecurityMetricSnapshot.org_id == test_org.org_id
    )
    snapshots = (await test_db.scalars(snapshot_stmt)).all()

    assert snapshots, "Snapshots should be persisted in the database"
    assert any(
        snapshot.metric_type == "overall_risk_score" for snapshot in snapshots
    ), "Overall risk score snapshot missing"
