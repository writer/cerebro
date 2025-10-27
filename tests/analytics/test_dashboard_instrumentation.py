from datetime import datetime, timezone

import pytest

from cerebro.analytics.dashboard_analytics import (
    DashboardAnalytics,
    ExecutiveSummary,
    SecurityMetrics,
)
from cerebro.analytics.identity_analytics import IdentityAnalyzer
from cerebro.analytics.risk_scoring import RiskHeatmap, RiskScoringEngine


class _FakeHistogram:
    def __init__(self):
        self.records = []

    def labels(self, **labels):
        histogram = self

        class _Observer:
            def observe(self_inner, value):
                histogram.records.append((labels, value))

        return _Observer()


@pytest.mark.asyncio
async def test_dashboard_generation_captures_timings(monkeypatch, test_db, test_org):
    fake_histogram = _FakeHistogram()
    monkeypatch.setattr(
        "cerebro.analytics.dashboard_analytics.dashboard_component_duration",
        fake_histogram,
    )

    async def _fake_security_metrics(self, org_id):
        return SecurityMetrics(
            total_findings=10,
            critical_findings=2,
            high_findings=3,
            open_findings=5,
            findings_trend=[1, 2, 3],
            critical_trend=[0, 1, 1],
            sla_breaches=1,
            mean_time_to_remediation=4.5,
            new_findings_24h=2,
            resolved_findings_24h=1,
        )

    async def _fake_executive_summary(self, org_id):
        return ExecutiveSummary(
            org_id=org_id,
            report_date=datetime.now(timezone.utc),
            overall_risk_score=25.0,
            risk_level="low",
            risk_trend="stable",
            dimension_scores={"vulnerability_exposure": 10.0},
            total_assets=20,
            total_identities=5,
            active_findings=3,
            compliance_score=92.0,
            top_5_risks=["Risk"],
            findings_burned_down_30d=1,
            new_controls_implemented=1,
            risk_score_change_30d=-2.0,
            recommended_investments=[{"priority": "high"}],
        )

    async def _fake_identity_dashboard(self, org_id):
        return {
            "summary": {
                "total_identities": 5,
                "high_privilege_identities": 2,
                "cross_provider_identities": 1,
                "avg_permissions_per_identity": 10.0,
                "max_permissions_per_identity": 20,
            },
            "privilege_distribution": {"admin": 2},
            "top_risky_identities": [],
            "privilege_anomalies": [],
            "mfa_compliance_by_provider": {},
            "provider_breakdown": {},
        }

    async def _fake_heatmap(self, org_id):
        return RiskHeatmap(
            org_id=org_id,
            heatmap_data={"github": {"repo": 70.0}},
            high_risk_areas=[],
            improvement_opportunities=[],
        )

    async def _fake_compliance(self, org_id):
        return {"CIS": {"total_controls": 10, "compliant_controls": 9, "compliance_percentage": 90.0, "status": "partial"}}

    monkeypatch.setattr(DashboardAnalytics, "generate_security_metrics", _fake_security_metrics)
    monkeypatch.setattr(DashboardAnalytics, "generate_executive_summary", _fake_executive_summary)
    monkeypatch.setattr(
        IdentityAnalyzer,
        "generate_identity_dashboard_data",
        _fake_identity_dashboard,
        raising=False,
    )
    monkeypatch.setattr(
        RiskScoringEngine,
        "generate_risk_heatmap",
        _fake_heatmap,
        raising=False,
    )
    monkeypatch.setattr(
        DashboardAnalytics,
        "_get_compliance_status_by_framework",
        _fake_compliance,
        raising=False,
    )

    analytics = DashboardAnalytics(test_db)
    payload = await analytics.generate_comprehensive_dashboard(test_org.org_id)

    timings = analytics.last_generation_timings
    expected_keys = {
        "security_metrics",
        "executive_summary",
        "identity_analytics",
        "risk_heatmap",
        "compliance_status",
        "total",
    }

    assert expected_keys.issubset(timings.keys())
    assert all(timings[key] >= 0 for key in expected_keys)
    recorded_components = {labels["component"] for labels, _ in fake_histogram.records}
    assert expected_keys.issubset(recorded_components)
    assert payload["executive_summary"]["org_id"] == str(test_org.org_id)
