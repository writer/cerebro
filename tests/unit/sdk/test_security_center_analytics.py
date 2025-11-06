from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from cerebro_sdk.security_center import (
    CustomerHealthSnapshot,
    CustomerRiskDashboard,
    CustomerTrendAnalysis,
    CustomerTrendSummary,
    VendorHealthAssessment,
    VendorPortfolioSnapshot,
    VendorRiskDashboard,
    VendorTrendAnalysis,
    VendorTrendSummary,
    assess_customer_health,
    assess_vendor_health,
    analyze_customer_snapshots,
    analyze_vendor_snapshots,
    build_customer_risk_dashboard,
    build_vendor_risk_dashboard,
    compute_customer_health_trend,
    compute_vendor_portfolio_trend,
    summarize_customer_portfolio,
    summarize_vendor_portfolio,
)
from cerebro_sdk.security_center.models import (
    SecurityCenterCustomerInsight,
    SecurityCenterVendorInsight,
)


REFERENCE_NOW = datetime(2024, 10, 24)


def _vendor(**overrides) -> SecurityCenterVendorInsight:
    base = dict(
        vendor_id="vendor-acme",
        name="Acme Cloud",
        category="security",
        risk_level="medium",
        inherent_risk_score=0.6,
        residual_risk_score=0.4,
        lifecycle_stage="active",
        next_review_due=REFERENCE_NOW + timedelta(days=10),
        business_criticality="high",
        metadata={},
        raw_metadata={},
    )
    base.update(overrides)
    return SecurityCenterVendorInsight(**base)


def _customer(**overrides) -> SecurityCenterCustomerInsight:
    base = dict(
        customer_id="customer-1",
        name="Globex",
        segment="enterprise",
        health_band="healthy",
        health_score=0.85,
        churn_risk_score=0.2,
        lifecycle_stage="active",
        account_manager="csm-jane",
        next_qbr_at=REFERENCE_NOW + timedelta(days=45),
        last_engagement_at=REFERENCE_NOW - timedelta(days=14),
        metadata={},
        raw_metadata={},
    )
    base.update(overrides)
    return SecurityCenterCustomerInsight(**base)


def test_assess_vendor_health_returns_review_status() -> None:
    vendor = _vendor()
    assessment = assess_vendor_health(vendor, REFERENCE_NOW)

    assert isinstance(assessment, VendorHealthAssessment)
    assert assessment.review_status == "due_soon"
    assert assessment.risk_delta == pytest.approx(-0.2)
    assert assessment.warnings == []


def test_summarize_vendor_portfolio_counts_overdue() -> None:
    vendor = _vendor()
    overdue_vendor = _vendor(
        vendor_id="vendor-beta",
        risk_level="high",
        next_review_due=REFERENCE_NOW - timedelta(days=5),
        residual_risk_score=0.8,
    )

    summary = summarize_vendor_portfolio([vendor, overdue_vendor], REFERENCE_NOW)

    assert summary.total == 2
    assert summary.by_risk_level["high"] == 1
    assert summary.overdue_reviews == 1
    assert summary.due_soon_reviews == 1
    assert summary.average_residual_risk == pytest.approx((0.4 + 0.8) / 2)


def test_assess_customer_health_returns_engagement_metrics() -> None:
    customer = _customer()
    assessment = assess_customer_health(customer, REFERENCE_NOW)

    assert assessment.engagement_gap_days == 14
    assert assessment.next_qbr_in_days == 45


def test_summarize_customer_portfolio_detects_at_risk_accounts() -> None:
    healthy = _customer()
    at_risk = _customer(
        customer_id="customer-2",
        name="Initech",
        segment="midmarket",
        health_band="at_risk",
        health_score=0.55,
        churn_risk_score=0.6,
        last_engagement_at=REFERENCE_NOW - timedelta(days=60),
        next_qbr_at=REFERENCE_NOW - timedelta(days=5),
    )

    summary = summarize_customer_portfolio([healthy, at_risk], REFERENCE_NOW)

    assert summary.total == 2
    assert summary.by_segment["enterprise"] == 1
    assert summary.by_segment["midmarket"] == 1
    assert summary.at_risk_count == 1
    assert summary.average_health_score == pytest.approx((0.85 + 0.55) / 2)
    assert summary.average_churn_risk == pytest.approx((0.2 + 0.6) / 2)


def test_compute_vendor_portfolio_trend_direction() -> None:
    vendor = _vendor()
    overdue = _vendor(
        vendor_id="vendor-beta",
        residual_risk_score=0.8,
        next_review_due=REFERENCE_NOW - timedelta(days=5),
    )

    trend = compute_vendor_portfolio_trend(
        [
            VendorPortfolioSnapshot(timestamp=REFERENCE_NOW - timedelta(days=7), vendors=[overdue]),
            VendorPortfolioSnapshot(timestamp=REFERENCE_NOW, vendors=[vendor, overdue]),
        ]
    )

    assert isinstance(trend, VendorTrendSummary)
    assert trend.residual_risk_change is not None and trend.residual_risk_change < 0
    assert trend.direction == "improving"


def test_compute_customer_health_trend_direction() -> None:
    healthy = _customer()
    at_risk = _customer(
        customer_id="customer-2",
        health_score=0.4,
        churn_risk_score=0.7,
        health_band="at_risk",
    )

    trend = compute_customer_health_trend(
        [
            CustomerHealthSnapshot(timestamp=REFERENCE_NOW - timedelta(days=30), customers=[at_risk]),
            CustomerHealthSnapshot(timestamp=REFERENCE_NOW, customers=[healthy, at_risk]),
        ]
    )

    assert isinstance(trend, CustomerTrendSummary)
    assert trend.health_score_change is not None and trend.health_score_change > 0
    assert trend.direction == "improving"


def test_build_vendor_risk_dashboard_includes_critical_vendors() -> None:
    vendor = _vendor()
    overdue = _vendor(
        vendor_id="vendor-beta",
        residual_risk_score=0.9,
        next_review_due=REFERENCE_NOW - timedelta(days=5),
    )

    dashboard = build_vendor_risk_dashboard([vendor, overdue], REFERENCE_NOW, critical_limit=3)

    assert isinstance(dashboard, VendorRiskDashboard)
    assert dashboard.kpis.total_vendors == 2
    assert dashboard.kpis.overdue_reviews == 1
    assert any(item.vendor_id == "vendor-beta" for item in dashboard.critical_vendors)


def test_build_customer_risk_dashboard_prioritizes_at_risk_accounts() -> None:
    healthy = _customer()
    at_risk = _customer(
        customer_id="customer-2",
        health_band="at_risk",
        health_score=0.55,
        churn_risk_score=0.6,
    )

    dashboard = build_customer_risk_dashboard([healthy, at_risk], REFERENCE_NOW, at_risk_limit=3)

    assert isinstance(dashboard, CustomerRiskDashboard)
    assert dashboard.kpis.total_customers == 2
    assert dashboard.kpis.at_risk_customers == 1
    assert dashboard.at_risk_customers[0].customer_id == "customer-2"


def test_analyze_vendor_snapshots_surface_alerts() -> None:
    vendor = _vendor()
    overdue = _vendor(
        vendor_id="vendor-beta",
        residual_risk_score=0.9,
        next_review_due=REFERENCE_NOW - timedelta(days=5),
    )

    snapshots = [
        VendorPortfolioSnapshot(timestamp=REFERENCE_NOW - timedelta(days=35), vendors=[vendor]),
        VendorPortfolioSnapshot(timestamp=REFERENCE_NOW - timedelta(days=5), vendors=[vendor, overdue]),
        VendorPortfolioSnapshot(timestamp=REFERENCE_NOW, vendors=[vendor, overdue]),
    ]

    analysis = analyze_vendor_snapshots(snapshots, REFERENCE_NOW)

    assert isinstance(analysis, VendorTrendAnalysis)
    assert any(alert.metric.startswith("vendor") for alert in analysis.alerts)
    assert any(window.window == "7d" for window in analysis.windows)


def test_analyze_customer_snapshots_surface_alerts() -> None:
    healthy = _customer()
    at_risk = _customer(
        customer_id="customer-2",
        health_band="at_risk",
        health_score=0.5,
        churn_risk_score=0.7,
    )

    snapshots = [
        CustomerHealthSnapshot(timestamp=REFERENCE_NOW - timedelta(days=40), customers=[healthy]),
        CustomerHealthSnapshot(timestamp=REFERENCE_NOW - timedelta(days=10), customers=[healthy]),
        CustomerHealthSnapshot(timestamp=REFERENCE_NOW, customers=[healthy, at_risk]),
    ]

    analysis = analyze_customer_snapshots(snapshots, REFERENCE_NOW)

    assert isinstance(analysis, CustomerTrendAnalysis)
    assert any(alert.metric.startswith("customer") for alert in analysis.alerts)
    assert any(window.window == "30d" for window in analysis.windows)
