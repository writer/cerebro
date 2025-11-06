from __future__ import annotations

from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from cerebro_sdk.analytics import (
    IntegrationAccountSummary,
    IntegrationCoverageRecord,
    IntegrationScopeBreakdown,
)
from cerebro_sdk.findings import FindingRecord
from cerebro_sdk.security_center import (
    CustomerEngagement,
    ExposureCollections,
    FindingsSummary,
    IntegrationCoverageHealth,
    IntegrationSummary,
    OrgExposureDashboard,
    RelationsContext,
    VendorExposure,
    build_org_exposure_dashboard,
    build_relations_index,
    compute_coverage_health,
    get_customer_engagement,
    get_vendor_exposure,
)
from cerebro_sdk.security_center.models import (
    SecurityCenterCustomerInsight,
    SecurityCenterVendorInsight,
)


REFERENCE_NOW = datetime(2024, 10, 24)


@pytest.fixture()
def vendors() -> list[SecurityCenterVendorInsight]:
    return [
        SecurityCenterVendorInsight(
            vendor_id="vendor-acme",
            name="Acme Cloud",
            category="security",
            risk_level="medium",
            inherent_risk_score=0.6,
            residual_risk_score=0.4,
            lifecycle_stage="active",
            next_review_due=REFERENCE_NOW + timedelta(days=15),
            business_criticality="high",
            metadata={
                "integration": {
                    "integration_type": "github",
                    "authentication_methods": ["oauth"],
                    "network_access": ["api"],
                }
            },
            raw_metadata={"tags": {"integration": "github"}},
        ),
        SecurityCenterVendorInsight(
            vendor_id="vendor-beta",
            name="Beta Compliance",
            category="compliance",
            risk_level="high",
            inherent_risk_score=0.7,
            residual_risk_score=0.9,
            lifecycle_stage="active",
            next_review_due=REFERENCE_NOW - timedelta(days=2),
            business_criticality="medium",
            metadata={
                "integration": {"integration_type": "jira", "network_access": ["api"]},
            },
            raw_metadata={"tags": {"integration": "jira"}},
        ),
    ]


@pytest.fixture()
def customers() -> list[SecurityCenterCustomerInsight]:
    return [
        SecurityCenterCustomerInsight(
            customer_id="customer-alpha",
            name="Alpha Corp",
            segment="enterprise",
            health_band="healthy",
            health_score=0.88,
            churn_risk_score=0.15,
            lifecycle_stage="active",
            account_manager="csm-amy",
            next_qbr_at=REFERENCE_NOW + timedelta(days=40),
            last_engagement_at=REFERENCE_NOW - timedelta(days=14),
            metadata={
                "success_programs": ["design_partner"],
                "adoption": {"metrics": {"github": 0.92}},
                "engagement": {"open_support_tickets": 1},
            },
            raw_metadata={"tags": {"success_program": "design_partner"}},
        ),
        SecurityCenterCustomerInsight(
            customer_id="customer-beta",
            name="Beta Inc",
            segment="midmarket",
            health_band="at_risk",
            health_score=0.55,
            churn_risk_score=0.65,
            lifecycle_stage="active",
            account_manager="csm-bob",
            next_qbr_at=REFERENCE_NOW - timedelta(days=5),
            last_engagement_at=REFERENCE_NOW - timedelta(days=45),
            metadata={
                "success_programs": ["accelerate"],
                "adoption": {"metrics": {"jira": 0.5}},
                "engagement": {"open_support_tickets": 2},
            },
            raw_metadata={"tags": {"success_program": "accelerate"}},
        ),
    ]


@pytest.fixture()
def coverage() -> list[IntegrationCoverageRecord]:
    return [
        IntegrationCoverageRecord(
            integration="github",
            providers=["github"],
            status="ok",
            scopes=IntegrationScopeBreakdown(total=10, healthy=8, warning=1, critical=1),
            accounts=IntegrationAccountSummary(total=2),
            coverage_ratio=0.8,
            last_success=REFERENCE_NOW - timedelta(hours=6),
            evaluated_at=REFERENCE_NOW,
        ),
        IntegrationCoverageRecord(
            integration="jira",
            providers=["jira"],
            status="degraded",
            scopes=IntegrationScopeBreakdown(total=5, healthy=2, warning=2, critical=1),
            accounts=IntegrationAccountSummary(total=1),
            coverage_ratio=0.4,
            last_success=REFERENCE_NOW - timedelta(days=2),
            evaluated_at=REFERENCE_NOW,
        ),
    ]


@pytest.fixture()
def findings() -> list[FindingRecord]:
    return [
        FindingRecord(
            finding_id=uuid4(),
            org_id=uuid4(),
            account_id=uuid4(),
            provider="github",
            rule_id=uuid4(),
            rule_version=1,
            resource_id=uuid4(),
            principal_id=None,
            first_seen=REFERENCE_NOW - timedelta(days=14),
            status="open",
            severity="medium",
            fingerprint="fp-1",
            title="Github token stale",
            summary=None,
            last_seen=REFERENCE_NOW - timedelta(days=1),
            evidence=None,
        ),
        FindingRecord(
            finding_id=uuid4(),
            org_id=uuid4(),
            account_id=uuid4(),
            provider="jira",
            rule_id=uuid4(),
            rule_version=1,
            resource_id=uuid4(),
            principal_id=None,
            first_seen=REFERENCE_NOW - timedelta(days=7),
            status="open",
            severity="high",
            fingerprint="fp-2",
            title="Jira sync stalled",
            summary=None,
            last_seen=REFERENCE_NOW - timedelta(days=1),
            evidence=None,
        ),
    ]


@pytest.fixture()
def context(vendors, customers, coverage, findings) -> RelationsContext:
    return RelationsContext(
        fetch_vendors=lambda org_id: vendors,
        fetch_customers=lambda org_id: customers,
        fetch_coverage=lambda: coverage,
        fetch_findings=lambda org_id: findings,
        provider_aliases={"github": ["gh"]},
    )


@pytest.mark.asyncio()
async def test_compute_coverage_health_matches_percentages(coverage) -> None:
    health = compute_coverage_health(coverage[0])

    assert isinstance(health, IntegrationCoverageHealth)
    assert health.healthy_percentage == pytest.approx(0.8)
    assert health.critical_percentage == pytest.approx(0.1)
    assert health.overall_score == pytest.approx(0.8 - 0.05 - 0.1)


@pytest.mark.asyncio()
async def test_build_relations_index_maps_provider_keys(context) -> None:
    index = await build_relations_index("org-1", context)

    assert index.vendors[0].vendor_id == "vendor-acme"
    assert "github" in index.vendor_provider_keys["vendor-acme"]
    assert "support" in index.customer_provider_keys["customer-beta"]
    assert index.findings_by_provider["github"][0].title == "Github token stale"


@pytest.mark.asyncio()
async def test_get_vendor_exposure_returns_dashboard(context) -> None:
    index = await build_relations_index("org-1", context)
    exposure = await get_vendor_exposure("org-1", "vendor-acme", context, index)

    assert isinstance(exposure, VendorExposure)
    assert exposure.vendor.vendor_id == "vendor-acme"
    assert exposure.coverage_health[0].integration == "github"
    assert len(exposure.related_findings) == 1
    assert exposure.dashboard.kpis.total_vendors == 1


@pytest.mark.asyncio()
async def test_get_customer_engagement_returns_dashboard(context) -> None:
    index = await build_relations_index("org-1", context)
    engagement = await get_customer_engagement("org-1", "customer-alpha", context, index)

    assert isinstance(engagement, CustomerEngagement)
    assert engagement.customer.customer_id == "customer-alpha"
    assert engagement.related_integrations[0].integration == "github"
    assert engagement.dashboard.kpis.total_customers == 1


@pytest.mark.asyncio()
async def test_build_org_exposure_dashboard_combines_metrics(context) -> None:
    dashboard = await build_org_exposure_dashboard("org-1", context)

    assert isinstance(dashboard, OrgExposureDashboard)
    assert dashboard.integration.total == 2
    assert dashboard.integration.degraded == 1
    assert dashboard.findings.total == 2
    assert len(dashboard.exposures.top_vendors) == 2
    assert len(dashboard.alerts) >= 1
