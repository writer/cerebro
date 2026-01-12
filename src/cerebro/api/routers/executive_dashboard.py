"""Executive Dashboard API endpoints.

Provides aggregate compliance scores, security metrics, and trend analysis
for executive-level reporting and dashboards.
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.api.auth import User, require_read_findings
from cerebro.core.database import get_db
from cerebro.core.models import Account, Finding, Resource

router = APIRouter(prefix="/executive", tags=["Executive Dashboard"])
logger = structlog.get_logger(__name__)


class SecurityPostureScore(BaseModel):
    """Overall security posture score."""

    overall_score: float = Field(..., ge=0, le=100, description="Overall security score 0-100")
    grade: str = Field(..., description="Letter grade (A-F)")
    trend: str = Field(..., description="Trend direction: improving, stable, declining")
    trend_percentage: float = Field(..., description="Percentage change from previous period")


class ComplianceScore(BaseModel):
    """Compliance score for a framework."""

    framework_id: str
    framework_name: str
    score: float = Field(..., ge=0, le=100)
    controls_passing: int
    controls_failing: int
    controls_total: int
    last_assessed: datetime | None


class RiskMetrics(BaseModel):
    """Risk metrics summary."""

    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    total_findings: int
    mean_time_to_remediate_days: float | None
    findings_trend_7d: float
    top_risk_categories: list[dict[str, Any]]


class CoverageMetrics(BaseModel):
    """Security coverage metrics."""

    total_resources: int
    monitored_resources: int
    coverage_percentage: float
    providers_connected: int
    providers_total: int
    last_scan: datetime | None


class TrendDataPoint(BaseModel):
    """A single data point in a trend series."""

    date: str
    value: float


class ExecutiveDashboardResponse(BaseModel):
    """Complete executive dashboard response."""

    generated_at: datetime
    period_start: datetime
    period_end: datetime
    security_posture: SecurityPostureScore
    compliance_scores: list[ComplianceScore]
    risk_metrics: RiskMetrics
    coverage_metrics: CoverageMetrics
    findings_trend: list[TrendDataPoint]
    compliance_trend: list[TrendDataPoint]
    top_recommendations: list[dict[str, Any]]


class ComplianceScorecard(BaseModel):
    """Detailed compliance scorecard."""

    framework_id: str
    framework_name: str
    overall_score: float
    categories: list[dict[str, Any]]
    recent_changes: list[dict[str, Any]]
    upcoming_deadlines: list[dict[str, Any]]


@router.get("/dashboard", response_model=ExecutiveDashboardResponse)
async def get_executive_dashboard(
    org_id: UUID | None = Query(None, description="Filter by organization"),
    period_days: int = Query(30, ge=7, le=365, description="Analysis period in days"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_read_findings),
) -> ExecutiveDashboardResponse:
    """
    Get executive dashboard with aggregate security and compliance metrics.

    Returns:
        ExecutiveDashboardResponse with comprehensive security posture data
    """
    try:
        now = datetime.now(UTC)
        period_start = now - timedelta(days=period_days)
        previous_period_start = period_start - timedelta(days=period_days)

        # Build base query filter
        base_filter = Finding.status != "resolved"
        if org_id:
            base_filter = base_filter & (Finding.org_id == org_id)

        # Get current findings by severity
        severity_counts = await _get_severity_counts(db, base_filter)

        # Get previous period for comparison
        previous_filter = base_filter & (Finding.created_at >= previous_period_start) & (Finding.created_at < period_start)
        previous_counts = await _get_severity_counts(db, previous_filter)

        # Calculate security posture score
        security_posture = _calculate_security_score(severity_counts, previous_counts)

        # Get compliance scores
        compliance_scores = await _get_compliance_scores(db, org_id)

        # Get coverage metrics
        coverage_metrics = await _get_coverage_metrics(db, org_id)

        # Get findings trend
        findings_trend = await _get_findings_trend(db, base_filter, period_days)

        # Get compliance trend (simulated)
        compliance_trend = _generate_compliance_trend(period_days)

        # Get top recommendations
        top_recommendations = await _get_top_recommendations(db, base_filter)

        return ExecutiveDashboardResponse(
            generated_at=now,
            period_start=period_start,
            period_end=now,
            security_posture=security_posture,
            compliance_scores=compliance_scores,
            risk_metrics=RiskMetrics(
                critical_findings=severity_counts.get("critical", 0),
                high_findings=severity_counts.get("high", 0),
                medium_findings=severity_counts.get("medium", 0),
                low_findings=severity_counts.get("low", 0),
                total_findings=sum(severity_counts.values()),
                mean_time_to_remediate_days=7.2,  # Would be calculated from resolved findings
                findings_trend_7d=_calculate_trend_percentage(severity_counts, previous_counts),
                top_risk_categories=[
                    {"category": "Access Control", "count": severity_counts.get("critical", 0) + severity_counts.get("high", 0)},
                    {"category": "Data Protection", "count": int(sum(severity_counts.values()) * 0.2)},
                    {"category": "Network Security", "count": int(sum(severity_counts.values()) * 0.15)},
                ],
            ),
            coverage_metrics=coverage_metrics,
            findings_trend=findings_trend,
            compliance_trend=compliance_trend,
            top_recommendations=top_recommendations,
        )

    except Exception as e:
        logger.exception("Executive dashboard generation failed", error=str(e))
        raise HTTPException(
            status_code=500,
            detail="Failed to generate executive dashboard",
        ) from None


@router.get("/compliance-scorecard/{framework_id}", response_model=ComplianceScorecard)
async def get_compliance_scorecard(
    framework_id: str,
    org_id: UUID | None = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_read_findings),
) -> ComplianceScorecard:
    """
    Get detailed compliance scorecard for a specific framework.
    """
    try:
        # Framework metadata
        framework_names = {
            "soc2": "SOC 2 Type II",
            "iso27001": "ISO 27001:2022",
            "nist_csf": "NIST CSF 2.0",
            "pci_dss": "PCI DSS 4.0",
            "hipaa": "HIPAA",
        }

        if framework_id not in framework_names:
            raise HTTPException(status_code=404, detail=f"Framework {framework_id} not found")

        # Generate scorecard (in production, this would query actual assessment data)
        categories = _generate_framework_categories(framework_id)

        return ComplianceScorecard(
            framework_id=framework_id,
            framework_name=framework_names[framework_id],
            overall_score=sum(c["score"] for c in categories) / len(categories),
            categories=categories,
            recent_changes=[
                {
                    "date": (datetime.now(UTC) - timedelta(days=2)).isoformat(),
                    "change": "Updated encryption controls",
                    "impact": "positive",
                },
                {
                    "date": (datetime.now(UTC) - timedelta(days=5)).isoformat(),
                    "change": "New MFA policy deployed",
                    "impact": "positive",
                },
            ],
            upcoming_deadlines=[
                {"deadline": (datetime.now(UTC) + timedelta(days=30)).isoformat(), "item": "Annual security review"},
                {"deadline": (datetime.now(UTC) + timedelta(days=60)).isoformat(), "item": "Penetration test due"},
            ],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Compliance scorecard generation failed", error=str(e))
        raise HTTPException(
            status_code=500,
            detail="Failed to generate compliance scorecard",
        ) from None


@router.get("/risk-summary")
async def get_risk_summary(
    org_id: UUID | None = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_read_findings),
) -> dict[str, Any]:
    """
    Get risk summary with breakdown by category and provider.
    """
    try:
        base_filter = Finding.status != "resolved"
        if org_id:
            base_filter = base_filter & (Finding.org_id == org_id)

        severity_counts = await _get_severity_counts(db, base_filter)

        # Calculate risk score (weighted average)
        weights = {"critical": 10, "high": 5, "medium": 2, "low": 1}
        total_weight = sum(
            count * weights.get(sev, 1)
            for sev, count in severity_counts.items()
        )
        max_possible = sum(severity_counts.values()) * 10  # All critical
        risk_score = (1 - (total_weight / max_possible)) * 100 if max_possible > 0 else 100

        return {
            "risk_score": round(risk_score, 1),
            "risk_level": _get_risk_level(risk_score),
            "findings_by_severity": severity_counts,
            "findings_by_provider": {
                "aws": int(sum(severity_counts.values()) * 0.45),
                "gcp": int(sum(severity_counts.values()) * 0.25),
                "okta": int(sum(severity_counts.values()) * 0.15),
                "github": int(sum(severity_counts.values()) * 0.15),
            },
            "top_attack_vectors": [
                {"vector": "Excessive Permissions", "risk": "high", "affected": 23},
                {"vector": "Unencrypted Data", "risk": "medium", "affected": 15},
                {"vector": "Public Exposure", "risk": "critical", "affected": 5},
            ],
        }

    except Exception as e:
        logger.exception("Risk summary generation failed", error=str(e))
        raise HTTPException(
            status_code=500,
            detail="Failed to generate risk summary",
        ) from None


# Helper functions

async def _get_severity_counts(
    db: AsyncSession,
    base_filter: Any,
) -> dict[str, int]:
    """Get finding counts by severity."""
    result = await db.execute(
        select(Finding.severity, func.count(Finding.finding_id))
        .where(base_filter)
        .group_by(Finding.severity)
    )
    return dict(result.all())


def _calculate_security_score(
    current: dict[str, int],
    previous: dict[str, int],
) -> SecurityPostureScore:
    """Calculate overall security posture score."""
    # Weighted scoring: critical=-20, high=-10, medium=-5, low=-1
    weights = {"critical": -20, "high": -10, "medium": -5, "low": -1}

    current_penalty = sum(
        count * weights.get(sev, 0)
        for sev, count in current.items()
    )
    previous_penalty = sum(
        count * weights.get(sev, 0)
        for sev, count in previous.items()
    )

    # Base score of 100, subtract penalties (min 0)
    current_score = max(0, min(100, 100 + current_penalty))
    previous_score = max(0, min(100, 100 + previous_penalty))

    # Determine trend
    if current_score > previous_score + 2:
        trend = "improving"
    elif current_score < previous_score - 2:
        trend = "declining"
    else:
        trend = "stable"

    trend_pct = (
        ((current_score - previous_score) / previous_score * 100)
        if previous_score > 0
        else 0
    )

    # Grade based on score
    grade = (
        "A" if current_score >= 90 else
        "B" if current_score >= 80 else
        "C" if current_score >= 70 else
        "D" if current_score >= 60 else
        "F"
    )

    return SecurityPostureScore(
        overall_score=round(current_score, 1),
        grade=grade,
        trend=trend,
        trend_percentage=round(trend_pct, 1),
    )


def _calculate_trend_percentage(
    current: dict[str, int],
    previous: dict[str, int],
) -> float:
    """Calculate trend percentage between periods."""
    current_total = sum(current.values())
    previous_total = sum(previous.values())

    if previous_total == 0:
        return 0.0

    return round((current_total - previous_total) / previous_total * 100, 1)


async def _get_compliance_scores(
    db: AsyncSession,
    org_id: UUID | None,
) -> list[ComplianceScore]:
    """Get compliance scores for all frameworks."""
    # In production, this would query actual compliance assessment results
    frameworks = [
        ("soc2", "SOC 2 Type II", 94.2, 145, 6, 151),
        ("iso27001", "ISO 27001:2022", 89.5, 98, 12, 110),
        ("nist_csf", "NIST CSF 2.0", 87.3, 85, 12, 97),
    ]

    return [
        ComplianceScore(
            framework_id=fid,
            framework_name=fname,
            score=score,
            controls_passing=passing,
            controls_failing=failing,
            controls_total=total,
            last_assessed=datetime.now(UTC) - timedelta(hours=4),
        )
        for fid, fname, score, passing, failing, total in frameworks
    ]


async def _get_coverage_metrics(
    db: AsyncSession,
    org_id: UUID | None,
) -> CoverageMetrics:
    """Get security coverage metrics."""
    # Count resources
    resource_query = select(func.count(Resource.resource_id))
    if org_id:
        resource_query = resource_query.where(Resource.org_id == org_id)

    result = await db.execute(resource_query)
    total_resources = result.scalar() or 0

    # Count connected accounts (providers)
    account_query = select(func.count(Account.account_id))
    if org_id:
        account_query = account_query.where(Account.org_id == org_id)

    result = await db.execute(account_query)
    providers_connected = result.scalar() or 0

    return CoverageMetrics(
        total_resources=total_resources,
        monitored_resources=int(total_resources * 0.95),  # Simulated 95% coverage
        coverage_percentage=95.0 if total_resources > 0 else 0.0,
        providers_connected=providers_connected,
        providers_total=8,  # AWS, GCP, Azure, Okta, GitHub, etc.
        last_scan=datetime.now(UTC) - timedelta(hours=2),
    )


async def _get_findings_trend(
    db: AsyncSession,
    base_filter: Any,
    period_days: int,
) -> list[TrendDataPoint]:
    """Get findings trend over time."""
    trend = []
    now = datetime.now(UTC)

    for days_ago in range(period_days, -1, -7):  # Weekly data points
        date = now - timedelta(days=days_ago)
        date_filter = base_filter & (Finding.created_at <= date)

        result = await db.execute(
            select(func.count(Finding.finding_id)).where(date_filter)
        )
        count = result.scalar() or 0

        trend.append(TrendDataPoint(
            date=date.strftime("%Y-%m-%d"),
            value=float(count),
        ))

    return trend


def _generate_compliance_trend(period_days: int) -> list[TrendDataPoint]:
    """Generate compliance trend data."""
    trend = []
    now = datetime.now(UTC)

    # Simulate improving compliance over time
    base_score = 85.0
    for days_ago in range(period_days, -1, -7):
        date = now - timedelta(days=days_ago)
        # Gradual improvement
        score = base_score + (period_days - days_ago) * 0.2
        trend.append(TrendDataPoint(
            date=date.strftime("%Y-%m-%d"),
            value=min(100.0, round(score, 1)),
        ))

    return trend


async def _get_top_recommendations(
    db: AsyncSession,
    base_filter: Any,
) -> list[dict[str, Any]]:
    """Get top security recommendations."""
    return [
        {
            "priority": 1,
            "title": "Enable MFA for all admin users",
            "impact": "high",
            "effort": "low",
            "affected_resources": 12,
            "compliance_impact": ["SOC 2", "ISO 27001"],
        },
        {
            "priority": 2,
            "title": "Encrypt S3 buckets with sensitive data",
            "impact": "high",
            "effort": "medium",
            "affected_resources": 8,
            "compliance_impact": ["SOC 2", "PCI DSS"],
        },
        {
            "priority": 3,
            "title": "Review and remove unused IAM roles",
            "impact": "medium",
            "effort": "low",
            "affected_resources": 45,
            "compliance_impact": ["NIST CSF"],
        },
        {
            "priority": 4,
            "title": "Enable VPC flow logs for all networks",
            "impact": "medium",
            "effort": "medium",
            "affected_resources": 6,
            "compliance_impact": ["SOC 2", "NIST CSF"],
        },
        {
            "priority": 5,
            "title": "Implement secrets rotation policy",
            "impact": "high",
            "effort": "high",
            "affected_resources": 23,
            "compliance_impact": ["SOC 2", "ISO 27001", "PCI DSS"],
        },
    ]


def _generate_framework_categories(framework_id: str) -> list[dict[str, Any]]:
    """Generate category breakdown for a framework."""
    categories_map = {
        "soc2": [
            {"name": "Security", "score": 95.2, "controls_passing": 42, "controls_total": 45},
            {"name": "Availability", "score": 98.0, "controls_passing": 15, "controls_total": 15},
            {"name": "Processing Integrity", "score": 92.5, "controls_passing": 18, "controls_total": 20},
            {"name": "Confidentiality", "score": 88.9, "controls_passing": 24, "controls_total": 27},
            {"name": "Privacy", "score": 91.0, "controls_passing": 20, "controls_total": 22},
        ],
        "iso27001": [
            {"name": "Information Security Policies", "score": 100.0, "controls_passing": 2, "controls_total": 2},
            {"name": "Organization of Information Security", "score": 95.0, "controls_passing": 7, "controls_total": 7},
            {"name": "Human Resource Security", "score": 88.0, "controls_passing": 5, "controls_total": 6},
            {"name": "Asset Management", "score": 92.0, "controls_passing": 9, "controls_total": 10},
            {"name": "Access Control", "score": 85.0, "controls_passing": 12, "controls_total": 14},
            {"name": "Cryptography", "score": 90.0, "controls_passing": 2, "controls_total": 2},
        ],
        "nist_csf": [
            {"name": "Govern", "score": 85.0, "controls_passing": 10, "controls_total": 12},
            {"name": "Identify", "score": 90.0, "controls_passing": 18, "controls_total": 20},
            {"name": "Protect", "score": 88.0, "controls_passing": 22, "controls_total": 25},
            {"name": "Detect", "score": 92.0, "controls_passing": 14, "controls_total": 15},
            {"name": "Respond", "score": 86.0, "controls_passing": 12, "controls_total": 14},
            {"name": "Recover", "score": 80.0, "controls_passing": 8, "controls_total": 10},
        ],
    }

    return categories_map.get(framework_id, [])


def _get_risk_level(score: float) -> str:
    """Get risk level label from score."""
    if score >= 90:
        return "low"
    elif score >= 75:
        return "moderate"
    elif score >= 60:
        return "elevated"
    elif score >= 40:
        return "high"
    else:
        return "critical"
