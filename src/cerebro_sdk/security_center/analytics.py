"""Vendor and customer analytics for the Security Center SDK."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Literal, Sequence, cast

from .models import SecurityCenterCustomerInsight, SecurityCenterVendorInsight

DAY_SECONDS = 24 * 60 * 60
REVIEW_DUE_SOON_THRESHOLD_DAYS = 30


def _ensure_datetime(value: datetime | None) -> datetime | None:
    return value if isinstance(value, datetime) else None


def _now(now: datetime | None) -> datetime:
    return now if now is not None else datetime.utcnow()


def _normalize(value: str | None) -> str:
    return (value or "").strip().lower()


def _days_between(a: datetime, b: datetime) -> int:
    delta = b - a
    return round(delta.total_seconds() / DAY_SECONDS)


def _coerce_number(value: object, warnings: list[str], context: str) -> float | None:
    if value is None:
        warnings.append(f"Missing value for {context}")
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        warnings.append(f"Non-numeric value for {context}")
        return None
    return number


def _classify_review_status(days: int | None) -> Literal["on_track", "due_soon", "overdue"]:
    if days is None:
        return "on_track"
    if days < 0:
        return "overdue"
    if days <= REVIEW_DUE_SOON_THRESHOLD_DAYS:
        return "due_soon"
    return "on_track"


@dataclass(slots=True)
class VendorHealthAssessment:
    vendor_id: str
    name: str
    risk_level: str
    inherent_risk_score: float | None
    residual_risk_score: float | None
    risk_delta: float | None
    review_due_in_days: int | None
    review_status: Literal["on_track", "due_soon", "overdue"]
    business_criticality: str | None
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class VendorPortfolioSummary:
    total: int
    by_risk_level: dict[str, int]
    overdue_reviews: int
    due_soon_reviews: int
    average_residual_risk: float | None


@dataclass(slots=True)
class CustomerHealthAssessment:
    customer_id: str
    name: str
    health_score: float | None
    health_band: str | None
    churn_risk_score: float | None
    engagement_gap_days: int | None
    next_qbr_in_days: int | None
    account_manager: str | None
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CustomerPortfolioSummary:
    total: int
    average_health_score: float | None
    average_churn_risk: float | None
    by_segment: dict[str, int]
    at_risk_count: int


@dataclass(slots=True)
class VendorPortfolioSnapshot:
    timestamp: datetime
    vendors: Sequence[SecurityCenterVendorInsight]


@dataclass(slots=True)
class VendorTrendPoint:
    timestamp: datetime
    total: int
    overdue_reviews: int
    due_soon_reviews: int
    average_residual_risk: float | None


@dataclass(slots=True)
class VendorTrendSummary:
    points: list[VendorTrendPoint]
    residual_risk_change: float | None
    direction: Literal["improving", "declining", "steady", None]


@dataclass(slots=True)
class CustomerHealthSnapshot:
    timestamp: datetime
    customers: Sequence[SecurityCenterCustomerInsight]


@dataclass(slots=True)
class CustomerTrendPoint:
    timestamp: datetime
    total: int
    at_risk_count: int
    average_health_score: float | None
    average_churn_risk: float | None


@dataclass(slots=True)
class CustomerTrendSummary:
    points: list[CustomerTrendPoint]
    health_score_change: float | None
    direction: Literal["improving", "declining", "steady", None]


@dataclass(slots=True)
class TrendAlert:
    severity: Literal["info", "warning", "critical"]
    metric: str
    message: str


@dataclass(slots=True)
class VendorTrendWindow:
    window: Literal["7d", "30d"]
    residual_risk_change: float | None
    overdue_review_change: float | None
    direction: Literal["improving", "declining", "steady", None]


@dataclass(slots=True)
class CustomerTrendWindow:
    window: Literal["7d", "30d"]
    health_score_change: float | None
    at_risk_change: float | None
    direction: Literal["improving", "declining", "steady", None]


@dataclass(slots=True)
class VendorTrendAnalysis:
    summary: VendorTrendSummary
    windows: list[VendorTrendWindow]
    alerts: list[TrendAlert]


@dataclass(slots=True)
class CustomerTrendAnalysis:
    summary: CustomerTrendSummary
    windows: list[CustomerTrendWindow]
    alerts: list[TrendAlert]


@dataclass(slots=True)
class VendorRiskKpis:
    total_vendors: int
    high_risk_vendors: int
    medium_risk_vendors: int
    low_risk_vendors: int
    overdue_reviews: int
    due_soon_reviews: int
    average_residual_risk: float | None


@dataclass(slots=True)
class VendorRiskDashboard:
    kpis: VendorRiskKpis
    by_risk_level: dict[str, int]
    critical_vendors: list[VendorHealthAssessment]
    assessments: list[VendorHealthAssessment]
    warnings: list[str]


@dataclass(slots=True)
class CustomerRiskKpis:
    total_customers: int
    healthy_customers: int
    neutral_customers: int
    at_risk_customers: int
    average_health_score: float | None
    average_churn_risk: float | None


@dataclass(slots=True)
class CustomerRiskDashboard:
    kpis: CustomerRiskKpis
    by_health_band: dict[str, int]
    at_risk_customers: list[CustomerHealthAssessment]
    assessments: list[CustomerHealthAssessment]
    warnings: list[str]


def assess_vendor_health(
    vendor: SecurityCenterVendorInsight,
    now: datetime | None = None,
) -> VendorHealthAssessment:
    timestamp = _now(now)
    warnings: list[str] = []
    inherent = _coerce_number(vendor.inherent_risk_score, warnings, f"vendor {vendor.vendor_id} inherent risk")
    residual = _coerce_number(vendor.residual_risk_score, warnings, f"vendor {vendor.vendor_id} residual risk")
    risk_delta = None
    if inherent is not None and residual is not None:
        risk_delta = residual - inherent

    review_due = _ensure_datetime(vendor.next_review_due)
    review_due_in_days = _days_between(timestamp, review_due) if review_due else None
    review_status = _classify_review_status(review_due_in_days)

    return VendorHealthAssessment(
        vendor_id=vendor.vendor_id,
        name=vendor.name,
        risk_level=vendor.risk_level,
        inherent_risk_score=inherent,
        residual_risk_score=residual,
        risk_delta=risk_delta,
        review_due_in_days=review_due_in_days,
        review_status=review_status,
        business_criticality=vendor.business_criticality,
        warnings=warnings,
    )


def summarize_vendor_portfolio(
    vendors: Sequence[SecurityCenterVendorInsight],
    now: datetime | None = None,
) -> VendorPortfolioSummary:
    if not vendors:
        return VendorPortfolioSummary(total=0, by_risk_level={}, overdue_reviews=0, due_soon_reviews=0, average_residual_risk=None)

    timestamp = _now(now)
    by_risk: dict[str, int] = {}
    overdue = 0
    due_soon = 0
    residual_sum = 0.0
    residual_count = 0

    for vendor in vendors:
        assessment = assess_vendor_health(vendor, timestamp)
        level = _normalize(assessment.risk_level) or "unknown"
        by_risk[level] = by_risk.get(level, 0) + 1

        if assessment.review_status == "overdue":
            overdue += 1
        elif assessment.review_status == "due_soon":
            due_soon += 1

        if assessment.residual_risk_score is not None:
            residual_sum += assessment.residual_risk_score
            residual_count += 1

    average_residual = residual_sum / residual_count if residual_count else None
    return VendorPortfolioSummary(
        total=len(vendors),
        by_risk_level=by_risk,
        overdue_reviews=overdue,
        due_soon_reviews=due_soon,
        average_residual_risk=average_residual,
    )


def assess_customer_health(
    customer: SecurityCenterCustomerInsight,
    now: datetime | None = None,
) -> CustomerHealthAssessment:
    timestamp = _now(now)
    warnings: list[str] = []
    health_score = _coerce_number(customer.health_score, warnings, f"customer {customer.customer_id} health")
    churn_risk = _coerce_number(customer.churn_risk_score, warnings, f"customer {customer.customer_id} churn risk")

    last_engagement = _ensure_datetime(customer.last_engagement_at)
    engagement_gap = _days_between(last_engagement, timestamp) if last_engagement else None
    next_qbr = _ensure_datetime(customer.next_qbr_at)
    next_qbr_in = _days_between(timestamp, next_qbr) if next_qbr else None

    return CustomerHealthAssessment(
        customer_id=customer.customer_id,
        name=customer.name,
        health_score=health_score,
        health_band=customer.health_band,
        churn_risk_score=churn_risk,
        engagement_gap_days=engagement_gap,
        next_qbr_in_days=next_qbr_in,
        account_manager=customer.account_manager,
        warnings=warnings,
    )


def summarize_customer_portfolio(
    customers: Sequence[SecurityCenterCustomerInsight],
    now: datetime | None = None,
) -> CustomerPortfolioSummary:
    if not customers:
        return CustomerPortfolioSummary(total=0, average_health_score=None, average_churn_risk=None, by_segment={}, at_risk_count=0)

    timestamp = _now(now)
    by_segment: dict[str, int] = {}
    health_sum = 0.0
    health_count = 0
    churn_sum = 0.0
    churn_count = 0
    at_risk_count = 0

    for customer in customers:
        assessment = assess_customer_health(customer, timestamp)
        segment = _normalize(customer.segment) or "unknown"
        by_segment[segment] = by_segment.get(segment, 0) + 1

        customer_at_risk = False
        if assessment.health_score is not None:
            health_sum += assessment.health_score
            health_count += 1
            if assessment.health_score < 0.6:
                customer_at_risk = True
        if assessment.churn_risk_score is not None:
            churn_sum += assessment.churn_risk_score
            churn_count += 1
            if assessment.churn_risk_score >= 0.5:
                customer_at_risk = True

        band = _normalize(assessment.health_band)
        if band in {"at_risk", "critical"}:
            customer_at_risk = True

        if customer_at_risk:
            at_risk_count += 1

    average_health = health_sum / health_count if health_count else None
    average_churn = churn_sum / churn_count if churn_count else None

    return CustomerPortfolioSummary(
        total=len(customers),
        average_health_score=average_health,
        average_churn_risk=average_churn,
        by_segment=by_segment,
        at_risk_count=at_risk_count,
    )


def build_vendor_risk_dashboard(
    vendors: Sequence[SecurityCenterVendorInsight],
    now: datetime | None = None,
    *,
    critical_limit: int = 5,
) -> VendorRiskDashboard:
    timestamp = _now(now)
    summary = summarize_vendor_portfolio(vendors, timestamp)
    assessments = [assess_vendor_health(vendor, timestamp) for vendor in vendors]
    warnings = [warning for assessment in assessments for warning in assessment.warnings]

    high_risk = [assessment for assessment in assessments if _normalize(assessment.risk_level) == "high"]
    critical = [
        assessment
        for assessment in assessments
        if assessment.review_status == "overdue"
        or _normalize(assessment.risk_level) == "high"
        or _normalize(assessment.business_criticality) == "high"
    ]
    critical.sort(key=lambda assessment: assessment.residual_risk_score or 0.0, reverse=True)
    critical = critical[:critical_limit]

    kpis = VendorRiskKpis(
        total_vendors=summary.total,
        high_risk_vendors=len(high_risk),
        medium_risk_vendors=summary.by_risk_level.get("medium", 0),
        low_risk_vendors=summary.by_risk_level.get("low", 0),
        overdue_reviews=summary.overdue_reviews,
        due_soon_reviews=summary.due_soon_reviews,
        average_residual_risk=summary.average_residual_risk,
    )

    return VendorRiskDashboard(
        kpis=kpis,
        by_risk_level=summary.by_risk_level,
        critical_vendors=critical,
        assessments=assessments,
        warnings=warnings,
    )


def build_customer_risk_dashboard(
    customers: Sequence[SecurityCenterCustomerInsight],
    now: datetime | None = None,
    *,
    at_risk_limit: int = 5,
) -> CustomerRiskDashboard:
    timestamp = _now(now)
    summary = summarize_customer_portfolio(customers, timestamp)
    assessments = [assess_customer_health(customer, timestamp) for customer in customers]
    warnings = [warning for assessment in assessments for warning in assessment.warnings]

    by_band: dict[str, int] = {}
    for customer in customers:
        band = _normalize(customer.health_band) or "unknown"
        by_band[band] = by_band.get(band, 0) + 1

    at_risk_customers = [
        assessment
        for assessment in assessments
        if _normalize(assessment.health_band) in {"at_risk", "critical"}
        or (assessment.health_score is not None and assessment.health_score < 0.6)
        or (assessment.churn_risk_score is not None and assessment.churn_risk_score >= 0.5)
    ]
    at_risk_customers.sort(key=lambda assessment: assessment.churn_risk_score or 0.0, reverse=True)
    at_risk_customers = at_risk_customers[:at_risk_limit]

    healthy_count = by_band.get("healthy", 0)
    neutral_count = by_band.get("neutral", 0) + by_band.get("stable", 0)

    kpis = CustomerRiskKpis(
        total_customers=summary.total,
        healthy_customers=healthy_count,
        neutral_customers=neutral_count,
        at_risk_customers=summary.at_risk_count,
        average_health_score=summary.average_health_score,
        average_churn_risk=summary.average_churn_risk,
    )

    return CustomerRiskDashboard(
        kpis=kpis,
        by_health_band=by_band,
        at_risk_customers=at_risk_customers,
        assessments=assessments,
        warnings=warnings,
    )


def _compute_change(values: Iterable[float | None]) -> float | None:
    filtered = [value for value in values if value is not None]
    if len(filtered) < 2:
        return None
    return filtered[-1] - filtered[0]


def _filter_points_within(points: Sequence[Mapping[str, object]], now: datetime, window_seconds: int) -> list[Mapping[str, object]]:
    threshold = now.timestamp() - window_seconds
    return [point for point in points if isinstance(point.get("timestamp"), datetime) and point["timestamp"].timestamp() >= threshold]


def _derive_direction(
    change: float | None,
    preference: Literal["higher_is_better", "lower_is_better"],
) -> Literal["improving", "declining", "steady", None]:
    if change is None:
        return None
    if abs(change) < 0.01:
        return "steady"
    if preference == "higher_is_better":
        return "improving" if change > 0 else "declining"
    return "improving" if change < 0 else "declining"


def compute_vendor_portfolio_trend(snapshots: Sequence[VendorPortfolioSnapshot]) -> VendorTrendSummary:
    points: list[VendorTrendPoint] = []
    for snapshot in sorted(snapshots, key=lambda entry: entry.timestamp):
        summary = summarize_vendor_portfolio(snapshot.vendors, snapshot.timestamp)
        points.append(
            VendorTrendPoint(
                timestamp=snapshot.timestamp,
                total=summary.total,
                overdue_reviews=summary.overdue_reviews,
                due_soon_reviews=summary.due_soon_reviews,
                average_residual_risk=summary.average_residual_risk,
            )
        )

    residual_change = _compute_change([point.average_residual_risk for point in points])
    direction = _derive_direction(residual_change, "lower_is_better")
    return VendorTrendSummary(points=points, residual_risk_change=residual_change, direction=direction)


def compute_customer_health_trend(snapshots: Sequence[CustomerHealthSnapshot]) -> CustomerTrendSummary:
    points: list[CustomerTrendPoint] = []
    for snapshot in sorted(snapshots, key=lambda entry: entry.timestamp):
        summary = summarize_customer_portfolio(snapshot.customers, snapshot.timestamp)
        points.append(
            CustomerTrendPoint(
                timestamp=snapshot.timestamp,
                total=summary.total,
                at_risk_count=summary.at_risk_count,
                average_health_score=summary.average_health_score,
                average_churn_risk=summary.average_churn_risk,
            )
        )

    health_change = _compute_change([point.average_health_score for point in points])
    direction = _derive_direction(health_change, "higher_is_better")
    return CustomerTrendSummary(points=points, health_score_change=health_change, direction=direction)


def analyze_vendor_snapshots(
    snapshots: Sequence[VendorPortfolioSnapshot],
    now: datetime | None = None,
) -> VendorTrendAnalysis:
    timestamp = _now(now)
    summary = compute_vendor_portfolio_trend(snapshots)
    windows: list[VendorTrendWindow] = []

    for days in (7, 30):
        window_points = [
            point
            for point in summary.points
            if point.timestamp.timestamp() >= timestamp.timestamp() - days * DAY_SECONDS
        ]
        residual_change = _compute_change([point.average_residual_risk for point in window_points])
        overdue_change = _compute_change([float(point.overdue_reviews) for point in window_points])
        window = VendorTrendWindow(
            window=cast(Literal["7d", "30d"], f"{days}d"),
            residual_risk_change=residual_change,
            overdue_review_change=overdue_change,
            direction=_derive_direction(residual_change, "lower_is_better"),
        )
        windows.append(window)

    alerts: list[TrendAlert] = []
    window_map = {window.window: window for window in windows}
    last_30 = window_map.get("30d")
    if last_30 and last_30.residual_risk_change is not None and last_30.residual_risk_change > 0.05:
        alerts.append(
            TrendAlert(
                severity="warning",
                metric="vendor_residual_risk",
                message=f"Vendor residual risk increased by {last_30.residual_risk_change * 100:.1f}pts in 30d",
            )
        )
    if last_30 and last_30.overdue_review_change is not None and last_30.overdue_review_change > 0:
        alerts.append(
            TrendAlert(
                severity="critical" if last_30.overdue_review_change >= 3 else "warning",
                metric="vendor_overdue_reviews",
                message=f"{int(last_30.overdue_review_change)} additional vendor reviews overdue over last 30d",
            )
        )

    last_7 = window_map.get("7d")
    if last_7 and last_7.overdue_review_change is not None and last_7.overdue_review_change > 0:
        alerts.append(
            TrendAlert(
                severity="warning",
                metric="vendor_overdue_reviews_7d",
                message=f"{int(last_7.overdue_review_change)} vendor reviews became overdue in the last 7d",
            )
        )

    return VendorTrendAnalysis(summary=summary, windows=windows, alerts=alerts)


def analyze_customer_snapshots(
    snapshots: Sequence[CustomerHealthSnapshot],
    now: datetime | None = None,
) -> CustomerTrendAnalysis:
    timestamp = _now(now)
    summary = compute_customer_health_trend(snapshots)
    windows: list[CustomerTrendWindow] = []

    for days in (7, 30):
        window_points = [
            point
            for point in summary.points
            if point.timestamp.timestamp() >= timestamp.timestamp() - days * DAY_SECONDS
        ]
        health_change = _compute_change([point.average_health_score for point in window_points])
        at_risk_change = _compute_change([float(point.at_risk_count) for point in window_points])
        window = CustomerTrendWindow(
            window=cast(Literal["7d", "30d"], f"{days}d"),
            health_score_change=health_change,
            at_risk_change=at_risk_change,
            direction=_derive_direction(health_change, "higher_is_better"),
        )
        windows.append(window)

    alerts: list[TrendAlert] = []
    window_map = {window.window: window for window in windows}
    last_30 = window_map.get("30d")
    if last_30 and last_30.health_score_change is not None and last_30.health_score_change < -0.05:
        alerts.append(
            TrendAlert(
                severity="warning",
                metric="customer_health_score",
                message=f"Customer health dropped {abs(last_30.health_score_change) * 100:.1f}pts over 30d",
            )
        )
    if last_30 and last_30.at_risk_change is not None and last_30.at_risk_change > 0:
        alerts.append(
            TrendAlert(
                severity="critical" if last_30.at_risk_change >= 3 else "warning",
                metric="customer_at_risk",
                message=f"{int(last_30.at_risk_change)} more customers moved to at-risk in the last 30d",
            )
        )

    last_7 = window_map.get("7d")
    if last_7 and last_7.at_risk_change is not None and last_7.at_risk_change > 0:
        alerts.append(
            TrendAlert(
                severity="warning",
                metric="customer_at_risk_7d",
                message=f"{int(last_7.at_risk_change)} customers became at-risk in the last 7d",
            )
        )

    return CustomerTrendAnalysis(summary=summary, windows=windows, alerts=alerts)


__all__ = [
    "VendorHealthAssessment",
    "VendorPortfolioSummary",
    "CustomerHealthAssessment",
    "CustomerPortfolioSummary",
    "VendorPortfolioSnapshot",
    "VendorTrendPoint",
    "VendorTrendSummary",
    "CustomerHealthSnapshot",
    "CustomerTrendPoint",
    "CustomerTrendSummary",
    "VendorTrendWindow",
    "CustomerTrendWindow",
    "VendorTrendAnalysis",
    "CustomerTrendAnalysis",
    "VendorRiskDashboard",
    "VendorRiskKpis",
    "CustomerRiskDashboard",
    "CustomerRiskKpis",
    "TrendAlert",
    "assess_vendor_health",
    "summarize_vendor_portfolio",
    "assess_customer_health",
    "summarize_customer_portfolio",
    "build_vendor_risk_dashboard",
    "build_customer_risk_dashboard",
    "compute_vendor_portfolio_trend",
    "compute_customer_health_trend",
    "analyze_vendor_snapshots",
    "analyze_customer_snapshots",
]
