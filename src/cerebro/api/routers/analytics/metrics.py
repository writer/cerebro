"""Metrics and time-series analytics API endpoints."""

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.analytics.time_series import MetricType, TrendAnalyzer
from cerebro.api.auth import User, get_current_user, require_scopes
from cerebro.api.org_access import require_org_access
from cerebro.core.analytics_db import get_analytics_db
from cerebro.core.database import get_db
from cerebro.core.models import Organization

router = APIRouter(dependencies=[Depends(get_current_user)])


@router.get("/organizations/{org_id}/metrics/trends")
async def get_metric_trends(
    org_id: UUID,
    metric_type: str = Query(..., description="Metric type to analyze"),
    days_back: int = Query(default=30, description="Days of historical data"),
    db: AsyncSession = Depends(get_db),
    analytics_db: Any = Depends(get_analytics_db),
    current_user: User = Depends(require_org_access(require_scopes("read:findings"))),
) -> dict[str, Any]:
    """Get trend analysis for a specific metric."""

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        metric_enum = MetricType(metric_type)
    except ValueError:
        raise HTTPException(
            status_code=400, detail=f"Invalid metric type: {metric_type}"
        ) from None

    trend_analyzer = TrendAnalyzer(analytics_db)
    trend = await trend_analyzer.analyze_metric_trend(org_id, metric_enum, days_back)

    return {
        "metric_type": trend.metric_type,
        "current_value": trend.current_value,
        "previous_value": trend.previous_value,
        "change_absolute": trend.change_absolute,
        "change_percentage": round(trend.change_percentage, 2),
        "trend_direction": trend.trend_direction,
        "confidence": round(trend.confidence, 2),
        "data_points": trend.data_points,
        "sparkline_values": [point["value"] for point in trend.data_points],
    }


@router.get("/organizations/{org_id}/metrics/sparklines")
async def get_metrics_sparklines(
    org_id: UUID,
    days_back: int = Query(default=7, description="Days of data for sparklines"),
    db: AsyncSession = Depends(get_db),
    analytics_db: Any = Depends(get_analytics_db),
    current_user: User = Depends(require_org_access(require_scopes("read:findings"))),
) -> dict[str, list[float]]:
    """Get sparkline data for key metrics."""

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    trend_analyzer = TrendAnalyzer(analytics_db)

    # Generate sparklines for key metrics
    sparklines = {}

    key_metrics = [
        MetricType.FINDING_COUNT,
        MetricType.MEAN_TIME_TO_REMEDIATION,
        MetricType.SLA_BREACH_COUNT,
    ]

    for metric_type in key_metrics:
        sparkline_data = await trend_analyzer.generate_sparkline_data(
            org_id, metric_type, days_back
        )
        sparklines[metric_type.value] = sparkline_data

    return sparklines


@router.get("/organizations/{org_id}/analytics/trend/{card_type}")
async def get_card_sparkline(
    org_id: UUID,
    card_type: str,
    days_back: int = Query(default=7, description="Days of historical data"),
    db: AsyncSession = Depends(get_db),
    analytics_db: Any = Depends(get_analytics_db),
    current_user: User = Depends(require_org_access(require_scopes("read:findings"))),
) -> dict[str, Any]:
    """Get sparkline data for specific dashboard cards."""

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Map card types to metrics
    card_to_metric = {
        "findings": MetricType.FINDING_COUNT,
        "criticals": MetricType.CRITICAL_FINDING_COUNT,
        "sla_breaches": MetricType.SLA_BREACH_COUNT,
        "mttr": MetricType.MEAN_TIME_TO_REMEDIATION,
    }

    if card_type not in card_to_metric:
        raise HTTPException(status_code=400, detail=f"Invalid card type: {card_type}")

    metric_type = card_to_metric[card_type]
    trend_analyzer = TrendAnalyzer(analytics_db)

    # Get trend analysis with sparkline
    trend = await trend_analyzer.analyze_metric_trend(org_id, metric_type, days_back)
    sparkline_data = await trend_analyzer.generate_sparkline_data(
        org_id, metric_type, days_back
    )

    return {
        "card_type": card_type,
        "current_value": trend.current_value,
        "change_percentage": (
            round(trend.change_percentage, 1) if trend.change_percentage else 0
        ),
        "trend_direction": trend.trend_direction,
        "sparkline": sparkline_data,
    }
