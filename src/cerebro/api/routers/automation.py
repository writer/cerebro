"""Automation telemetry API endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.api.auth import User, get_current_user
from cerebro.core.database import get_db
from cerebro.automation.telemetry_health import (
    TelemetryHealthSnapshot,
    evaluate_health_thresholds,
    fetch_telemetry_health,
)
from cerebro.automation.alerting import (
    AlertResult,
    AlertRule,
    collect_telemetry_alerts,
    default_rules,
)


router = APIRouter(prefix="/automation", tags=["automation", "telemetry"])


class TelemetryHealthResponse(BaseModel):
    """Response payload for telemetry health endpoint."""

    snapshot: Dict[str, Any]
    issues: List[str]


class TelemetryAlertItem(BaseModel):
    """Single telemetry alert record returned by preview endpoint."""

    rule_id: str
    severity: str
    metric: str
    metric_value: float
    message: str
    triggered_at: datetime
    channels: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TelemetryAlertsResponse(BaseModel):
    """Response payload for alerts preview endpoint."""

    alerts: List[TelemetryAlertItem]
    snapshot: Dict[str, Any]


def _snapshot_to_dict(snapshot: TelemetryHealthSnapshot) -> Dict[str, Any]:
    return snapshot.to_dict()


def _serialize_alert(alert: AlertResult) -> TelemetryAlertItem:
    return TelemetryAlertItem(
        rule_id=alert.rule.rule_id,
        severity=alert.severity.value,
        metric=alert.rule.metric,
        metric_value=alert.metric_value,
        message=alert.message,
        triggered_at=alert.triggered_at,
        channels=list(alert.channels),
        metadata=dict(alert.metadata),
    )


@router.get("/telemetry/health", response_model=TelemetryHealthResponse)
async def get_telemetry_health(
    *,
    window_days: int = Query(7, ge=1, le=30),
    max_missing_metadata_ratio: float = Query(0.25, ge=0.0, le=1.0),
    max_missing_component_ratio: float = Query(0.1, ge=0.0, le=1.0),
    min_total_events: int = Query(10, ge=0),
    _user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TelemetryHealthResponse:
    """Return aggregated telemetry health metrics with rule-based issues."""

    snapshot = await fetch_telemetry_health(window_days, db_session=db)
    issues = evaluate_health_thresholds(
        snapshot,
        max_missing_metadata_ratio=max_missing_metadata_ratio,
        max_missing_component_ratio=max_missing_component_ratio,
        min_total_events=min_total_events,
    )
    return TelemetryHealthResponse(snapshot=_snapshot_to_dict(snapshot), issues=issues)


@router.get("/telemetry/alerts", response_model=TelemetryAlertsResponse)
async def preview_telemetry_alerts(
    *,
    window_days: int = Query(7, ge=1, le=30),
    rule_ids: Optional[List[str]] = Query(None, alias="rule_id"),
    _user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TelemetryAlertsResponse:
    """Preview telemetry alerts for the provided rule selection."""

    available_rules = list(default_rules())
    rules_selection: Optional[Sequence[AlertRule]]

    if rule_ids:
        rule_set = {rule_id for rule_id in rule_ids}
        filtered = [rule for rule in available_rules if rule.rule_id in rule_set]
        rules_selection = tuple(filtered)
    else:
        rules_selection = tuple(available_rules)

    alerts, snapshot = await collect_telemetry_alerts(
        window_days=window_days,
        rules=rules_selection,
        cooldown_store=None,
        db_session=db,
    )

    serialized = [_serialize_alert(alert) for alert in alerts]
    return TelemetryAlertsResponse(
        alerts=serialized, snapshot=_snapshot_to_dict(snapshot)
    )
