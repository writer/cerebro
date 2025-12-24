"""Agent tool exposing telemetry automation insights."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from cerebro.automation.alerting import (
    AlertResult,
    RuleSeverity,
    collect_telemetry_alerts,
    default_rules,
)
from cerebro.automation.telemetry_health import evaluate_health_thresholds
from cerebro.core.database import async_session_factory

from .base import AgentContext, StructuredTool, ToolPermissionLevel, ToolResult


class TelemetryAutomationInput(BaseModel):
    """Inputs for telemetry automation summary tool."""

    window_days: int = Field(1, ge=1, le=30, description="Number of days to evaluate")
    severity: Optional[RuleSeverity] = Field(
        default=None,
        description="Filter alerts by minimum severity (inclusive)",
    )
    max_missing_metadata_ratio: float = Field(
        default=0.3,
        ge=0.0,
        le=1.0,
        description="Threshold for missing metadata ratio",
    )
    max_missing_component_ratio: float = Field(
        default=0.15,
        ge=0.0,
        le=1.0,
        description="Threshold for missing component ratio",
    )
    min_total_events: int = Field(
        default=25,
        ge=0,
        description="Minimum total events threshold",
    )
    limit_alerts: int = Field(
        default=10,
        ge=0,
        le=50,
        description="Maximum number of alerts to return",
    )


class TelemetryAutomationAlert(BaseModel):
    """Structured alert row returned to agents."""

    rule_id: str
    severity: RuleSeverity
    message: str
    metric: str
    metric_value: float
    triggered_at: datetime
    channels: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TelemetryAutomationOutput(BaseModel):
    """Structured output with health issues and alert previews."""

    snapshot: Dict[str, Any]
    issues: List[str]
    alerts: List[TelemetryAutomationAlert]


class TelemetryAutomationSummaryTool(StructuredTool):
    """Summarize telemetry health with alert previews for automation agents."""

    tool_name = "automation.telemetry_summary"
    tool_description = (
        "Evaluate telemetry health metrics and preview automation alerts, "
        "including threshold breaches and recent alert triggers."
    )
    input_model = TelemetryAutomationInput
    output_model = TelemetryAutomationOutput
    required_permission = ToolPermissionLevel.READ_ONLY

    async def _run(  # type: ignore[override]
        self,
        context: AgentContext,
        window_days: int,
        severity: Optional[RuleSeverity],
        max_missing_metadata_ratio: float,
        max_missing_component_ratio: float,
        min_total_events: int,
        limit_alerts: int,
    ) -> ToolResult:
        del context  # unused for read-only evaluation

        async with async_session_factory() as session:
            rules = list(default_rules())
            if severity is not None:
                severity_order = list(RuleSeverity)
                min_index = severity_order.index(severity)
                allowed = set(severity_order[min_index:])
                rules = [rule for rule in rules if rule.severity in allowed]

            alerts, snapshot = await collect_telemetry_alerts(
                window_days=window_days,
                rules=tuple(rules),
                cooldown_store=None,
                db_session=session,
            )

        issues = evaluate_health_thresholds(
            snapshot,
            max_missing_metadata_ratio=max_missing_metadata_ratio,
            max_missing_component_ratio=max_missing_component_ratio,
            min_total_events=min_total_events,
        )

        if limit_alerts:
            alerts = alerts[:limit_alerts]

        serialized = [self._serialize_alert(alert) for alert in alerts]

        output = TelemetryAutomationOutput(
            snapshot=snapshot.to_dict(),
            issues=issues,
            alerts=serialized,
        )
        return ToolResult(success=True, data=output.model_dump())

    @staticmethod
    def _serialize_alert(alert: AlertResult) -> TelemetryAutomationAlert:
        return TelemetryAutomationAlert(
            rule_id=alert.rule.rule_id,
            severity=alert.severity,
            message=alert.message,
            metric=alert.rule.metric,
            metric_value=alert.metric_value,
            triggered_at=alert.triggered_at,
            channels=list(alert.channels),
            metadata=dict(alert.metadata),
        )
