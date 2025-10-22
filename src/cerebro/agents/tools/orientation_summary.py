"""Agent tool exposing orientation analytics."""

from __future__ import annotations

"""Agent tool exposing orientation analytics."""

from typing import Any, Dict, List

from pydantic import BaseModel, Field

from cerebro.analytics.orientation import generate_orientation_summary

from .base import StructuredTool, AgentContext, ToolResult, ToolPermissionLevel


class OrientationSummaryInput(BaseModel):
    """Inputs accepted by :class:`OrientationSummaryTool`."""

    window_hours: int = Field(
        default=24,
        gt=0,
        description="Observation window length in hours",
    )
    baseline_hours: int = Field(
        default=168,
        gt=0,
        description="Baseline window length in hours prior to the observation window",
    )


class OrientationEventRow(BaseModel):
    """Single trending row returned to the agent."""

    key: str
    current_count: int
    baseline_count: int
    percent_change: float


class OrientationSummaryOutput(BaseModel):
    """Structured orientation summary payload."""

    generated_at: str
    window: Dict[str, Any]
    baseline: Dict[str, Any]
    total_events_current: int
    total_events_baseline: int
    top_event_types: List[OrientationEventRow]
    top_components: List[OrientationEventRow]


class OrientationSummaryTool(StructuredTool):
    """Summarize trending telemetry signals for analyst orientation."""

    tool_name = "orientation_summary"
    tool_description = (
        "Highlight trending event types and components from frontend telemetry "
        "by comparing an observation window to a baseline."
    )
    input_model = OrientationSummaryInput
    output_model = OrientationSummaryOutput
    required_permission = ToolPermissionLevel.READ_ONLY

    async def _run(
        self,
        context: AgentContext,
        window_hours: int,
        baseline_hours: int,
    ) -> ToolResult:
        summary = await generate_orientation_summary(window_hours, baseline_hours)

        # Convert raw dictionaries into the strongly typed output model
        transformed = {
            **summary,
            "top_event_types": [OrientationEventRow(**row) for row in summary["top_event_types"]],
            "top_components": [OrientationEventRow(**row) for row in summary["top_components"]],
        }
        validated = self.output_model(**transformed)
        return ToolResult(success=True, data=validated.model_dump())
