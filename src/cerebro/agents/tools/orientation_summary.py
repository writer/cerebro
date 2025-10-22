"""Agent tool exposing orientation analytics."""

from __future__ import annotations

from typing import Any, Dict, List

from pydantic import BaseModel, Field

from cerebro.analytics.orientation import generate_orientation_summary

from .base import StructuredTool, AgentContext, ToolResult, ToolPermissionLevel


class OrientationSummaryInput(BaseModel):
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
    key: str
    current_count: int
    baseline_count: int
    percent_change: float


class OrientationSummaryOutput(BaseModel):
    generated_at: str
    window: Dict[str, Any]
    baseline: Dict[str, Any]
    total_events_current: int
    total_events_baseline: int
    top_event_types: List[Dict[str, Any]]
    top_components: List[Dict[str, Any]]


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
        # Validate against output model for consistency
        validated = self.output_model(**summary)
        return ToolResult(success=True, data=validated.model_dump())
