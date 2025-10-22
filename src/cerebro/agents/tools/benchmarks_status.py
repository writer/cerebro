"""Agent tool to surface benchmark health and regressions."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from .base import StructuredTool, AgentContext, ToolResult, ToolPermissionLevel


DEFAULT_SCORECARD_PATH = Path("benchmarks/results/scorecard.json")


class BenchmarksStatusInput(BaseModel):
    """Input for retrieving benchmark status."""

    include_details: bool = Field(
        default=False,
        description="Include failing scenario details with turn counts and rewards",
    )
    scorecard_path: Optional[str] = Field(
        default=None,
        description="Override path to benchmark scorecard JSON",
    )


class BenchmarkScenario(BaseModel):
    scenario_id: str
    passed: bool
    turn_count: Optional[int] = None
    reward: Optional[float] = None


class BenchmarksStatusOutput(BaseModel):
    """Structured benchmark summary."""

    scorecard_path: str
    total_scenarios: int
    passed: int
    failed: int
    failing_scenarios: List[BenchmarkScenario]
    summary: str


class BenchmarksStatusTool(StructuredTool):
    """Expose benchmark regression status to agents."""

    tool_name = "benchmarks_status"
    tool_description = "Summarize benchmark scorecard results and highlight regressions"
    input_model = BenchmarksStatusInput
    output_model = BenchmarksStatusOutput
    required_permission = ToolPermissionLevel.READ_ONLY

    async def _run(
        self,
        context: AgentContext,
        include_details: bool,
        scorecard_path: Optional[str] = None,
    ) -> ToolResult:
        path = Path(scorecard_path) if scorecard_path else DEFAULT_SCORECARD_PATH
        if not path.exists():
            return ToolResult(
                success=False,
                error=f"Benchmark scorecard not found at {path}"
            )

        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            return ToolResult(success=False, error=f"Invalid scorecard JSON: {exc}")

        total = len(payload)
        passing = [sid for sid, metrics in payload.items() if metrics.get("passed")]
        failing = [sid for sid in payload.keys() if sid not in passing]

        failing_details: List[BenchmarkScenario] = []
        if include_details:
            for sid in failing:
                metrics: Dict[str, Any] = payload.get(sid, {})
                failing_details.append(
                    BenchmarkScenario(
                        scenario_id=sid,
                        passed=False,
                        turn_count=metrics.get("turn_count"),
                        reward=metrics.get("reward"),
                    )
                )

        summary = (
            f"Benchmarks: {len(passing)} passed / {len(failing)} failed."
            if total
            else "Benchmarks scorecard empty."
        )

        output = BenchmarksStatusOutput(
            scorecard_path=str(path),
            total_scenarios=total,
            passed=len(passing),
            failed=len(failing),
            failing_scenarios=failing_details,
            summary=summary,
        )

        return ToolResult(success=True, data=output.model_dump())
