"""Pydantic models describing benchmark case definitions and results."""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, Field


class BenchmarkAssertion(BaseModel):
    """A deterministic check that a benchmark case must satisfy."""

    type: str = Field(..., description="Identifier of the assertion to apply")
    value: object = Field(..., description="Threshold or expected value")


class BenchmarkStep(BaseModel):
    """Single replay step captured from a playbook or incident."""

    speaker: str
    message: str
    tool_calls: list[str] = Field(default_factory=list)
    duration_ms: float | None = None
    score: float | None = None


class BenchmarkCase(BaseModel):
    """User-defined scenario capturing expected deterministic behaviour."""

    case_id: str = Field(..., description="Unique ID for the benchmark case")
    title: str
    playbook: str
    disposable_org: str = Field(
        ..., description="Name of the sandbox tenant to provision"
    )
    incident: str | None = Field(
        default=None, description="Historical incident reference"
    )
    steps: list[BenchmarkStep] = Field(default_factory=list)
    assertions: list[BenchmarkAssertion] = Field(default_factory=list)


@dataclass
class BenchmarkMetrics:
    """Computed metrics for a benchmark execution."""

    turn_count: int
    tool_call_count: int
    total_duration_ms: float
    outcome: str | None
    average_score: float | None


@dataclass
class BenchmarkCaseResult:
    """Result of evaluating a single benchmark case."""

    case: BenchmarkCase
    metrics: BenchmarkMetrics
    assertions: dict[str, bool]
    failures: list[str]

    @property
    def passed(self) -> bool:
        return not self.failures


@dataclass
class BenchmarkSuiteResult:
    """Aggregate outcome of running a benchmark suite."""

    cases: list[BenchmarkCaseResult]

    @property
    def passed(self) -> bool:
        return all(case_result.passed for case_result in self.cases)

    def scorecard(self) -> dict[str, dict[str, object]]:
        """Return a serialisable summary for CI scorecards."""

        return {
            result.case.case_id: {
                "passed": result.passed,
                "turn_count": result.metrics.turn_count,
                "tool_calls": result.metrics.tool_call_count,
                "total_duration_ms": result.metrics.total_duration_ms,
                "outcome": result.metrics.outcome,
                "average_score": result.metrics.average_score,
                "failed_assertions": result.failures,
            }
            for result in self.cases
        }
