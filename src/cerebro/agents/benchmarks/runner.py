"""Execution logic for deterministic benchmark suites."""

from __future__ import annotations

from statistics import mean
from typing import Dict, Iterable, List

import structlog

from .models import (
    BenchmarkAssertion,
    BenchmarkCase,
    BenchmarkCaseResult,
    BenchmarkMetrics,
    BenchmarkSuiteResult,
)

logger = structlog.get_logger(__name__)


class BenchmarkRunner:
    """Replay benchmark cases and evaluate pass/fail criteria."""

    def __init__(self, cases: Iterable[BenchmarkCase]) -> None:
        self._cases = list(cases)

    def run(self) -> BenchmarkSuiteResult:
        results: List[BenchmarkCaseResult] = []
        for case in self._cases:
            result = self._run_case(case)
            results.append(result)
        return BenchmarkSuiteResult(cases=results)

    def _run_case(self, case: BenchmarkCase) -> BenchmarkCaseResult:
        logger.info(
            "benchmarks.case.start",
            case_id=case.case_id,
            title=case.title,
            playbook=case.playbook,
            disposable_org=case.disposable_org,
        )

        metrics = self._calculate_metrics(case)
        assertion_results, failures = self._evaluate_assertions(case, metrics)

        if failures:
            logger.warning(
                "benchmarks.case.failed",
                case_id=case.case_id,
                failed_assertions=failures,
            )
        else:
            logger.info("benchmarks.case.passed", case_id=case.case_id)

        return BenchmarkCaseResult(
            case=case,
            metrics=metrics,
            assertions=assertion_results,
            failures=failures,
        )

    @staticmethod
    def _calculate_metrics(case: BenchmarkCase) -> BenchmarkMetrics:
        turn_count = len(case.steps)
        tool_call_count = sum(len(step.tool_calls) for step in case.steps)
        total_duration_ms = sum(step.duration_ms or 0.0 for step in case.steps)
        outcomes = [
            step.message for step in case.steps if "OUTCOME" in step.message.upper()
        ]
        outcome = outcomes[-1] if outcomes else None
        scores = [step.score for step in case.steps if step.score is not None]
        average_score = mean(scores) if scores else None

        return BenchmarkMetrics(
            turn_count=turn_count,
            tool_call_count=tool_call_count,
            total_duration_ms=total_duration_ms,
            outcome=outcome,
            average_score=average_score,
        )

    @staticmethod
    def _evaluate_assertions(
        case: BenchmarkCase,
        metrics: BenchmarkMetrics,
    ) -> tuple[Dict[str, bool], List[str]]:
        results: Dict[str, bool] = {}
        failures: List[str] = []

        for assertion in case.assertions:
            passed = BenchmarkRunner._evaluate_single_assertion(
                assertion,
                metrics,
            )
            results[assertion.type] = passed
            if not passed:
                failures.append(assertion.type)

        return results, failures

    @staticmethod
    def _evaluate_single_assertion(
        assertion: BenchmarkAssertion,
        metrics: BenchmarkMetrics,
    ) -> bool:
        assertion_type = assertion.type
        value = assertion.value

        if assertion_type == "turn_count_max":
            limit = int(value)  # type: ignore[call-overload]
            return metrics.turn_count <= limit

        if assertion_type == "max_tool_calls":
            limit = int(value)  # type: ignore[call-overload]
            return metrics.tool_call_count <= limit

        if assertion_type == "requires_outcome":
            if metrics.outcome is None:
                return False
            expected = str(value).upper()
            return expected in metrics.outcome.upper()

        if assertion_type == "max_duration_ms":
            limit = float(value)  # type: ignore[arg-type]
            return metrics.total_duration_ms <= limit + 1e-6

        if assertion_type == "min_average_score":
            if metrics.average_score is None:
                return False
            try:
                threshold = float(value)  # type: ignore[arg-type]
            except (TypeError, ValueError):  # pragma: no cover - defensive guard
                return False
            return metrics.average_score >= threshold - 1e-6

        logger.warning("benchmarks.assertion.unknown", assertion=assertion_type)
        return False
