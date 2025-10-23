"""Helpers for summarising benchmark scorecards and producing Slack payloads."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from statistics import mean
from typing import Any, Dict, Iterable, List, Optional


@dataclasses.dataclass(slots=True)
class BenchmarkCaseSummary:
    case_id: str
    passed: bool
    turn_count: Optional[int]
    tool_calls: Optional[int]
    total_duration_ms: Optional[float]
    failed_assertions: List[str]
    outcome: Optional[str]
    average_score: Optional[float]

    @classmethod
    def from_mapping(cls, case_id: str, payload: Dict[str, Any]) -> "BenchmarkCaseSummary":
        return cls(
            case_id=case_id,
            passed=bool(payload.get("passed", False)),
            turn_count=payload.get("turn_count"),
            tool_calls=payload.get("tool_calls"),
            total_duration_ms=payload.get("total_duration_ms"),
            failed_assertions=list(payload.get("failed_assertions", [])),
            outcome=payload.get("outcome"),
            average_score=payload.get("average_score"),
        )


@dataclasses.dataclass(slots=True)
class BenchmarkSummary:
    cases: List[BenchmarkCaseSummary]

    @property
    def total_cases(self) -> int:
        return len(self.cases)

    @property
    def passed_cases(self) -> List[BenchmarkCaseSummary]:
        return [case for case in self.cases if case.passed]

    @property
    def failed_cases(self) -> List[BenchmarkCaseSummary]:
        return [case for case in self.cases if not case.passed]

    @property
    def has_failures(self) -> bool:
        return any(not case.passed for case in self.cases)

    def average_duration_ms(self) -> Optional[float]:
        durations = [case.total_duration_ms for case in self.cases if case.total_duration_ms]
        if not durations:
            return None
        return mean(durations)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_cases": self.total_cases,
            "failed_cases": [dataclasses.asdict(case) for case in self.failed_cases],
            "passed_cases": [dataclasses.asdict(case) for case in self.passed_cases],
        }


def load_benchmark_summary(scorecard_path: Path) -> BenchmarkSummary:
    with scorecard_path.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)

    cases: List[BenchmarkCaseSummary] = [
        BenchmarkCaseSummary.from_mapping(case_id, payload)
        for case_id, payload in raw.items()
    ]

    cases.sort(key=lambda case: case.case_id)
    return BenchmarkSummary(cases=cases)


def _format_failed_case(case: BenchmarkCaseSummary) -> str:
    assertions = ", ".join(case.failed_assertions) if case.failed_assertions else "unknown"
    duration = f"{case.total_duration_ms:.0f}ms" if case.total_duration_ms else "n/a"
    return (
        f"• *{case.case_id}* — failed assertions: {assertions} | turns: {case.turn_count or 'n/a'} | "
        f"duration: {duration}"
    )


def build_slack_payload(
    summary: BenchmarkSummary,
    *,
    run_url: Optional[str] = None,
) -> Dict[str, Any]:
    status_line = (
        "All benchmark cases passed" if not summary.has_failures else f"{len(summary.failed_cases)} case(s) failing"
    )

    fallback = f"Benchmark results: {status_line}; total cases {summary.total_cases}"

    blocks: List[Dict[str, Any]] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "Benchmark Regression Summary"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Total cases:* {summary.total_cases}"},
                {"type": "mrkdwn", "text": f"*Failures:* {len(summary.failed_cases)}"},
            ],
        },
    ]

    if summary.failed_cases:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "\n".join(_format_failed_case(case) for case in summary.failed_cases[:10]),
                },
            }
        )
    else:
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": ":tada: All benchmark cases are passing."},
            }
        )

    if run_url:
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"<{run_url}|View workflow run>",
                    }
                ],
            }
        )

    return {
        "text": fallback,
        "blocks": blocks,
    }
