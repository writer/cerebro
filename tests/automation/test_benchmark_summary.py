from __future__ import annotations

import json
from pathlib import Path

from cerebro.automation.benchmark_summary import (
    BenchmarkSummary,
    build_slack_payload,
    load_benchmark_summary,
)


def _write_scorecard(tmp_path: Path, payload: dict[str, dict[str, object]]) -> Path:
    path = tmp_path / "scorecard.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def test_load_benchmark_summary(tmp_path: Path) -> None:
    path = _write_scorecard(
        tmp_path,
        {
            "case_a": {
                "passed": True,
                "turn_count": 5,
                "tool_calls": 3,
                "total_duration_ms": 1200,
                "failed_assertions": [],
                "outcome": "SUCCESS",
                "average_score": 0.9,
            },
            "case_b": {
                "passed": False,
                "turn_count": 8,
                "tool_calls": 4,
                "total_duration_ms": 2500,
                "failed_assertions": ["requires_outcome"],
                "outcome": "FAILURE",
                "average_score": 0.3,
            },
        },
    )

    summary = load_benchmark_summary(path)

    assert isinstance(summary, BenchmarkSummary)
    assert summary.total_cases == 2
    assert summary.has_failures is True
    assert len(summary.failed_cases) == 1
    assert summary.failed_cases[0].case_id == "case_b"


def test_build_slack_payload_includes_failures(tmp_path: Path) -> None:
    path = _write_scorecard(
        tmp_path,
        {
            "case_a": {"passed": True, "failed_assertions": []},
            "case_b": {
                "passed": False,
                "failed_assertions": ["turn_count_max"],
                "total_duration_ms": 4000,
            },
        },
    )

    summary = load_benchmark_summary(path)
    payload = build_slack_payload(summary, run_url="https://example.com")

    assert payload["blocks"][0]["type"] == "header"
    assert "Failures" in payload["blocks"][1]["fields"][1]["text"]
    assert "case_b" in payload["blocks"][2]["text"]["text"]
    assert "example.com" in payload["blocks"][3]["elements"][0]["text"]
