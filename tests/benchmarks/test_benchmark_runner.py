import json
from pathlib import Path

from cerebro.agents.benchmarks import BenchmarkRunner, load_benchmark_cases


def _write_case(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def test_benchmark_runner_pass(tmp_path: Path) -> None:
    _write_case(
        tmp_path / "success_case.json",
        {
            "case_id": "success_case",
            "title": "Successful Benchmark",
            "playbook": "credential_exfiltration",
            "disposable_org": "bench-success",
            "steps": [
                {
                    "speaker": "analyst",
                    "message": "kickoff",
                    "tool_calls": ["query"],
                    "duration_ms": 100,
                    "score": 0.6,
                },
                {
                    "speaker": "agent",
                    "message": "OUTCOME: SUCCESS",
                    "tool_calls": [],
                    "duration_ms": 50,
                    "score": 0.9,
                },
            ],
            "assertions": [
                {"type": "turn_count_max", "value": 5},
                {"type": "requires_outcome", "value": "SUCCESS"},
                {"type": "min_average_score", "value": 0.7},
            ],
        },
    )

    cases = load_benchmark_cases(tmp_path)
    runner = BenchmarkRunner(cases)
    result = runner.run()

    assert result.passed is True
    scorecard = result.scorecard()
    assert scorecard["success_case"]["passed"] is True
    assert scorecard["success_case"]["turn_count"] == 2
    assert scorecard["success_case"]["average_score"] == 0.75


def test_benchmark_runner_failure(tmp_path: Path) -> None:
    _write_case(
        tmp_path / "failure_case.json",
        {
            "case_id": "failure_case",
            "title": "Failing Benchmark",
            "playbook": "lateral_movement",
            "disposable_org": "bench-failure",
            "steps": [
                {
                    "speaker": "agent",
                    "message": "OUTCOME: FAILURE",
                    "tool_calls": [],
                    "duration_ms": 75,
                }
            ],
            "assertions": [{"type": "requires_outcome", "value": "SUCCESS"}],
        },
    )

    cases = load_benchmark_cases(tmp_path)
    runner = BenchmarkRunner(cases)
    result = runner.run()

    assert result.passed is False
    scorecard = result.scorecard()
    failed = scorecard["failure_case"]
    assert failed["passed"] is False
    assert failed["failed_assertions"] == ["requires_outcome"]
