"""Tests for benchmark models."""

import pytest

from cerebro.agents.benchmarks.models import (
    BenchmarkAssertion,
    BenchmarkCase,
    BenchmarkCaseResult,
    BenchmarkMetrics,
    BenchmarkStep,
    BenchmarkSuiteResult,
)


class TestBenchmarkAssertion:
    """Test BenchmarkAssertion model."""

    def test_create_assertion(self):
        """Test creating an assertion."""
        assertion = BenchmarkAssertion(type="contains", value="expected text")
        assert assertion.type == "contains"
        assert assertion.value == "expected text"

    def test_assertion_with_numeric_value(self):
        """Test assertion with numeric threshold."""
        assertion = BenchmarkAssertion(type="min_score", value=0.8)
        assert assertion.type == "min_score"
        assert assertion.value == 0.8


class TestBenchmarkStep:
    """Test BenchmarkStep model."""

    def test_create_step_minimal(self):
        """Test creating a step with minimal fields."""
        step = BenchmarkStep(speaker="user", message="Hello")
        assert step.speaker == "user"
        assert step.message == "Hello"
        assert step.tool_calls == []
        assert step.duration_ms is None
        assert step.score is None

    def test_create_step_full(self):
        """Test creating a step with all fields."""
        step = BenchmarkStep(
            speaker="assistant",
            message="Response",
            tool_calls=["tool1", "tool2"],
            duration_ms=150.5,
            score=0.95,
        )
        assert step.speaker == "assistant"
        assert step.message == "Response"
        assert step.tool_calls == ["tool1", "tool2"]
        assert step.duration_ms == 150.5
        assert step.score == 0.95


class TestBenchmarkCase:
    """Test BenchmarkCase model."""

    def test_create_case_minimal(self):
        """Test creating a case with required fields only."""
        case = BenchmarkCase(
            case_id="test-001",
            title="Test Case",
            playbook="test_playbook",
            disposable_org="sandbox-org",
        )
        assert case.case_id == "test-001"
        assert case.title == "Test Case"
        assert case.playbook == "test_playbook"
        assert case.disposable_org == "sandbox-org"
        assert case.incident is None
        assert case.steps == []
        assert case.assertions == []

    def test_create_case_with_steps(self):
        """Test creating a case with steps."""
        steps = [
            BenchmarkStep(speaker="user", message="Start"),
            BenchmarkStep(speaker="assistant", message="OK"),
        ]
        case = BenchmarkCase(
            case_id="test-002",
            title="Test with Steps",
            playbook="playbook",
            disposable_org="org",
            steps=steps,
        )
        assert len(case.steps) == 2
        assert case.steps[0].speaker == "user"

    def test_create_case_with_assertions(self):
        """Test creating a case with assertions."""
        assertions = [
            BenchmarkAssertion(type="contains", value="expected"),
            BenchmarkAssertion(type="min_score", value=0.7),
        ]
        case = BenchmarkCase(
            case_id="test-003",
            title="Test with Assertions",
            playbook="playbook",
            disposable_org="org",
            assertions=assertions,
        )
        assert len(case.assertions) == 2


class TestBenchmarkMetrics:
    """Test BenchmarkMetrics dataclass."""

    def test_create_metrics(self):
        """Test creating metrics."""
        metrics = BenchmarkMetrics(
            turn_count=5,
            tool_call_count=3,
            total_duration_ms=1500.0,
            outcome="success",
            average_score=0.85,
        )
        assert metrics.turn_count == 5
        assert metrics.tool_call_count == 3
        assert metrics.total_duration_ms == 1500.0
        assert metrics.outcome == "success"
        assert metrics.average_score == 0.85

    def test_create_metrics_with_none(self):
        """Test creating metrics with None values."""
        metrics = BenchmarkMetrics(
            turn_count=0,
            tool_call_count=0,
            total_duration_ms=0.0,
            outcome=None,
            average_score=None,
        )
        assert metrics.outcome is None
        assert metrics.average_score is None


class TestBenchmarkCaseResult:
    """Test BenchmarkCaseResult dataclass."""

    @pytest.fixture
    def sample_case(self):
        """Create a sample benchmark case."""
        return BenchmarkCase(
            case_id="test-001",
            title="Sample Case",
            playbook="playbook",
            disposable_org="org",
        )

    @pytest.fixture
    def sample_metrics(self):
        """Create sample metrics."""
        return BenchmarkMetrics(
            turn_count=3,
            tool_call_count=2,
            total_duration_ms=500.0,
            outcome="success",
            average_score=0.9,
        )

    def test_passed_no_failures(self, sample_case, sample_metrics):
        """Test passed property when no failures."""
        result = BenchmarkCaseResult(
            case=sample_case,
            metrics=sample_metrics,
            assertions={"check1": True, "check2": True},
            failures=[],
        )
        assert result.passed is True

    def test_passed_with_failures(self, sample_case, sample_metrics):
        """Test passed property when there are failures."""
        result = BenchmarkCaseResult(
            case=sample_case,
            metrics=sample_metrics,
            assertions={"check1": True, "check2": False},
            failures=["check2 failed"],
        )
        assert result.passed is False


class TestBenchmarkSuiteResult:
    """Test BenchmarkSuiteResult dataclass."""

    @pytest.fixture
    def passing_result(self):
        """Create a passing case result."""
        case = BenchmarkCase(
            case_id="pass-001",
            title="Passing",
            playbook="p",
            disposable_org="o",
        )
        metrics = BenchmarkMetrics(
            turn_count=1,
            tool_call_count=1,
            total_duration_ms=100.0,
            outcome="ok",
            average_score=1.0,
        )
        return BenchmarkCaseResult(
            case=case, metrics=metrics, assertions={}, failures=[]
        )

    @pytest.fixture
    def failing_result(self):
        """Create a failing case result."""
        case = BenchmarkCase(
            case_id="fail-001",
            title="Failing",
            playbook="p",
            disposable_org="o",
        )
        metrics = BenchmarkMetrics(
            turn_count=1,
            tool_call_count=0,
            total_duration_ms=50.0,
            outcome="error",
            average_score=0.0,
        )
        return BenchmarkCaseResult(
            case=case, metrics=metrics, assertions={}, failures=["error occurred"]
        )

    def test_suite_passed_all_pass(self, passing_result):
        """Test suite passed when all cases pass."""
        suite = BenchmarkSuiteResult(cases=[passing_result, passing_result])
        assert suite.passed is True

    def test_suite_passed_one_fails(self, passing_result, failing_result):
        """Test suite fails when any case fails."""
        suite = BenchmarkSuiteResult(cases=[passing_result, failing_result])
        assert suite.passed is False

    def test_suite_passed_empty(self):
        """Test empty suite is considered passed."""
        suite = BenchmarkSuiteResult(cases=[])
        assert suite.passed is True

    def test_scorecard(self, passing_result, failing_result):
        """Test scorecard generation."""
        suite = BenchmarkSuiteResult(cases=[passing_result, failing_result])
        scorecard = suite.scorecard()

        assert "pass-001" in scorecard
        assert "fail-001" in scorecard

        assert scorecard["pass-001"]["passed"] is True
        assert scorecard["pass-001"]["turn_count"] == 1
        assert scorecard["pass-001"]["failed_assertions"] == []

        assert scorecard["fail-001"]["passed"] is False
        assert scorecard["fail-001"]["failed_assertions"] == ["error occurred"]
