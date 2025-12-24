"""
Control test execution and result management for compliance automation.

Bridges the gap between technical security rules and compliance framework controls.
"""

import asyncio
import logging
import os

logger = logging.getLogger(__name__)
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any
from uuid import uuid4

# Use TYPE_CHECKING to avoid runtime dependencies
if TYPE_CHECKING:
    from ..query.engine import QueryEngine
    from ..rules.engine import RuleEngine

from .evidence_service import EvidenceService
from .frameworks import ComplianceControl
from .storage import FileBasedEvidenceRepository

# Define EvidenceItem locally for backward compatibility


@dataclass
class EvidenceItem:
    """Legacy evidence item - use ComplianceEvidenceMetadata for new code."""

    control_id: str
    evidence_type: str
    data: dict[str, Any]
    collected_at: datetime
    query_used: str


class TestStatus(Enum):
    """Status of a control test execution."""

    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    PENDING = "pending"
    SKIP = "skip"


class ControlFrequency(Enum):
    """How often controls should be tested."""

    CONTINUOUS = "continuous"  # Real-time/streaming
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    ANNUALLY = "annually"


@dataclass
class ControlTest:
    """Definition of how to test a compliance control."""

    id: str
    control_id: str
    framework_name: str
    name: str
    description: str

    # Test execution
    rule_ids: list[str] = field(default_factory=list)  # CEL rules to evaluate
    sql_queries: list[str] = field(default_factory=list)  # SQL queries for evidence
    assertion: str | None = None  # CEL expression for pass/fail logic

    # Configuration
    frequency: ControlFrequency = ControlFrequency.QUARTERLY
    owner: str | None = None
    enabled: bool = True

    # Pass/fail thresholds
    pass_threshold: float = 1.0  # 1.0 = 100% pass required
    sample_size: int | None = None  # For controls requiring sampling

    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


@dataclass
class ControlTestResult:
    """Result of a control test execution."""

    id: str
    test_id: str
    control_id: str
    framework_name: str

    # Execution details
    status: TestStatus
    started_at: datetime
    finished_at: datetime
    period_start: datetime  # Audit period start
    period_end: datetime  # Audit period end

    # Results
    pass_count: int = 0
    fail_count: int = 0
    error_count: int = 0
    total_count: int = 0
    pass_rate: float = 0.0

    # Evidence and context
    evidence_items: list[str] = field(default_factory=list)  # Evidence item IDs
    rule_results: dict[str, Any] = field(default_factory=dict)
    error_messages: list[str] = field(default_factory=list)

    # Audit trail
    executor: str | None = None  # Who/what executed the test
    execution_context: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_seconds(self) -> float:
        """Test execution duration in seconds."""
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def passed(self) -> bool:
        """Whether the test passed overall."""
        return self.status == TestStatus.PASS


@dataclass
class ControlCoverage:
    """Coverage metrics for a compliance framework."""

    framework_name: str
    total_controls: int
    automated_controls: int
    manual_controls: int
    tested_controls: int
    passing_controls: int
    failing_controls: int
    error_controls: int
    coverage_percentage: float
    pass_percentage: float
    last_updated: datetime


class ControlTestRunner:
    """Executes control tests and produces compliance evidence."""

    def __init__(
        self, rule_engine: "RuleEngine", query_engine: "QueryEngine", db_session=None
    ):
        self.rule_engine = rule_engine
        self.query_engine = query_engine
        evidence_path = os.getenv("CEREBRO_EVIDENCE_PATH", "/tmp/cerebro_evidence")
        self.evidence_repository = FileBasedEvidenceRepository(evidence_path)
        self.evidence_service = EvidenceService(
            self.evidence_repository, query_engine=query_engine
        )

    async def run_control_test(
        self,
        test: ControlTest | None = None,
        period_start: datetime | None = None,
        period_end: datetime | None = None,
        *,
        org_id: Any | None = None,
        framework_id: str | None = None,
        control_id: str | None = None,
        collect_evidence: bool = True,
    ) -> ControlTestResult:
        """Execute a single control test."""
        if period_end is None:
            period_end = datetime.now()

        if test is None:
            if not framework_id or not control_id:
                raise ValueError(
                    "Either 'test' or ('framework_id' and 'control_id') must be provided"
                )

            from cerebro.compliance.framework_registry import get_framework_registry

            registry = get_framework_registry()
            evidence_queries = registry.get_evidence_queries(framework_id, control_id)
            test = ControlTest(
                id=f"{framework_id}:{control_id}",
                control_id=control_id,
                framework_name=framework_id,
                name=f"{framework_id} {control_id}",
                description="",
                sql_queries=evidence_queries,
                enabled=True,
            )

        if period_start is None:
            period_start = self._get_default_period_start(test.frequency, period_end)

        result = ControlTestResult(
            id=str(uuid4()),
            test_id=test.id,
            control_id=test.control_id,
            framework_name=test.framework_name,
            status=TestStatus.PENDING,
            started_at=datetime.now(),
            finished_at=datetime.now(),  # Will be updated
            period_start=period_start,
            period_end=period_end,
            executor="system",
        )

        try:
            evidence_ids: list[str] = []
            if collect_evidence and test.sql_queries:
                evidence_ids = await self.evidence_service.collect_compliance_evidence(
                    control_id=test.control_id,
                    framework_name=test.framework_name,
                    queries=test.sql_queries,
                    collector_id=result.executor or "system",
                    test_run_id=result.id,
                )

            result.evidence_items = evidence_ids

            # Determine pass/fail based on evidence metadata
            for evidence_id in evidence_ids:
                metadata = await self.evidence_repository.get_metadata(evidence_id)
                if not metadata:
                    result.error_count += 1
                    continue

                tags = getattr(metadata, "tags", {}) or {}
                if tags.get("collection_error") == "true":
                    result.error_count += 1
                    continue

                control_status = getattr(metadata, "control_status", None)
                if control_status == "compliant":
                    result.pass_count += 1
                elif control_status == "non_compliant":
                    result.fail_count += 1
                else:
                    result.error_count += 1

            result.total_count = len(evidence_ids)
            result.pass_rate = result.pass_count / max(result.total_count, 1)

            # Execute CEL rules if specified
            rule_results = {}
            if test.rule_ids:
                for rule_id in test.rule_ids:
                    try:
                        # Mock rule execution - in real implementation would use RuleEngine
                        rule_result = await self._execute_rule(
                            rule_id, period_start, period_end
                        )
                        rule_results[rule_id] = rule_result
                    except Exception as e:
                        rule_results[rule_id] = {"error": str(e)}
                        result.error_messages.append(f"Rule {rule_id}: {e!s}")

            result.rule_results = rule_results

            rules_pass = all(
                r.get("status") == "pass"
                for r in rule_results.values()
                if isinstance(r, dict) and "status" in r
            )

            if result.total_count == 0:
                result.status = TestStatus.SKIP
            elif result.error_count > 0 or result.error_messages:
                result.status = TestStatus.ERROR
            elif (
                result.fail_count > 0
                or not rules_pass
                or result.pass_rate < test.pass_threshold
            ):
                result.status = TestStatus.FAIL
            else:
                result.status = TestStatus.PASS

        except Exception as e:
            result.status = TestStatus.ERROR
            result.error_messages.append(str(e))

        result.finished_at = datetime.now()
        return result

    async def run_framework_tests(
        self,
        framework_name: str,
        tests: list[ControlTest],
        period_start: datetime | None = None,
        period_end: datetime | None = None,
    ) -> list[ControlTestResult]:
        """Execute all tests for a compliance framework."""
        # Run tests in parallel for efficiency
        tasks = [
            self.run_control_test(test, period_start, period_end)
            for test in tests
            if test.enabled
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle any exceptions
        valid_results: list[ControlTestResult] = []
        for i, result in enumerate(results):
            if isinstance(result, BaseException):
                # Create error result for failed test
                test = tests[i]
                error_result = ControlTestResult(
                    id=str(uuid4()),
                    test_id=test.id,
                    control_id=test.control_id,
                    framework_name=framework_name,
                    status=TestStatus.ERROR,
                    started_at=datetime.now(),
                    finished_at=datetime.now(),
                    period_start=period_start or datetime.now() - timedelta(days=30),
                    period_end=period_end or datetime.now(),
                    error_messages=[str(result)],
                )
                valid_results.append(error_result)
            else:
                valid_results.append(result)

        return valid_results

    async def calculate_coverage(
        self,
        framework_name: str,
        all_controls: list[ComplianceControl],
        test_results: list[ControlTestResult],
    ) -> ControlCoverage:
        """Calculate compliance coverage metrics."""
        total_controls = len(all_controls)
        automated_controls = len(
            [c for c in all_controls if c.automation_level == "automated"]
        )
        manual_controls = total_controls - automated_controls

        # Map results by control ID
        results_by_control = {r.control_id: r for r in test_results}

        tested_controls = len(results_by_control)
        passing_controls = len([r for r in test_results if r.status == TestStatus.PASS])
        failing_controls = len([r for r in test_results if r.status == TestStatus.FAIL])
        error_controls = len([r for r in test_results if r.status == TestStatus.ERROR])

        coverage_percentage = (tested_controls / max(total_controls, 1)) * 100
        pass_percentage = (
            (passing_controls / max(tested_controls, 1)) * 100
            if tested_controls > 0
            else 0
        )

        return ControlCoverage(
            framework_name=framework_name,
            total_controls=total_controls,
            automated_controls=automated_controls,
            manual_controls=manual_controls,
            tested_controls=tested_controls,
            passing_controls=passing_controls,
            failing_controls=failing_controls,
            error_controls=error_controls,
            coverage_percentage=coverage_percentage,
            pass_percentage=pass_percentage,
            last_updated=datetime.now(),
        )

    def _get_default_period_start(
        self, frequency: ControlFrequency, end_date: datetime
    ) -> datetime:
        """Get default period start based on test frequency."""
        if frequency == ControlFrequency.CONTINUOUS:
            return end_date - timedelta(hours=1)
        elif frequency == ControlFrequency.DAILY:
            return end_date - timedelta(days=1)
        elif frequency == ControlFrequency.WEEKLY:
            return end_date - timedelta(weeks=1)
        elif frequency == ControlFrequency.MONTHLY:
            return end_date - timedelta(days=30)
        elif frequency == ControlFrequency.QUARTERLY:
            return end_date - timedelta(days=90)
        elif frequency == ControlFrequency.ANNUALLY:
            return end_date - timedelta(days=365)
        else:
            return end_date - timedelta(days=30)

    async def _execute_rule(
        self, rule_id: str, period_start: datetime, period_end: datetime
    ) -> dict[str, Any]:
        """Execute a CEL rule and return results."""
        try:
            from uuid import NAMESPACE_URL, UUID, uuid5

            from ..rules.engine import EvaluationContext

            # Get rule from database or rule store
            # For now, using a placeholder - in production this would fetch from rule store
            rule_expression = "resource.findings_count == 0"  # Default rule

            # Create evaluation context
            context = EvaluationContext(
                resource={
                    "period_start": period_start.isoformat(),
                    "period_end": period_end.isoformat(),
                    "findings_count": 0,  # Would be queried from actual findings
                }
            )

            # Execute rule using real CEL engine
            rule_result = self.rule_engine.evaluate_rule(
                rule_id=(
                    UUID(rule_id)
                    if len(rule_id) == 36
                    else uuid5(NAMESPACE_URL, rule_id)
                ),
                expression=rule_expression,
                context=context,
            )

            return {
                "rule_id": rule_id,
                "status": "pass" if rule_result.matched else "fail",
                "findings_count": 0,  # Would be actual findings count
                "period_start": period_start.isoformat(),
                "period_end": period_end.isoformat(),
                "error": rule_result.error,
                "execution_time_ms": rule_result.execution_time_ms,
            }

        except Exception as e:
            return {
                "rule_id": rule_id,
                "status": "error",
                "findings_count": 0,
                "period_start": period_start.isoformat(),
                "period_end": period_end.isoformat(),
                "error": str(e),
            }

    async def _evaluate_assertion(
        self,
        assertion: str,
        evidence_items: list[EvidenceItem],
        rule_results: dict[str, Any],
    ) -> bool:
        """Evaluate CEL assertion to determine pass/fail."""
        try:
            from uuid import NAMESPACE_URL, uuid5

            from ..rules.engine import EvaluationContext

            # Prepare evidence data for CEL evaluation
            evidence_data = [
                {
                    "control_id": item.control_id,
                    "evidence_type": item.evidence_type,
                    "data": item.data,
                    "collected_at": item.collected_at.isoformat(),
                    "query_used": item.query_used,
                }
                for item in evidence_items
            ]

            # Create evaluation context
            context = EvaluationContext(
                config={
                    "evidence_items": evidence_data,
                    "evidence_count": len(evidence_items),
                    "error_count": len(
                        [e for e in evidence_items if e.evidence_type == "query_error"]
                    ),
                    "valid_evidence_count": len(
                        [e for e in evidence_items if e.evidence_type != "query_error"]
                    ),
                },
                resource=rule_results,
            )

            # Execute CEL assertion
            rule_result = self.rule_engine.evaluate_rule(
                rule_id=uuid5(NAMESPACE_URL, assertion),
                expression=assertion,
                context=context,
            )

            return rule_result.matched and rule_result.error is None

        except Exception as e:
            logger.error(f"Failed to evaluate assertion '{assertion}': {e}")
            # Fallback to basic logic if CEL evaluation fails
            return (
                len([e for e in evidence_items if e.evidence_type != "query_error"]) > 0
            )

    def _default_pass_logic(
        self, evidence_items: list[EvidenceItem], rule_results: dict[str, Any]
    ) -> bool:
        """Default pass/fail logic when no assertion is specified."""
        # Pass if we have evidence and no query errors
        has_evidence = (
            len([e for e in evidence_items if e.evidence_type != "query_error"]) > 0
        )
        rules_pass = all(
            r.get("status") == "pass" for r in rule_results.values() if "status" in r
        )
        return has_evidence and (not rule_results or rules_pass)


class ControlTestScheduler:
    """Schedules and manages periodic execution of control tests."""

    def __init__(self, test_runner: ControlTestRunner):
        self.test_runner = test_runner
        self.scheduled_tests: dict[str, ControlTest] = {}
        self.running = False

    def schedule_test(self, test: ControlTest):
        """Add a test to the scheduler."""
        self.scheduled_tests[test.id] = test

    async def run_scheduler(self):
        """Main scheduler loop."""
        self.running = True
        while self.running:
            try:
                await self._execute_due_tests()
                await asyncio.sleep(300)  # Check every 5 minutes
            except Exception as e:
                print(f"Scheduler error: {e}")
                await asyncio.sleep(60)  # Wait and retry

    async def _execute_due_tests(self):
        """Execute tests that are due to run."""
        now = datetime.now()
        due_tests = []

        for test in self.scheduled_tests.values():
            if not test.enabled:
                continue

            # Simple logic - in production would track last execution time
            if self._is_test_due(test, now):
                due_tests.append(test)

        if due_tests:
            print(f"Executing {len(due_tests)} due tests...")
            results = await asyncio.gather(
                *[self.test_runner.run_control_test(test) for test in due_tests],
                return_exceptions=True,
            )

            # Process results (store, alert, etc.)
            for result in results:
                if isinstance(result, ControlTestResult):
                    await self._process_test_result(result)

    def _is_test_due(self, test: ControlTest, current_time: datetime) -> bool:
        """Check if a test is due to run."""
        # Simplified logic - would check last execution time in real implementation
        return True

    async def _process_test_result(self, result: ControlTestResult):
        """Process a completed test result."""
        # Store result, send alerts if failing, update dashboards
        print(
            f"Test {result.test_id} for control {result.control_id}: {result.status.value}"
        )

        if result.status == TestStatus.FAIL:
            print(f"ALERT: Control {result.control_id} is failing!")
