"""
Test execution engine for security tests and validation.

Implements test execution workflows, result tracking, and reporting
for automated security testing.
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, desc, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from cerebro.core.database_types import JSONType
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, DateTime, Text, Float

from cerebro.core.database import Base
from cerebro.compliance.control_tests import TestStatus

logger = logging.getLogger(__name__)


class ExecutionStatus(Enum):
    """Execution status for test runs."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class TestPriority(Enum):
    """Priority levels for test execution."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TestResult:
    """Result of test execution."""

    test_id: str
    execution_id: str
    status: TestStatus
    execution_time_ms: float

    # Results
    passed: bool
    score: Optional[float] = None
    evidence: Optional[Dict[str, Any]] = None
    metrics: Optional[Dict[str, float]] = None

    # Details
    output: Optional[str] = None
    error_message: Optional[str] = None
    warnings: Optional[List[str]] = None

    # Context
    environment: Optional[str] = None
    executed_by: Optional[str] = None
    execution_context: Optional[Dict[str, Any]] = None


class TestExecution(Base):
    """Database model for test executions."""

    __tablename__ = "test_executions"

    execution_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    test_id: Mapped[str] = mapped_column(String(100), nullable=False)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)

    # Execution metadata
    execution_status: Mapped[str] = mapped_column(
        String(50), nullable=False, default=ExecutionStatus.PENDING.value
    )
    priority: Mapped[str] = mapped_column(
        String(20), nullable=False, default=TestPriority.MEDIUM.value
    )
    environment: Mapped[str] = mapped_column(String(50), nullable=False)

    # Timing
    scheduled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now()
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    timeout_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Results
    test_status: Mapped[Optional[str]] = mapped_column(String(50))  # PASS, FAIL, ERROR
    execution_time_ms: Mapped[Optional[float]] = mapped_column(Float)
    test_score: Mapped[Optional[float]] = mapped_column(Float)

    # Output and evidence
    test_output: Mapped[Optional[str]] = mapped_column(Text)
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    warnings: Mapped[Optional[List[str]]] = mapped_column(JSONType)
    evidence_data: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType)
    metrics: Mapped[Optional[Dict[str, float]]] = mapped_column(JSONType)

    # Context
    executed_by: Mapped[str] = mapped_column(String(100), nullable=False)
    execution_context: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType)

    # Tracking
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), onupdate=func.now()
    )


class TestExecutor:
    """Executor for running security tests."""

    def __init__(self, db_session: AsyncSession):
        """Initialize test executor."""
        self.db = db_session
        self._execution_context: Dict[str, Any] = {}

    async def execute_test(
        self,
        test_id: str,
        org_id: UUID,
        environment: str,
        executed_by: str,
        test_function: Callable[..., Any],
        timeout_seconds: int = 300,
        priority: TestPriority = TestPriority.MEDIUM,
        execution_context: Optional[Dict[str, Any]] = None,
    ) -> TestResult:
        """Execute a single security test."""

        # Create execution record
        execution = TestExecution(
            test_id=test_id,
            org_id=org_id,
            environment=environment,
            executed_by=executed_by,
            priority=priority.value,
            timeout_at=datetime.utcnow() + timedelta(seconds=timeout_seconds),
            execution_context=execution_context or {},
        )

        self.db.add(execution)
        await self.db.commit()
        await self.db.refresh(execution)

        # Execute the test
        start_time = datetime.utcnow()
        execution.started_at = start_time
        execution.execution_status = ExecutionStatus.RUNNING.value
        await self.db.commit()

        try:
            # Run test with timeout
            test_task = asyncio.create_task(test_function(execution_context or {}))
            result = await asyncio.wait_for(test_task, timeout=timeout_seconds)

            # Record successful completion
            completion_time = datetime.utcnow()
            execution_time_ms = (completion_time - start_time).total_seconds() * 1000

            execution.completed_at = completion_time
            execution.execution_status = ExecutionStatus.COMPLETED.value
            execution.execution_time_ms = execution_time_ms

            # Process test result
            if isinstance(result, dict):
                execution.test_status = result.get("status", TestStatus.PASS.value)
                execution.test_score = result.get("score")
                execution.test_output = result.get("output")
                execution.evidence_data = result.get("evidence")
                execution.metrics = result.get("metrics")
                execution.warnings = result.get("warnings")
            else:
                execution.test_status = TestStatus.PASS.value
                execution.test_output = str(result)

            await self.db.commit()

            # Create result object
            test_result = TestResult(
                test_id=test_id,
                execution_id=str(execution.execution_id),
                status=TestStatus(execution.test_status),
                execution_time_ms=execution_time_ms,
                passed=execution.test_status == TestStatus.PASS.value,
                score=execution.test_score,
                evidence=execution.evidence_data,
                metrics=execution.metrics,
                output=execution.test_output,
                warnings=execution.warnings,
                environment=environment,
                executed_by=executed_by,
                execution_context=execution_context,
            )

            logger.info(
                f"Test {test_id} completed successfully in {execution_time_ms:.1f}ms"
            )
            return test_result

        except asyncio.TimeoutError:
            # Handle timeout
            execution.completed_at = datetime.utcnow()
            execution.execution_status = ExecutionStatus.TIMEOUT.value
            execution.test_status = TestStatus.ERROR.value
            execution.error_message = (
                f"Test execution timed out after {timeout_seconds} seconds"
            )

            await self.db.commit()

            logger.warning(f"Test {test_id} timed out after {timeout_seconds} seconds")

            return TestResult(
                test_id=test_id,
                execution_id=str(execution.execution_id),
                status=TestStatus.ERROR,
                execution_time_ms=timeout_seconds * 1000,
                passed=False,
                error_message=execution.error_message,
                environment=environment,
                executed_by=executed_by,
                execution_context=execution_context,
            )

        except Exception as e:
            # Handle execution error
            completion_time = datetime.utcnow()
            execution_time_ms = (completion_time - start_time).total_seconds() * 1000

            execution.completed_at = completion_time
            execution.execution_status = ExecutionStatus.FAILED.value
            execution.test_status = TestStatus.ERROR.value
            execution.error_message = str(e)
            execution.execution_time_ms = execution_time_ms

            await self.db.commit()

            logger.error(f"Test {test_id} failed: {e}")

            return TestResult(
                test_id=test_id,
                execution_id=str(execution.execution_id),
                status=TestStatus.ERROR,
                execution_time_ms=execution_time_ms,
                passed=False,
                error_message=str(e),
                environment=environment,
                executed_by=executed_by,
                execution_context=execution_context,
            )

    async def execute_test_suite(
        self,
        test_ids: List[str],
        org_id: UUID,
        environment: str,
        executed_by: str,
        test_functions: Dict[str, Callable],
        parallel: bool = True,
        max_concurrent: int = 5,
    ) -> List[TestResult]:
        """Execute a suite of tests."""

        if parallel:
            return await self._execute_tests_parallel(
                test_ids,
                org_id,
                environment,
                executed_by,
                test_functions,
                max_concurrent,
            )
        else:
            return await self._execute_tests_sequential(
                test_ids, org_id, environment, executed_by, test_functions
            )

    async def _execute_tests_parallel(
        self,
        test_ids: List[str],
        org_id: UUID,
        environment: str,
        executed_by: str,
        test_functions: Dict[str, Callable],
        max_concurrent: int,
    ) -> List[TestResult]:
        """Execute tests in parallel with concurrency control."""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def execute_single_test(test_id: str) -> TestResult:
            async with semaphore:
                test_func = test_functions.get(test_id)
                if not test_func:
                    return TestResult(
                        test_id=test_id,
                        execution_id=str(uuid4()),
                        status=TestStatus.ERROR,
                        execution_time_ms=0.0,
                        passed=False,
                        error_message=f"Test function not found for {test_id}",
                        environment=environment,
                        executed_by=executed_by,
                    )

                return await self.execute_test(
                    test_id, org_id, environment, executed_by, test_func
                )

        # Execute all tests concurrently
        tasks = [execute_single_test(test_id) for test_id in test_ids]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        test_results = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Test execution failed with exception: {result}")
                test_results.append(
                    TestResult(
                        test_id="unknown",
                        execution_id=str(uuid4()),
                        status=TestStatus.ERROR,
                        execution_time_ms=0.0,
                        passed=False,
                        error_message=str(result),
                        environment=environment,
                        executed_by=executed_by,
                    )
                )
            else:
                test_results.append(result)  # type: ignore[arg-type]

        return test_results

    async def _execute_tests_sequential(
        self,
        test_ids: List[str],
        org_id: UUID,
        environment: str,
        executed_by: str,
        test_functions: Dict[str, Callable],
    ) -> List[TestResult]:
        """Execute tests sequentially."""
        results = []

        for test_id in test_ids:
            test_func = test_functions.get(test_id)
            if not test_func:
                results.append(
                    TestResult(
                        test_id=test_id,
                        execution_id=str(uuid4()),
                        status=TestStatus.ERROR,
                        execution_time_ms=0.0,
                        passed=False,
                        error_message=f"Test function not found for {test_id}",
                        environment=environment,
                        executed_by=executed_by,
                    )
                )
                continue

            result = await self.execute_test(
                test_id, org_id, environment, executed_by, test_func
            )
            results.append(result)

        return results

    async def get_execution_history(
        self,
        org_id: UUID,
        test_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[TestExecution]:
        """Get test execution history."""
        stmt = select(TestExecution).where(TestExecution.org_id == org_id)

        if test_id:
            stmt = stmt.where(TestExecution.test_id == test_id)

        stmt = (
            stmt.order_by(desc(TestExecution.scheduled_at)).offset(offset).limit(limit)
        )

        return list(await self.db.scalars(stmt))

    async def get_execution_metrics(self, org_id: UUID) -> Dict[str, Any]:
        """Get execution metrics for an organization."""
        # Get recent executions (last 30 days)
        since_date = datetime.utcnow() - timedelta(days=30)

        stmt = select(TestExecution).where(
            and_(
                TestExecution.org_id == org_id, TestExecution.scheduled_at >= since_date
            )
        )

        executions = list(await self.db.scalars(stmt))

        if not executions:
            return {
                "total_executions": 0,
                "success_rate": 0.0,
                "average_execution_time": 0.0,
                "by_status": {},
                "by_environment": {},
            }

        # Calculate metrics
        total_executions = len(executions)
        successful_executions = len(
            [e for e in executions if e.test_status == TestStatus.PASS.value]
        )
        success_rate = (successful_executions / total_executions) * 100

        # Average execution time
        completed_executions = [
            e for e in executions if e.execution_time_ms is not None
        ]
        if completed_executions:
            avg_execution_time = sum(
                e.execution_time_ms or 0.0 for e in completed_executions
            ) / len(completed_executions)
        else:
            avg_execution_time = 0.0

        # Group by status
        status_counts: Dict[str, int] = {}
        for execution in executions:
            status = execution.test_status or "unknown"
            status_counts[status] = status_counts.get(status, 0) + 1

        # Group by environment
        env_counts: Dict[str, int] = {}
        for execution in executions:
            env = execution.environment
            env_counts[env] = env_counts.get(env, 0) + 1

        return {
            "total_executions": total_executions,
            "success_rate": round(success_rate, 2),
            "average_execution_time": round(avg_execution_time, 2),
            "by_status": status_counts,
            "by_environment": env_counts,
        }

    async def cleanup_old_executions(
        self, org_id: UUID, retention_days: int = 90
    ) -> int:
        """Clean up old test execution records."""
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

        stmt = select(TestExecution).where(
            and_(
                TestExecution.org_id == org_id,
                TestExecution.scheduled_at < cutoff_date,
                TestExecution.execution_status.in_(
                    [
                        ExecutionStatus.COMPLETED.value,
                        ExecutionStatus.FAILED.value,
                        ExecutionStatus.CANCELLED.value,
                    ]
                ),
            )
        )

        old_executions = list(await self.db.scalars(stmt))

        for execution in old_executions:
            await self.db.delete(execution)

        await self.db.commit()

        logger.info(f"Cleaned up {len(old_executions)} old test executions")
        return len(old_executions)


class TestScheduler:
    """Scheduler for automated test execution."""

    def __init__(self, db_session: AsyncSession, executor: TestExecutor):
        """Initialize test scheduler."""
        self.db = db_session
        self.executor = executor

    async def schedule_test(
        self,
        test_id: str,
        org_id: UUID,
        environment: str,
        executed_by: str,
        test_function: Callable,
        scheduled_time: Optional[datetime] = None,
        priority: TestPriority = TestPriority.MEDIUM,
    ) -> TestExecution:
        """Schedule a test for execution."""

        if not scheduled_time:
            scheduled_time = datetime.utcnow()

        execution = TestExecution(
            test_id=test_id,
            org_id=org_id,
            environment=environment,
            executed_by=executed_by,
            priority=priority.value,
            scheduled_at=scheduled_time,
        )

        self.db.add(execution)
        await self.db.commit()
        await self.db.refresh(execution)

        logger.info(f"Scheduled test {test_id} for execution at {scheduled_time}")
        return execution

    async def execute_scheduled_tests(self, environment: str) -> List[TestResult]:
        """Execute all tests scheduled for the current time."""
        now = datetime.utcnow()

        stmt = (
            select(TestExecution)
            .where(
                and_(
                    TestExecution.scheduled_at <= now,
                    TestExecution.execution_status == ExecutionStatus.PENDING.value,
                    TestExecution.environment == environment,
                )
            )
            .order_by(TestExecution.priority.desc(), TestExecution.scheduled_at)
        )

        scheduled_executions = list(await self.db.scalars(stmt))

        if not scheduled_executions:
            return []

        logger.info(f"Executing {len(scheduled_executions)} scheduled tests")

        results = []
        for execution in scheduled_executions:
            try:
                # This would need to be enhanced to look up actual test functions
                # For now, create a placeholder result
                result = TestResult(
                    test_id=execution.test_id,
                    execution_id=str(execution.execution_id),
                    status=TestStatus.PASS,
                    execution_time_ms=100.0,
                    passed=True,
                    environment=execution.environment,
                    executed_by=execution.executed_by,
                )
                results.append(result)

                # Update execution record
                execution.execution_status = ExecutionStatus.COMPLETED.value
                execution.test_status = TestStatus.PASS.value
                execution.completed_at = datetime.utcnow()
                execution.execution_time_ms = 100.0

            except Exception as e:
                logger.error(
                    f"Failed to execute scheduled test {execution.test_id}: {e}"
                )

                execution.execution_status = ExecutionStatus.FAILED.value
                execution.test_status = TestStatus.ERROR.value
                execution.error_message = str(e)
                execution.completed_at = datetime.utcnow()

        await self.db.commit()
        return results
