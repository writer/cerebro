"""Pre-audit health check orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.agents.models import AgentReviewTask, AgentSession, AgentType
from cerebro.agents.notification_service import NotificationService
from cerebro.agents.review_service import AgentReviewService
from cerebro.agents.ticketing_service import TicketingService
from cerebro.compliance.frameworks import ComplianceControl, ComplianceFramework, get_framework
from cerebro.compliance.preaudit_models import (
    AuditScheduleStatus,
    ComplianceAuditSchedule,
    ControlHealthStatus,
    PreAuditControlFinding,
    PreAuditRun,
    PreAuditRunStatus,
)
from cerebro.core.database import async_session_factory
from cerebro.query.bootstrap import get_query_engine
from cerebro.query.engine import QueryEngine, QueryResult


logger = structlog.get_logger(__name__)


@dataclass
class ControlEvaluation:
    """In-memory representation for a control's outcome prior to persistence."""

    framework: str
    control: ComplianceControl
    status: ControlHealthStatus
    pass_rate: Optional[float]
    evidence_summary: Dict[str, Any]
    issue_summary: Optional[str]
    remediation: Optional[str]
    priority: Optional[str]
    owner: Optional[str]


class PreAuditHealthCheckService:
    """Runs compliance control evaluations ahead of scheduled audits."""

    def __init__(self, query_engine: Optional[QueryEngine] = None) -> None:
        self._query_engine = query_engine or get_query_engine()

    async def register_schedule(
        self,
        *,
        org_id: UUID,
        frameworks: Iterable[str],
        audit_date: datetime,
        owner_emails: Iterable[str],
        prep_window_weeks: int = 4,
        auto_assign_tasks: bool = True,
        create_tickets: bool = True,
    ) -> ComplianceAuditSchedule:
        """Create a new audit schedule if one does not already exist for the period."""

        normalized_frameworks = sorted({name.lower() for name in frameworks})
        normalized_owners = sorted({email.lower() for email in owner_emails if email})

        if not normalized_frameworks:
            raise ValueError("At least one framework must be provided")

        if audit_date.tzinfo is None:
            audit_date = audit_date.replace(tzinfo=timezone.utc)

        first_run_at = audit_date - timedelta(weeks=max(prep_window_weeks, 1))
        first_run_at = first_run_at.replace(tzinfo=timezone.utc)

        async with async_session_factory() as db:
            stmt = (
                select(ComplianceAuditSchedule)
                .where(ComplianceAuditSchedule.org_id == org_id)
                .where(ComplianceAuditSchedule.audit_date == audit_date)
                .limit(1)
            )
            existing = await db.scalar(stmt)
            if existing:
                return existing

            schedule = ComplianceAuditSchedule(
                org_id=org_id,
                frameworks=normalized_frameworks,
                audit_date=audit_date,
                prep_window_weeks=prep_window_weeks,
                owner_emails=normalized_owners or ["compliance@"],
                auto_assign_tasks=auto_assign_tasks,
                create_tickets=create_tickets,
                next_run_at=first_run_at,
            )
            db.add(schedule)
            await db.commit()
            await db.refresh(schedule)
            return schedule

    async def due_schedules(self, *, as_of: Optional[datetime] = None) -> List[ComplianceAuditSchedule]:
        """Return schedules that should execute a pre-audit run."""

        now = as_of or datetime.now(timezone.utc)
        async with async_session_factory() as db:
            stmt = (
                select(ComplianceAuditSchedule)
                .where(ComplianceAuditSchedule.next_run_at != None)  # noqa: E711
                .where(ComplianceAuditSchedule.next_run_at <= now)
                .where(ComplianceAuditSchedule.status != AuditScheduleStatus.CANCELLED)
            )
            result = await db.scalars(stmt)
            return list(result)

    async def run_for_schedule(self, schedule_id: UUID) -> PreAuditRun:
        """Execute a pre-audit health check for a persisted schedule."""

        async with async_session_factory() as db:
            schedule = await db.get(ComplianceAuditSchedule, schedule_id)
            if not schedule:
                raise ValueError(f"Audit schedule {schedule_id} not found")

            run = PreAuditRun(schedule=schedule)
            db.add(run)
            await db.flush()

            try:
                evaluations = await self._evaluate_frameworks(schedule)
                self._apply_results(schedule, run, evaluations)
                await self._persist_findings(db, run, evaluations)
                await db.commit()
            except Exception as exc:  # pragma: no cover - defensive logging
                logger.exception("Pre-audit health check failed", schedule_id=str(schedule_id))
                run.status = PreAuditRunStatus.ERROR
                run.error_message = str(exc)
                schedule.status = AuditScheduleStatus.ACTIVE
                schedule.next_run_at = self._compute_next_run(schedule, run.run_at)
                await db.commit()
                raise

        if schedule.auto_assign_tasks:
            await self._ensure_remediation_tasks(schedule, run)

        return run

    async def run_on_demand(
        self,
        *,
        org_id: UUID,
        frameworks: Iterable[str],
        audit_date: datetime,
        owner_emails: Iterable[str],
    ) -> PreAuditRun:
        """Convenience helper to create a schedule and immediately run it."""

        schedule = await self.register_schedule(
            org_id=org_id,
            frameworks=frameworks,
            audit_date=audit_date,
            owner_emails=owner_emails,
        )
        return await self.run_for_schedule(schedule.id)

    async def _evaluate_frameworks(self, schedule: ComplianceAuditSchedule) -> List[ControlEvaluation]:
        results: List[ControlEvaluation] = []
        for framework_name in schedule.frameworks:
            framework = get_framework(framework_name)
            if not framework:
                logger.warning("Unknown framework referenced in schedule", framework=framework_name)
                continue
            results.extend(await self._evaluate_framework(schedule, framework))
        return results

    async def _evaluate_framework(
        self,
        schedule: ComplianceAuditSchedule,
        framework: ComplianceFramework,
    ) -> List[ControlEvaluation]:
        evaluations: List[ControlEvaluation] = []
        for control in framework.controls:
            evaluation = await self._evaluate_control(schedule, framework.name, control)
            evaluations.append(evaluation)
        return evaluations

    async def _evaluate_control(
        self,
        schedule: ComplianceAuditSchedule,
        framework_name: str,
        control: ComplianceControl,
    ) -> ControlEvaluation:
        evidence_summary: Dict[str, Any] = {
            "queries": [],
        }
        issues: List[str] = []
        remediation = control.remediation_guidance or None
        owner: Optional[str] = None

        best_pass_rate: Optional[float] = None
        missing_evidence = False

        if not control.sql_queries:
            missing_evidence = True
            issues.append("No automated evidence queries configured")
        else:
            for query in control.sql_queries:
                result = await self._safe_query(query)
                evidence_summary["queries"].append({
                    "sql": query,
                    "rows": result.total_rows,
                    "errors": result.errors,
                })

                if result.errors:
                    missing_evidence = True
                    issues.extend(result.errors)
                    continue

                pass_rate = self._derive_pass_rate(result)
                best_pass_rate = pass_rate if best_pass_rate is None else min(best_pass_rate, pass_rate)

                if pass_rate < 1.0 and result.rows:
                    sample = result.rows[0]
                    issues.append(self._summarise_violation(control, sample, result.total_rows))

        status = self._determine_status(control, best_pass_rate, missing_evidence)
        priority = self._derive_priority(control, status)

        if schedule.owner_emails:
            owner = schedule.owner_emails[0]

        return ControlEvaluation(
            framework=framework_name,
            control=control,
            status=status,
            pass_rate=best_pass_rate,
            evidence_summary=evidence_summary,
            issue_summary="; ".join(issues) if issues else None,
            remediation=remediation,
            priority=priority,
            owner=owner,
        )

    async def _safe_query(self, sql: str) -> QueryResult:
        try:
            return await self._query_engine.execute_query(sql)
        except Exception as exc:  # pragma: no cover - transport failures
            logger.exception("Query execution failed during pre-audit run", sql=sql)
            return QueryResult(
                columns=[],
                rows=[],
                total_rows=0,
                execution_time_ms=0,
                tables_queried=[],
                errors=[str(exc)],
            )

    def _derive_pass_rate(self, result: QueryResult) -> float:
        if result.total_rows == 0:
            return 1.0

        metrics: List[float] = []
        for row in result.rows:
            for key in ("compliance_rate", "pass_rate", "percent_compliant", "compliance"):
                value = row.get(key)
                if isinstance(value, (int, float)):
                    metrics.append(float(value))
        if metrics:
            normalised: List[float] = []
            for value in metrics:
                if value > 1.0:
                    normalised.append(min(1.0, value / 100.0))
                elif value < 0:
                    normalised.append(0.0)
                else:
                    normalised.append(value)
            clipped = [max(0.0, min(1.0, val)) for val in normalised]
            return min(clipped)
        return 0.0

    def _summarise_violation(self, control: ComplianceControl, sample: Dict[str, Any], total_rows: int) -> str:
        hint = ", ".join(f"{k}={v}" for k, v in list(sample.items())[:3]) if sample else "see findings"
        return f"{total_rows} finding(s) detected for {control.control_id} ({hint})"

    def _determine_status(
        self,
        control: ComplianceControl,
        pass_rate: Optional[float],
        missing_evidence: bool,
    ) -> ControlHealthStatus:
        if missing_evidence:
            return ControlHealthStatus.MISSING_EVIDENCE

        threshold = getattr(control, "pass_threshold", None) or 1.0
        effective_rate = pass_rate if pass_rate is not None else 0.0

        if effective_rate >= threshold:
            return ControlHealthStatus.PASSING

        warning_band = max(threshold - 0.15, threshold * 0.8)
        if effective_rate >= warning_band:
            return ControlHealthStatus.AT_RISK

        return ControlHealthStatus.FAILING

    def _derive_priority(self, control: ComplianceControl, status: ControlHealthStatus) -> Optional[str]:
        if status == ControlHealthStatus.PASSING:
            return None
        if control.control_type.name in {"PREVENTIVE", "TECHNICAL"}:
            return "critical" if status == ControlHealthStatus.FAILING else "high"
        if control.control_type.name in {"DETECTIVE", "CORRECTIVE"}:
            return "high" if status == ControlHealthStatus.FAILING else "medium"
        return "medium"

    def _apply_results(
        self,
        schedule: ComplianceAuditSchedule,
        run: PreAuditRun,
        evaluations: List[ControlEvaluation],
    ) -> None:
        passing = sum(1 for e in evaluations if e.status == ControlHealthStatus.PASSING)
        failing = sum(1 for e in evaluations if e.status == ControlHealthStatus.FAILING)
        at_risk = sum(1 for e in evaluations if e.status == ControlHealthStatus.AT_RISK)
        missing = sum(1 for e in evaluations if e.status == ControlHealthStatus.MISSING_EVIDENCE)

        run.status = PreAuditRunStatus.COMPLETED
        run.passing_controls = passing
        run.failing_controls = failing
        run.at_risk_controls = at_risk
        run.missing_controls = missing
        run.summary = {
            "frameworks": schedule.frameworks,
            "generated_at": run.run_at.isoformat(),
            "totals": {
                "passing": passing,
                "failing": failing,
                "at_risk": at_risk,
                "missing": missing,
            },
        }
        run.estimated_outcome = self._estimate_outcome(failing, at_risk, missing)

        schedule.last_run_at = run.run_at
        schedule.next_run_at = self._compute_next_run(schedule, run.run_at)
        schedule.status = self._derive_schedule_status(run)

    def _estimate_outcome(self, failing: int, at_risk: int, missing: int) -> str:
        if failing == 0 and at_risk == 0 and missing == 0:
            return "PASS"
        if failing == 0 and missing == 0:
            return f"PASS WITH {at_risk} EXCEPTIONS" if at_risk else "PASS"
        return f"FAIL - {failing + missing} controls outstanding"

    def _compute_next_run(self, schedule: ComplianceAuditSchedule, run_at: datetime) -> Optional[datetime]:
        follow_up = run_at + timedelta(days=7)
        if follow_up >= schedule.audit_date:
            return None
        return follow_up

    def _derive_schedule_status(self, run: PreAuditRun) -> AuditScheduleStatus:
        if run.failing_controls == 0 and run.at_risk_controls == 0 and run.missing_controls == 0:
            return AuditScheduleStatus.READY
        return AuditScheduleStatus.ACTIVE

    async def _persist_findings(
        self,
        db: AsyncSession,
        run: PreAuditRun,
        evaluations: List[ControlEvaluation],
    ) -> None:
        for evaluation in evaluations:
            finding = PreAuditControlFinding(
                run=run,
                framework_name=evaluation.framework,
                control_id=evaluation.control.control_id,
                control_title=evaluation.control.title,
                status=evaluation.status,
                pass_rate=evaluation.pass_rate,
                evidence_summary=evaluation.evidence_summary,
                issue_summary=evaluation.issue_summary,
                remediation_suggestion=evaluation.remediation,
                priority=evaluation.priority,
                owner=evaluation.owner,
            )
            db.add(finding)

    async def _ensure_remediation_tasks(self, schedule: ComplianceAuditSchedule, run: PreAuditRun) -> None:
        async with async_session_factory() as db:
            stmt = select(PreAuditControlFinding).where(PreAuditControlFinding.run_id == run.id)
            findings = list(await db.scalars(stmt))

            actionable = [
                finding
                for finding in findings
                if finding.status in {ControlHealthStatus.FAILING, ControlHealthStatus.AT_RISK}
            ]

            if not actionable:
                if not schedule.ready_notification_sent and run.estimated_outcome.startswith("PASS"):
                    await self._send_ready_notification(schedule, run)
                return

            agent_session = await self._ensure_agent_session(schedule)

            for finding in actionable:
                task = await AgentReviewService.create_task(
                    session=agent_session,
                    created_by="pre-audit",
                    title=f"Remediate {finding.control_id}",
                    summary=finding.issue_summary or finding.control_title,
                    payload={
                        "framework": finding.framework_name,
                        "control_id": finding.control_id,
                        "priority": finding.priority,
                        "pre_audit_run_id": str(run.id),
                    },
                    priority=finding.priority,
                    due_at=schedule.audit_date - timedelta(days=7),
                )

                await self._assign_task(task.id, finding.owner)
                await self._maybe_create_ticket(schedule, task.id, finding)
                finding.task_id = task.id

            await db.commit()

    async def _ensure_agent_session(self, schedule: ComplianceAuditSchedule) -> AgentSession:
        async with async_session_factory() as db:
            stmt = (
                select(AgentSession)
                .where(AgentSession.org_id == schedule.org_id)
                .where(AgentSession.title == f"Pre-Audit Preparation {schedule.audit_date.year}")
            )
            session = await db.scalar(stmt)
            if session:
                return session

            session = AgentSession(
                org_id=schedule.org_id,
                agent_type=AgentType.COMPLIANCE_ADVISOR,
                created_by="pre-audit",
                title=f"Pre-Audit Preparation {schedule.audit_date.year}",
                context={
                    "frameworks": schedule.frameworks,
                    "audit_date": schedule.audit_date.isoformat(),
                },
            )
            db.add(session)
            await db.commit()
            await db.refresh(session)
            return session

    async def _assign_task(self, task_id: UUID, owner: Optional[str]) -> None:
        if not owner:
            return

        async with async_session_factory() as db:
            task = await db.get(AgentReviewTask, task_id)
            if not task:
                return
            task.assigned_to = owner
            task.assigned_by = "pre-audit"
            task.assigned_at = datetime.now(timezone.utc)
            await db.commit()

    async def _maybe_create_ticket(
        self,
        schedule: ComplianceAuditSchedule,
        task_id: UUID,
        finding: PreAuditControlFinding,
    ) -> None:
        if not schedule.create_tickets:
            return

        try:
            ticket = await TicketingService.create_ticket(
                org_id=schedule.org_id,
                task_id=task_id,
                system="serval",
                summary=f"Pre-Audit remediation required: {finding.control_id}",
                metadata={
                    "framework": finding.framework_name,
                    "priority": finding.priority,
                    "pre_audit_run_id": str(finding.run_id),
                },
            )
        except Exception:  # pragma: no cover - external integrations
            logger.exception("Failed to create remediation ticket", control=finding.control_id)
            return

        finding.ticket_id = ticket.ticket_id

    async def _send_ready_notification(
        self,
        schedule: ComplianceAuditSchedule,
        run: PreAuditRun,
    ) -> None:
        session = await self._ensure_agent_session(schedule)
        task = await AgentReviewService.create_task(
            session=session,
            created_by="pre-audit",
            title="Audit readiness confirmed",
            summary=f"All controls passing for frameworks {', '.join(schedule.frameworks)}",
            payload={
                "pre_audit_run_id": str(run.id),
                "status": run.summary,
            },
        )
        for owner in schedule.owner_emails:
            await NotificationService.enqueue(
                org_id=schedule.org_id,
                task_id=task.id,
                channel="email",
                payload={
                    "to": owner,
                    "subject": "Ready for audit",
                    "body": f"Pre-audit run {run.id} completed with outcome {run.estimated_outcome}",
                },
            )
        async with async_session_factory() as db:
            stored = await db.get(ComplianceAuditSchedule, schedule.id)
            if stored:
                stored.ready_notification_sent = True
                await db.commit()


__all__ = ["PreAuditHealthCheckService"]
