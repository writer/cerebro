"""Self-service security knowledge helpers for agent question answering."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.types import String

from cerebro.agents.analytics_service import AgentAnalyticsService
from cerebro.agents.models import AgentSelfServiceQuestion, AgentSelfServiceReport
from cerebro.compliance.preaudit_models import (
    ComplianceAuditSchedule,
    ControlHealthStatus,
    PreAuditControlFinding,
    PreAuditRun,
)
from cerebro.core.database import async_session_factory
from cerebro.core.models import Finding
from cerebro.query.bootstrap import get_query_engine
from cerebro.query.engine import QueryEngine, QueryResult

logger = structlog.get_logger(__name__)


class QuestionType(str, Enum):
    ACCESS = "access"
    POLICY = "policy"
    FINDING = "finding"
    COMPLIANCE = "compliance"
    UNKNOWN = "unknown"


FOLLOW_UP_NOTE = "Ask security if anything looks off or you need a second opinion."


DEFAULT_POLICY_GUIDANCE: Sequence[dict[str, Any]] = (
    {
        "slug": "redis-production",
        "keywords": {"redis", "production"},
        "answer": (
            "Redis is approved for production use when deployed inside the VPC, "
            "uses encryption at rest and in transit, and has automated backups enabled."
        ),
        "evidence": [
            {
                "type": "policy",
                "reference": "Security Architecture Standard :: Data Stores :: Section 3.2",
            }
        ],
        "notes": "Ensure security groups restrict access to application subnets only.",
    },
    {
        "slug": "s3-versioning",
        "keywords": {"s3", "versioning", "dev"},
        "answer": (
            "S3 versioning is strongly recommended in dev and required in staging/production. "
            "Enable it unless the bucket is ephemeral and less than 14 days old."
        ),
        "evidence": [
            {
                "type": "policy",
                "reference": "Data Protection Policy :: S3 Hardening :: Clause 1.1",
            }
        ],
        "notes": "Buckets storing customer data must also enable MFA delete in production.",
    },
    {
        "slug": "third-party-integrations",
        "keywords": {"third", "party", "integration"},
        "answer": (
            "All third-party integrations require vendor security review and an approved data flow diagram "
            "before production access is granted."
        ),
        "evidence": [
            {
                "type": "policy",
                "reference": "Vendor Management SOP :: Onboarding Checklist",
            }
        ],
        "notes": "Submit new integrations through the Vendor Security Request form in GRC.",
    },
)


@dataclass
class SelfServiceClassification:
    question_type: QuestionType
    confidence: float
    intent: str | None = None
    subject_user: str | None = None
    subject_resource: str | None = None
    additional_context: dict[str, Any] | None = None

    def to_log_payload(self) -> dict[str, Any]:
        return {
            "question_type": self.question_type.value,
            "confidence": self.confidence,
            "intent": self.intent,
            "subject_user": self.subject_user,
            "subject_resource": self.subject_resource,
            "additional": self.additional_context or {},
        }


@dataclass
class SelfServiceAnswer:
    question_type: QuestionType
    confidence: float
    summary: str
    evidence: list[dict[str, Any]]
    details: dict[str, Any]
    follow_up: str = FOLLOW_UP_NOTE

    def to_dict(self) -> dict[str, Any]:
        return {
            "question_type": self.question_type.value,
            "confidence": self.confidence,
            "summary": self.summary,
            "evidence": self.evidence,
            "details": self.details,
            "follow_up": self.follow_up,
        }


class SelfServiceQuestionClassifier:
    """Lightweight heuristic classifier for common security questions."""

    ACCESS_KEYWORDS = {
        "access",
        "permission",
        "permissions",
        "who",
        "assume",
        "role",
        "admin",
    }
    POLICY_KEYWORDS = {
        "policy",
        "allowed",
        "allow",
        "can i",
        "should",
        "approved",
        "standard",
    }
    FINDING_KEYWORDS = {
        "finding",
        "findings",
        "critical",
        "false positive",
        "seen before",
        "team",
    }
    COMPLIANCE_KEYWORDS = {
        "compliance",
        "soc2",
        "control",
        "audit",
        "failing",
        "status",
    }

    _CROSS_ACCOUNT_PATTERNS = ("cross-account", "assume role", "sts")

    def classify(self, question: str) -> SelfServiceClassification:
        normalized = question.lower()
        scores = {
            QuestionType.ACCESS: self._score(normalized, self.ACCESS_KEYWORDS),
            QuestionType.POLICY: self._score(normalized, self.POLICY_KEYWORDS),
            QuestionType.FINDING: self._score(normalized, self.FINDING_KEYWORDS),
            QuestionType.COMPLIANCE: self._score(normalized, self.COMPLIANCE_KEYWORDS),
        }

        question_type = max(scores, key=lambda k: scores[k])
        confidence = scores[question_type]

        if confidence == 0:
            return SelfServiceClassification(
                question_type=QuestionType.UNKNOWN, confidence=0.0
            )

        intent, subject_user, subject_resource = None, None, None
        context: dict[str, Any] = {}

        if question_type is QuestionType.ACCESS:
            intent, subject_user, subject_resource, context = self._classify_access(
                normalized
            )
        elif question_type is QuestionType.POLICY:
            intent, context = self._classify_policy(normalized)
        elif question_type is QuestionType.FINDING:
            intent, context = self._classify_finding(normalized)
        elif question_type is QuestionType.COMPLIANCE:
            intent, context = self._classify_compliance(normalized)

        return SelfServiceClassification(
            question_type=question_type,
            confidence=confidence,
            intent=intent,
            subject_user=subject_user,
            subject_resource=subject_resource,
            additional_context=context,
        )

    def _score(self, question: str, keywords: Iterable[str]) -> float:
        keyword_list = list(keywords)
        hits = sum(1 for keyword in keyword_list if keyword in question)
        if hits == 0:
            return 0.0
        return round(min(1.0, hits / max(len(keyword_list), 4)), 2)

    def _classify_access(
        self, question: str
    ) -> tuple[str, str | None, str | None, dict[str, Any]]:
        user_match = re.search(r"does\s+([\w@\.\-]+)\s+have", question)
        resource_match = re.search(r"access\s+to\s+([^\?]+)", question)
        if question.startswith("who has access") and resource_match:
            return "resource_access_listing", None, resource_match.group(1).strip(), {}
        if user_match and resource_match:
            return (
                "user_resource_access_check",
                user_match.group(1).strip(),
                resource_match.group(1).strip(),
                {},
            )
        for pattern in self._CROSS_ACCOUNT_PATTERNS:
            if pattern in question:
                return "cross_account_permissions", None, None, {"pattern": pattern}
        if user_match:
            return "user_access_overview", user_match.group(1).strip(), None, {}
        return "access_overview", None, None, {}

    def _classify_policy(self, question: str) -> tuple[str, dict[str, Any]]:
        if question.startswith("can i") or question.startswith("is "):
            return "policy_allowance", {}
        if "allowed" in question:
            return "policy_allowance", {}
        if "what's our policy" in question or "what is our policy" in question:
            return "policy_lookup", {}
        return "policy_lookup", {}

    def _classify_finding(self, question: str) -> tuple[str, dict[str, Any]]:
        if "critical" in question:
            return "critical_findings_summary", {"severity": "critical"}
        if "false positive" in question:
            return "finding_validation", {}
        if "seen before" in question:
            return "finding_history", {}
        return "finding_overview", {}

    def _classify_compliance(self, question: str) -> tuple[str, dict[str, Any]]:
        if "next audit" in question:
            return "audit_schedule", {}
        if "control" in question and ("failing" in question or "at risk" in question):
            return "failing_controls", {}
        if "status" in question:
            framework = None
            match = re.search(r"status\s+of\s+(\w+)", question)
            if match:
                framework = match.group(1)
            elif "soc2" in question:
                framework = "soc2"
            return "framework_status", {"framework": framework}
        return "compliance_overview", {}


class SelfServiceKnowledgeService:
    """Resolve self-service security questions using internal data sources."""

    def __init__(
        self,
        *,
        query_engine: QueryEngine | None = None,
        session_factory: Any = None,
        classifier: SelfServiceQuestionClassifier | None = None,
    ) -> None:
        self.query_engine = query_engine or get_query_engine()
        self.session_factory = session_factory or async_session_factory
        self.classifier = classifier or SelfServiceQuestionClassifier()

    async def answer_question(
        self,
        *,
        org_id: UUID,
        session_id: UUID | None,
        user_id: str | None,
        question: str,
    ) -> SelfServiceAnswer:
        classification = self.classifier.classify(question)
        handler_map = {
            QuestionType.ACCESS: self._handle_access,
            QuestionType.POLICY: self._handle_policy,
            QuestionType.FINDING: self._handle_finding,
            QuestionType.COMPLIANCE: self._handle_compliance,
        }

        handler = handler_map.get(classification.question_type, self._handle_unknown)

        try:
            answer = await handler(org_id, classification, question)
        except (OSError, RuntimeError, ValueError) as exc:
            logger.exception("Self-service question handler failed", exc_info=exc)
            answer = SelfServiceAnswer(
                question_type=QuestionType.UNKNOWN,
                confidence=classification.confidence,
                summary="I couldn't fetch the latest data. Please ping security to double-check.",
                evidence=[],
                details={"error": str(exc)},
            )

        await self._record_question(
            org_id=org_id,
            session_id=session_id,
            user_id=user_id,
            question=question,
            classification=classification,
            answer=answer,
        )

        return answer

    async def _handle_access(
        self,
        org_id: UUID,
        classification: SelfServiceClassification,
        question: str,
    ) -> SelfServiceAnswer:
        intent = classification.intent or "access_overview"
        evidence: list[dict[str, Any]] = []
        details: dict[str, Any] = {"intent": intent}

        if intent == "cross_account_permissions":
            sql = (
                "SELECT principal_id, resource_id, permission, path_length "
                "FROM iam_edges "
                "WHERE LOWER(permission) LIKE '%sts:assumerole%' "
                "ORDER BY path_length ASC LIMIT 25"
            )
            result = await self._safe_query(sql)
            evidence = result.rows[:10]
            summary = (
                f"Found {result.total_rows} identity relationships that can assume cross-account roles."
                if result.total_rows
                else "No cross-account assume-role relationships detected."
            )
            details.update({"sql": sql, "row_count": result.total_rows})
            return SelfServiceAnswer(
                question_type=QuestionType.ACCESS,
                confidence=classification.confidence,
                summary=summary,
                evidence=evidence,
                details=details,
            )

        params: list[Any] = []
        clauses: list[str] = []

        if classification.subject_user:
            clauses.append("LOWER(principal_id) LIKE LOWER($1)")
            params.append(f"%{classification.subject_user.lower()}%")
        if classification.subject_resource:
            clauses.append("LOWER(resource_id) LIKE LOWER($%d)" % (len(params) + 1))
            params.append(f"%{classification.subject_resource.lower()}%")

        where_clause = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            "SELECT principal_id, resource_id, permission, path_length "
            "FROM iam_edges "
            f"{where_clause} "
            "ORDER BY path_length ASC LIMIT 25"
        )
        result = await self._safe_query(sql, params=params)

        evidence = result.rows[:10]
        details.update({"sql": sql, "params": params, "row_count": result.total_rows})

        if classification.subject_user and classification.subject_resource:
            summary = (
                f"Yes, {classification.subject_user} can reach {classification.subject_resource} "
                f"with {result.rows[0]['permission']}"
                if result.total_rows
                else f"No path from {classification.subject_user} to {classification.subject_resource} was found."
            )
        elif classification.subject_user:
            summary = (
                f"{classification.subject_user} has {result.total_rows} permission paths."
                if result.total_rows
                else f"No permissions found for {classification.subject_user}."
            )
        elif classification.subject_resource:
            summary = (
                f"Identified {result.total_rows} principals with access to {classification.subject_resource}."
                if result.total_rows
                else f"No principals found with access to {classification.subject_resource}."
            )
        else:
            summary = (
                f"Retrieved {result.total_rows} principal-resource relationships."
                if result.total_rows
                else "No IAM relationships matched the query."
            )

        return SelfServiceAnswer(
            question_type=QuestionType.ACCESS,
            confidence=classification.confidence,
            summary=summary,
            evidence=evidence,
            details=details,
        )

    async def _handle_policy(
        self,
        org_id: UUID,
        classification: SelfServiceClassification,
        question: str,
    ) -> SelfServiceAnswer:
        normalized = question.lower()
        matched_entry = None
        best_overlap = 0

        for entry in DEFAULT_POLICY_GUIDANCE:
            overlap = len(entry["keywords"] & set(normalized.split()))
            if overlap > best_overlap:
                matched_entry = entry
                best_overlap = overlap

        if matched_entry:
            evidence = list(matched_entry.get("evidence", []))
            details = {
                "policy_slug": matched_entry["slug"],
                "notes": matched_entry.get("notes"),
                "matched_keywords": best_overlap,
            }
            summary = matched_entry["answer"]
            confidence = max(
                classification.confidence, min(1.0, 0.6 + best_overlap * 0.1)
            )
        else:
            evidence = []
            details = {"matched_keywords": 0}
            summary = "I couldn't locate a published policy for that scenario. Please escalate to security so we can review."
            confidence = classification.confidence * 0.5

        return SelfServiceAnswer(
            question_type=QuestionType.POLICY,
            confidence=round(confidence, 2),
            summary=summary,
            evidence=evidence,
            details=details,
        )

    async def _handle_finding(
        self,
        org_id: UUID,
        classification: SelfServiceClassification,
        question: str,
    ) -> SelfServiceAnswer:
        severity = (
            classification.additional_context.get("severity")
            if classification.additional_context
            else None
        )

        async with self.session_factory() as session:  # type: ignore[func-returns-value]
            stmt = select(Finding).where(Finding.org_id == org_id)
            if severity:
                stmt = stmt.where(func.lower(Finding.severity) == severity.lower())
            stmt = stmt.order_by(Finding.first_seen.desc()).limit(20)
            findings = list((await session.execute(stmt)).scalars())

        evidence = [
            {
                "id": str(finding.finding_id),
                "title": finding.title,
                "severity": finding.severity,
                "status": finding.status,
                "resource_id": finding.resource_id,
                "created_at": (
                    finding.created_at.isoformat() if finding.created_at else None
                ),
            }
            for finding in findings
        ]

        if not findings:
            summary = "No matching findings were found in the last 20 records."
        elif severity:
            summary = f"Found {len(findings)} {severity.lower()} findings."
        else:
            summary = f"Retrieved {len(findings)} recent findings for your org."

        details = {
            "severity": severity,
            "result_count": len(findings),
        }

        return SelfServiceAnswer(
            question_type=QuestionType.FINDING,
            confidence=classification.confidence,
            summary=summary,
            evidence=evidence,
            details=details,
        )

    async def _handle_compliance(
        self,
        org_id: UUID,
        classification: SelfServiceClassification,
        question: str,
    ) -> SelfServiceAnswer:
        intent = classification.intent or "compliance_overview"
        evidence: list[dict[str, Any]] = []
        details: dict[str, Any] = {"intent": intent}

        async with self.session_factory() as session:  # type: ignore[func-returns-value]
            if intent == "audit_schedule":
                stmt = (
                    select(ComplianceAuditSchedule)
                    .where(ComplianceAuditSchedule.org_id == org_id)
                    .order_by(ComplianceAuditSchedule.audit_date.asc())
                )
                schedule = (await session.execute(stmt)).scalars().first()
                if schedule:
                    summary = (
                        f"Next audit for {', '.join(schedule.frameworks)} is scheduled on "
                        f"{schedule.audit_date.date().isoformat()}."
                    )
                    evidence.append(
                        {
                            "schedule_id": str(schedule.id),
                            "frameworks": schedule.frameworks,
                            "audit_date": schedule.audit_date.isoformat(),
                            "status": schedule.status.value,
                        }
                    )
                else:
                    summary = "No future audits are scheduled."
            elif intent == "failing_controls":
                control_stmt = (
                    select(PreAuditControlFinding)
                    .join(PreAuditRun, PreAuditControlFinding.run_id == PreAuditRun.id)
                    .join(
                        ComplianceAuditSchedule,
                        PreAuditRun.schedule_id == ComplianceAuditSchedule.id,
                    )
                    .where(ComplianceAuditSchedule.org_id == org_id)
                    .where(
                        PreAuditControlFinding.status.in_(
                            [
                                ControlHealthStatus.FAILING,
                                ControlHealthStatus.AT_RISK,
                            ]
                        )
                    )
                    .order_by(PreAuditControlFinding.created_at.desc())
                    .limit(20)
                )
                failing = list((await session.execute(control_stmt)).scalars())
                evidence = [
                    {
                        "control_id": finding.control_id,
                        "framework": finding.framework_name,
                        "status": finding.status.value,
                        "issue": finding.issue_summary,
                        "priority": finding.priority,
                    }
                    for finding in failing
                ]
                summary = (
                    f"There are {len(failing)} controls failing or at risk."
                    if failing
                    else "All tracked controls are currently passing."
                )
            else:  # framework_status or overview
                framework = None
                if classification.additional_context:
                    framework = classification.additional_context.get("framework")

                run_stmt = (
                    select(PreAuditRun)
                    .join(
                        ComplianceAuditSchedule,
                        PreAuditRun.schedule_id == ComplianceAuditSchedule.id,
                    )
                    .where(ComplianceAuditSchedule.org_id == org_id)
                    .order_by(PreAuditRun.run_at.desc())
                )
                if framework:
                    run_stmt = run_stmt.where(
                        func.lower(
                            cast(ComplianceAuditSchedule.frameworks, String)
                        ).like(f"%{framework.lower()}%")
                    )
                run = (await session.execute(run_stmt.limit(1))).scalars().first()
                if run:
                    summary = (
                        f"Latest pre-audit run estimates {run.estimated_outcome.lower()} "
                        f"with {run.failing_controls} failing controls and {run.at_risk_controls} at risk."
                    )
                    evidence.append(
                        {
                            "run_id": str(run.id),
                            "schedule_id": str(run.schedule_id),
                            "estimated_outcome": run.estimated_outcome,
                            "totals": {
                                "passing": run.passing_controls,
                                "failing": run.failing_controls,
                                "at_risk": run.at_risk_controls,
                                "missing": run.missing_controls,
                            },
                        }
                    )
                else:
                    summary = "No pre-audit runs have been recorded yet."

        return SelfServiceAnswer(
            question_type=QuestionType.COMPLIANCE,
            confidence=classification.confidence,
            summary=summary,
            evidence=evidence,
            details=details,
        )

    async def _handle_unknown(
        self,
        org_id: UUID,
        classification: SelfServiceClassification,
        question: str,
    ) -> SelfServiceAnswer:
        return SelfServiceAnswer(
            question_type=QuestionType.UNKNOWN,
            confidence=classification.confidence,
            summary="I couldn't classify that question. Please reach out to security for help.",
            evidence=[],
            details={"intent": "unknown"},
        )

    async def _safe_query(
        self, sql: str, params: list[Any] | None = None
    ) -> QueryResult:
        try:
            return await self.query_engine.execute_query(sql, params=params)
        except (OSError, RuntimeError, ValueError) as exc:
            logger.warning("Self-service query failed", sql=sql, error=str(exc))
            return QueryResult(
                columns=[],
                rows=[],
                total_rows=0,
                execution_time_ms=0.0,
                tables_queried=[],
                errors=[str(exc)],
            )

    async def _record_question(
        self,
        *,
        org_id: UUID,
        session_id: UUID | None,
        user_id: str | None,
        question: str,
        classification: SelfServiceClassification,
        answer: SelfServiceAnswer,
    ) -> None:
        payload = classification.to_log_payload()
        payload.update({"answer_confidence": answer.confidence})

        if session_id:
            await AgentAnalyticsService.record_event(
                org_id=org_id,
                session_id=session_id,
                event_type="self_service_question",
                payload=payload,
            )

        async with self.session_factory() as session:  # type: ignore[func-returns-value]
            record = AgentSelfServiceQuestion(
                org_id=org_id,
                session_id=session_id,
                user_id=user_id,
                question=question,
                question_type=classification.question_type.value,
                question_intent=classification.intent,
                handler_key=payload.get("intent"),
                confidence=classification.confidence,
                answer_summary=answer.summary,
                evidence=answer.evidence,
                details={
                    "classification": payload,
                    "answer": answer.details,
                },
            )
            session.add(record)
            await session.commit()


class SelfServiceAnalytics:
    """Aggregate self-service questions for reporting and documentation planning."""

    def __init__(self, session_factory: Any = None) -> None:
        self.session_factory = session_factory or async_session_factory

    async def generate_monthly_reports(
        self,
        *,
        as_of: datetime | None = None,
    ) -> list[AgentSelfServiceReport]:
        if as_of is None:
            as_of = datetime.now(UTC)

        period_end = datetime(as_of.year, as_of.month, 1, tzinfo=UTC)
        period_start = (period_end - timedelta(days=1)).replace(day=1)

        reports: list[AgentSelfServiceReport] = []
        async with self.session_factory() as session:  # type: ignore[func-returns-value]
            org_ids = await self._list_org_ids(session, period_start, period_end)
            for org_id in org_ids:
                report = await self._build_report(
                    session, org_id, period_start, period_end
                )
                if report:
                    session.add(report)
                    reports.append(report)
            if reports:
                await session.commit()

        return reports

    async def _list_org_ids(
        self,
        session: AsyncSession,
        period_start: datetime,
        period_end: datetime,
    ) -> list[UUID]:
        stmt = (
            select(AgentSelfServiceQuestion.org_id)
            .where(AgentSelfServiceQuestion.created_at >= period_start)
            .where(AgentSelfServiceQuestion.created_at < period_end)
            .distinct()
        )
        result = await session.execute(stmt)
        return [row[0] for row in result.all()]

    async def _build_report(
        self,
        session: AsyncSession,
        org_id: UUID,
        period_start: datetime,
        period_end: datetime,
    ) -> AgentSelfServiceReport | None:
        stmt = (
            select(
                AgentSelfServiceQuestion.question,
                AgentSelfServiceQuestion.question_type,
                func.count().label("count"),
            )
            .where(AgentSelfServiceQuestion.org_id == org_id)
            .where(AgentSelfServiceQuestion.created_at >= period_start)
            .where(AgentSelfServiceQuestion.created_at < period_end)
            .group_by(
                AgentSelfServiceQuestion.question,
                AgentSelfServiceQuestion.question_type,
            )
            .order_by(func.count().desc())
            .limit(10)
        )
        top_entries = (await session.execute(stmt)).all()
        if not top_entries:
            return None

        total_stmt = (
            select(func.count())
            .select_from(AgentSelfServiceQuestion)
            .where(AgentSelfServiceQuestion.org_id == org_id)
            .where(AgentSelfServiceQuestion.created_at >= period_start)
            .where(AgentSelfServiceQuestion.created_at < period_end)
        )
        total: int = (await session.execute(total_stmt)).scalar_one()

        breakdown = [
            {
                "question": row.question,
                "question_type": row.question_type,
                "count": row.count,
                "percentage": round((row.count / total) * 100, 2) if total else 0.0,  # type: ignore[operator]
            }
            for row in top_entries
        ]

        recommendations = "Top 10 self-service questions requested this month. Consider documenting these in the knowledge base."

        return AgentSelfServiceReport(
            org_id=org_id,
            period_start=period_start,
            period_end=period_end,
            total_questions=total,
            question_breakdown=breakdown,
            recommendations=recommendations,
        )
