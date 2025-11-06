from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

from cerebro.agents.models import AgentSelfServiceQuestion, AgentSelfServiceReport
from cerebro.agents.self_service import (
    QuestionType,
    SelfServiceAnalytics,
    SelfServiceKnowledgeService,
)
from cerebro.compliance.preaudit_models import ComplianceAuditSchedule, PreAuditRun, PreAuditRunStatus
from cerebro.core.models import Organization
from cerebro.query.engine import QueryResult


class _SessionContext:
    def __init__(self, session):
        self._session = session

    async def __aenter__(self):
        return self._session

    async def __aexit__(self, exc_type, exc, tb):
        return False


def _session_factory(session):
    return lambda: _SessionContext(session)


class _StubQueryEngine:
    def __init__(self, responses: Optional[Dict[str, QueryResult]] = None) -> None:
        self.responses = responses or {}

    async def execute_query(self, sql: str, params: Optional[List[Any]] = None) -> QueryResult:
        key = next((name for name in self.responses if name in sql.lower()), None)
        if key:
            return self.responses[key]
        return QueryResult(
            columns=[],
            rows=[],
            total_rows=0,
            execution_time_ms=0.0,
            tables_queried=[],
            errors=["no matching stub"],
        )


def _query_result(rows: List[Dict[str, Any]]) -> QueryResult:
    return QueryResult(
        columns=list(rows[0].keys()) if rows else [],
        rows=rows,
        total_rows=len(rows),
        execution_time_ms=1.0,
        tables_queried=["stub"],
        errors=[],
    )


@pytest.mark.asyncio()
async def test_access_question_logs_answer(test_db):
    org = Organization(name="Self Service Org")
    test_db.add(org)
    await test_db.commit()
    await test_db.refresh(org)

    stub = _StubQueryEngine(
        {
            "iam_edges": _query_result([
                {
                    "principal_id": "alice@example.com",
                    "resource_id": "arn:aws:s3:::customer-data",
                    "permission": "s3:*",
                    "path_length": 1,
                }
            ])
        }
    )
    service = SelfServiceKnowledgeService(
        query_engine=stub,
        session_factory=_session_factory(test_db),
    )

    answer = await service.answer_question(
        org_id=org.org_id,
        session_id=None,
        user_id="eng@example.com",
        question="Does alice@example.com have access to the customer-data S3 bucket?",
    )

    assert answer.question_type == QuestionType.ACCESS
    assert "alice@example.com" in answer.summary.lower()
    assert answer.evidence

    rows = list((await test_db.execute(select(AgentSelfServiceQuestion)) ).scalars())
    assert len(rows) == 1
    assert rows[0].question_type == QuestionType.ACCESS.value
    assert rows[0].answer_summary


@pytest.mark.asyncio()
async def test_policy_question_uses_catalog(test_db):
    org = Organization(name="Policy Org")
    test_db.add(org)
    await test_db.commit()
    await test_db.refresh(org)

    service = SelfServiceKnowledgeService(session_factory=_session_factory(test_db))

    answer = await service.answer_question(
        org_id=org.org_id,
        session_id=None,
        user_id=None,
        question="Is Redis allowed in production?",
    )

    assert answer.question_type == QuestionType.POLICY
    assert "redis" in answer.summary.lower()
    assert answer.evidence


@pytest.mark.asyncio()
async def test_compliance_question_reads_schedule(test_db):
    org = Organization(name="Compliance Org")
    test_db.add(org)
    await test_db.commit()
    await test_db.refresh(org)

    schedule = ComplianceAuditSchedule(
        id=uuid4(),
        org_id=org.org_id,
        frameworks=["soc2"],
        audit_date=datetime(2025, 5, 1, tzinfo=timezone.utc),
    )
    run = PreAuditRun(
        id=uuid4(),
        schedule_id=schedule.id,
        run_at=datetime(2025, 1, 15, tzinfo=timezone.utc),
        status=PreAuditRunStatus.COMPLETED,
        summary={},
        estimated_outcome="PASS",
        passing_controls=12,
        failing_controls=1,
        at_risk_controls=2,
        missing_controls=0,
    )
    test_db.add(schedule)
    test_db.add(run)
    await test_db.commit()

    service = SelfServiceKnowledgeService(session_factory=_session_factory(test_db))
    answer = await service.answer_question(
        org_id=org.org_id,
        session_id=None,
        user_id=None,
        question="When is our next audit?",
    )

    assert answer.question_type == QuestionType.COMPLIANCE
    assert "next audit" in answer.summary.lower()
    assert answer.evidence


@pytest.mark.asyncio()
async def test_monthly_report_generation(test_db):
    org = Organization(name="Analytics Org")
    test_db.add(org)
    await test_db.commit()
    await test_db.refresh(org)

    record = AgentSelfServiceQuestion(
        org_id=org.org_id,
        session_id=None,
        user_id="eng@example.com",
        question="Who has access to prod?",
        question_type=QuestionType.ACCESS.value,
        question_intent="resource_access_listing",
        handler_key="resource_access_listing",
        confidence=0.8,
        answer_summary="Example",
        evidence=[],
        details={},
        created_at=datetime(2025, 1, 10, tzinfo=timezone.utc),
    )
    test_db.add(record)
    await test_db.commit()

    analytics = SelfServiceAnalytics(session_factory=_session_factory(test_db))
    reports = await analytics.generate_monthly_reports(as_of=datetime(2025, 2, 2, tzinfo=timezone.utc))

    assert len(reports) == 1
    stored = list((await test_db.execute(select(AgentSelfServiceReport))).scalars())
    assert stored
    assert stored[0].total_questions == 1
    assert stored[0].question_breakdown
