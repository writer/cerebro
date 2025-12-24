from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import select

from cerebro.agents.models import AgentReviewTask
from cerebro.compliance.frameworks import (
    ComplianceControl,
    ComplianceFramework,
    ControlType,
    EvidenceType,
)
from cerebro.compliance.pre_audit_service import PreAuditHealthCheckService
from cerebro.compliance.preaudit_models import (
    ControlHealthStatus,
    PreAuditControlFinding,
)
from cerebro.core.database import async_session_factory
from cerebro.query.engine import QueryResult

UTC = UTC


class _StubQueryEngine:
    async def execute_query(
        self, sql: str, params: list[Any] | None = None
    ) -> QueryResult:
        if "pass_control" in sql:
            return QueryResult(
                columns=[],
                rows=[],
                total_rows=0,
                execution_time_ms=1,
                tables_queried=["stub"],
                errors=[],
            )
        if "at_risk_control" in sql:
            return QueryResult(
                columns=["compliance_rate"],
                rows=[{"compliance_rate": 0.87}],
                total_rows=1,
                execution_time_ms=1,
                tables_queried=["stub"],
                errors=[],
            )
        if "fail_control" in sql:
            return QueryResult(
                columns=["username"],
                rows=[{"username": "alice"}, {"username": "bob"}],
                total_rows=2,
                execution_time_ms=1,
                tables_queried=["stub"],
                errors=[],
            )
        return QueryResult(
            columns=[],
            rows=[],
            total_rows=0,
            execution_time_ms=1,
            tables_queried=["stub"],
            errors=["query not supported"],
        )


@pytest.mark.asyncio()
async def test_pre_audit_service_classifies_controls(monkeypatch):
    control_pass = ComplianceControl(
        control_id="PASS-1",
        title="Passing control",
        description="",
        category="identity",
        control_type=ControlType.PREVENTIVE,
        required_evidence=[EvidenceType.CONFIGURATION],
        sql_queries=["SELECT * FROM pass_control"],
        remediation_guidance="",
        frequency="quarterly",
        automation_level="automated",
    )
    control_at_risk = ComplianceControl(
        control_id="AT-1",
        title="At risk control",
        description="",
        category="identity",
        control_type=ControlType.PREVENTIVE,
        required_evidence=[EvidenceType.CONFIGURATION],
        sql_queries=["SELECT * FROM at_risk_control"],
        remediation_guidance="Reduce MFA gap",
        frequency="quarterly",
        automation_level="automated",
    )
    control_fail = ComplianceControl(
        control_id="FAIL-1",
        title="Failing control",
        description="",
        category="identity",
        control_type=ControlType.PREVENTIVE,
        required_evidence=[EvidenceType.CONFIGURATION],
        sql_queries=["SELECT * FROM fail_control"],
        remediation_guidance="Enable MFA",
        frequency="quarterly",
        automation_level="automated",
    )
    control_missing = ComplianceControl(
        control_id="MISS-1",
        title="Missing evidence",
        description="",
        category="identity",
        control_type=ControlType.ADMINISTRATIVE,
        required_evidence=[EvidenceType.POLICY_DOCUMENT],
        sql_queries=[],
        remediation_guidance="Document policy",
        frequency="annually",
        automation_level="manual",
    )

    framework = ComplianceFramework(
        name="SOC2",
        version="test",
        description="",
        controls=[control_pass, control_at_risk, control_fail, control_missing],
    )

    def _fake_get_framework(name: str) -> ComplianceFramework | None:
        return framework if name.lower() == "soc2" else None

    monkeypatch.setattr(
        "cerebro.compliance.pre_audit_service.get_framework",
        _fake_get_framework,
    )

    service = PreAuditHealthCheckService(query_engine=_StubQueryEngine())

    run = await service.run_on_demand(
        org_id=uuid4(),
        frameworks=["soc2"],
        audit_date=datetime(2025, 12, 1, tzinfo=UTC),
        owner_emails=["owner@example.com"],
    )

    assert run.passing_controls == 1
    assert run.at_risk_controls == 1
    assert run.failing_controls == 1
    assert run.missing_controls == 1

    async with async_session_factory() as db:
        findings = list(
            await db.scalars(
                select(PreAuditControlFinding).where(
                    PreAuditControlFinding.run_id == run.id
                )
            )
        )
        statuses = {f.control_id: f.status for f in findings}
        assert statuses["PASS-1"] == ControlHealthStatus.PASSING
        assert statuses["AT-1"] == ControlHealthStatus.AT_RISK
        assert statuses["FAIL-1"] == ControlHealthStatus.FAILING
        assert statuses["MISS-1"] == ControlHealthStatus.MISSING_EVIDENCE

        tasks = list(await db.scalars(select(AgentReviewTask)))
        # Only failing and at-risk controls should create tasks
        control_ids_with_tasks = {f.control_id for f in findings if f.task_id}
        assert control_ids_with_tasks == {"AT-1", "FAIL-1"}
        # Tasks should have been assigned to owner@example.com
        assert all(
            task.assigned_to == "owner@example.com"
            for task in tasks
            if task.assigned_to
        )
