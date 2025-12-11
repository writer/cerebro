from datetime import datetime, timezone
from typing import Any, Dict
from uuid import uuid4

import pytest
from pydantic import BaseModel
from sqlalchemy import select

from cerebro.agents.models import (
    AgentReviewTask,
    AgentSession,
    AgentType,
    ReviewTaskStatus,
)
from cerebro.agents.review_service import AgentReviewService
from cerebro.agents.runtime_facade import AgentRuntimeFacade
from cerebro.agents.service import AgentSessionService
from cerebro.agents.tool_stats import performance_tracker
from cerebro.agents.tools.base import (
    AgentContext,
    Tool,
    ToolExecutor,
    ToolPermissionLevel,
    ToolResult,
)
from cerebro.core.database import async_session_factory
from cerebro.core.models import Organization


class _DummyInputs(BaseModel):
    reason: str = "investigate"


class _DummyDestructiveTool(Tool):
    @property
    def name(self) -> str:
        return "dummy_destructive"

    @property
    def description(self) -> str:
        return "Performs a destructive remediation"

    @property
    def input_schema(self):
        return _DummyInputs

    @property
    def output_schema(self):
        return _DummyInputs

    @property
    def permission_level(self) -> ToolPermissionLevel:
        return ToolPermissionLevel.WRITE_DESTRUCTIVE

    async def execute(self, inputs: BaseModel, context: AgentContext) -> ToolResult:
        return ToolResult(
            success=True,
            data={"ack": True},
            metadata={"summary": "Patched security group ingress"},
        )


class _ScoredTool(Tool):
    def __init__(self, name: str, permission: ToolPermissionLevel = ToolPermissionLevel.READ_ONLY):
        self._name = name
        self._permission = permission

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._name

    @property
    def input_schema(self):
        return _DummyInputs

    @property
    def output_schema(self):
        return _DummyInputs

    @property
    def permission_level(self) -> ToolPermissionLevel:
        return self._permission

    async def execute(self, inputs: BaseModel, context: AgentContext) -> ToolResult:
        return ToolResult(success=True)


@pytest.mark.asyncio
async def test_destructive_tool_execution_enqueues_review_task():
    async with async_session_factory() as db_session:
        org = Organization(name="Review Org", created_at=datetime.now(timezone.utc))
        db_session.add(org)
        await db_session.commit()
        await db_session.refresh(org)

        session = AgentSession(
            org_id=org.org_id,
            agent_type=AgentType.SECURITY_ANALYST,
            created_by="operator@example.com",
            title="Review Session",
            context={}
        )
        db_session.add(session)
        await db_session.commit()
        await db_session.refresh(session)

    context = AgentContext(
        session_id=session.id,
        org_id=session.org_id,
        user_id="operator@example.com",
        agent_type=session.agent_type.value,
        permission_level=ToolPermissionLevel.ADMIN,
        provider_scope=[],
        finding_ids=[],
        cel_context={},
    )
    context.dry_run = False

    tool = _DummyDestructiveTool()
    executor = ToolExecutor()

    result = await executor.execute_tool(
        tool=tool,
        raw_inputs={"reason": "investigate"},
        context=context,
        dry_run=False,
    )

    assert result.success

    async with async_session_factory() as db_session:
        rows = await db_session.execute(
            select(AgentReviewTask).where(AgentReviewTask.session_id == session.id)
        )
        tasks = rows.scalars().all()

    assert len(tasks) == 1
    assert tasks[0].status == ReviewTaskStatus.PENDING
    assert tasks[0].tool_invocation_id is not None


@pytest.mark.asyncio
async def test_review_task_resolution_updates_status():
    async with async_session_factory() as db_session:
        org = Organization(name="Resolve Org", created_at=datetime.now(timezone.utc))
        db_session.add(org)
        await db_session.commit()
        await db_session.refresh(org)

        session = AgentSession(
            org_id=org.org_id,
            agent_type=AgentType.SECURITY_ANALYST,
            created_by="reviewer@example.com",
            title="Resolve Session",
            context={}
        )
        db_session.add(session)
        await db_session.commit()
        await db_session.refresh(session)

    task = await AgentReviewService.create_task(
        session=session,
        created_by="reviewer@example.com",
        title="Review destructive action",
        summary="Ensure change ticket exists",
        payload={"reference": "CHG-123"},
    )

    service = AgentSessionService()
    resolved = await service.resolve_review_task(
        task_id=task.id,
        resolved_by="approver@example.com",
        status="approved",
        notes="Looks good",
    )

    assert resolved is not None
    assert resolved["status"] == "approved"
    assert resolved["resolved_by"] == "approver@example.com"
    assert resolved["resolution_notes"] == "Looks good"


@pytest.mark.asyncio
async def test_runtime_facade_skill_based_routing_prefers_openai():
    facade = AgentRuntimeFacade()
    context: Dict[str, Any] = {"finding_ids": [str(uuid4())]}
    skill_tags = facade._extract_skill_tags(AgentType.SECURITY_ANALYST, context)  # type: ignore[attr-defined]
    assert "analysis" in skill_tags
    runtime = facade._select_runtime(AgentType.SECURITY_ANALYST, context, skill_tags)  # type: ignore[attr-defined]
    assert runtime == "openai"


@pytest.mark.asyncio
async def test_tool_performance_tracker_sorts_by_success_rate():
    performance_tracker._stats.clear()  # type: ignore[attr-defined]

    fast_tool = _ScoredTool("fast")
    slow_tool = _ScoredTool("slow")

    await performance_tracker.record(tool_name="fast", success=True, duration_seconds=0.1)
    await performance_tracker.record(tool_name="fast", success=True, duration_seconds=0.2)
    await performance_tracker.record(tool_name="slow", success=False, duration_seconds=0.05)

    ordered = performance_tracker.sort_tools([slow_tool, fast_tool], "security_analyst")
    assert ordered[0].name == "fast"
