from __future__ import annotations

import anyio
import pytest
from pydantic import BaseModel

from cerebro.agents.models import AgentSession, AgentType
from cerebro.agents.tools.base import (
    AgentContext,
    StructuredTool,
    ToolExecutor,
    ToolPermissionLevel,
    ToolResult,
)
from cerebro.core.models import Organization


class _EmptyInput(BaseModel):
    pass


class _Output(BaseModel):
    ok: bool


class _SleepTool(StructuredTool):
    tool_name = "sleep_tool"
    tool_description = "sleep"
    input_model = _EmptyInput
    output_model = _Output
    required_permission = ToolPermissionLevel.READ_ONLY

    async def _run(self, context: AgentContext, **kwargs) -> ToolResult:
        await anyio.sleep(0.05)
        return ToolResult(success=True, data={"ok": True})


class _InstantTool(StructuredTool):
    tool_name = "instant_tool"
    tool_description = "instant"
    input_model = _EmptyInput
    output_model = _Output
    required_permission = ToolPermissionLevel.READ_ONLY

    async def _run(self, context: AgentContext, **kwargs) -> ToolResult:
        return ToolResult(success=True, data={"ok": True})


async def _make_session(test_db):
    org = Organization(name="Tool Org")
    test_db.add(org)
    await test_db.commit()
    await test_db.refresh(org)

    session = AgentSession(
        org_id=org.org_id,
        agent_type=AgentType.SECURITY_ANALYST,
        created_by="tester",
        context={},
    )
    test_db.add(session)
    await test_db.commit()
    await test_db.refresh(session)
    return org, session


@pytest.mark.asyncio()
async def test_tool_executor_enforces_timeout(monkeypatch, test_db):
    monkeypatch.setenv("AGENT_TOOL_TIMEOUT_SECONDS_READ_ONLY", "0.01")
    org, session = await _make_session(test_db)

    context = AgentContext(
        session_id=session.id,
        org_id=org.org_id,
        user_id="user@example.com",
        agent_type=AgentType.SECURITY_ANALYST.value,
        permission_level=ToolPermissionLevel.READ_ONLY,
    )

    executor = ToolExecutor()
    result = await executor.execute_tool(_SleepTool(), raw_inputs={}, context=context)

    assert result.success is False
    assert (result.metadata or {}).get("error_code") == "TOOL_TIMEOUT"


@pytest.mark.asyncio()
async def test_tool_executor_rate_limits_by_session(monkeypatch, test_db):
    monkeypatch.setenv("AGENT_TOOL_RATE_LIMIT_PER_MINUTE", "1")
    org, session = await _make_session(test_db)

    context = AgentContext(
        session_id=session.id,
        org_id=org.org_id,
        user_id="user@example.com",
        agent_type=AgentType.SECURITY_ANALYST.value,
        permission_level=ToolPermissionLevel.READ_ONLY,
    )

    executor = ToolExecutor()
    ok = await executor.execute_tool(_InstantTool(), raw_inputs={}, context=context)
    assert ok.success is True

    blocked = await executor.execute_tool(_InstantTool(), raw_inputs={}, context=context)
    assert blocked.success is False
    assert (blocked.metadata or {}).get("error_code") == "TOOL_RATE_LIMITED"
