import pytest
from datetime import datetime, timezone

from cerebro.agents.models import AgentSession, AgentType, ToolInvocation, ToolInvocationStatus
from cerebro.agents.service import AgentSessionService
from cerebro.core.database import async_session_factory
from cerebro.core.models import Organization


@pytest.mark.asyncio
async def test_simulate_policy_expression_matches_invocation():
    async with async_session_factory() as db_session:
        org = Organization(
            name="PolicySim Org",
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(org)
        await db_session.commit()
        await db_session.refresh(org)

        session = AgentSession(
            org_id=org.org_id,
            agent_type=AgentType.SECURITY_ANALYST,
            created_by="policy@example.com",
            title="Policy Simulation Session",
            context={},
        )
        db_session.add(session)
        await db_session.commit()
        await db_session.refresh(session)

        invocation = ToolInvocation(
            session_id=session.id,
            tool_name="remediation_tool",
            tool_version="1.0",
            input_data={"action": "delete"},
            output_data={"status": "ok"},
            status=ToolInvocationStatus.SUCCESS,
            cel_context={
                "inputs": {"action": "delete"},
                "user_id": "policy@example.com",
            },
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        db_session.add(invocation)
        await db_session.commit()

    service = AgentSessionService()
    result = await service.simulate_policy_expression(
        org_id=org.org_id,
        expression="resource.inputs.action == 'delete'",
        tool_name="remediation_tool",
        limit=5,
    )

    assert result["evaluated_count"] == 1
    assert result["matched_count"] == 1
    assert result["mismatched_count"] == 0
    assert result["error_count"] == 0
    assert result["examples"]
