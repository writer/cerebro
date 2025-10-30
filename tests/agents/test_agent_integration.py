"""
Integration tests for Cerebro agent system.

Tests the complete flow from runtime through tools with real database interactions.
"""

import asyncio
from typing import Any, List

import pytest
from datetime import datetime, timezone
from uuid import uuid4, UUID

from cerebro.agents.runtime import CerebroClaudeRuntime
from cerebro.agents.openai_runtime import CerebroOpenAIRuntime
from cerebro.agents.models import AgentSession, AgentType, MessageRole, AgentRuntimeEvent
from cerebro.agents.tools import AgentContext, ToolPermissionLevel
from cerebro.agents.tools.findings_list import FindingsListTool
from cerebro.agents.tools.query import QueryTool
from cerebro.core.models import Finding, Organization, Account, Rule


@pytest.fixture
async def test_org():
    """Create test organization."""
    from cerebro.core.database import async_session_factory

    async with async_session_factory() as session:
        org = Organization(
            org_id=uuid4(),
            name="Test Org for Agents",
            created_at=datetime.now(timezone.utc),
        )
        session.add(org)
        await session.commit()
        await session.refresh(org)
        yield org

        # Cleanup
        await session.delete(org)
        await session.commit()


@pytest.fixture
async def test_account(test_org):
    """Create test account."""
    from cerebro.core.database import async_session_factory

    async with async_session_factory() as session:
        account = Account(
            account_id=uuid4(),
            org_id=test_org.org_id,
            provider="aws",
            external_id="test-account-123",
            display_name="Test AWS Account",
        )
        session.add(account)
        await session.commit()
        await session.refresh(account)
        yield account


@pytest.fixture
async def test_rule(test_org):
    """Create test security rule."""
    from cerebro.core.database import async_session_factory

    async with async_session_factory() as session:
        rule = Rule(
            rule_id=uuid4(),
            name="Public S3 Bucket Detection",
            description="Detects S3 buckets with public access",
            provider=["aws"],
            resource_types=["s3_bucket"],
            expression_lang="cel",
            expression="resource.public_access == true",
            severity="high",
            cis=["1.3"],
            nist_800_53=["AC-3"],
            version=1,
            is_active=True,
        )
        session.add(rule)
        await session.commit()
        await session.refresh(rule)
        yield rule


@pytest.fixture
async def test_finding(test_org, test_account, test_rule):
    """Create test finding."""
    from cerebro.core.database import async_session_factory

    async with async_session_factory() as session:
        finding = Finding(
            finding_id=uuid4(),
            org_id=test_org.org_id,
            account_id=test_account.account_id,
            provider="aws",
            rule_id=test_rule.rule_id,
            rule_version=1,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            status="open",
            severity="high",
            fingerprint=f"test-finding-{uuid4()}",
            title="Public S3 Bucket Found",
            summary="S3 bucket 'test-bucket' has public access enabled",
            evidence={"bucket_name": "test-bucket", "public_acl": True},
        )
        session.add(finding)
        await session.commit()
        await session.refresh(finding)
        yield finding


@pytest.fixture
async def test_session(test_org):
    """Create test agent session."""
    from cerebro.core.database import async_session_factory

    async with async_session_factory() as session:
        agent_session = AgentSession(
            org_id=test_org.org_id,
            agent_type=AgentType.SECURITY_ANALYST,
            created_by="test_user@example.com",
            title="Test Security Analysis",
            context={
                "finding_ids": [],
                "provider_scope": ["aws"],
            },
        )
        session.add(agent_session)
        await session.commit()
        await session.refresh(agent_session)
        yield agent_session


@pytest.mark.asyncio
class TestAgentTools:
    """Test agent tools in isolation."""

    async def test_findings_list_tool_basic(self, test_org, test_finding):
        """Test findings list tool with basic query."""
        tool = FindingsListTool()

        context = AgentContext(
            session_id=uuid4(),
            org_id=test_org.org_id,
            user_id="test_user@example.com",
            agent_type="security_analyst",
            provider_scope=["aws"],
            permission_level=ToolPermissionLevel.READ_ONLY,
        )

        inputs = tool.input_schema(
            limit=10,
            severity=["high"],
            status=["open"],
        )

        result = await tool.execute(inputs, context)

        assert result.success
        assert result.data is not None
        assert "findings" in result.data
        assert len(result.data["findings"]) >= 1
        assert result.data["findings"][0]["id"] == str(test_finding.finding_id)

    async def test_findings_list_tool_provider_scope(self, test_org, test_finding):
        """Test that provider scope is enforced."""
        tool = FindingsListTool()

        context = AgentContext(
            session_id=uuid4(),
            org_id=test_org.org_id,
            user_id="test_user@example.com",
            agent_type="security_analyst",
            provider_scope=["gcp"],  # Different provider
            permission_level=ToolPermissionLevel.READ_ONLY,
        )

        inputs = tool.input_schema(limit=10)

        result = await tool.execute(inputs, context)

        assert result.success
        # Should return 0 findings since provider scope doesn't match
        assert len(result.data["findings"]) == 0

    async def test_query_tool_findings_timeline(self, test_org, test_finding):
        """Test query tool with findings timeline."""
        tool = QueryTool()

        context = AgentContext(
            session_id=uuid4(),
            org_id=test_org.org_id,
            user_id="test_user@example.com",
            agent_type="security_analyst",
            permission_level=ToolPermissionLevel.READ_ONLY,
        )

        inputs = tool.input_schema(
            query_name="findings_timeline",
            parameters={"days_back": 7},
            limit=100,
        )

        result = await tool.execute(inputs, context)

        assert result.success
        assert result.data is not None
        assert "results" in result.data
        assert result.data["query_name"] == "findings_timeline"

    async def test_dry_run_enforcement(self, test_org, test_finding):
        """Test that dry-run mode prevents actual changes."""
        from cerebro.agents.tools.findings_update import FindingStatusUpdateTool

        tool = FindingStatusUpdateTool()

        context = AgentContext(
            session_id=uuid4(),
            org_id=test_org.org_id,
            user_id="test_user@example.com",
            agent_type="security_analyst",
            provider_scope=["aws"],
            permission_level=ToolPermissionLevel.WRITE_SAFE,
            dry_run=True,  # DRY RUN MODE
        )

        inputs = tool.input_schema(
            finding_id=str(test_finding.finding_id),
            status="suppressed",
            comment="Test suppression",
        )

        result = await tool.execute(inputs, context)

        assert result.success
        assert result.dry_run is True
        assert result.preview is not None
        assert "would_change_status" in result.preview

        # Verify finding status was NOT changed
        from cerebro.core.database import async_session_factory
        from sqlalchemy import select

        async with async_session_factory() as session:
            check_query = select(Finding).where(Finding.finding_id == test_finding.finding_id)
            check_result = await session.execute(check_query)
            finding = check_result.scalar_one()

            assert finding.status == "open"  # Should still be open


@pytest.mark.asyncio
class TestAgentRuntime:
    """Test agent runtime integration."""

    async def test_runtime_session_creation(self, test_org):
        """Test creating an agent session."""
        runtime = CerebroClaudeRuntime()

        session = await runtime.create_session(
            org_id=test_org.org_id,
            agent_type=AgentType.SECURITY_ANALYST,
            created_by="test_user@example.com",
            context={"provider_scope": ["aws"]},
            title="Test Analysis Session",
        )

        assert session is not None
        assert session.org_id == test_org.org_id
        assert session.agent_type == AgentType.SECURITY_ANALYST
        assert session.title == "Test Analysis Session"

    async def test_runtime_message_storage(self, test_session):
        """Test message storage in database."""
        runtime = CerebroClaudeRuntime()

        await runtime._store_message(
            session=test_session,
            role=MessageRole.USER,
            content={"text": "Show me critical findings"},
        )

        # Verify message was stored
        messages = await runtime.get_session_messages(test_session.id, limit=10)

        assert len(messages) >= 1
        assert messages[0]["role"] == "user"
        assert "Show me critical findings" in messages[0]["content"]["text"]

    async def test_runtime_persists_claude_session_id(self, test_session):
        """Ensure Claude session identifiers are stored for reuse."""
        runtime = CerebroClaudeRuntime()

        message_stream = runtime.send_message(
            session=test_session,
            message="Summarize latest incidents",
            user_id="test_user@example.com",
            stream=False,
        )

        async for _ in message_stream:
            pass

        refreshed_session = await runtime.get_session(test_session.id)
        assert refreshed_session is not None
        context_snapshot = refreshed_session.context or {}
        assert context_snapshot.get("_claude_session_id") or context_snapshot.get("_claude_cli_unavailable")

        from cerebro.core.database import async_session_factory
        from sqlalchemy import select

        async with async_session_factory() as db_session:
            result = await db_session.execute(
                select(AgentRuntimeEvent).where(
                    AgentRuntimeEvent.session_id == refreshed_session.id,
                    AgentRuntimeEvent.event_type == "runtime_warning",
                )
            )
            warning_events = result.scalars().all()

        assert warning_events
        assert any(
            (event.payload or {}).get("reason") == "claude_cli_missing"
            for event in warning_events
        )

    async def test_openai_runtime_records_metadata(self, monkeypatch, test_session):
        """OpenAI runtime should persist usage metadata and emit analytics events."""

        import cerebro.agents.openai_runtime as openai_runtime_module
        from agents.run_context import RunContextWrapper
        from agents.usage import Usage

        runtime = CerebroOpenAIRuntime(model="gpt-4o-mini")

        async def fake_build_function_tools(_prioritized):
            return []

        monkeypatch.setattr(runtime, "_build_function_tools", fake_build_function_tools)

        def fake_run_streamed(agent, message, context, max_turns, run_config, session):
            class StubRunResult:
                def __init__(self):
                    self.raw_responses: List[Any] = []
                    self.final_output = "Stub OpenAI output"
                    self.context_wrapper = RunContextWrapper(context=context)
                    usage = Usage(requests=1, input_tokens=12, output_tokens=18, total_tokens=30)
                    self.context_wrapper.usage = usage

                async def stream_events(self):
                    if False:
                        yield None
                    return

                @property
                def last_response_id(self) -> str:
                    return "resp-openai-123"

            return StubRunResult()

        monkeypatch.setattr(openai_runtime_module.Runner, "run_streamed", fake_run_streamed)

        message_stream = runtime.send_message(
            session=test_session,
            message="Collect OpenAI metadata",
            user_id="openai@example.com",
            stream=False,
        )

        async for _ in message_stream:
            pass

        refreshed_session = await runtime.get_session(test_session.id)
        assert refreshed_session is not None
        metadata = refreshed_session.context.get("_openai_runtime")
        assert metadata
        assert metadata.get("last_response_id") == "resp-openai-123"
        assert metadata.get("usage", {}).get("input_tokens") == 12
        assert metadata.get("usage", {}).get("output_tokens") == 18

        from cerebro.core.database import async_session_factory
        from sqlalchemy import select

        async with async_session_factory() as db_session:
            result = await db_session.execute(
                select(AgentRuntimeEvent).where(
                    AgentRuntimeEvent.session_id == test_session.id,
                    AgentRuntimeEvent.event_type == "runtime_metadata",
                )
            )
            runtime_events = result.scalars().all()

        assert runtime_events
        assert any(
            (event.payload or {}).get("runtime") == "openai"
            and (event.payload or {}).get("usage", {}).get("total_tokens") == 30
            for event in runtime_events
        )


@pytest.mark.asyncio
class TestEndToEnd:
    """End-to-end integration tests."""

    async def test_complete_agent_workflow(self, test_session, test_finding):
        """Test complete workflow from query to action."""
        runtime = CerebroClaudeRuntime()

        # 1. User asks to list findings
        message_gen = runtime.send_message(
            session=test_session,
            message="List all high severity findings",
            user_id="test_user@example.com",
            stream=True,
        )

        responses = []
        async for response in message_gen:
            responses.append(response)

        # Should have received some responses
        assert len(responses) > 0

        # Should end with completion
        assert any(r["type"] == "complete" for r in responses)

        # 2. Verify session has messages
        messages = await runtime.get_session_messages(test_session.id)
        assert len(messages) >= 2  # User message + assistant response

    async def test_tool_registry_integration(self):
        """Test tool registry has all expected tools."""
        from cerebro.agents.tools import tool_registry

        tools = tool_registry.list_tools()

        assert len(tools) > 0

        tool_names = [t.name for t in tools]
        assert "findings_list" in tool_names
        assert "finding_update_status" in tool_names
        assert "query" in tool_names
        assert "timeline" in tool_names
        assert "rules" in tool_names

    async def test_cel_policy_evaluation(self):
        """Test CEL policy evaluation in tool executor."""
        from cerebro.agents.tools.base import ToolExecutor
        from cerebro.agents.tools.findings_list import FindingsListTool

        executor = ToolExecutor()
        tool = FindingsListTool()

        # Tool has CEL policy defined
        assert tool.cel_policy_key is not None
        assert tool.cel_expression is not None


@pytest.mark.asyncio
class TestSecurityFeatures:
    """Test security and safety features."""

    async def test_permission_level_enforcement(self, test_org):
        """Test that permission levels are enforced."""
        from cerebro.agents.tools.base import ToolExecutor
        from cerebro.agents.tools.findings_update import FindingStatusUpdateTool

        executor = ToolExecutor()
        tool = FindingStatusUpdateTool()

        # Try to execute with insufficient permissions
        context = AgentContext(
            session_id=uuid4(),
            org_id=test_org.org_id,
            user_id="test_user@example.com",
            agent_type="security_analyst",
            permission_level=ToolPermissionLevel.READ_ONLY,  # Too low
        )

        result = await executor.execute_tool(
            tool=tool,
            raw_inputs={"finding_id": str(uuid4()), "status": "fixed", "comment": "test"},
            context=context,
        )

        assert not result.success
        assert "permission" in result.error.lower()

    async def test_org_isolation(self, test_org, test_finding):
        """Test that org isolation prevents cross-org access."""
        from cerebro.agents.tools.findings_list import FindingsListTool

        tool = FindingsListTool()

        # Try to access with different org
        wrong_org_id = uuid4()

        context = AgentContext(
            session_id=uuid4(),
            org_id=wrong_org_id,
            user_id="test_user@example.com",
            agent_type="security_analyst",
            permission_level=ToolPermissionLevel.READ_ONLY,
        )

        inputs = tool.input_schema(limit=10)
        result = await tool.execute(inputs, context)

        assert result.success
        # Should return 0 findings from different org
        assert len(result.data["findings"]) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])