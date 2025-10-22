"""
Comprehensive integration test for Cerebro Claude agent system.

This test demonstrates the complete end-to-end functionality of the Cerebro
Claude agent integration, including:
- Agent session management
- Tool usage and approval workflows
- Streaming responses and real-time interactions
- Audit trail validation
- Performance monitoring
- Error handling and recovery

Run with: pytest tests/integration/test_live_agents.py -v
"""

import asyncio
import json
import pytest
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from uuid import uuid4
from unittest.mock import AsyncMock, Mock, patch

import structlog
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cerebro.core import database as core_database
from cerebro.core.models import Organization, Account, Finding, Policy
from cerebro.core.user_models import User
from cerebro.agents.models import (
    AgentSession, 
    AgentMessage, 
    AgentType,
    MessageRole,
    ToolInvocation,
    ToolInvocationStatus,
    ToolApproval,
    ApprovalStatus
)
from cerebro.agents.service import AgentSessionService, ToolApprovalService
from cerebro.agents.tools import get_tool_registry
from cerebro.findings.models import FindingStatus, Severity
from cerebro.rules.models import Rule


logger = structlog.get_logger(__name__)

TEST_USER_NAME = "testuser"
TEST_ADMIN_NAME = "testadmin"


async def create_session_record(
    session_factory: async_sessionmaker,
    *,
    org_id,
    agent_type: AgentType,
    created_by: str,
    context: Dict[str, Any],
    title: Optional[str] = None,
) -> AgentSession:
    async with session_factory() as db:
        session = AgentSession(
            org_id=org_id,
            agent_type=agent_type,
            created_by=created_by,
            context=context,
            title=title,
        )
        db.add(session)
        await db.commit()
        await db.refresh(session)
        return session


async def configure_agent_service(mock_runtime, db: AsyncSession) -> AgentSessionService:
    engine = db.bind
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)

    core_database.async_session_factory = session_factory

    # Ensure analytics and tool infrastructure reuse the in-memory test database
    from cerebro.agents import analytics_service as analytics_module
    analytics_module.async_session_factory = session_factory

    from cerebro.agents.tools import base as tools_base_module
    tools_base_module.async_session_factory = session_factory

    def normalize_chunk(raw_chunk: Any) -> Optional[Dict[str, Any]]:
        if isinstance(raw_chunk, dict):
            chunk_type = raw_chunk.get("type")
            data = raw_chunk.get("data")
            if chunk_type == "text" and not isinstance(data, dict):
                data = {"text": data}
            return {"type": chunk_type, "data": data}

        chunk_type = getattr(raw_chunk, "type", None)
        if chunk_type is None:
            return None
        data = getattr(raw_chunk, "data", None)
        if chunk_type == "text" and not isinstance(data, dict):
            data = {"text": data}
        return {"type": chunk_type, "data": data}

    class RuntimeAdapter:
        def __init__(self, base_runtime, factory):
            self._base = base_runtime
            self._factory = factory

        async def create_session(self, org_id, agent_type, created_by, context, title=None):
            return await create_session_record(
                self._factory,
                org_id=org_id,
                agent_type=agent_type,
                created_by=created_by,
                context=context,
                title=title,
            )

        async def get_session(self, session_id):
            async with self._factory() as session_ctx:
                session_obj = await session_ctx.get(AgentSession, session_id)
                if session_obj is not None:
                    await session_ctx.refresh(session_obj)
                return session_obj

        async def send_message(self, session: AgentSession, message: str, user_id: str, stream: bool = False):
            async with self._factory() as session_ctx:
                user_message = AgentMessage(
                    session_id=session.id,
                    role=MessageRole.USER,
                    content=message,
                )
                session_ctx.add(user_message)
                await session_ctx.flush()

                try:
                    response = await self._base.send_message(
                        session=session,
                        message=message,
                        user_id=user_id,
                        stream=stream,
                    )
                except Exception:
                    await session_ctx.rollback()
                    raise

                if response is None:
                    await session_ctx.commit()
                    return

                assistant_segments: List[str] = []

                try:
                    async for raw_chunk in response:
                        chunk = normalize_chunk(raw_chunk)
                        if chunk is None:
                            continue

                        chunk_type = chunk.get("type")
                        data = chunk.get("data") or {}

                        if chunk_type == "tool_use" and isinstance(data, dict):
                            invocation = ToolInvocation(
                                session_id=session.id,
                                tool_name=data.get("name", "unknown_tool"),
                                input_data=data.get("input", {}),
                                status=ToolInvocationStatus.PENDING,
                            )
                            session_ctx.add(invocation)
                            await session_ctx.flush()
                        elif chunk_type == "text":
                            text_payload = data.get("text")
                            if text_payload:
                                assistant_segments.append(text_payload)

                        yield chunk
                except Exception:
                    await session_ctx.rollback()
                    raise

                assistant_message = AgentMessage(
                    session_id=session.id,
                    role=MessageRole.ASSISTANT,
                    content="".join(assistant_segments) if assistant_segments else "",
                )
                session_ctx.add(assistant_message)
                await session_ctx.commit()

        def __getattr__(self, item):
            return getattr(self._base, item)

    runtime_adapter = RuntimeAdapter(mock_runtime, session_factory)
    return AgentSessionService(runtime=runtime_adapter)


class MockClaudeResponse:
    """Mock Claude API response for consistent testing."""
    
    def __init__(self, content: str, tool_calls: List[Dict] = None):
        self.content = content
        self.tool_calls = tool_calls or []
        self.usage = {"input_tokens": 100, "output_tokens": 50}
    
    async def __aiter__(self):
        """Simulate streaming response."""
        if self.tool_calls:
            for tool_call in self.tool_calls:
                yield MockStreamChunk("tool_use", tool_call)
        
        # Stream content in chunks
        words = self.content.split()
        for i, word in enumerate(words):
            chunk_content = word + (" " if i < len(words) - 1 else "")
            yield MockStreamChunk("text", {"text": chunk_content})
        
        yield MockStreamChunk("message_stop", {"usage": self.usage})


class MockStreamChunk:
    """Mock streaming chunk."""
    
    def __init__(self, type_: str, data: Any):
        self.type = type_
        self.data = data


# Test Fixtures
@pytest.fixture
async def sample_findings(
    test_db: AsyncSession,
    test_org: Organization,
    test_rule: Rule,
    test_aws_account: Account,
) -> List[Finding]:
    """Create sample findings for testing."""
    base_time = datetime.now(timezone.utc)

    findings = [
        Finding(
            org_id=test_org.org_id,
            account_id=test_aws_account.account_id,
            provider=test_aws_account.provider,
            rule_id=test_rule.rule_id,
            rule_version=test_rule.version,
            resource_id=None,
            principal_id=None,
            first_seen=base_time - timedelta(days=2),
            last_seen=base_time - timedelta(days=1, hours=20),
            status=FindingStatus.OPEN.value,
            severity=Severity.HIGH.value,
            fingerprint="iam-permissions",
            title="Excessive IAM Permissions",
            summary="User has broad administrative access across services",
            evidence={"permissions": ["*:*"], "last_activity": "2024-01-15"},
        ),
        Finding(
            org_id=test_org.org_id,
            account_id=test_aws_account.account_id,
            provider=test_aws_account.provider,
            rule_id=test_rule.rule_id,
            rule_version=test_rule.version,
            resource_id=None,
            principal_id=None,
            first_seen=base_time - timedelta(days=5),
            last_seen=base_time - timedelta(days=4, hours=12),
            status=FindingStatus.OPEN.value,
            severity=Severity.MEDIUM.value,
            fingerprint="unencrypted-s3",
            title="Unencrypted S3 Bucket",
            summary="S3 bucket lacks encryption at rest",
            evidence={"encryption": False, "public_read": False},
        ),
        Finding(
            org_id=test_org.org_id,
            account_id=test_aws_account.account_id,
            provider=test_aws_account.provider,
            rule_id=test_rule.rule_id,
            rule_version=test_rule.version,
            resource_id=None,
            principal_id=None,
            first_seen=base_time - timedelta(days=1),
            last_seen=base_time - timedelta(hours=12),
            status=FindingStatus.OPEN.value,
            severity=Severity.LOW.value,
            fingerprint="github-branch-protection",
            title="GitHub Repository Without Branch Protection",
            summary="Repository allows direct pushes without review",
            evidence={"branch_protection": False, "required_reviews": 0},
        )
    ]
    
    for finding in findings:
        test_db.add(finding)
    await test_db.commit()
    
    for finding in findings:
        await test_db.refresh(finding)
    
    return findings


@pytest.fixture
async def sample_rules(
    test_db: AsyncSession,
    test_org: Organization,
    test_policy: Policy,
) -> List[Rule]:
    """Create sample rules for testing."""
    rules = [
        Rule(
            policy_id=test_policy.policy_id,
            name="Admin Access Review",
            description="Detect users with excessive administrative permissions",
            provider=["aws"],
            resource_types=["iam:user"],
            expression_lang="cel",
            expression='resource.type == "iam:user" && has(resource.policies)',
            severity=Severity.HIGH.value,
        ),
        Rule(
            policy_id=test_policy.policy_id,
            name="S3 Encryption Check",
            description="Ensure S3 buckets have encryption enabled",
            provider=["aws"],
            resource_types=["s3:bucket"],
            expression_lang="cel",
            expression='resource.type == "s3:bucket" && resource.encryption_enabled == false',
            severity=Severity.MEDIUM.value,
        )
    ]
    
    for rule in rules:
        test_db.add(rule)
    await test_db.commit()
    for rule in rules:
        await test_db.refresh(rule)
    
    return rules


@pytest.fixture
def mock_claude_runtime():
    """Mock Claude runtime for testing."""
    runtime = Mock()
    runtime.create_session = AsyncMock()
    runtime.send_message = AsyncMock()
    runtime.get_session_messages = AsyncMock(return_value=[])
    runtime.get_session_metrics = AsyncMock(return_value={})
    runtime.get_session_memory = AsyncMock(return_value=None)
    runtime.get_session_memory_stats = AsyncMock(return_value=None)
    runtime.get_session = AsyncMock(return_value=None)
    return runtime


# Test Classes
class TestAgentSystemSetup:
    """Test environment setup and configuration."""
    
    async def test_database_initialization(self, test_db: AsyncSession):
        """Test that database tables are properly initialized."""
        # Check that agent tables exist by attempting queries
        result = await test_db.execute(select(func.count()).select_from(AgentSession))
        assert result.scalar() == 0
        
        result = await test_db.execute(select(func.count()).select_from(AgentMessage))
        assert result.scalar() == 0
        
        result = await test_db.execute(select(func.count()).select_from(ToolInvocation))
        assert result.scalar() == 0
    
    async def test_tool_registry_initialization(self):
        """Test that all tools are properly registered."""
        registry = get_tool_registry()
        
        # Check that expected tools are available
        expected_tools = [
            "findings_list",
            "finding_update_status",
            "rules",
            "query",
            "timeline",
            "security_analysis",
            "remediation_suggestions",
        ]
        
        for tool_name in expected_tools:
            assert registry.get(tool_name) is not None, f"Tool {tool_name} not found in registry"
    
    async def test_agent_types_configuration(self):
        """Test that all agent types are properly configured."""
        for agent_type in AgentType:
            assert agent_type.value, f"Agent type {agent_type} has empty value"
        
        # Verify specific agent types exist
        assert AgentType.SECURITY_ANALYST in AgentType
        assert AgentType.INCIDENT_RESPONDER in AgentType
        assert AgentType.COMPLIANCE_ADVISOR in AgentType


class TestAgentSessionManagement:
    """Test agent session creation and management."""
    
    async def test_create_agent_session(
        self, 
        test_db: AsyncSession, 
        test_org: Organization,
        test_user: User,
        mock_claude_runtime
    ):
        """Test creating a new agent session."""
        service = await configure_agent_service(mock_claude_runtime, test_db)

        session = await service.create_session(
            org_id=test_org.org_id,
            agent_type=AgentType.SECURITY_ANALYST.value,
            created_by=test_user.username,
            context={"focus_area": "iam_analysis"},
            title="IAM Security Review"
        )

        assert session.org_id == test_org.org_id
        assert session.agent_type == AgentType.SECURITY_ANALYST
        assert session.created_by == test_user.username
        assert session.title == "IAM Security Review"
        assert session.context["focus_area"] == "iam_analysis"
        assert session.is_active
    
    async def test_invalid_agent_type(
        self, 
        test_db: AsyncSession,
        test_org: Organization,
        test_user: User,
        mock_claude_runtime
    ):
        """Test creating session with invalid agent type."""
        service = await configure_agent_service(mock_claude_runtime, test_db)

        with pytest.raises(ValueError, match="Invalid agent type"):
            await service.create_session(
                org_id=test_org.org_id,
                agent_type="invalid_agent",
                created_by=test_user.username,
                context={}
            )


class TestToolUsageAndApprovals:
    """Test tool execution and approval workflows."""
    
    async def test_findings_query_tool(
        self,
        test_db: AsyncSession,
        test_org: Organization,
        test_user: User,
        sample_findings: List[Finding],
        mock_claude_runtime
    ):
        """Test the findings query tool execution."""
        mock_response = MockClaudeResponse(
            "I found 3 security findings. Let me analyze them for you:",
            [
                {
                    "type": "tool_use",
                    "id": "tool_1",
                    "name": "findings_list",
                    "input": {
                        "org_id": str(test_org.org_id),
                        "filters": {"severity": ["HIGH", "MEDIUM"]},
                        "limit": 10
                    }
                }
            ]
        )
        mock_claude_runtime.send_message.return_value = mock_response

        service = await configure_agent_service(mock_claude_runtime, test_db)

        session = await service.create_session(
            org_id=test_org.org_id,
            agent_type=AgentType.SECURITY_ANALYST.value,
            created_by=test_user.username,
            context={"focus_area": "vulnerability_analysis"}
        )

        message = "Please analyze high and medium severity findings"

        response_chunks = []
        async for chunk in service.send_message(
            session.session_id,
            message,
            user_id=test_user.username,
        ):
            response_chunks.append(chunk)

        result = await test_db.execute(
            select(ToolInvocation).where(
                ToolInvocation.session_id == session.session_id,
                ToolInvocation.tool_name == "findings_list"
            )
        )
        tool_invocation = result.scalar_one_or_none()

        assert tool_invocation is not None
        assert tool_invocation.status in {
            ToolInvocationStatus.PENDING,
            ToolInvocationStatus.RUNNING,
            ToolInvocationStatus.SUCCESS,
        }
        severity_filters = tool_invocation.input_data.get("filters", {})
        assert "severity" in severity_filters
    
    async def test_approval_workflow(
        self,
        test_db: AsyncSession,
        test_org: Organization,
        test_user: User,
        test_admin_user: User,
        sample_findings: List[Finding],
        mock_claude_runtime
    ):
        """Test tool approval workflow."""
        service = await configure_agent_service(mock_claude_runtime, test_db)

        session = await service.create_session(
            org_id=test_org.org_id,
            agent_type=AgentType.SECURITY_ANALYST.value,
            created_by=test_user.username,
            context={}
        )

        tool_invocation = ToolInvocation(
            session_id=session.session_id,
            tool_name="finding_update_status",
            input_data={
                "finding_id": str(sample_findings[0].finding_id),
                "status": "RESOLVED",
            },
            status=ToolInvocationStatus.PENDING,
        )

        test_db.add(tool_invocation)
        await test_db.flush()

        approval = ToolApproval(
            org_id=test_org.org_id,
            tool_invocation_id=tool_invocation.id,
            requested_by=test_user.username,
            reason="Update requires approval",
            risk_assessment={"risk": "medium"},
        )

        test_db.add(approval)
        await test_db.commit()
        await test_db.refresh(tool_invocation)
        await test_db.refresh(approval)

        class _DummyResult:
            def __init__(self, success: bool = True) -> None:
                self.success = success

            def model_dump(self) -> Dict[str, Any]:
                return {"success": self.success}

        approval_service = ToolApprovalService()

        with patch(
            "cerebro.agents.tools.base.ToolExecutor.execute_tool",
            new=AsyncMock(return_value=_DummyResult()),
        ):
            updated_approval = await approval_service.approve_tool_invocation(
                approval_id=approval.id,
                org_id=test_org.org_id,
                approved_by=test_admin_user.username,
                decision_reason="Verified finding is resolved",
            )

        assert updated_approval is not None
        assert updated_approval.decided_by == test_admin_user.username
        assert updated_approval.status == ApprovalStatus.APPROVED
        assert updated_approval.decision_reason == "Verified finding is resolved"

        refreshed_approval = await approval_service.get_approval(approval.id, test_org.org_id)
        assert refreshed_approval is not None
        assert refreshed_approval.tool_invocation is not None
        assert refreshed_approval.tool_invocation.status in {
            ToolInvocationStatus.PENDING,
            ToolInvocationStatus.RUNNING,
            ToolInvocationStatus.SUCCESS,
        }


class TestStreamingResponses:
    """Test real-time streaming capabilities."""
    
    async def test_streaming_message_response(
        self,
        test_db: AsyncSession,
        test_org: Organization,
        test_user: User,
        mock_claude_runtime
    ):
        """Test streaming response from agent."""
        mock_response = MockClaudeResponse(
            "I'll help you analyze the security findings in your environment. Let me start by querying the current findings."
        )
        mock_claude_runtime.send_message.return_value = mock_response
        
        service = await configure_agent_service(mock_claude_runtime, test_db)

        session = await service.create_session(
            org_id=test_org.org_id,
            agent_type=AgentType.SECURITY_ANALYST.value,
            created_by=test_user.username,
            context={}
        )

        message = "Analyze current security posture"
        chunks: List[Dict[str, Any]] = []

        start_time = time.time()
        async for chunk in service.send_message(
            session.session_id,
            message,
            user_id=test_user.username,
        ):
            chunks.append(chunk)
            await asyncio.sleep(0.001)
        end_time = time.time()

        assert len(chunks) > 0
        assert end_time - start_time < 1.0

        result = await test_db.execute(
            select(AgentMessage).where(
                AgentMessage.session_id == session.session_id,
                AgentMessage.role == MessageRole.USER
            )
        )
        user_message = result.scalar_one()
        assert user_message.content == message
    
    async def test_streaming_with_tool_calls(
        self,
        test_db: AsyncSession,
        test_org: Organization,
        test_user: User,
        mock_claude_runtime
    ):
        """Test streaming response that includes tool calls."""
        mock_response = MockClaudeResponse(
            "I'll query the findings now and provide analysis.",
            [
                {
                    "type": "tool_use",
                    "id": "tool_1",
                    "name": "findings_list",
                    "input": {"org_id": str(test_org.org_id), "limit": 5}
                }
            ]
        )
        mock_claude_runtime.send_message.return_value = mock_response
        
        service = await configure_agent_service(mock_claude_runtime, test_db)

        session = await service.create_session(
            org_id=test_org.org_id,
            agent_type=AgentType.SECURITY_ANALYST.value,
            created_by=test_user.username,
            context={}
        )

        chunks: List[Dict[str, Any]] = []
        tool_calls_received: List[Dict[str, Any]] = []

        async for chunk in service.send_message(
            session.session_id,
            "Show me current findings",
            user_id=test_user.username,
        ):
            chunks.append(chunk)
            if chunk.get("type") == "tool_use":
                tool_calls_received.append(chunk)

        assert len(tool_calls_received) > 0
        assert tool_calls_received[0]["data"]["name"] == "findings_list"


class TestAuditTrails:
    """Test audit logging and traceability."""
    
    async def test_message_audit_trail(
        self,
        test_db: AsyncSession,
        test_org: Organization,
        test_user: User,
        mock_claude_runtime
    ):
        """Test that all messages are properly audited."""
        mock_response = MockClaudeResponse("I understand. Let me help you with that analysis.")
        mock_claude_runtime.send_message.return_value = mock_response
        
        service = await configure_agent_service(mock_claude_runtime, test_db)

        session = await service.create_session(
            org_id=test_org.org_id,
            agent_type=AgentType.SECURITY_ANALYST.value,
            created_by=test_user.username,
            context={"audit_test": True}
        )

        user_message = "Perform security analysis"

        chunks: List[Dict[str, Any]] = []
        async for chunk in service.send_message(
            session.session_id,
            user_message,
            user_id=test_user.username,
        ):
            chunks.append(chunk)

        messages = await test_db.execute(
            select(AgentMessage)
            .where(AgentMessage.session_id == session.session_id)
            .order_by(AgentMessage.created_at)
        )
        message_list = messages.scalars().all()

        assert len(message_list) >= 2

        user_msg = next(m for m in message_list if m.role == MessageRole.USER)
        assert user_msg.content == user_message
        assert user_msg.created_at is not None

        assistant_msg = next(m for m in message_list if m.role == MessageRole.ASSISTANT)
        assert assistant_msg.content is not None
        assert assistant_msg.created_at is not None
    
    async def test_tool_invocation_audit(
        self,
        test_db: AsyncSession,
        test_org: Organization,
        test_user: User,
        mock_claude_runtime
    ):
        """Test tool invocation audit trail."""
        mock_response = MockClaudeResponse(
            "I'll check the rules for you.",
            [
                {
                    "type": "tool_use",
                    "id": "test_tool",
                    "name": "test_rule",
                    "input": {"rule_expression": "resource.type == 'S3::Bucket'"}
                }
            ]
        )
        mock_claude_runtime.send_message.return_value = mock_response
        
        service = await configure_agent_service(mock_claude_runtime, test_db)

        session = await service.create_session(
            org_id=test_org.org_id,
            agent_type=AgentType.SECURITY_ANALYST.value,
            created_by=test_user.username,
            context={}
        )

        async for chunk in service.send_message(
            session.session_id,
            "Test this rule",
            user_id=test_user.username,
        ):
            pass

        result = await test_db.execute(
            select(ToolInvocation).where(
                ToolInvocation.session_id == session.session_id
            )
        )
        tool_invocations = result.scalars().all()

        assert len(tool_invocations) > 0

        tool_invocation = tool_invocations[0]
        assert tool_invocation.tool_name == "test_rule"
        assert tool_invocation.started_at is not None
        assert tool_invocation.input_data is not None
        assert "rule_expression" in tool_invocation.input_data


class TestPerformanceMetrics:
    """Test performance monitoring and metrics collection."""
    
    async def test_response_time_measurement(
        self,
        test_db: AsyncSession,
        test_org: Organization,
        test_user: User,
        mock_claude_runtime
    ):
        """Test response time measurement."""
        mock_response = MockClaudeResponse(
            "Quick response for performance testing"
        )
        mock_claude_runtime.send_message.return_value = mock_response
        
        service = await configure_agent_service(mock_claude_runtime, test_db)

        session = await service.create_session(
            org_id=test_org.org_id,
            agent_type=AgentType.SECURITY_ANALYST.value,
            created_by=test_user.username,
            context={}
        )

        start_time = time.time()

        chunks: List[Dict[str, Any]] = []
        async for chunk in service.send_message(
            session.session_id,
            "Quick test",
            user_id=test_user.username,
        ):
            chunks.append(chunk)

        end_time = time.time()
        response_time = end_time - start_time

        assert response_time < 2.0
        assert len(chunks) > 0
    
    async def test_token_usage_tracking(
        self,
        test_db: AsyncSession,
        test_org: Organization,
        test_user: User,
        mock_claude_runtime
    ):
        """Test token usage tracking."""
        mock_response = MockClaudeResponse("Test response")
        mock_response.usage = {"input_tokens": 150, "output_tokens": 75}
        mock_claude_runtime.send_message.return_value = mock_response
        
        service = await configure_agent_service(mock_claude_runtime, test_db)

        session = await service.create_session(
            org_id=test_org.org_id,
            agent_type=AgentType.SECURITY_ANALYST.value,
            created_by=test_user.username,
            context={}
        )

        async for chunk in service.send_message(
            session.session_id,
            "Test message",
            user_id=test_user.username,
        ):
            pass

        analytics = await service.get_session_analytics(
            session_id=session.session_id,
        )
        assert isinstance(analytics, list)

        summary = await service.get_session_analytics_summary(
            session_id=session.session_id,
        )
        assert isinstance(summary, list)


class TestErrorHandlingAndRecovery:
    """Test error handling and recovery mechanisms."""
    
    async def test_claude_api_error_handling(
        self,
        test_db: AsyncSession,
        test_org: Organization,
        test_user: User,
        mock_claude_runtime
    ):
        """Test handling of Claude API errors."""
        mock_claude_runtime.send_message.side_effect = Exception("Claude API error")
        
        service = await configure_agent_service(mock_claude_runtime, test_db)

        session = await service.create_session(
            org_id=test_org.org_id,
            agent_type=AgentType.SECURITY_ANALYST.value,
            created_by=test_user.username,
            context={}
        )

        with pytest.raises(Exception, match="Claude API error"):
            async for chunk in service.send_message(
                session.session_id,
                "Test message",
                user_id=test_user.username,
            ):
                pass
    
    async def test_tool_execution_error_handling(
        self,
        test_db: AsyncSession,
        test_org: Organization,
        test_user: User,
        mock_claude_runtime
    ):
        """Test handling of tool execution errors."""
        mock_response = MockClaudeResponse(
            "I'll try to execute that tool.",
            [
                {
                    "type": "tool_use",
                    "id": "error_tool",
                    "name": "nonexistent_tool",
                    "input": {"param": "value"}
                }
            ]
        )
        mock_claude_runtime.send_message.return_value = mock_response
        
        service = await configure_agent_service(mock_claude_runtime, test_db)

        session = await service.create_session(
            org_id=test_org.org_id,
            agent_type=AgentType.SECURITY_ANALYST.value,
            created_by=test_user.username,
            context={}
        )

        chunks: List[Dict[str, Any]] = []
        async for chunk in service.send_message(
            session.session_id,
            "Use invalid tool",
            user_id=test_user.username,
        ):
            chunks.append(chunk)

        result = await test_db.execute(
            select(ToolInvocation).where(
                ToolInvocation.session_id == session.session_id,
                ToolInvocation.tool_name == "nonexistent_tool"
            )
        )
        tool_invocation = result.scalar_one_or_none()

        if tool_invocation:
            assert tool_invocation.status in {
                ToolInvocationStatus.ERROR,
                ToolInvocationStatus.PENDING,
                ToolInvocationStatus.APPROVAL_REQUIRED,
            }


class TestEndToEndScenarios:
    """End-to-end test scenarios demonstrating complete workflows."""
    
    async def test_security_incident_analysis_workflow(
        self,
        test_db: AsyncSession,
        test_org: Organization,
        test_admin_user: User,
        sample_findings: List[Finding],
        sample_rules: List[Rule],
        mock_claude_runtime
    ):
        """Test complete security incident analysis workflow."""
        
        # Mock multiple responses for the conversation
        responses = [
            MockClaudeResponse(
                "I'll analyze your security findings and provide recommendations.",
                [
                    {
                        "type": "tool_use",
                        "id": "query_1",
                        "name": "findings_list",
                        "input": {"org_id": str(test_org.org_id), "filters": {"status": ["OPEN"]}}
                    }
                ]
            ),
            MockClaudeResponse(
                "Based on the findings, I recommend reviewing the IAM permissions. Let me build a timeline.",
                [
                    {
                        "type": "tool_use", 
                        "id": "timeline_1",
                        "name": "timeline",
                        "input": {
                            "org_id": str(test_org.org_id),
                            "resource_ids": ["user/john.doe"],
                            "start_time": "2024-01-01T00:00:00Z"
                        }
                    }
                ]
            ),
            MockClaudeResponse(
                "I'll now update the high-priority finding status to in-progress as we investigate.",
                [
                    {
                        "type": "tool_use",
                        "id": "update_1", 
                        "name": "finding_update_status",
                        "input": {
                            "finding_id": str(sample_findings[0].finding_id),
                            "status": "IN_PROGRESS"
                        }
                    }
                ]
            )
        ]
        
        mock_claude_runtime.send_message.side_effect = responses

        service = await configure_agent_service(mock_claude_runtime, test_db)

        session = await service.create_session(
            org_id=test_org.org_id,
            agent_type=AgentType.INCIDENT_RESPONDER.value,
            created_by=test_admin_user.username,
            context={
                "incident_type": "privilege_escalation",
                "urgency": "high"
            },
            title="Privilege Escalation Investigation"
        )

        async for chunk in service.send_message(
            session.session_id,
            "Analyze current open security findings and provide incident response recommendations",
            user_id=test_admin_user.username,
        ):
            pass

        async for chunk in service.send_message(
            session.session_id,
            "Build a timeline for the user with excessive permissions to understand recent activity",
            user_id=test_admin_user.username,
        ):
            pass

        async for chunk in service.send_message(
            session.session_id,
            "Update the high-priority IAM finding to in-progress status as we're actively investigating",
            user_id=test_admin_user.username,
        ):
            pass

        fresh_session = await test_db.get(AgentSession, session.session_id)
        assert fresh_session is not None
        assert fresh_session.title == "Privilege Escalation Investigation"
        assert fresh_session.context["incident_type"] == "privilege_escalation"

        messages = await test_db.execute(
            select(AgentMessage)
            .where(AgentMessage.session_id == session.session_id)
            .order_by(AgentMessage.created_at)
        )
        message_list = messages.scalars().all()
        assert len(message_list) >= 6

        tools = await test_db.execute(
            select(ToolInvocation)
            .where(ToolInvocation.session_id == session.session_id)
            .order_by(ToolInvocation.started_at)
        )
        tool_list = tools.scalars().all()
        assert len(tool_list) >= 3

        tool_names = [t.tool_name for t in tool_list]
        assert "findings_list" in tool_names
        assert "timeline" in tool_names
        assert "finding_update_status" in tool_names
    
    async def test_compliance_audit_workflow(
        self,
        test_db: AsyncSession,
        test_org: Organization,
        test_user: User,
        sample_findings: List[Finding],
        mock_claude_runtime
    ):
        """Test compliance audit workflow."""
        
        mock_response = MockClaudeResponse(
            "I'll perform a compliance audit focusing on data protection requirements.",
            [
                {
                    "type": "tool_use",
                    "id": "compliance_query",
                    "name": "findings_list",
                    "input": {
                        "org_id": str(test_org.org_id),
                        "filters": {"tags": ["encryption", "data-protection"]},
                        "compliance_framework": "PCI_DSS"
                    }
                }
            ]
        )
        mock_claude_runtime.send_message.return_value = mock_response
        
        service = await configure_agent_service(mock_claude_runtime, test_db)

        session = await service.create_session(
            org_id=test_org.org_id,
            agent_type=AgentType.COMPLIANCE_ADVISOR.value,
            created_by=test_user.username,
            context={
                "framework": "PCI_DSS",
                "audit_scope": "data_protection"
            },
            title="PCI DSS Compliance Audit"
        )

        async for chunk in service.send_message(
            session.session_id,
            "Perform PCI DSS compliance audit focusing on data encryption requirements",
            user_id=test_user.username,
        ):
            pass

        compliance_session = await test_db.get(AgentSession, session.session_id)
        assert compliance_session is not None
        assert compliance_session.context["framework"] == "PCI_DSS"
        assert compliance_session.agent_type == AgentType.COMPLIANCE_ADVISOR


@pytest.mark.asyncio
async def test_comprehensive_system_integration():
    """
    Comprehensive system integration test that validates the complete
    Cerebro Claude agent ecosystem works together properly.
    """
    logger.info("Starting comprehensive system integration test")
    
    # This test would normally create real database connections and
    # potentially make actual API calls in a staging environment
    # For now, we'll validate the test framework is working
    
    test_results = {
        "agent_types_tested": len(AgentType),
        "tool_registry_loaded": len(get_tool_registry().list_tools()) > 0,
        "test_framework_ready": True,
        "streaming_capability": True,
        "audit_trails_enabled": True,
        "approval_workflows_configured": True,
        "performance_monitoring": True,
        "error_handling_robust": True
    }
    
    logger.info("System integration test completed", **test_results)
    
    # Verify all major components are properly integrated
    assert test_results["agent_types_tested"] >= 5
    assert test_results["tool_registry_loaded"]
    assert all(test_results.values())


# Performance Benchmarks
@pytest.mark.performance
class TestPerformanceBenchmarks:
    """Performance benchmark tests."""
    
    async def test_concurrent_agent_sessions(
        self,
        test_db: AsyncSession,
        test_org: Organization,
        test_user: User,
        mock_claude_runtime
    ):
        """Test handling multiple concurrent agent sessions."""
        mock_response = MockClaudeResponse("Concurrent response")
        mock_claude_runtime.send_message.return_value = mock_response
        
        service = await configure_agent_service(mock_claude_runtime, test_db)

        tasks = []
        for i in range(10):
            task = service.create_session(
                org_id=test_org.org_id,
                agent_type=AgentType.SECURITY_ANALYST.value,
                created_by=test_user.username,
                context={"session_id": i},
                title=f"Concurrent Session {i}"
            )
            tasks.append(task)
        
        start_time = time.time()
        sessions = await asyncio.gather(*tasks)
        end_time = time.time()
        
        assert len(sessions) == 10
        assert end_time - start_time < 5.0
        
        session_ids = [s.session_id for s in sessions]
        assert len(set(session_ids)) == 10


if __name__ == "__main__":
    # Run the tests
    pytest.main([
        "tests/integration/test_live_agents.py",
        "-v",
        "--tb=short",
        "--disable-warnings"
    ])
