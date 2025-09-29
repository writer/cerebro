"""
Core integration test for Cerebro Claude agent system without API dependencies.

This test focuses specifically on the agent functionality without importing
the full API stack that has circular dependencies.
"""

import asyncio
import pytest
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from uuid import uuid4
from unittest.mock import AsyncMock, Mock, patch

import structlog
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

# Import only core agent functionality
from cerebro.agents.models import (
    AgentSession, 
    AgentMessage, 
    AgentType,
    MessageRole,
    ToolInvocation,
    ToolInvocationStatus,
    ToolApproval,
    ApprovalStatus,
    Base as AgentBase
)


logger = structlog.get_logger(__name__)


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


@pytest.fixture
async def agent_db() -> AsyncSession:
    """Create test database session with only agent tables."""
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
    from sqlalchemy.pool import StaticPool
    
    # Use in-memory SQLite for tests
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        echo=False,
    )
    
    # Create only agent tables
    async with engine.begin() as conn:
        await conn.run_sync(AgentBase.metadata.create_all)
    
    # Create session
    async_session = async_sessionmaker(engine, expire_on_commit=False)
    
    async with async_session() as session:
        yield session
    
    await engine.dispose()


@pytest.fixture
def mock_claude_runtime():
    """Mock Claude runtime for testing."""
    runtime = Mock()
    runtime.start_conversation = AsyncMock()
    runtime.send_message = AsyncMock()
    runtime.get_conversation_history = AsyncMock(return_value=[])
    return runtime


class TestAgentModels:
    """Test agent data models."""
    
    async def test_agent_session_creation(self, agent_db: AsyncSession):
        """Test creating an agent session."""
        session = AgentSession(
            org_id=uuid4(),
            agent_type=AgentType.SECURITY_ANALYST,
            created_by="testuser",
            title="Test Session",
            context={"test": True},
            is_active=True
        )
        
        agent_db.add(session)
        await agent_db.commit()
        await agent_db.refresh(session)
        
        assert session.session_id is not None
        assert session.agent_type == AgentType.SECURITY_ANALYST
        assert session.created_by == "testuser"
        assert session.title == "Test Session"
        assert session.context["test"] is True
        assert session.is_active
    
    async def test_agent_message_creation(self, agent_db: AsyncSession):
        """Test creating agent messages."""
        session = AgentSession(
            org_id=uuid4(),
            agent_type=AgentType.SECURITY_ANALYST,
            created_by="testuser",
            context={}
        )
        agent_db.add(session)
        await agent_db.commit()
        await agent_db.refresh(session)
        
        user_message = AgentMessage(
            session_id=session.session_id,
            role=MessageRole.USER,
            content="Test user message",
        )
        
        assistant_message = AgentMessage(
            session_id=session.session_id,
            role=MessageRole.ASSISTANT,
            content="Test assistant response",
        )
        
        agent_db.add_all([user_message, assistant_message])
        await agent_db.commit()
        
        # Verify messages are stored
        result = await agent_db.execute(
            select(AgentMessage)
            .where(AgentMessage.session_id == session.session_id)
            .order_by(AgentMessage.created_at)
        )
        messages = result.scalars().all()
        
        assert len(messages) == 2
        assert messages[0].role == MessageRole.USER
        assert messages[0].content == "Test user message"
        assert messages[1].role == MessageRole.ASSISTANT
        assert messages[1].content == "Test assistant response"
    
    async def test_tool_invocation_creation(self, agent_db: AsyncSession):
        """Test creating tool invocations."""
        session = AgentSession(
            org_id=uuid4(),
            agent_type=AgentType.SECURITY_ANALYST,
            created_by="testuser",
            context={}
        )
        agent_db.add(session)
        await agent_db.commit()
        await agent_db.refresh(session)
        
        message = AgentMessage(
            session_id=session.session_id,
            role=MessageRole.ASSISTANT,
            content="I'll use a tool to help you."
        )
        agent_db.add(message)
        await agent_db.commit()
        await agent_db.refresh(message)
        
        tool_invocation = ToolInvocation(
            session_id=session.session_id,
            message_id=message.message_id,
            tool_name="query_findings",
            tool_input={"filters": {"severity": "HIGH"}},
            status=ToolInvocationStatus.PENDING,
            requires_approval=True
        )
        
        agent_db.add(tool_invocation)
        await agent_db.commit()
        await agent_db.refresh(tool_invocation)
        
        assert tool_invocation.invocation_id is not None
        assert tool_invocation.tool_name == "query_findings"
        assert tool_invocation.tool_input["filters"]["severity"] == "HIGH"
        assert tool_invocation.status == ToolInvocationStatus.PENDING
        assert tool_invocation.requires_approval
    
    async def test_tool_approval_workflow(self, agent_db: AsyncSession):
        """Test tool approval workflow."""
        # Create session and tool invocation
        session = AgentSession(
            org_id=uuid4(),
            agent_type=AgentType.SECURITY_ANALYST,
            created_by="testuser",
            context={}
        )
        agent_db.add(session)
        await agent_db.commit()
        await agent_db.refresh(session)
        
        message = AgentMessage(
            session_id=session.session_id,
            role=MessageRole.ASSISTANT,
            content="Tool execution requested."
        )
        agent_db.add(message)
        await agent_db.commit()
        await agent_db.refresh(message)
        
        tool_invocation = ToolInvocation(
            session_id=session.session_id,
            message_id=message.message_id,
            tool_name="update_finding_status",
            tool_input={"finding_id": str(uuid4()), "status": "RESOLVED"},
            status=ToolInvocationStatus.PENDING,
            requires_approval=True
        )
        agent_db.add(tool_invocation)
        await agent_db.commit()
        await agent_db.refresh(tool_invocation)
        
        # Create approval
        approval = ToolApproval(
            invocation_id=tool_invocation.invocation_id,
            approved_by="admin",
            status=ApprovalStatus.APPROVED,
            reason="Verified finding resolution"
        )
        agent_db.add(approval)
        await agent_db.commit()
        await agent_db.refresh(approval)
        
        # Update tool invocation status
        tool_invocation.status = ToolInvocationStatus.APPROVED
        await agent_db.commit()
        
        # Verify approval workflow
        assert approval.approved_by == "admin"
        assert approval.status == ApprovalStatus.APPROVED
        assert approval.reason == "Verified finding resolution"
        assert tool_invocation.status == ToolInvocationStatus.APPROVED


class TestAgentTypes:
    """Test agent type configuration."""
    
    def test_all_agent_types_exist(self):
        """Test that all expected agent types are defined."""
        expected_types = [
            "security_analyst",
            "incident_responder", 
            "identity_advisor",
            "compliance_advisor",
            "attack_path_analyst"
        ]
        
        actual_types = [agent_type.value for agent_type in AgentType]
        
        for expected_type in expected_types:
            assert expected_type in actual_types, f"Agent type {expected_type} not found"
    
    def test_agent_type_enum_values(self):
        """Test agent type enum values."""
        assert AgentType.SECURITY_ANALYST.value == "security_analyst"
        assert AgentType.INCIDENT_RESPONDER.value == "incident_responder"
        assert AgentType.IDENTITY_ADVISOR.value == "identity_advisor"
        assert AgentType.COMPLIANCE_ADVISOR.value == "compliance_advisor"
        assert AgentType.ATTACK_PATH_ANALYST.value == "attack_path_analyst"


class TestMessageRoles:
    """Test message role configuration."""
    
    def test_message_roles_exist(self):
        """Test that all message roles are defined."""
        expected_roles = ["user", "assistant", "tool", "system"]
        actual_roles = [role.value for role in MessageRole]
        
        for expected_role in expected_roles:
            assert expected_role in actual_roles
    
    def test_message_role_values(self):
        """Test message role enum values."""
        assert MessageRole.USER.value == "user"
        assert MessageRole.ASSISTANT.value == "assistant"
        assert MessageRole.TOOL.value == "tool"
        assert MessageRole.SYSTEM.value == "system"


class TestToolInvocationStatus:
    """Test tool invocation status configuration."""
    
    def test_tool_status_values(self):
        """Test tool invocation status enum values."""
        assert ToolInvocationStatus.PENDING.value == "pending"
        assert ToolInvocationStatus.APPROVED.value == "approved"
        assert ToolInvocationStatus.REJECTED.value == "rejected"
        assert ToolInvocationStatus.EXECUTED.value == "executed"
        assert ToolInvocationStatus.FAILED.value == "failed"


class TestStreamingSimulation:
    """Test streaming response simulation."""
    
    async def test_mock_streaming_response(self):
        """Test mock streaming response functionality."""
        mock_response = MockClaudeResponse(
            "This is a test streaming response.",
            [
                {
                    "type": "tool_use",
                    "id": "test_tool",
                    "name": "test_function",
                    "input": {"param": "value"}
                }
            ]
        )
        
        chunks = []
        async for chunk in mock_response:
            chunks.append(chunk)
        
        # Should have tool call chunks + text chunks + stop chunk
        assert len(chunks) > 5
        
        # First chunk should be tool use
        assert chunks[0].type == "tool_use"
        assert chunks[0].data["name"] == "test_function"
        
        # Last chunk should be message stop
        assert chunks[-1].type == "message_stop"
        assert "usage" in chunks[-1].data
    
    async def test_streaming_performance(self):
        """Test streaming response performance."""
        mock_response = MockClaudeResponse(
            "Quick response for performance testing with multiple words to simulate real streaming"
        )
        
        start_time = time.time()
        
        chunks = []
        async for chunk in mock_response:
            chunks.append(chunk)
            # Simulate processing time
            await asyncio.sleep(0.001)
        
        end_time = time.time()
        
        # Should complete quickly even with simulated processing
        assert end_time - start_time < 1.0
        assert len(chunks) > 10  # Multiple word chunks


class TestDatabaseOperations:
    """Test database operations and queries."""
    
    async def test_session_queries(self, agent_db: AsyncSession):
        """Test querying agent sessions."""
        org_id = uuid4()
        
        # Create multiple sessions
        sessions = [
            AgentSession(
                org_id=org_id,
                agent_type=AgentType.SECURITY_ANALYST,
                created_by="user1",
                title=f"Session {i}",
                context={"index": i}
            )
            for i in range(3)
        ]
        
        agent_db.add_all(sessions)
        await agent_db.commit()
        
        # Query by org_id
        result = await agent_db.execute(
            select(AgentSession).where(AgentSession.org_id == org_id)
        )
        org_sessions = result.scalars().all()
        
        assert len(org_sessions) == 3
        
        # Query by agent type
        result = await agent_db.execute(
            select(AgentSession).where(
                AgentSession.agent_type == AgentType.SECURITY_ANALYST
            )
        )
        analyst_sessions = result.scalars().all()
        
        assert len(analyst_sessions) == 3
    
    async def test_message_ordering(self, agent_db: AsyncSession):
        """Test message ordering by timestamp."""
        session = AgentSession(
            org_id=uuid4(),
            agent_type=AgentType.SECURITY_ANALYST,
            created_by="testuser",
            context={}
        )
        agent_db.add(session)
        await agent_db.commit()
        await agent_db.refresh(session)
        
        # Create messages with specific order
        messages = [
            AgentMessage(
                session_id=session.session_id,
                role=MessageRole.USER,
                content="First message",
            ),
            AgentMessage(
                session_id=session.session_id,
                role=MessageRole.ASSISTANT,
                content="Second message",
            ),
            AgentMessage(
                session_id=session.session_id,
                role=MessageRole.USER,
                content="Third message",
            )
        ]
        
        agent_db.add_all(messages)
        await agent_db.commit()
        
        # Query messages in order
        result = await agent_db.execute(
            select(AgentMessage)
            .where(AgentMessage.session_id == session.session_id)
            .order_by(AgentMessage.created_at)
        )
        ordered_messages = result.scalars().all()
        
        assert len(ordered_messages) == 3
        assert ordered_messages[0].content == "First message"
        assert ordered_messages[1].content == "Second message"
        assert ordered_messages[2].content == "Third message"
    
    async def test_tool_invocation_queries(self, agent_db: AsyncSession):
        """Test tool invocation queries."""
        session = AgentSession(
            org_id=uuid4(),
            agent_type=AgentType.SECURITY_ANALYST,
            created_by="testuser",
            context={}
        )
        agent_db.add(session)
        await agent_db.commit()
        await agent_db.refresh(session)
        
        message = AgentMessage(
            session_id=session.session_id,
            role=MessageRole.ASSISTANT,
            content="Tool usage message"
        )
        agent_db.add(message)
        await agent_db.commit()
        await agent_db.refresh(message)
        
        # Create tool invocations with different statuses
        tool_invocations = [
            ToolInvocation(
                session_id=session.session_id,
                message_id=message.message_id,
                tool_name="query_findings",
                tool_input={"status": "OPEN"},
                status=ToolInvocationStatus.EXECUTED,
                requires_approval=False
            ),
            ToolInvocation(
                session_id=session.session_id,
                message_id=message.message_id,
                tool_name="update_finding",
                tool_input={"id": "123", "status": "RESOLVED"},
                status=ToolInvocationStatus.PENDING,
                requires_approval=True
            )
        ]
        
        agent_db.add_all(tool_invocations)
        await agent_db.commit()
        
        # Query pending approvals
        result = await agent_db.execute(
            select(ToolInvocation).where(
                ToolInvocation.status == ToolInvocationStatus.PENDING,
                ToolInvocation.requires_approval == True
            )
        )
        pending_approvals = result.scalars().all()
        
        assert len(pending_approvals) == 1
        assert pending_approvals[0].tool_name == "update_finding"
        
        # Query executed tools
        result = await agent_db.execute(
            select(ToolInvocation).where(
                ToolInvocation.status == ToolInvocationStatus.EXECUTED
            )
        )
        executed_tools = result.scalars().all()
        
        assert len(executed_tools) == 1
        assert executed_tools[0].tool_name == "query_findings"


class TestConcurrentOperations:
    """Test concurrent database operations."""
    
    async def test_concurrent_session_creation(self, agent_db: AsyncSession):
        """Test creating multiple sessions concurrently."""
        org_id = uuid4()
        
        async def create_session(index: int) -> AgentSession:
            session = AgentSession(
                org_id=org_id,
                agent_type=AgentType.SECURITY_ANALYST,
                created_by=f"user{index}",
                title=f"Concurrent Session {index}",
                context={"index": index}
            )
            agent_db.add(session)
            await agent_db.commit()
            await agent_db.refresh(session)
            return session
        
        # Create multiple sessions concurrently
        tasks = [create_session(i) for i in range(5)]
        sessions = await asyncio.gather(*tasks)
        
        assert len(sessions) == 5
        assert len(set(s.session_id for s in sessions)) == 5  # All unique
        
        # Verify all sessions are in database
        result = await agent_db.execute(
            select(AgentSession).where(AgentSession.org_id == org_id)
        )
        db_sessions = result.scalars().all()
        
        assert len(db_sessions) == 5


@pytest.mark.asyncio
async def test_complete_agent_workflow():
    """
    Test a complete agent workflow without external dependencies.
    
    This test validates that the core agent system models and
    database operations work correctly together.
    """
    
    # This is a comprehensive integration test that validates
    # the agent system works end-to-end at the data layer
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
    from sqlalchemy.pool import StaticPool
    
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        echo=False,
    )
    
    async with engine.begin() as conn:
        await conn.run_sync(AgentBase.metadata.create_all)
    
    async_session = async_sessionmaker(engine, expire_on_commit=False)
    
    async with async_session() as session:
        
        # 1. Create agent session
        org_id = uuid4()
        agent_session = AgentSession(
            org_id=org_id,
            agent_type=AgentType.INCIDENT_RESPONDER,
            created_by="security_team",
            title="Security Incident Investigation",
            context={
                "incident_type": "data_breach",
                "urgency": "high",
                "affected_systems": ["web_app", "database"]
            },
            is_active=True
        )
        session.add(agent_session)
        await session.commit()
        await session.refresh(agent_session)
        
        # 2. Add conversation messages
        messages = [
            AgentMessage(
                session_id=agent_session.session_id,
                role=MessageRole.USER,
                content="We've detected unusual database access patterns. Please investigate."
            ),
            AgentMessage(
                session_id=agent_session.session_id,
                role=MessageRole.ASSISTANT,
                content="I'll investigate the database access patterns. Let me query recent findings."
            ),
        ]
        session.add_all(messages)
        await session.commit()
        
        # 3. Create tool invocations
        tool_invocations = [
            ToolInvocation(
                session_id=agent_session.session_id,
                message_id=messages[1].message_id,
                tool_name="query_findings",
                tool_input={
                    "filters": {
                        "resource_type": "database",
                        "severity": ["HIGH", "CRITICAL"],
                        "time_range": "24h"
                    }
                },
                status=ToolInvocationStatus.EXECUTED,
                requires_approval=False,
                execution_time_ms=1250,
                output_data={
                    "findings_count": 3,
                    "critical_findings": 1,
                    "high_findings": 2
                }
            ),
            ToolInvocation(
                session_id=agent_session.session_id,
                message_id=messages[1].message_id,
                tool_name="build_attack_timeline",
                tool_input={
                    "incident_id": str(uuid4()),
                    "start_time": "2024-01-15T00:00:00Z",
                    "end_time": "2024-01-15T23:59:59Z"
                },
                status=ToolInvocationStatus.PENDING,
                requires_approval=True
            )
        ]
        session.add_all(tool_invocations)
        await session.commit()
        
        # 4. Add approval for timeline tool
        approval = ToolApproval(
            invocation_id=tool_invocations[1].invocation_id,
            approved_by="security_manager",
            status=ApprovalStatus.APPROVED,
            reason="Approved for incident response investigation"
        )
        session.add(approval)
        await session.commit()
        
        # Update tool status
        tool_invocations[1].status = ToolInvocationStatus.APPROVED
        await session.commit()
        
        # 5. Verify complete workflow
        
        # Check session exists
        session_result = await session.execute(
            select(AgentSession).where(AgentSession.session_id == agent_session.session_id)
        )
        retrieved_session = session_result.scalar_one()
        
        assert retrieved_session.title == "Security Incident Investigation"
        assert retrieved_session.agent_type == AgentType.INCIDENT_RESPONDER
        assert retrieved_session.context["incident_type"] == "data_breach"
        assert retrieved_session.is_active
        
        # Check messages exist in order
        messages_result = await session.execute(
            select(AgentMessage)
            .where(AgentMessage.session_id == agent_session.session_id)
            .order_by(AgentMessage.created_at)
        )
        retrieved_messages = messages_result.scalars().all()
        
        assert len(retrieved_messages) == 2
        assert retrieved_messages[0].role == MessageRole.USER
        assert "database access patterns" in retrieved_messages[0].content
        assert retrieved_messages[1].role == MessageRole.ASSISTANT
        assert "query recent findings" in retrieved_messages[1].content
        
        # Check tool invocations
        tools_result = await session.execute(
            select(ToolInvocation)
            .where(ToolInvocation.session_id == agent_session.session_id)
            .order_by(ToolInvocation.created_at)
        )
        retrieved_tools = tools_result.scalars().all()
        
        assert len(retrieved_tools) == 2
        assert retrieved_tools[0].tool_name == "query_findings"
        assert retrieved_tools[0].status == ToolInvocationStatus.EXECUTED
        assert retrieved_tools[0].output_data["findings_count"] == 3
        
        assert retrieved_tools[1].tool_name == "build_attack_timeline"
        assert retrieved_tools[1].status == ToolInvocationStatus.APPROVED
        assert retrieved_tools[1].requires_approval
        
        # Check approval workflow
        approval_result = await session.execute(
            select(ToolApproval)
            .where(ToolApproval.invocation_id == tool_invocations[1].invocation_id)
        )
        retrieved_approval = approval_result.scalar_one()
        
        assert retrieved_approval.approved_by == "security_manager"
        assert retrieved_approval.status == ApprovalStatus.APPROVED
        assert "incident response" in retrieved_approval.reason
        
        logger.info(
            "Complete agent workflow test passed",
            session_id=str(agent_session.session_id),
            messages_count=len(retrieved_messages),
            tools_count=len(retrieved_tools),
            approvals_count=1
        )
    
    await engine.dispose()


if __name__ == "__main__":
    # Run the tests
    pytest.main([
        "tests/integration/test_agent_core.py",
        "-v",
        "--tb=short",
        "--disable-warnings"
    ])
