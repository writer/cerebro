"""
Cerebro Claude Runtime

Integrates Claude Code SDK with Cerebro's security architecture, providing
streaming agent capabilities with tool calling, audit logging, and safety guardrails.
"""

import asyncio
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional
from uuid import UUID

import structlog
from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions
from claude_agent_sdk.types import (
    AssistantMessage,
    UserMessage,
    TextBlock,
    ToolUseBlock,
    ToolResultBlock,
)

from cerebro.core.database import get_db
from cerebro.agents.models import (
    AgentSession,
    AgentMessage,
    MessageRole,
    AgentType,
)
from cerebro.agents.tools import tool_registry, ToolExecutor, AgentContext

logger = structlog.get_logger(__name__)


class CerebroClaudeRuntime:
    """
    Claude runtime for Cerebro security agents.
    
    Provides streaming conversation capabilities with security-focused tools,
    audit logging, and integration with Cerebro's append-only architecture.
    """
    
    def __init__(
        self,
        model: str = "claude-3-5-sonnet-20241022",
        max_tokens: int = 8192,
        temperature: float = 0.1,
    ):
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.tool_executor = ToolExecutor()
    
    async def create_session(
        self,
        org_id: UUID,
        agent_type: AgentType,
        created_by: str,
        context: Dict[str, Any],
        title: Optional[str] = None,
    ) -> AgentSession:
        """Create a new agent session."""
        from cerebro.core.database import async_session_factory
        async with async_session_factory() as db_session:
            session = AgentSession(
                org_id=org_id,
                agent_type=agent_type,
                created_by=created_by,
                title=title,
                context=context,
            )
            db_session.add(session)
            await db_session.commit()
            await db_session.refresh(session)
            
            logger.info(
                "Created agent session",
                session_id=session.id,
                agent_type=agent_type.value,
                org_id=org_id,
            )
            
            return session
    
    async def get_session(self, session_id: UUID) -> Optional[AgentSession]:
        """Get an existing agent session."""
        from cerebro.core.database import async_session_factory
        async with async_session_factory() as db_session:
            return await db_session.get(AgentSession, session_id)
    
    async def send_message(
        self,
        session: AgentSession,
        message: str,
        user_id: str,
        stream: bool = False,
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Send a message to the agent and stream the response.
        
        Yields dictionaries with:
        - type: "text" | "tool_use" | "tool_result" | "error" | "complete"
        - content: message content or tool data
        - metadata: additional information
        """
        
        # Store user message
        await self._store_message(session.id, MessageRole.USER, {"text": message})
        
        # Build agent context
        agent_context = await self._build_agent_context(session, user_id)
        
        # Get conversation history
        conversation = await self._build_conversation_history(session)
        
        try:
            # Configure Claude options
            options = ClaudeAgentOptions(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                system_prompt=self._get_system_prompt(session.agent_type),
                max_turns=1,  # Single turn to maintain control
            )
            
            # Create Claude client
            async with ClaudeSDKClient(options=options) as client:
                
                # Send message and get response
                await client.query(message)
                
                assistant_content = []
                tool_calls = []
                
                async for response_msg in client.receive_response():
                    
                    if isinstance(response_msg, AssistantMessage):
                        for block in response_msg.content:
                            
                            if isinstance(block, TextBlock):
                                # Stream text content
                                if stream:
                                    yield {
                                        "type": "text",
                                        "content": block.text,
                                        "metadata": {"streaming": True}
                                    }
                                assistant_content.append({"type": "text", "text": block.text})
                            
                            elif isinstance(block, ToolUseBlock):
                                # Execute tool call
                                tool_call_id = block.id
                                tool_name = block.name
                                tool_input = block.input
                                
                                logger.info(
                                    "Executing tool",
                                    tool_name=tool_name,
                                    session_id=session.id,
                                    tool_call_id=tool_call_id,
                                )
                                
                                if stream:
                                    yield {
                                        "type": "tool_use",
                                        "content": {
                                            "tool_name": tool_name,
                                            "input": tool_input,
                                            "status": "starting"
                                        },
                                        "metadata": {"tool_call_id": tool_call_id}
                                    }
                                
                                # Get tool from registry
                                tool = tool_registry.get(tool_name)
                                if not tool:
                                    error_msg = f"Unknown tool: {tool_name}"
                                    logger.error(error_msg, tool_name=tool_name)
                                    
                                    if stream:
                                        yield {
                                            "type": "tool_result",
                                            "content": {
                                                "tool_name": tool_name,
                                                "success": False,
                                                "error": error_msg
                                            },
                                            "metadata": {"tool_call_id": tool_call_id}
                                        }
                                    continue
                                
                                # Execute tool
                                tool_result = await self.tool_executor.execute_tool(
                                    tool=tool,
                                    raw_inputs=tool_input,
                                    context=agent_context,
                                )
                                
                                if stream:
                                    yield {
                                        "type": "tool_result",
                                        "content": {
                                            "tool_name": tool_name,
                                            "success": tool_result.success,
                                            "data": tool_result.data,
                                            "error": tool_result.error,
                                            "requires_approval": tool_result.requires_approval,
                                            "approval_id": str(tool_result.approval_id) if tool_result.approval_id else None,
                                        },
                                        "metadata": {"tool_call_id": tool_call_id}
                                    }
                                
                                # Store tool call and result
                                assistant_content.append({
                                    "type": "tool_use",
                                    "tool_name": tool_name,
                                    "input": tool_input,
                                    "output": tool_result.model_dump(),
                                })
                                
                                tool_calls.append({
                                    "tool_call_id": tool_call_id,
                                    "tool_name": tool_name,
                                    "result": tool_result,
                                })
                
                # Store assistant response
                await self._store_message(
                    session.id,
                    MessageRole.ASSISTANT,
                    {
                        "content": assistant_content,
                        "tool_calls": len(tool_calls),
                    }
                )
                
                # Final completion message
                if stream:
                    yield {
                        "type": "complete",
                        "content": {
                            "message_stored": True,
                            "tool_calls_executed": len(tool_calls),
                        },
                        "metadata": {"session_id": str(session.id)}
                    }
                
        except Exception as e:
            logger.exception("Agent message processing failed", session_id=session.id, error=str(e))
            
            # Store error message
            await self._store_message(
                session.id,
                MessageRole.ASSISTANT,
                {
                    "error": str(e),
                    "type": "system_error",
                }
            )
            
            yield {
                "type": "error",
                "content": {
                    "message": "Agent processing failed",
                    "error": str(e),
                },
                "metadata": {"session_id": str(session.id)}
            }
    
    async def _build_agent_context(
        self,
        session: AgentSession,
        user_id: str,
    ) -> AgentContext:
        """Build agent context for tool execution."""
        
        # Extract context information
        finding_ids = [
            UUID(fid) for fid in session.context.get("finding_ids", [])
        ]
        incident_id = None
        if session.context.get("incident_id"):
            incident_id = UUID(session.context["incident_id"])
        
        provider_scope = session.context.get("provider_scope", [])
        
        return AgentContext(
            session_id=session.id,
            org_id=session.org_id,
            user_id=user_id,
            agent_type=session.agent_type.value,
            provider_scope=provider_scope,
            finding_ids=finding_ids,
            incident_id=incident_id,
            cel_context={
                "agent_type": session.agent_type.value,
                "context": session.context,
            },
        )
    
    async def _build_conversation_history(
        self,
        session: AgentSession,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Build conversation history for Claude context."""
        from cerebro.core.database import async_session_factory
        async with async_session_factory() as db_session:
            messages = await db_session.execute(
                """
                SELECT role, content, created_at
                FROM agent_messages 
                WHERE session_id = :session_id
                ORDER BY created_at ASC
                LIMIT :limit
                """,
                {"session_id": session.id, "limit": limit}
            )
            
            conversation = []
            for row in messages:
                conversation.append({
                    "role": row.role,
                    "content": row.content,
                    "timestamp": row.created_at.isoformat(),
                })
            
            return conversation
    
    async def _store_message(
        self,
        session_id: UUID,
        role: MessageRole,
        content: Dict[str, Any],
    ) -> None:
        """Store message in database with append-only pattern."""
        from cerebro.core.database import async_session_factory
        async with async_session_factory() as db_session:
            message = AgentMessage(
                session_id=session_id,
                role=role,
                content=content,
            )
            db_session.add(message)
            await db_session.commit()
    
    def _get_system_prompt(self, agent_type: AgentType) -> str:
        """Get system prompt for specific agent type."""
        
        base_prompt = """You are a specialized security agent within the Cerebro security system of record. 
You have access to powerful tools for analyzing security findings, investigating incidents, and providing 
actionable recommendations.

SAFETY GUIDELINES:
- Always default to dry-run mode for any potentially destructive actions
- Request human approval for any changes to production systems
- Never expose sensitive credentials or secrets in responses
- All your actions are audited in append-only logs
- Provide clear, actionable recommendations with compliance mappings

RESPONSE STYLE:
- Be concise and technical - assume security expertise
- Cite specific evidence from findings and audit trails
- Map security issues to CIS, NIST, or CWE frameworks when relevant
- Prioritize actions by risk and business impact
- Always provide clear next steps"""
        
        agent_prompts = {
            AgentType.SECURITY_ANALYST: """
ROLE: Security Analyst
FOCUS: Triage findings, assess risk, cluster similar issues, recommend remediation
EXPERTISE: Vulnerability assessment, risk scoring, compliance mapping, threat analysis
""",
            AgentType.INCIDENT_RESPONDER: """
ROLE: Incident Response Specialist  
FOCUS: Build timelines, coordinate containment, collect evidence, manage incidents
EXPERTISE: Digital forensics, incident coordination, timeline analysis, containment strategies
""",
            AgentType.IDENTITY_ADVISOR: """
ROLE: Identity & Access Management Advisor
FOCUS: Analyze IAM configurations, privilege escalation, access reviews, identity stitching
EXPERTISE: Identity governance, privilege management, access controls, identity correlation
""",
            AgentType.COMPLIANCE_ADVISOR: """
ROLE: Compliance & Risk Advisor
FOCUS: Map findings to frameworks, generate compliance reports, track remediation
EXPERTISE: CIS Controls, NIST Cybersecurity Framework, SOC 2, compliance management
""",
            AgentType.ATTACK_PATH_ANALYST: """
ROLE: Attack Path & Threat Analyst
FOCUS: Model attack paths, identify choke points, recommend defensive measures
EXPERTISE: Attack path modeling, threat modeling, network analysis, defensive architecture
"""
        }
        
        agent_specific = agent_prompts.get(agent_type, "")
        
        return f"{base_prompt}\n\n{agent_specific}"
    
    async def get_session_messages(
        self,
        session_id: UUID,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Get messages from a session."""
        from cerebro.core.database import async_session_factory
        async with async_session_factory() as db_session:
            messages = await db_session.execute(
                """
                SELECT id, role, content, created_at, input_tokens, output_tokens
                FROM agent_messages 
                WHERE session_id = :session_id
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :offset
                """,
                {"session_id": session_id, "limit": limit, "offset": offset}
            )
            
            return [
                {
                    "id": str(row.id),
                    "role": row.role,
                    "content": row.content,
                    "created_at": row.created_at.isoformat(),
                    "input_tokens": row.input_tokens,
                    "output_tokens": row.output_tokens,
                }
                for row in messages
            ]
    
    async def get_session_metrics(self, session_id: UUID) -> Dict[str, Any]:
        """Get metrics for a session."""
        from cerebro.core.database import async_session_factory
        async with async_session_factory() as db_session:
            # Message counts and token usage
            message_stats = await db_session.execute(
                """
                SELECT 
                    role,
                    COUNT(*) as count,
                    SUM(COALESCE(input_tokens, 0)) as total_input_tokens,
                    SUM(COALESCE(output_tokens, 0)) as total_output_tokens
                FROM agent_messages 
                WHERE session_id = :session_id
                GROUP BY role
                """,
                {"session_id": session_id}
            )
            
            # Tool invocation stats
            tool_stats = await db_session.execute(
                """
                SELECT 
                    tool_name,
                    status,
                    COUNT(*) as count
                FROM tool_invocations 
                WHERE session_id = :session_id
                GROUP BY tool_name, status
                """,
                {"session_id": session_id}
            )
            
            return {
                "session_id": str(session_id),
                "message_stats": [dict(row) for row in message_stats],
                "tool_stats": [dict(row) for row in tool_stats],
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }
