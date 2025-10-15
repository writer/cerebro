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
    TextBlock,
    ToolUseBlock,
    ResultMessage,
    SystemMessage,
)

from sqlalchemy import func, select

from cerebro.agents.models import (
    AgentSession,
    AgentMessage,
    MessageRole,
    AgentType,
    ToolInvocation,
)
from cerebro.agents.prompts import build_security_agent_prompt
from cerebro.agents.runtime_common import AgentRuntimePersistenceMixin
from cerebro.agents.tools import tool_registry, ToolExecutor
from cerebro.agents.mcp_bridge import create_cerebro_mcp_server

logger = structlog.get_logger(__name__)


class CerebroClaudeRuntime(AgentRuntimePersistenceMixin):
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
        """Create a new agent session with automatic context injection."""
        from cerebro.core.database import async_session_factory

        prepared_context = await self._prepare_session_context(
            org_id=org_id,
            agent_type=agent_type,
            created_by=created_by,
            context=context,
        )

        session = await self._persist_session(
            org_id=org_id,
            agent_type=agent_type,
            created_by=created_by,
            context=prepared_context,
            title=title,
        )

        logger.info(
            "Created agent session with auto-context",
            session_id=session.id,
            agent_type=agent_type.value,
            org_id=org_id,
            has_org_context=("_auto_loaded_org_context" in prepared_context),
            has_system_context=("_auto_loaded_system_context" in prepared_context),
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

        The SDK now handles tool calling automatically via MCP servers.

        Yields dictionaries with:
        - type: "text" | "tool_use" | "system" | "error" | "complete"
        - content: message content or tool data
        - metadata: additional information
        """

        # Store user message
        await self._store_message(session, MessageRole.USER, {"text": message})

        # Build agent context
        agent_context = await self._build_agent_context(session, user_id)

        try:
            # Get available tools from registry based on permission level
            available_tools = tool_registry.list_tools(agent_context.permission_level)

            # Create MCP server from Cerebro tools
            mcp_server = create_cerebro_mcp_server(
                tools=available_tools,
                context=agent_context,
                executor=self.tool_executor,
                server_name="cerebro",
                server_version="1.0.0",
            )

            # Build allowed tools list (mcp__servername__toolname format)
            allowed_tools = [f"mcp__cerebro__{tool.name}" for tool in available_tools]

            # Configure Claude options with MCP server and session context
            options = ClaudeAgentOptions(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                system_prompt=build_security_agent_prompt(session.agent_type, session=session),
                mcp_servers={"cerebro": mcp_server},
                allowed_tools=allowed_tools,
            )

            # Track response data
            assistant_content = []
            tool_calls_count = 0
            total_input_tokens = 0
            total_output_tokens = 0

            # Create Claude client and send query
            async with ClaudeSDKClient(options=options) as client:
                await client.connect()

                # Send the user message
                await client.query(message, session_id=str(session.id))

                # Process streaming responses
                async for response_msg in client.receive_messages():

                    # Handle assistant messages
                    if isinstance(response_msg, AssistantMessage):
                        for block in response_msg.content:

                            if isinstance(block, TextBlock):
                                # Stream text content to user
                                if stream:
                                    yield {
                                        "type": "text",
                                        "content": block.text,
                                        "metadata": {"streaming": True}
                                    }
                                assistant_content.append({"type": "text", "text": block.text})

                            elif isinstance(block, ToolUseBlock):
                                # Tool use - SDK handles execution automatically
                                tool_name = block.name
                                tool_input = block.input
                                tool_call_id = block.id

                                logger.info(
                                    "Tool invoked by agent",
                                    tool_name=tool_name,
                                    session_id=session.id,
                                    tool_call_id=tool_call_id,
                                )

                                tool_calls_count += 1

                                if stream:
                                    yield {
                                        "type": "tool_use",
                                        "content": {
                                            "tool_name": tool_name,
                                            "input": tool_input,
                                        },
                                        "metadata": {"tool_call_id": tool_call_id}
                                    }

                                assistant_content.append({
                                    "type": "tool_use",
                                    "tool_call_id": tool_call_id,
                                    "tool_name": tool_name,
                                    "input": tool_input,
                                })

                    # Handle system messages
                    elif isinstance(response_msg, SystemMessage):
                        logger.info(
                            "System message received",
                            subtype=response_msg.subtype,
                            session_id=session.id,
                        )

                        if stream:
                            yield {
                                "type": "system",
                                "content": {
                                    "subtype": response_msg.subtype,
                                    "data": response_msg.data,
                                },
                                "metadata": {}
                            }

                    # Handle result messages (token usage, completion)
                    elif isinstance(response_msg, ResultMessage):
                        # Extract token usage
                        if hasattr(response_msg, 'usage') and response_msg.usage:
                            usage = response_msg.usage
                            total_input_tokens = getattr(usage, 'input_tokens', 0)
                            total_output_tokens = getattr(usage, 'output_tokens', 0)

                        logger.info(
                            "Result message received",
                            session_id=session.id,
                            input_tokens=total_input_tokens,
                            output_tokens=total_output_tokens,
                        )

                # Store assistant response with all content
                await self._store_message(
                    session,
                    MessageRole.ASSISTANT,
                    {
                        "content": assistant_content,
                        "tool_calls": tool_calls_count,
                        "token_usage": {
                            "input_tokens": total_input_tokens,
                            "output_tokens": total_output_tokens,
                            "total_tokens": total_input_tokens + total_output_tokens,
                        }
                    },
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens,
                )

                # Final completion message
                if stream:
                    yield {
                        "type": "complete",
                        "content": {
                            "message_stored": True,
                            "tool_calls_executed": tool_calls_count,
                        },
                        "metadata": {"session_id": str(session.id)}
                    }

        except Exception as e:
            logger.exception("Agent message processing failed", session_id=session.id, error=str(e))

            # Store error message
            await self._store_message(
                session,
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
    
    async def get_session_messages(
        self,
        session_id: UUID,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Get messages from a session."""
        from cerebro.core.database import async_session_factory
        async with async_session_factory() as db_session:
            stmt = (
                select(
                    AgentMessage.id,
                    AgentMessage.role,
                    AgentMessage.content,
                    AgentMessage.created_at,
                    AgentMessage.input_tokens,
                    AgentMessage.output_tokens,
                )
                .where(AgentMessage.session_id == session_id)
                .order_by(AgentMessage.created_at.desc())
                .limit(limit)
                .offset(offset)
            )

            result = await db_session.execute(stmt)
            rows = result.all()

            return [
                {
                    "id": str(row.id),
                    "role": row.role,
                    "content": row.content,
                    "created_at": row.created_at.isoformat(),
                    "input_tokens": row.input_tokens,
                    "output_tokens": row.output_tokens,
                }
                for row in rows
            ]
    
    async def get_session_metrics(self, session_id: UUID) -> Dict[str, Any]:
        """Get metrics for a session."""
        metrics = await self._get_session_metrics(session_id)
        metrics["generated_at"] = datetime.now(timezone.utc).isoformat()
        return metrics
