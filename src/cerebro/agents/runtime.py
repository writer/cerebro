"""
Cerebro Claude Runtime

Integrates Claude Code SDK with Cerebro's security architecture, providing
streaming agent capabilities with tool calling, audit logging, and safety guardrails.
"""

import asyncio
import inspect
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional
from uuid import UUID

import structlog
from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions, CLINotFoundError
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
from cerebro.agents.analytics_service import AgentAnalyticsService
from cerebro.agents.prompts import build_security_agent_prompt
from cerebro.agents.runtime_common import AgentRuntimePersistenceMixin
from cerebro.agents.tools import tool_registry, ToolExecutor
from cerebro.agents.tool_stats import performance_tracker
from cerebro.agents.mcp_bridge import create_cerebro_mcp_server
from cerebro.agents.metrics import record_runtime_metadata_event

try:
    CLAUDE_OPTIONS_METADATA_SUPPORTED = (
        "metadata" in inspect.signature(ClaudeAgentOptions).parameters
    )
except (TypeError, ValueError):  # pragma: no cover - defensive reflection
    CLAUDE_OPTIONS_METADATA_SUPPORTED = hasattr(ClaudeAgentOptions, "metadata")


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
        self.backend_name = "claude"
    
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

        start_time, telemetry_span = self._begin_runtime_operation(
            session=session,
            operation="send_message",
        )

        memory_context = await self._retrieve_memory_snippets(
            session=session,
            query=message,
        )

        memory_ids = [entry.get("id") for entry in memory_context.entries if entry.get("id")]
        previous_ids = set(session.context.get("_recent_memory_ids", []))
        new_entries = [
            entry for entry in memory_context.entries if entry.get("id") not in previous_ids
        ]
        if new_entries:
            self._log_memory_activity(session, new_entries)
        await self._update_session_context(session, {"_recent_memory_ids": memory_ids})
        memory_brief = self._compose_memory_brief(memory_context)

        # Store user message for audit trail and memory
        await self._store_message(
            session,
            MessageRole.USER,
            {
                "text": message,
                "memory_context": memory_context.entries,
                "memory_new_entries": new_entries,
            },
        )
        await self._capture_memory(
            session=session,
            role=MessageRole.USER,
            content=message,
        )

        # Build agent context
        agent_context = await self._build_agent_context(
            session,
            user_id,
            memory_entries=memory_context.entries,
        )

        assistant_content = []
        if memory_brief:
            assistant_content.append(
                {
                    "type": "memory_brief",
                    "text": memory_brief,
                    "entry_ids": memory_ids,
                }
            )
            if stream:
                yield {
                    "type": "memory_brief",
                    "content": {
                        "summary": memory_brief,
                        "entries": new_entries or memory_context.entries,
                    },
                    "metadata": {
                        "total_entries": len(memory_context.entries),
                        "new_entries": len(new_entries),
                    },
                }
        tool_calls_count = 0
        total_input_tokens = 0
        total_output_tokens = 0

        # Get available tools from registry based on permission level
        available_tools = performance_tracker.sort_tools(
            tool_registry.list_tools(agent_context.permission_level),
            agent_context.agent_type,
        )
        tool_rankings = performance_tracker.get_rankings(
            available_tools,
            agent_context.agent_type,
        )
        await AgentAnalyticsService.record_event(
            org_id=session.org_id,
            session_id=session.id,
            event_type="tool_rankings",
            payload={
                "rankings": tool_rankings[:10],
            },
        )

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

        claude_session_id: Optional[str] = session.context.get("_claude_session_id")

        options_metadata = {
            "cerebro_session_id": str(session.id),
            "org_id": str(session.org_id),
            "user_id": user_id,
            "agent_type": session.agent_type.value,
            "permission_level": agent_context.permission_level.value,
            "provider_scope": agent_context.provider_scope,
            "memory_entry_count": len(memory_context.entries),
        }
        if claude_session_id:
            options_metadata["claude_session_id"] = claude_session_id

        # Configure Claude options with MCP server and session context
        options_kwargs = {
            "model": self.model,
            "system_prompt": build_security_agent_prompt(
                session.agent_type,
                session=session,
                memory_snippets=memory_context.prompt_snippets,
            ),
            "mcp_servers": {"cerebro": mcp_server},
            "allowed_tools": allowed_tools,
        }

        if CLAUDE_OPTIONS_METADATA_SUPPORTED:
            options_kwargs["metadata"] = options_metadata

        options = ClaudeAgentOptions(**options_kwargs)

        try:
            # Create Claude client and send query
            async with ClaudeSDKClient(options=options) as client:
                await client.connect()

                if not claude_session_id and hasattr(client, "create_session"):
                    try:
                        create_response = await client.create_session(
                            options=options,
                            metadata=options_metadata,
                            session_id=str(session.id),
                        )
                        claude_session_id = (
                            create_response.get("session_id")
                            if isinstance(create_response, dict)
                            else None
                        )
                        if claude_session_id:
                            await self._update_session_context(
                                session,
                                {"_claude_session_id": claude_session_id},
                            )
                            options_metadata["claude_session_id"] = claude_session_id
                    except Exception as create_error:  # pragma: no cover - defensive logging
                        logger.debug(
                            "Failed to establish Claude SDK session",
                            session_id=session.id,
                            error=str(create_error),
                        )

                # Send the user message
                await client.query(
                    message,
                    session_id=claude_session_id or str(session.id),
                )

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
                        },
                        "memory_context": memory_context.entries,
                    },
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens,
                )

                assistant_text = "\n".join(
                    block["text"]
                    for block in assistant_content
                    if isinstance(block, dict) and block.get("type") == "text"
                ).strip()
                if assistant_text:
                    await self._capture_memory(
                        session=session,
                        role=MessageRole.ASSISTANT,
                        content=assistant_text,
                        metadata={"tool_calls": tool_calls_count},
                    )

                record_runtime_metadata_event(
                    backend=self.backend_name,
                    status="recorded",
                )

                self._complete_runtime_operation(
                    session=session,
                    start_time=start_time,
                    telemetry_span=telemetry_span,
                    success=True,
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens,
                    tool_calls=tool_calls_count,
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

        except CLINotFoundError as cli_error:
            logger.warning(
                "Claude CLI not available, using fallback response",
                session_id=session.id,
                error=str(cli_error),
            )

            fallback_text = await self._generate_cli_fallback_response(
                session=session,
                agent_context=agent_context,
                available_tools=available_tools,
                user_message=message,
            )

            if stream:
                yield {
                    "type": "text",
                    "content": fallback_text,
                    "metadata": {"fallback": "claude_cli_missing"},
                }

            assistant_content = [{"type": "text", "text": fallback_text}]
            tool_calls_count = 0
            total_input_tokens = 0
            total_output_tokens = 0

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
                    },
                    "fallback": "claude_cli_missing",
                    "memory_context": memory_context.entries,
                },
                input_tokens=total_input_tokens,
                output_tokens=total_output_tokens,
            )

            await self._capture_memory(
                session=session,
                role=MessageRole.ASSISTANT,
                content=fallback_text,
                metadata={"fallback": True},
            )

            await self._update_session_context(
                session,
                {"_claude_cli_unavailable": True},
            )

            await AgentAnalyticsService.record_event(
                org_id=session.org_id,
                session_id=session.id,
                event_type="runtime_warning",
                payload={
                    "runtime": self.backend_name,
                    "reason": "claude_cli_missing",
                },
            )

            record_runtime_metadata_event(
                backend=self.backend_name,
                status="warning",
            )

            self._complete_runtime_operation(
                session=session,
                start_time=start_time,
                telemetry_span=telemetry_span,
                success=True,
                input_tokens=total_input_tokens,
                output_tokens=total_output_tokens,
                tool_calls=tool_calls_count,
            )

            if stream:
                yield {
                    "type": "complete",
                    "content": {
                        "message_stored": True,
                        "tool_calls_executed": tool_calls_count,
                        "fallback": "claude_cli_missing",
                    },
                    "metadata": {"session_id": str(session.id)},
                }

            return

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

            record_runtime_metadata_event(
                backend=self.backend_name,
                status="error",
            )

            self._complete_runtime_operation(
                session=session,
                start_time=start_time,
                telemetry_span=telemetry_span,
                success=False,
                input_tokens=total_input_tokens,
                output_tokens=total_output_tokens,
                tool_calls=tool_calls_count,
                error=e,
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

    async def _generate_cli_fallback_response(
        self,
        *,
        session: AgentSession,
        agent_context: "AgentContext",
        available_tools: List[Any],
        user_message: str,
    ) -> str:
        """Generate a deterministic assistant response when Claude CLI is unavailable."""

        fallback_lines = [
            "Claude CLI is unavailable in this environment, so I'm providing a local dry-run response.",
            f"User request: {user_message}",
        ]

        findings_tool = next(
            (tool for tool in available_tools if getattr(tool, "name", None) == "findings_list"),
            None,
        )

        if findings_tool is not None:
            try:
                provider_scope = agent_context.provider_scope or []
                inputs_model = findings_tool.input_schema(
                    org_id=session.org_id,
                    severity=["high"],
                    provider=provider_scope if provider_scope else None,
                    limit=5,
                )

                result = await findings_tool.execute(inputs_model, agent_context)

                if result.success and result.data:
                    findings = (result.data or {}).get("findings", [])
                    if findings:
                        fallback_lines.append("")
                        fallback_lines.append("Recent high-severity findings:")
                        for finding in findings[:3]:
                            fallback_lines.append(
                                "- [{severity}] {title} (status: {status})".format(
                                    severity=str(finding.get("severity", "unknown")).upper(),
                                    title=finding.get("title", "Untitled Finding"),
                                    status=finding.get("status", "unknown"),
                                )
                            )
                        if len(findings) > 3:
                            fallback_lines.append(
                                f"…and {len(findings) - 3} additional findings."
                            )
                        fallback_lines.append("")
                        fallback_lines.append(
                            "Use findings_list with severity=['high'] for the complete dataset."
                        )
                    else:
                        fallback_lines.append(
                            "No high-severity findings were returned by the dataset in this environment."
                        )
                else:
                    error_message = result.error or "Findings tool returned no data."
                    fallback_lines.append(
                        f"Findings retrieval (dry-run) error: {error_message}"
                    )
            except Exception as tool_error:  # pragma: no cover - defensive logging
                logger.debug(
                    "Fallback findings retrieval failed",
                    session_id=session.id,
                    error=str(tool_error),
                )
        else:
            fallback_lines.append(
                "Findings data unavailable because the findings_list tool is not registered."
            )

        fallback_lines.append("")
        fallback_lines.append(
            "This response was generated from local data sources without invoking Claude."
        )

        return "\n".join(line for line in fallback_lines if line is not None)
