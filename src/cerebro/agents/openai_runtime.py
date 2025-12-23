"""OpenAI Agents runtime implementation for Cerebro."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional
from uuid import UUID

import structlog
from agents import (
    Agent,
    FunctionTool,
    ItemHelpers,
    RunConfig,
    Runner,
    set_default_openai_key,
)
from agents.items import MessageOutputItem, RunItem
from agents.run_context import RunContextWrapper
from agents.stream_events import (
    AgentUpdatedStreamEvent,
    RawResponsesStreamEvent,
    RunItemStreamEvent,
)

from cerebro.agents.memory_session import OpenAIAgentConversationSession
from cerebro.agents.models import AgentMessage, AgentSession, AgentType, MessageRole
from cerebro.agents.prompts import build_security_agent_prompt
from cerebro.agents.runtime_common import AgentRuntimePersistenceMixin
from cerebro.agents.tools import AgentContext, ToolExecutor, tool_registry, Tool
from cerebro.agents.tool_stats import performance_tracker
from cerebro.agents.metrics import record_runtime_metadata_event
from cerebro.core.config import settings
from cerebro.agents.analytics_service import AgentAnalyticsService

logger = structlog.get_logger(__name__)


@dataclass
class OpenAIRuntimeContext:
    """Context payload made available to OpenAI tool functions."""

    agent_context: AgentContext


class CerebroOpenAIRuntime(AgentRuntimePersistenceMixin):
    """Runtime that orchestrates Cerebro agents via the OpenAI Agents SDK."""

    def __init__(
        self,
        model: Optional[str] = None,
        max_turns: int = 10,
    ) -> None:
        self.model = model or settings.openai_model
        self.max_turns = max_turns
        self.tool_executor = ToolExecutor()
        self._function_tool_cache: Dict[str, FunctionTool] = {}
        self.backend_name = "openai"

        if settings.openai_api_key:
            set_default_openai_key(settings.openai_api_key)

    async def create_session(
        self,
        org_id: UUID,
        agent_type: AgentType,
        created_by: str,
        context: Dict[str, Any],
        title: Optional[str] = None,
    ) -> AgentSession:
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
            "Created OpenAI agent session",
            session_id=session.id,
            agent_type=agent_type.value,
            org_id=org_id,
        )

        return session

    async def get_session(self, session_id: UUID) -> Optional[AgentSession]:
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
        start_time, telemetry_span = self._begin_runtime_operation(
            session=session,
            operation="send_message",
        )

        memory_context = await self._retrieve_memory_snippets(
            session=session,
            query=message,
        )

        memory_ids = [
            entry.get("id") for entry in memory_context.entries if entry.get("id")
        ]
        previous_ids = set(session.context.get("_recent_memory_ids", []))
        new_entries = [
            entry
            for entry in memory_context.entries
            if entry.get("id") not in previous_ids
        ]
        if new_entries:
            self._log_memory_activity(session, new_entries)
        await self._update_session_context(session, {"_recent_memory_ids": memory_ids})
        memory_brief = self._compose_memory_brief(memory_context)

        assistant_blocks: List[Dict[str, Any]] = []
        tool_calls_count = 0
        total_input_tokens = 0
        total_output_tokens = 0

        # Record the user message for auditability and memory
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

        agent_context = await self._build_agent_context(
            session,
            user_id,
            memory_entries=memory_context.entries,
        )
        agent_context.dry_run = session.context.get(
            "dry_run", settings.agent_default_dry_run
        )

        runtime_context = OpenAIRuntimeContext(agent_context=agent_context)

        conversation_session = OpenAIAgentConversationSession(session)

        base_tools = tool_registry.list_tools(agent_context.permission_level)
        prioritized_tools = performance_tracker.sort_tools(
            base_tools,
            agent_context.agent_type,
        )
        tool_rankings = performance_tracker.get_rankings(
            prioritized_tools,
            agent_context.agent_type,
        )
        await AgentAnalyticsService.record_event(
            org_id=session.org_id,
            session_id=session.id,
            event_type="tool_rankings",
            payload={"rankings": tool_rankings[:10]},
        )
        tools = await self._build_function_tools(prioritized_tools)

        if memory_brief:
            assistant_blocks.append(
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

        agent = Agent(
            name=f"{session.agent_type.value}_agent",
            instructions=build_security_agent_prompt(
                session.agent_type,
                session=session,
                memory_snippets=memory_context.prompt_snippets,
            ),
            tools=tools,  # type: ignore[arg-type]
            model=self.model,
        )

        run_config = RunConfig(
            model=self.model,
            workflow_name=f"Cerebro OpenAI {session.agent_type.value}",
        )

        try:
            run_result = Runner.run_streamed(
                agent,
                message,
                context=runtime_context,
                max_turns=self.max_turns,
                run_config=run_config,
                session=conversation_session,
            )

            async for event in run_result.stream_events():
                if isinstance(event, RawResponsesStreamEvent):
                    continue

                if isinstance(event, AgentUpdatedStreamEvent):
                    logger.info(
                        "Agent handoff occurred",
                        session_id=session.id,
                        new_agent=event.new_agent.name,
                    )
                    continue

                if isinstance(event, RunItemStreamEvent):
                    run_item: RunItem = event.item

                    if event.name == "message_output_created" and isinstance(
                        run_item, MessageOutputItem
                    ):
                        text = ItemHelpers.text_message_output(run_item)
                        if text:
                            assistant_blocks.append({"type": "text", "text": text})
                            if stream:
                                yield {
                                    "type": "text",
                                    "content": text,
                                    "metadata": {"streaming": True},
                                }
                        continue

                    if event.name == "tool_called":
                        tool_calls_count += 1
                        try:
                            payload = run_item.raw_item.model_dump(exclude_unset=True)  # type: ignore[union-attr]
                        except AttributeError:
                            payload = {}

                        assistant_blocks.append(
                            {
                                "type": "tool_use",
                                "tool_name": getattr(
                                    run_item.raw_item, "name", "unknown"
                                ),
                                "tool_call_id": getattr(run_item.raw_item, "id", None),
                                "input": payload,
                            }
                        )

                        if stream:
                            yield {
                                "type": "tool_use",
                                "content": {
                                    "tool_name": getattr(
                                        run_item.raw_item, "name", "unknown"
                                    ),
                                    "input": payload,
                                },
                                "metadata": {
                                    "tool_call_id": getattr(
                                        run_item.raw_item, "id", None
                                    ),
                                },
                            }
                        continue

            total_input_tokens, total_output_tokens = self._summarize_usage(
                run_result.raw_responses
            )

            usage_snapshot = run_result.context_wrapper.usage
            usage_payload = {
                "requests": usage_snapshot.requests,
                "input_tokens": usage_snapshot.input_tokens,
                "cached_input_tokens": getattr(
                    getattr(usage_snapshot, "input_tokens_details", None),
                    "cached_tokens",
                    None,
                ),
                "output_tokens": usage_snapshot.output_tokens,
                "reasoning_tokens": getattr(
                    getattr(usage_snapshot, "output_tokens_details", None),
                    "reasoning_tokens",
                    None,
                ),
                "total_tokens": usage_snapshot.total_tokens,
            }

            runtime_metadata = {
                "model": self.model,
                "conversation_session_id": conversation_session.session_id,
                "last_response_id": getattr(run_result, "last_response_id", None),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "usage": usage_payload,
            }

            await self._update_session_context(
                session,
                {"_openai_runtime": runtime_metadata},
            )

            await AgentAnalyticsService.record_event(
                org_id=session.org_id,
                session_id=session.id,
                event_type="runtime_metadata",
                payload={
                    "runtime": self.backend_name,
                    **runtime_metadata,
                },
            )

            record_runtime_metadata_event(backend=self.backend_name, status="recorded")

            if not assistant_blocks:
                if isinstance(run_result.final_output, str):
                    assistant_blocks.append(
                        {"type": "text", "text": run_result.final_output}
                    )
                elif run_result.final_output is not None:
                    assistant_blocks.append(
                        {
                            "type": "text",
                            "text": json.dumps(
                                run_result.final_output, ensure_ascii=False
                            ),
                        }
                    )

            await self._store_message(
                session,
                MessageRole.ASSISTANT,
                {
                    "content": assistant_blocks,
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
                for block in assistant_blocks
                if isinstance(block, dict) and block.get("type") == "text"
            ).strip()
            if assistant_text:
                await self._capture_memory(
                    session=session,
                    role=MessageRole.ASSISTANT,
                    content=assistant_text,
                    metadata={"tool_calls": tool_calls_count},
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
                    },
                    "metadata": {"session_id": str(session.id)},
                }

        except Exception as exc:  # pragma: no cover - runtime guard
            logger.exception(
                "OpenAI agent message processing failed",
                session_id=session.id,
                error=str(exc),
            )

            await self._store_message(
                session,
                MessageRole.ASSISTANT,
                {
                    "error": str(exc),
                    "type": "system_error",
                },
            )

            await AgentAnalyticsService.record_event(
                org_id=session.org_id,
                session_id=session.id,
                event_type="runtime_error",
                payload={
                    "runtime": self.backend_name,
                    "message": str(exc),
                    "reason": "exception",
                },
            )

            record_runtime_metadata_event(backend=self.backend_name, status="error")

            self._complete_runtime_operation(
                session=session,
                start_time=start_time,
                telemetry_span=telemetry_span,
                success=False,
                input_tokens=total_input_tokens,
                output_tokens=total_output_tokens,
                tool_calls=tool_calls_count,
                error=exc,
            )

            yield {
                "type": "error",
                "content": {
                    "message": "Agent processing failed",
                    "error": str(exc),
                },
                "metadata": {"session_id": str(session.id)},
            }

    async def _build_function_tools(
        self,
        prioritized: Optional[List[Tool]] = None,
    ) -> List[FunctionTool]:
        if prioritized is None:
            prioritized = tool_registry.list_tools()

        # Populate cache lazily
        if not self._function_tool_cache:
            for tool in tool_registry.list_tools():

                async def _invoke_tool(
                    ctx: RunContextWrapper[OpenAIRuntimeContext],
                    raw_arguments: str,
                    *,
                    _tool=tool,
                ) -> str:
                    try:
                        parsed_arguments = (
                            json.loads(raw_arguments) if raw_arguments else {}
                        )
                    except json.JSONDecodeError:
                        parsed_arguments = {}

                    agent_context = ctx.context.agent_context
                    result = await self.tool_executor.execute_tool(
                        tool=_tool,
                        raw_inputs=parsed_arguments,
                        context=agent_context,
                        dry_run=agent_context.dry_run,
                    )
                    return json.dumps(result.model_dump())

                self._function_tool_cache[tool.name] = FunctionTool(
                    name=tool.name,
                    description=tool.description,
                    params_json_schema=tool.input_schema.model_json_schema(),
                    on_invoke_tool=_invoke_tool,
                )

        return [
            self._function_tool_cache[tool.name]
            for tool in prioritized
            if tool.name in self._function_tool_cache
        ]

    @staticmethod
    def _summarize_usage(raw_responses: List[Any]) -> tuple[int, int]:
        input_tokens = 0
        output_tokens = 0
        for response in raw_responses:
            usage = getattr(response, "usage", None)
            if not usage:
                continue
            input_tokens += getattr(usage, "input_tokens", 0) or 0
            output_tokens += getattr(usage, "output_tokens", 0) or 0
        return input_tokens, output_tokens

    async def get_session_messages(
        self,
        session_id: UUID,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        from cerebro.core.database import async_session_factory
        from sqlalchemy import select

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
        metrics = await self._get_session_metrics(session_id)
        metrics["generated_at"] = datetime.now(timezone.utc).isoformat()
        return metrics
