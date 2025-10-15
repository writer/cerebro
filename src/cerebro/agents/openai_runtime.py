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
from cerebro.agents.tools import AgentContext, ToolExecutor, tool_registry
from cerebro.core.config import settings

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
        self._function_tools: List[FunctionTool] | None = None

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
        assistant_blocks: List[Dict[str, Any]] = []
        tool_calls_count = 0

        # Record the user message for auditability
        await self._store_message(
            session,
            MessageRole.USER,
            {"text": message},
        )

        agent_context = await self._build_agent_context(session, user_id)
        agent_context.dry_run = session.context.get(
            "dry_run", settings.agent_default_dry_run
        )

        runtime_context = OpenAIRuntimeContext(agent_context=agent_context)

        conversation_session = OpenAIAgentConversationSession(session)

        agent = Agent(
            name=f"{session.agent_type.value}_agent",
            instructions=build_security_agent_prompt(session.agent_type, session=session),
            tools=await self._build_function_tools(),
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
                            payload = run_item.raw_item.model_dump(exclude_unset=True)  # type: ignore[attr-defined]
                        except AttributeError:
                            payload = {}

                        assistant_blocks.append(
                            {
                                "type": "tool_use",
                                "tool_name": getattr(run_item.raw_item, "name", "unknown"),
                                "tool_call_id": getattr(run_item.raw_item, "id", None),
                                "input": payload,
                            }
                        )

                        if stream:
                            yield {
                                "type": "tool_use",
                                "content": {
                                    "tool_name": getattr(run_item.raw_item, "name", "unknown"),
                                    "input": payload,
                                },
                                "metadata": {
                                    "tool_call_id": getattr(run_item.raw_item, "id", None),
                                },
                            }
                        continue

            total_input_tokens, total_output_tokens = self._summarize_usage(
                run_result.raw_responses
            )

            if not assistant_blocks:
                if isinstance(run_result.final_output, str):
                    assistant_blocks.append({"type": "text", "text": run_result.final_output})
                elif run_result.final_output is not None:
                    assistant_blocks.append(
                        {
                            "type": "text",
                            "text": json.dumps(run_result.final_output, ensure_ascii=False),
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
                },
                input_tokens=total_input_tokens,
                output_tokens=total_output_tokens,
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

            yield {
                "type": "error",
                "content": {
                    "message": "Agent processing failed",
                    "error": str(exc),
                },
                "metadata": {"session_id": str(session.id)},
            }

    async def _build_function_tools(self) -> List[FunctionTool]:
        if self._function_tools is not None:
            return self._function_tools

        function_tools: List[FunctionTool] = []
        for tool in tool_registry.list_tools():

            async def _invoke_tool(
                ctx: RunContextWrapper[OpenAIRuntimeContext],
                raw_arguments: str,
                *,
                _tool=tool,
            ) -> str:
                try:
                    parsed_arguments = json.loads(raw_arguments) if raw_arguments else {}
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

            function_tools.append(
                FunctionTool(
                    name=tool.name,
                    description=tool.description,
                    params_json_schema=tool.input_schema.model_json_schema(),
                    on_invoke_tool=_invoke_tool,
                )
            )

        self._function_tools = function_tools
        return function_tools

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
