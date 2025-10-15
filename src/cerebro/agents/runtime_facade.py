"""Facade providing runtime selection between Claude and OpenAI backends."""

from __future__ import annotations

from typing import Any, AsyncIterator, Dict, Optional
from uuid import UUID

import structlog

from cerebro.agents.models import AgentSession, AgentType
from cerebro.agents.openai_runtime import CerebroOpenAIRuntime
from cerebro.agents.runtime import CerebroClaudeRuntime
from cerebro.core.config import settings

logger = structlog.get_logger(__name__)

RuntimeKey = str


class AgentRuntimeFacade:
    """Route agent operations to the appropriate runtime implementation."""

    def __init__(self, default_runtime: Optional[str] = None) -> None:
        self.default_runtime: RuntimeKey = (
            (default_runtime or settings.agent_default_runtime).lower()
        )
        self._runtimes: Dict[RuntimeKey, Any] = {}

    async def create_session(
        self,
        org_id: UUID,
        agent_type: AgentType,
        created_by: str,
        context: Dict[str, Any],
        title: Optional[str] = None,
    ) -> AgentSession:
        runtime_key = (
            context.get("_runtime_engine")
            or context.get("runtime_engine")
            or context.get("runtime")
        )
        if runtime_key is None:
            runtime_key = self.default_runtime

        runtime_key = self._normalize_key(runtime_key)
        prepared_context = dict(context)
        prepared_context["_runtime_engine"] = runtime_key

        runtime = self._get_runtime(runtime_key)
        session = await runtime.create_session(
            org_id=org_id,
            agent_type=agent_type,
            created_by=created_by,
            context=prepared_context,
            title=title,
        )
        return session

    async def get_session(self, session_id: UUID) -> Optional[AgentSession]:
        runtime = self._get_runtime(self.default_runtime)
        return await runtime.get_session(session_id)

    async def send_message(
        self,
        session: AgentSession,
        message: str,
        user_id: str,
        stream: bool = False,
    ) -> AsyncIterator[Dict[str, Any]]:
        runtime = self._runtime_for_session(session)
        async for chunk in runtime.send_message(
            session=session,
            message=message,
            user_id=user_id,
            stream=stream,
        ):
            yield chunk

    async def get_session_messages(
        self,
        session: AgentSession,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Dict[str, Any]]:
        runtime = self._runtime_for_session(session)
        return await runtime.get_session_messages(session.id, limit, offset)

    async def get_session_metrics(self, session: AgentSession) -> Dict[str, Any]:
        runtime = self._runtime_for_session(session)
        return await runtime.get_session_metrics(session.id)

    def _runtime_for_session(self, session: AgentSession):
        runtime_key = session.context.get("_runtime_engine") or self.default_runtime
        runtime_key = self._normalize_key(runtime_key)
        return self._get_runtime(runtime_key)

    def _get_runtime(self, runtime_key: RuntimeKey):
        normalized = self._normalize_key(runtime_key)
        if normalized not in self._runtimes:
            if normalized == "openai":
                self._runtimes[normalized] = CerebroOpenAIRuntime()
            else:
                self._runtimes[normalized] = CerebroClaudeRuntime(
                    model=settings.claude_model,
                    max_tokens=settings.claude_max_tokens,
                    temperature=settings.claude_temperature,
                )
            logger.info("Initialized agent runtime", backend=normalized)
        return self._runtimes[normalized]

    @staticmethod
    def _normalize_key(value: str) -> RuntimeKey:
        normalized = value.lower()
        if normalized not in {"claude", "openai"}:
            normalized = "claude"
        return normalized
