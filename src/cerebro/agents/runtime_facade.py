"""Facade providing runtime selection between Claude and OpenAI backends."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional
from uuid import UUID

import structlog

from cerebro.agents.models import AgentSession, AgentType
from cerebro.agents.openai_runtime import CerebroOpenAIRuntime
from cerebro.agents.runtime import CerebroClaudeRuntime
from cerebro.core.config import settings
from cerebro.core.database import async_session_factory

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
        skill_tags = self._extract_skill_tags(agent_type, context=context)
        runtime_key = self._select_runtime(agent_type, context, skill_tags)

        prepared_context = dict(context)
        prepared_context["_runtime_engine"] = runtime_key
        prepared_context["_skill_tags"] = skill_tags

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
        runtime = await self._maybe_switch_runtime(session, message)
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
        runtime = await self._runtime_for_session(session)
        return await runtime.get_session_messages(session.id, limit, offset)

    async def get_session_metrics(self, session: AgentSession) -> Dict[str, Any]:
        runtime = await self._runtime_for_session(session)
        return await runtime.get_session_metrics(session.id)

    async def _runtime_for_session(self, session: AgentSession):
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

    async def _maybe_switch_runtime(
        self,
        session: AgentSession,
        message: str,
    ):
        context_snapshot = dict(session.context or {})
        skill_tags = self._extract_skill_tags(
            session.agent_type,
            context=context_snapshot,
            message=message,
        )

        desired_runtime = self._select_runtime(session.agent_type, context_snapshot, skill_tags)
        current_runtime = self._normalize_key(
            session.context.get("_runtime_engine") or self.default_runtime
        )

        if desired_runtime != current_runtime:
            logger.info(
                "Routing agent session to new runtime",
                session_id=session.id,
                from_runtime=current_runtime,
                to_runtime=desired_runtime,
                skill_tags=skill_tags,
            )
            await self._update_session_context(
                session.id,
                {
                    "_runtime_engine": desired_runtime,
                    "_skill_tags": skill_tags,
                    "_last_routing_reason": {
                        "excerpt": message[-200:],
                        "skill_tags": skill_tags,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                },
            )
            session.context["_runtime_engine"] = desired_runtime
            session.context["_skill_tags"] = skill_tags
            return self._get_runtime(desired_runtime)

        if session.context.get("_skill_tags") != skill_tags:
            await self._update_session_context(session.id, {"_skill_tags": skill_tags})
            session.context["_skill_tags"] = skill_tags

        return self._get_runtime(current_runtime)

    def _select_runtime(
        self,
        agent_type: AgentType,
        context: Dict[str, Any],
        skill_tags: List[str],
    ) -> RuntimeKey:
        preference_map = settings.agent_runtime_preferences or {}

        for tag in skill_tags:
            preferred = preference_map.get(tag)
            if preferred:
                return self._normalize_key(preferred)

        preferred = preference_map.get(agent_type.value)
        if preferred:
            return self._normalize_key(preferred)

        fallback = context.get("runtime_engine") or context.get("runtime")
        if fallback:
            return self._normalize_key(fallback)

        return self.default_runtime

    def _extract_skill_tags(
        self,
        agent_type: AgentType,
        context: Dict[str, Any],
        message: Optional[str] = None,
    ) -> List[str]:
        tags: List[str] = []

        finding_ids = context.get("finding_ids") or []
        incident_id = context.get("incident_id")
        remediation_goal = context.get("remediation_goal")
        requested_tools = (context.get("requested_tools") or [])

        if finding_ids:
            tags.append("analysis")
        if incident_id:
            tags.append("incident_response")
        if remediation_goal:
            tags.append("remediation")
        if context.get("query") or context.get("soql"):
            tags.append("querying")
        if requested_tools:
            tags.extend([f"tool:{name}" for name in requested_tools])

        if message:
            lowered = message.lower()
            if any(word in lowered for word in ("incident", "breach", "contain")):
                tags.append("incident_response")
            if any(word in lowered for word in ("sql", "query", "report")):
                tags.append("reporting")
            if "remediat" in lowered or "patch" in lowered:
                tags.append("remediation")

        tags.append(agent_type.value)

        # ensure uniqueness while preserving order
        seen = set()
        unique_tags: List[str] = []
        for tag in tags:
            if tag and tag not in seen:
                seen.add(tag)
                unique_tags.append(tag)
        return unique_tags

    async def _update_session_context(
        self,
        session_id: UUID,
        updates: Dict[str, Any],
    ) -> None:
        async with async_session_factory() as db_session:
            db_session_obj = await db_session.get(AgentSession, session_id)
            if not db_session_obj:
                return
            merged = dict(db_session_obj.context or {})
            merged.update(updates)
            db_session_obj.context = merged
            await db_session.commit()
