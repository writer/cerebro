"""Shared helpers for Cerebro agent runtimes."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from uuid import UUID

import structlog
from sqlalchemy import func, select

from cerebro.agents.models import (
    AgentMessage,
    AgentSession,
    AgentType,
    MessageRole,
    ToolInvocation,
)
from cerebro.agents.analytics_service import AgentAnalyticsService
from cerebro.agents.memory_store import AgentMemoryStore
from cerebro.agents.metrics import record_runtime_metrics
from cerebro.agents.telemetry import RuntimeSpan, start_runtime_span
from cerebro.agents.tools import AgentContext
from cerebro.core.database import async_session_factory
from cerebro.core.config import settings

logger = structlog.get_logger(__name__)


@dataclass
class RetrievedMemory:
    prompt_snippets: List[str]
    entries: List[Dict[str, Any]]


class AgentRuntimePersistenceMixin:
    """Mixin providing persistence and context utilities for agent runtimes."""

    backend_name: str = "unknown"

    async def _prepare_session_context(
        self,
        *,
        org_id: UUID,
        agent_type: AgentType,
        created_by: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Load organizational, system, and historical session context for a new session."""

        prepared_context = dict(context)

        try:
            from cerebro.agents.tools.org_context import GetOrgContextTool
            from cerebro.agents.tools.system_context import GetSystemContextTool

            temp_context = AgentContext(
                session_id=UUID("00000000-0000-0000-0000-000000000000"),
                org_id=org_id,
                user_id=created_by,
                agent_type=agent_type.value,
            )

            org_context_tool = GetOrgContextTool()
            system_context_tool = GetSystemContextTool()

            org_context_result = await org_context_tool.execute(
                inputs=org_context_tool.input_model(
                    include_repositories=True,
                    include_providers=True,
                    include_statistics=True,
                    include_tools=True,
                ),
                context=temp_context,
            )
            system_context_result = await system_context_tool.execute(
                inputs=system_context_tool.input_model(
                    include_database=True,
                    include_environment=True,
                    include_providers=True,
                    include_health=True,
                ),
                context=temp_context,
            )

            if org_context_result.success and system_context_result.success:
                prepared_context["_auto_loaded_org_context"] = org_context_result.data
                prepared_context["_auto_loaded_system_context"] = (
                    system_context_result.data
                )

                org_data = org_context_result.data or {}
                logger.info(
                    "Auto-loaded context for agent session",
                    org_id=org_id,
                    agent_type=agent_type.value,
                    org_name=org_data.get("org_name"),
                    providers_count=len(
                        org_data.get("providers_connected", [])
                    ),
                    tools_count=org_data.get("agent_tools_count"),
                )
            else:
                logger.warning(
                    "Failed to auto-load context for agent session",
                    org_id=org_id,
                    agent_type=agent_type.value,
                    org_context_success=org_context_result.success,
                    system_context_success=system_context_result.success,
                )
        except Exception as exc:  # pragma: no cover - defensive logging only
            logger.warning(
                "Context auto-loading failed, continuing without",
                org_id=org_id,
                agent_type=agent_type.value,
                error=str(exc),
            )

        # Load cross-session memory (learned facts, preferences, corrections)
        try:
            session_memory = await self._load_session_memory(org_id, created_by)
            if session_memory:
                prepared_context["_auto_loaded_session_memory"] = session_memory
                logger.info(
                    "Auto-loaded session memory",
                    org_id=org_id,
                    memory_entries=len(session_memory),
                )
        except Exception as exc:  # pragma: no cover - defensive logging only
            logger.warning(
                "Session memory loading failed, continuing without",
                org_id=org_id,
                error=str(exc),
            )

        return prepared_context

    async def _load_session_memory(
        self,
        org_id: UUID,
        user_id: str,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Load persisted session context from previous sessions."""
        from datetime import datetime, timezone
        from sqlalchemy import select, and_, or_
        from cerebro.agents.models import AgentSessionContext

        async with async_session_factory() as db_session:
            # Load non-expired context entries for this org
            now = datetime.now(timezone.utc)
            stmt = (
                select(AgentSessionContext)
                .where(
                    and_(
                        AgentSessionContext.org_id == org_id,
                        or_(
                            AgentSessionContext.expires_at.is_(None),
                            AgentSessionContext.expires_at > now,
                        ),
                    )
                )
                .order_by(AgentSessionContext.created_at.desc())
                .limit(limit)
            )
            result = await db_session.execute(stmt)
            entries = result.scalars().all()

            return [
                {
                    "key": entry.context_key,
                    "value": entry.context_value,
                    "type": entry.context_type,
                    "confidence": entry.confidence,
                    "learned_from": entry.learned_from,
                    "created_at": (
                        entry.created_at.isoformat() if entry.created_at else None
                    ),
                }
                for entry in entries
            ]

    async def _persist_session(
        self,
        *,
        org_id: UUID,
        agent_type: AgentType,
        created_by: str,
        context: Dict[str, Any],
        title: Optional[str],
    ) -> AgentSession:
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
                org_id=org_id,
                agent_type=agent_type.value,
            )

            return session

    async def _build_agent_context(
        self,
        session: AgentSession,
        user_id: str,
        *,
        memory_entries: Optional[List[Dict[str, Any]]] = None,
    ) -> AgentContext:
        finding_ids = [UUID(fid) for fid in session.context.get("finding_ids", [])]
        incident_id = None
        if session.context.get("incident_id"):
            incident_id = UUID(session.context["incident_id"])

        provider_scope = session.context.get("provider_scope", [])

        agent_context = AgentContext(
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
        if memory_entries:
            agent_context.memory_entries = memory_entries
        return agent_context

    async def _store_message(
        self,
        session: AgentSession,
        role: MessageRole,
        content: Dict[str, Any],
        *,
        input_tokens: Optional[int] = None,
        output_tokens: Optional[int] = None,
    ) -> None:
        async with async_session_factory() as db_session:
            message = AgentMessage(
                session_id=session.id,
                role=role,
                content=content,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            )
            db_session.add(message)
            await db_session.commit()
            await db_session.refresh(message)

            logger.info(
                "Agent message stored",
                session_id=session.id,
                message_id=message.id,
                role=role.value,
                org_id=session.org_id,
                content_length=len(str(content)),
                tool_calls=(
                    content.get("tool_calls", 0) if isinstance(content, dict) else 0
                ),
            )

    async def _get_session_metrics(self, session_id: UUID) -> Dict[str, Any]:
        async with async_session_factory() as db_session:
            message_stats_stmt = (
                select(
                    AgentMessage.role.label("role"),
                    func.count().label("count"),
                    func.sum(func.coalesce(AgentMessage.input_tokens, 0)).label(
                        "total_input_tokens"
                    ),
                    func.sum(func.coalesce(AgentMessage.output_tokens, 0)).label(
                        "total_output_tokens"
                    ),
                )
                .where(AgentMessage.session_id == session_id)
                .group_by(AgentMessage.role)
            )
            message_stats = (
                (await db_session.execute(message_stats_stmt)).mappings().all()
            )

            tool_stats_stmt = (
                select(
                    ToolInvocation.tool_name.label("tool_name"),
                    ToolInvocation.status.label("status"),
                    func.count().label("count"),
                )
                .where(ToolInvocation.session_id == session_id)
                .group_by(ToolInvocation.tool_name, ToolInvocation.status)
            )
            tool_stats = (await db_session.execute(tool_stats_stmt)).mappings().all()

            return {
                "session_id": str(session_id),
                "message_stats": [dict(row) for row in message_stats],
                "tool_stats": [dict(row) for row in tool_stats],
            }

    async def _capture_memory(
        self,
        *,
        session: AgentSession,
        role: MessageRole,
        content: str,
        metadata: Optional[Dict[str, object]] = None,
    ) -> None:
        try:
            store = await AgentMemoryStore.shared()
            await store.add_message(
                session=session,
                role=role,
                content=content,
                metadata=metadata,
            )
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.debug(
                "Failed to capture agent memory entry",
                session_id=session.id,
                role=role.value,
                error=str(exc),
            )

    async def _retrieve_memory_snippets(
        self,
        *,
        session: AgentSession,
        query: str,
        limit: int = 5,
    ) -> RetrievedMemory:
        try:
            store = await AgentMemoryStore.shared()
            limit = min(limit, settings.agent_memory_max_snippets)
            # retrieve_relevant returns List[str] (the snippets themselves)
            prompt_snippets = await store.retrieve_relevant(
                session=session,
                query=query,
                limit=limit,
            )
            if prompt_snippets:
                await AgentAnalyticsService.record_event(
                    org_id=session.org_id,
                    session_id=session.id,
                    event_type="memory_retrieved",
                    payload={
                        "count": len(prompt_snippets),
                    },
                )
            # Convert snippets to entry dicts for compatibility
            entries = [{"snippet": s} for s in prompt_snippets]
            return RetrievedMemory(prompt_snippets=prompt_snippets, entries=entries)
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.debug(
                "Failed to retrieve agent memory",
                session_id=session.id,
                error=str(exc),
            )
            return RetrievedMemory(prompt_snippets=[], entries=[])

    async def _update_session_context(
        self,
        session: AgentSession,
        updates: Dict[str, Any],
    ) -> None:
        async with async_session_factory() as db_session:
            db_session_session = await db_session.get(AgentSession, session.id)
            if not db_session_session:
                return
            merged = dict(db_session_session.context or {})
            merged.update(updates)
            db_session_session.context = merged
            await db_session.commit()
            session.context = merged

    def _compose_memory_brief(
        self,
        memory: RetrievedMemory,
        *,
        max_entries: int = 3,
    ) -> Optional[str]:
        if not memory.entries:
            return None
        summaries = []
        for entry in memory.entries[:max_entries]:
            summary = entry.get("summary") or entry.get("snippet")
            if summary:
                summaries.append(summary)
        if not summaries:
            return None
        return "\n".join(f"• {text}" for text in summaries)

    def _log_memory_activity(
        self,
        session: AgentSession,
        new_entries: List[Dict[str, Any]],
    ) -> None:
        if not new_entries:
            return
        logger.info(
            "Memory recall surfaced new entries",
            session_id=session.id,
            org_id=session.org_id,
            backend=self.backend_name,
            new_entry_ids=[entry.get("id") for entry in new_entries],
        )

    def _begin_runtime_operation(
        self,
        *,
        session: AgentSession,
        operation: str,
    ) -> tuple[float, RuntimeSpan]:
        start_time = time.perf_counter()
        telemetry_span = start_runtime_span(
            backend=self.backend_name,
            agent_type=session.agent_type.value,
            operation=operation,
            session_id=str(session.id),
        )
        return start_time, telemetry_span

    def _complete_runtime_operation(
        self,
        *,
        session: AgentSession,
        start_time: float,
        telemetry_span: RuntimeSpan,
        success: bool,
        input_tokens: int,
        output_tokens: int,
        tool_calls: int,
        error: Optional[BaseException] = None,
    ) -> None:
        duration = time.perf_counter() - start_time
        record_runtime_metrics(
            backend=self.backend_name,
            agent_type=session.agent_type.value,
            duration_seconds=duration,
            success=success,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            tool_calls=tool_calls,
            error_type=type(error).__name__ if error else None,
        )
        telemetry_span.finish(
            success=success,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            tool_calls=tool_calls,
            error=error,
        )
