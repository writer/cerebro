"""High-level playbook helpers built on top of agent facades."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Optional
from uuid import UUID

from sqlalchemy import select
from prometheus_client import CollectorRegistry
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.agents.models import AgentPolicySuggestion, AgentReviewTask

from cerebro_sdk.agents.base import AsyncManagerBase
from cerebro_sdk.agents.notifications import AgentNotificationManager
from cerebro_sdk.agents.sessions import AgentManager
from cerebro_sdk.agents.tooling import AgentToolingManager
from cerebro_sdk.agents.types import (
    AgentNotificationRecord,
    AgentPolicySuggestionRecord,
    AgentTicketRecord,
)


class AgentPlaybook(AsyncManagerBase):
    """High-level helpers orchestrating common agent playbooks."""

    def __init__(
        self, db: AsyncSession, *, registry: CollectorRegistry | None = None
    ) -> None:
        super().__init__(db)
        self._registry = registry

    async def start_incident_playbook(
        self,
        *,
        org_id: UUID,
        created_by: str,
        incident_id: UUID | str,
        finding_ids: Optional[Iterable[UUID | str]] = None,
        title: Optional[str] = None,
    ):
        manager = AgentManager(self._db)
        session = await manager.create_incident_session(
            org_id=org_id,
            created_by=created_by,
            incident_id=incident_id,
            title=title,
        )
        if finding_ids:
            await manager.link_findings(
                session_id=session.session_id, finding_ids=finding_ids
            )
            refreshed_session = await manager.get_session(session.session_id)
            if refreshed_session is None:
                raise RuntimeError("Failed to refresh session after linking findings")
            session = refreshed_session
        return session

    async def kickoff_findings_playbook(
        self,
        *,
        org_id: UUID,
        created_by: str,
        finding_ids: Iterable[UUID | str],
        title: Optional[str] = None,
    ):
        manager = AgentManager(self._db)
        return await manager.create_session_for_findings(
            org_id=org_id,
            created_by=created_by,
            finding_ids=finding_ids,
            title=title,
        )

    async def memory_snapshot(self, session_id: UUID):
        manager = AgentManager(self._db)
        return await manager.get_memory_stats(session_id=session_id)

    async def schedule_notifications(
        self,
        *,
        task_id: UUID,
        channels: Iterable[str],
    ) -> list[AgentNotificationRecord]:
        task = await self._db.get(AgentReviewTask, task_id)
        if not task:
            return []
        notification_manager = AgentNotificationManager(
            self._db, registry=self._registry
        )
        results: list[AgentNotificationRecord] = []
        for channel in channels:
            record = await notification_manager.enqueue_notification(
                org_id=task.org_id,
                task_id=task_id,
                channel=channel,
            )
            results.append(record)
        return results

    async def escalate_to_ticket(
        self,
        *,
        task_id: UUID,
        system: str,
        summary: str,
        metadata: Optional[dict[str, object]] = None,
    ) -> Optional[AgentTicketRecord]:
        task = await self._db.get(AgentReviewTask, task_id)
        if not task:
            return None
        notification_manager = AgentNotificationManager(
            self._db, registry=self._registry
        )
        return await notification_manager.create_ticket(
            org_id=task.org_id,
            task_id=task_id,
            system=system,
            summary=summary,
            metadata=metadata,
        )

    async def record_policy_suggestion(
        self,
        *,
        org_id: UUID,
        tool_name: str,
        cel_expression: str,
        support_delta: int = 1,
        reject_delta: int = 0,
        details: Optional[dict[str, object]] = None,
    ) -> AgentPolicySuggestionRecord:
        now = datetime.now(timezone.utc)
        stmt = select(AgentPolicySuggestion).where(
            AgentPolicySuggestion.org_id == org_id,
            AgentPolicySuggestion.tool_name == tool_name,
            AgentPolicySuggestion.cel_expression == cel_expression,
        )
        existing = await self._db.scalar(stmt)
        tooling = AgentToolingManager(self._db)
        if existing:
            async with self._transaction():
                existing.support_count += support_delta
                existing.reject_count += reject_delta
                existing.details.update(details or {})
                existing.last_seen = now
            await self._db.refresh(existing)
            return tooling._policy_to_record(existing)  # type: ignore[attr-defined]

        async with self._transaction():
            suggestion = AgentPolicySuggestion(
                org_id=org_id,
                tool_name=tool_name,
                cel_expression=cel_expression,
                support_count=support_delta,
                reject_count=reject_delta,
                details=dict(details or {}),
                last_seen=now,
                created_at=now,
            )
            self._db.add(suggestion)
        await self._db.refresh(suggestion)
        return tooling._policy_to_record(suggestion)  # type: ignore[attr-defined]
