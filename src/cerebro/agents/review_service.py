"""Service helpers for human-in-the-loop agent review tasks."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import select

from cerebro.agents.models import AgentReviewTask, AgentSession, ReviewTaskStatus
from cerebro.core.database import async_session_factory


class AgentReviewService:
    """Operations for creating and resolving agent review tasks."""

    @staticmethod
    async def create_task(
        *,
        session: AgentSession,
        created_by: str,
        title: str,
        summary: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        message_id: Optional[UUID] = None,
        tool_invocation_id: Optional[UUID] = None,
        promotion_target: Optional[str] = None,
    ) -> AgentReviewTask:
        async with async_session_factory() as db_session:
            task = AgentReviewTask(
                org_id=session.org_id,
                session_id=session.id,
                message_id=message_id,
                tool_invocation_id=tool_invocation_id,
                created_by=created_by,
                title=title,
                summary=summary,
                payload=payload or {},
                promotion_target=promotion_target,
            )
            db_session.add(task)
            await db_session.commit()
            await db_session.refresh(task)
            return task

    @staticmethod
    async def list_tasks(
        *,
        org_id: UUID,
        status: Optional[ReviewTaskStatus] = None,
        limit: int = 50,
    ) -> List[AgentReviewTask]:
        async with async_session_factory() as db_session:
            stmt = select(AgentReviewTask).where(AgentReviewTask.org_id == org_id)
            if status:
                stmt = stmt.where(AgentReviewTask.status == status)
            stmt = stmt.order_by(AgentReviewTask.created_at.desc()).limit(limit)
            result = await db_session.execute(stmt)
            return list(result.scalars())

    @staticmethod
    async def resolve_task(
        *,
        task_id: UUID,
        resolved_by: str,
        status: ReviewTaskStatus,
        notes: Optional[str] = None,
    ) -> Optional[AgentReviewTask]:
        async with async_session_factory() as db_session:
            task = await db_session.get(AgentReviewTask, task_id)
            if not task:
                return None
            task.status = status
            task.resolved_by = resolved_by
            task.resolution_notes = notes
            task.resolved_at = datetime.now(timezone.utc)
            await db_session.commit()
            await db_session.refresh(task)
            return task
