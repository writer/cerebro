"""Review queue helpers for the Cerebro SDK."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.agents.models import (
    AgentReviewComment,
    AgentReviewHistory,
    AgentReviewTask,
    ReviewTaskStatus,
)

from cerebro_sdk.agents.base import AsyncManagerBase
from cerebro_sdk.agents.types import (
    AgentInvalidStatusError,
    AgentReviewCommentRecord,
    AgentReviewExportRecord,
    AgentReviewHistoryRecord,
    AgentReviewTaskRecord,
)


class AgentReviewManager(AsyncManagerBase):
    """Access and update the agent review queue."""

    def __init__(self, db: AsyncSession) -> None:
        super().__init__(db)

    async def list_tasks(
        self,
        *,
        org_id: UUID,
        status: ReviewTaskStatus | str | None = None,
        limit: int = 50,
    ) -> list[AgentReviewTaskRecord]:
        stmt = select(AgentReviewTask).where(AgentReviewTask.org_id == org_id)
        if status:
            try:
                status_enum = self._require_enum(
                    status,
                    ReviewTaskStatus,
                    message=f"Invalid review task status '{status}'",
                )
            except AgentInvalidStatusError:
                return []
            stmt = stmt.where(AgentReviewTask.status == status_enum)
        stmt = stmt.order_by(AgentReviewTask.created_at.desc()).limit(limit)
        tasks = list(await self._db.scalars(stmt))
        return [self._to_record(task) for task in tasks]

    async def update_task_status(
        self,
        *,
        task_id: UUID,
        status: ReviewTaskStatus | str,
        resolved_by: str,
        notes: Optional[str] = None,
    ) -> Optional[AgentReviewTaskRecord]:
        task = await self._db.get(AgentReviewTask, task_id)
        if not task:
            return None
        status_enum = self._require_enum(
            status,
            ReviewTaskStatus,
            message=f"Invalid review task status '{status}'",
        )

        async with self._transaction():
            old_status = task.status
            task.status = status_enum
            task.resolved_by = resolved_by
            task.resolved_at = datetime.now(timezone.utc)
            task.resolution_notes = notes
            await self._db.flush()

            await self._record_history(
                task_id=task.id,
                changed_by=resolved_by,
                change_type="status_change",
                field_name="status",
                old_value={"status": old_status.value},
                new_value={"status": status_enum.value},
                metadata={"notes": notes} if notes else {},
            )

        await self._db.refresh(task)
        return self._to_record(task)

    async def bulk_update(
        self,
        *,
        org_id: UUID,
        task_ids: Iterable[UUID],
        status: ReviewTaskStatus | str | None = None,
        resolved_by: Optional[str] = None,
        notes: Optional[str] = None,
        escalated_to: Optional[str] = None,
        due_at: Optional[datetime] = None,
        priority: Optional[str] = None,
        notification_channel: Optional[str] = None,
    ) -> list[AgentReviewTaskRecord]:
        ids = list(task_ids)
        if not ids:
            return []

        stmt = (
            select(AgentReviewTask)
            .where(AgentReviewTask.org_id == org_id)
            .where(AgentReviewTask.id.in_(ids))
        )
        tasks = list(await self._db.scalars(stmt))
        if not tasks:
            return []

        status_enum: Optional[ReviewTaskStatus] = None
        if status:
            status_enum = self._require_enum(
                status,
                ReviewTaskStatus,
                message=f"Invalid review task status '{status}'",
            )

        async with self._transaction():
            for task in tasks:
                if priority:
                    task.priority = priority
                if due_at:
                    task.due_at = due_at
                if notification_channel:
                    task.notification_channel = notification_channel
                if escalated_to:
                    task.escalated_to = escalated_to
                if status_enum:
                    old_status = task.status
                    task.status = status_enum
                    task.resolved_by = resolved_by
                    task.resolved_at = datetime.now(timezone.utc)
                    task.resolution_notes = notes
                    await self._db.flush()
                    await self._record_history(
                        task_id=task.id,
                        changed_by=resolved_by or "system",
                        change_type="status_change",
                        field_name="status",
                        old_value={"status": old_status.value},
                        new_value={"status": status_enum.value},
                        metadata={"notes": notes} if notes else {},
                    )

        for task in tasks:
            await self._db.refresh(task)
        return [self._to_record(task) for task in tasks]

    async def export_tasks(
        self,
        *,
        org_id: UUID,
        status: ReviewTaskStatus | str | None = None,
        include_comments: bool = True,
        include_history: bool = True,
        history_limit: int = 200,
        limit: int = 100,
    ) -> list[AgentReviewExportRecord]:
        tasks = await self.list_tasks(org_id=org_id, status=status, limit=limit)
        exports: list[AgentReviewExportRecord] = []
        for task in tasks:
            comments: list[AgentReviewCommentRecord] = []
            history: list[AgentReviewHistoryRecord] = []
            if include_comments:
                comments = await self.list_comments(task_id=task.task_id)
            if include_history:
                history = await self.list_history(task_id=task.task_id, limit=history_limit)
            exports.append(
                AgentReviewExportRecord(
                    task=task,
                    comments=comments,
                    history=history,
                )
            )
        return exports

    async def assign_task(
        self,
        *,
        task_id: UUID,
        assigned_to: str,
        assigned_by: str,
    ) -> Optional[AgentReviewTaskRecord]:
        task = await self._db.get(AgentReviewTask, task_id)
        if not task:
            return None
        now = datetime.now(timezone.utc)
        async with self._transaction():
            task.assigned_to = assigned_to
            task.assigned_by = assigned_by
            task.assigned_at = now
            await self._db.flush()
            await self._record_history(
                task_id=task.id,
                changed_by=assigned_by,
                change_type="assignment",
                field_name="assigned_to",
                old_value=None,
                new_value={"assigned_to": assigned_to},
                metadata={},
            )
        await self._db.refresh(task)
        return self._to_record(task)

    async def add_comment(
        self,
        *,
        task_id: UUID,
        author: str,
        content: str,
        metadata: Optional[dict[str, object]] = None,
    ) -> AgentReviewCommentRecord:
        async with self._transaction():
            comment = AgentReviewComment(
                task_id=task_id,
                author=author,
                content=content,
                extra_metadata=dict(metadata or {}),
            )
            self._db.add(comment)
            await self._db.flush()
            await self._record_history(
                task_id=task_id,
                changed_by=author,
                change_type="comment",
                field_name="comments",
                old_value=None,
                new_value={"comment_id": str(comment.id)},
                metadata=dict(metadata or {}),
            )

        await self._db.refresh(comment)
        return self._comment_to_record(comment)

    async def list_comments(self, *, task_id: UUID) -> list[AgentReviewCommentRecord]:
        stmt = (
            select(AgentReviewComment)
            .where(AgentReviewComment.task_id == task_id)
            .order_by(AgentReviewComment.created_at.asc())
        )
        comments = list(await self._db.scalars(stmt))
        return [self._comment_to_record(comment) for comment in comments]

    async def list_history(self, *, task_id: UUID, limit: int = 100) -> list[AgentReviewHistoryRecord]:
        stmt = (
            select(AgentReviewHistory)
            .where(AgentReviewHistory.task_id == task_id)
            .order_by(AgentReviewHistory.created_at.desc())
            .limit(limit)
        )
        history_items = list(await self._db.scalars(stmt))
        return [self._history_to_record(item) for item in history_items]

    async def _record_history(
        self,
        *,
        task_id: UUID,
        changed_by: str,
        change_type: str,
        field_name: Optional[str],
        old_value: Optional[dict[str, object]],
        new_value: Optional[dict[str, object]],
        metadata: dict[str, object],
    ) -> None:
        history = AgentReviewHistory(
            task_id=task_id,
            changed_by=changed_by,
            change_type=change_type,
            field_name=field_name,
            old_value=old_value,
            new_value=new_value,
            extra_metadata=metadata,
        )
        self._db.add(history)

    @staticmethod
    def _to_record(task: AgentReviewTask) -> AgentReviewTaskRecord:
        return AgentReviewTaskRecord(
            task_id=task.id,
            session_id=task.session_id,
            org_id=task.org_id,
            status=task.status.value,
            title=task.title,
            summary=task.summary,
            payload=dict(task.payload or {}),
            promotion_target=task.promotion_target,
            priority=task.priority,
            due_at=task.due_at,
            escalated_to=task.escalated_to,
            notification_channel=task.notification_channel,
            ticket_reference=task.ticket_reference,
            created_by=task.created_by,
            created_at=task.created_at,
            resolved_by=task.resolved_by,
            resolved_at=task.resolved_at,
            resolution_notes=task.resolution_notes,
            assigned_to=task.assigned_to,
        )

    @staticmethod
    def _comment_to_record(comment: AgentReviewComment) -> AgentReviewCommentRecord:
        return AgentReviewCommentRecord(
            comment_id=comment.id,
            task_id=comment.task_id,
            author=comment.author,
            content=comment.content,
            created_at=comment.created_at,
            metadata=dict(comment.extra_metadata or {}),
        )

    @staticmethod
    def _history_to_record(item: AgentReviewHistory) -> AgentReviewHistoryRecord:
        return AgentReviewHistoryRecord(
            history_id=item.id,
            task_id=item.task_id,
            changed_by=item.changed_by,
            change_type=item.change_type,
            field_name=item.field_name,
            old_value=dict(item.old_value or {}) if item.old_value else None,
            new_value=dict(item.new_value or {}) if item.new_value else None,
            created_at=item.created_at,
            metadata=dict(item.extra_metadata or {}),
        )
