"""Service helpers for human-in-the-loop agent review tasks."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from uuid import UUID

from sqlalchemy import select

from cerebro.agents.models import (
    AgentPolicySuggestion,
    AgentReviewComment,
    AgentReviewHistory,
    AgentReviewTask,
    AgentSession,
    ReviewTaskStatus,
)
from cerebro.agents.notification_service import NotificationService
from cerebro.agents.ticketing_service import TicketingService
from cerebro.core.database import async_session_factory


logger = logging.getLogger(__name__)


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
        priority: Optional[str] = None,
        due_at: Optional[datetime] = None,
        notification_channel: Optional[str] = None,
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
                priority=priority,
                due_at=due_at,
                notification_channel=notification_channel,
            )
            db_session.add(task)
            await db_session.commit()
            await db_session.refresh(task)
            await AgentReviewService._emit_websocket_event(task, "review_task_created")
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
            AgentReviewService._apply_resolution_updates(
                task,
                status=status,
                resolved_by=resolved_by,
                notes=notes,
            )
            await AgentReviewService._record_policy_signal(db_session, task, status)
            await db_session.commit()
            await db_session.refresh(task)
            await AgentReviewService._emit_websocket_event(task, "review_task_updated")
            return task

    @staticmethod
    async def bulk_update_tasks(
        *,
        org_id: UUID,
        task_ids: List[UUID],
        status: Optional[ReviewTaskStatus] = None,
        resolved_by: Optional[str] = None,
        notes: Optional[str] = None,
        escalated_to: Optional[str] = None,
        due_at: Optional[datetime] = None,
        priority: Optional[str] = None,
        notification_channel: Optional[str] = None,
        ticket_system: Optional[str] = None,
        ticket_summary: Optional[str] = None,
        ticket_metadata: Optional[Dict[str, Any]] = None,
    ) -> List[AgentReviewTask]:
        if not task_ids:
            return []

        post_notifications: List[Tuple[UUID, str, Dict[str, Any]]] = []
        post_tickets: List[Tuple[UUID, str, str, Dict[str, Any]]] = []

        async with async_session_factory() as db_session:
            stmt = (
                select(AgentReviewTask)
                .where(AgentReviewTask.org_id == org_id)
                .where(AgentReviewTask.id.in_(task_ids))
            )
            result = await db_session.execute(stmt)
            tasks = list(result.scalars())
            if not tasks:
                return []

            for task in tasks:
                if priority:
                    task.priority = priority
                if due_at:
                    task.due_at = due_at
                if notification_channel:
                    task.notification_channel = notification_channel

                if status:
                    old_status = task.status
                    AgentReviewService._apply_resolution_updates(
                        task,
                        status=status,
                        resolved_by=resolved_by,
                        notes=notes,
                        escalated_to=escalated_to,
                    )
                    await AgentReviewService._record_policy_signal(db_session, task, status)
                    
                    # Record status change
                    await AgentReviewService._record_history(
                        db_session,
                        task_id=task.id,
                        changed_by=resolved_by or "system",
                        change_type="status_change",
                        field_name="status",
                        old_value={"status": old_status.value},
                        new_value={"status": status.value},
                        metadata={"notes": notes} if notes else {},
                    )

                    if notification_channel:
                        post_notifications.append(
                            (
                                task.id,
                                notification_channel,
                                {
                                    "status": status.value,
                                    "title": task.title,
                                    "summary": task.summary,
                                },
                            )
                        )

                    if ticket_system and ticket_summary and status in {ReviewTaskStatus.ESCALATED, ReviewTaskStatus.PROMOTED}:
                        post_tickets.append(
                            (
                                task.id,
                                ticket_system,
                                ticket_summary,
                                ticket_metadata or {},
                            )
                        )

            await db_session.commit()
            for task in tasks:
                await db_session.refresh(task)

        for task_id, channel, payload in post_notifications:
            task = next((t for t in tasks if t.id == task_id), None)
            if not task:
                continue
            await NotificationService.enqueue(
                org_id=task.org_id,
                task_id=task.id,
                channel=channel,
                payload=payload,
            )

        for task_id, system, summary, metadata in post_tickets:
            task = next((t for t in tasks if t.id == task_id), None)
            if not task:
                continue
            ticket = await TicketingService.create_ticket(
                org_id=task.org_id,
                task_id=task.id,
                system=system,
                summary=summary,
                metadata=metadata,
            )
            await AgentReviewService._update_ticket_reference(task.id, str(ticket.id))
            task.ticket_reference = str(ticket.id)

        for task in tasks:
            await AgentReviewService._emit_websocket_event(task, "review_task_updated")

        return tasks

    @staticmethod
    async def _update_ticket_reference(task_id: UUID, reference: str) -> None:
        async with async_session_factory() as db_session:
            task = await db_session.get(AgentReviewTask, task_id)
            if not task:
                return
            task.ticket_reference = reference
            await db_session.commit()

    @staticmethod
    def _apply_resolution_updates(
        task: AgentReviewTask,
        *,
        status: ReviewTaskStatus,
        resolved_by: Optional[str],
        notes: Optional[str],
        escalated_to: Optional[str] = None,
    ) -> None:
        task.status = status
        task.resolution_notes = notes
        task.resolved_at = datetime.now(timezone.utc)
        if resolved_by:
            task.resolved_by = resolved_by
        if status == ReviewTaskStatus.ESCALATED:
            task.escalated_to = escalated_to or task.escalated_to

    @staticmethod
    async def _record_policy_signal(
        db_session,
        task: AgentReviewTask,
        status: ReviewTaskStatus,
    ) -> None:
        payload = task.payload or {}
        tool_name = payload.get("tool_name")
        if not tool_name:
            return

        expression = payload.get("suggested_expression") or f'resource.tool_name == "{tool_name}"'

        stmt = (
            select(AgentPolicySuggestion)
            .where(AgentPolicySuggestion.org_id == task.org_id)
            .where(AgentPolicySuggestion.tool_name == tool_name)
            .where(AgentPolicySuggestion.cel_expression == expression)
            .limit(1)
        )
        result = await db_session.execute(stmt)
        suggestion = result.scalar_one_or_none()
        if suggestion is None:
            suggestion = AgentPolicySuggestion(
                org_id=task.org_id,
                tool_name=tool_name,
                cel_expression=expression,
                details={"example_payload": payload},
            )
            db_session.add(suggestion)

        if status in {ReviewTaskStatus.APPROVED, ReviewTaskStatus.PROMOTED}:
            suggestion.support_count = (suggestion.support_count or 0) + 1
        elif status in {ReviewTaskStatus.REJECTED, ReviewTaskStatus.ESCALATED}:
            suggestion.reject_count = (suggestion.reject_count or 0) + 1

        suggestion.last_seen = datetime.now(timezone.utc)
        suggestion.details.setdefault("last_resolution_notes", task.resolution_notes)

    @staticmethod
    def _serialize_for_websocket(task: AgentReviewTask) -> Dict[str, Any]:
        return {
            "id": str(task.id),
            "org_id": str(task.org_id),
            "session_id": str(task.session_id),
            "title": task.title,
            "summary": task.summary,
            "status": task.status.value,
            "priority": task.priority,
            "assigned_to": task.assigned_to,
            "escalated_to": task.escalated_to,
            "ticket_reference": task.ticket_reference,
            "resolved_at": task.resolved_at.isoformat() if task.resolved_at else None,
            "updated_at": (task.updated_at or task.resolved_at or task.created_at).isoformat(),
        }

    @staticmethod
    async def _emit_websocket_event(task: AgentReviewTask, event_type: str) -> None:
        try:
            from cerebro.api.websocket import websocket_notifier
        except Exception as exc:  # pragma: no cover - websocket optional
            logger.debug("WebSocket notifier unavailable: %s", exc)
            return

        payload = AgentReviewService._serialize_for_websocket(task)

        try:
            await websocket_notifier.notify_review_task_event(str(task.org_id), event_type, payload)
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.warning("Failed to emit review task websocket event: %s", exc)

    @staticmethod
    async def assign_task(
        *,
        task_id: UUID,
        assigned_to: str,
        assigned_by: str,
    ) -> Optional[AgentReviewTask]:
        """Assign a task to a user."""
        async with async_session_factory() as db_session:
            task = await db_session.get(AgentReviewTask, task_id)
            if not task:
                return None
            
            old_assignee = task.assigned_to
            task.assigned_to = assigned_to
            task.assigned_at = datetime.now(timezone.utc)
            task.assigned_by = assigned_by

            # Record history
            await AgentReviewService._record_history(
                db_session,
                task_id=task_id,
                changed_by=assigned_by,
                change_type="assignment",
                field_name="assigned_to",
                old_value={"assigned_to": old_assignee} if old_assignee else None,
                new_value={"assigned_to": assigned_to},
            )

            await db_session.commit()
            await db_session.refresh(task)
            await AgentReviewService._emit_websocket_event(task, "review_task_updated")
            return task

    @staticmethod
    async def add_comment(
        *,
        task_id: UUID,
        author: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[AgentReviewComment]:
        """Add a comment to a review task."""
        async with async_session_factory() as db_session:
            task = await db_session.get(AgentReviewTask, task_id)
            if not task:
                return None

            comment = AgentReviewComment(
                task_id=task_id,
                author=author,
                content=content,
                extra_metadata=metadata or {},
            )
            db_session.add(comment)

            # Record history
            await AgentReviewService._record_history(
                db_session,
                task_id=task_id,
                changed_by=author,
                change_type="comment_added",
                new_value={"content": content[:100]},
            )

            await db_session.commit()
            await db_session.refresh(comment)
            return comment

    @staticmethod
    async def get_comments(
        *,
        task_id: UUID,
        limit: int = 100,
    ) -> List[AgentReviewComment]:
        """Get all comments for a task."""
        async with async_session_factory() as db_session:
            stmt = (
                select(AgentReviewComment)
                .where(AgentReviewComment.task_id == task_id)
                .order_by(AgentReviewComment.created_at.desc())
                .limit(limit)
            )
            result = await db_session.execute(stmt)
            return list(result.scalars())

    @staticmethod
    async def get_history(
        *,
        task_id: UUID,
        limit: int = 100,
    ) -> List[AgentReviewHistory]:
        """Get change history for a task."""
        async with async_session_factory() as db_session:
            stmt = (
                select(AgentReviewHistory)
                .where(AgentReviewHistory.task_id == task_id)
                .order_by(AgentReviewHistory.created_at.desc())
                .limit(limit)
            )
            result = await db_session.execute(stmt)
            return list(result.scalars())

    @staticmethod
    async def _record_history(
        db_session,
        *,
        task_id: UUID,
        changed_by: str,
        change_type: str,
        field_name: Optional[str] = None,
        old_value: Optional[Dict[str, Any]] = None,
        new_value: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record a change in the audit trail."""
        history = AgentReviewHistory(
            task_id=task_id,
            changed_by=changed_by,
            change_type=change_type,
            field_name=field_name,
            old_value=old_value,
            new_value=new_value,
            extra_metadata=metadata or {},
        )
        db_session.add(history)

