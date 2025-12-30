"""Service helpers for human-in-the-loop agent review tasks."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

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

logger = structlog.get_logger(__name__)


class AgentReviewService:
    """Operations for creating and resolving agent review tasks."""

    @staticmethod
    async def create_task(
        *,
        session: AgentSession,
        created_by: str,
        title: str,
        summary: str | None = None,
        payload: dict[str, Any] | None = None,
        message_id: UUID | None = None,
        tool_invocation_id: UUID | None = None,
        promotion_target: str | None = None,
        priority: str | None = None,
        due_at: datetime | None = None,
        notification_channel: str | None = None,
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
        status: ReviewTaskStatus | None = None,
        limit: int = 50,
    ) -> list[AgentReviewTask]:
        async with async_session_factory() as db_session:
            stmt = select(AgentReviewTask).where(AgentReviewTask.org_id == org_id)
            if status:
                stmt = stmt.where(AgentReviewTask.status == status)
            stmt = stmt.order_by(AgentReviewTask.created_at.desc()).limit(limit)
            result = await db_session.execute(stmt)
            return list(result.scalars())

    @staticmethod
    async def list_tasks_page(
        *,
        org_id: UUID,
        status: ReviewTaskStatus | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> tuple[list[AgentReviewTask], str | None]:
        normalized_limit = max(1, min(limit, 200))

        async with async_session_factory() as db_session:
            stmt = (
                select(AgentReviewTask)
                .where(AgentReviewTask.org_id == org_id)
                .order_by(AgentReviewTask.created_at.desc(), AgentReviewTask.id.desc())
            )
            if status:
                stmt = stmt.where(AgentReviewTask.status == status)

            if cursor:
                payload = AgentReviewService._decode_cursor(cursor)
                created_raw = payload.get("created_at")
                task_id_raw = payload.get("task_id")

                created_at: datetime | None = None
                if isinstance(created_raw, str):
                    try:
                        created_at = datetime.fromisoformat(created_raw)
                    except ValueError:
                        created_at = None

                task_uuid: UUID | None = None
                if isinstance(task_id_raw, str):
                    try:
                        task_uuid = UUID(task_id_raw)
                    except (ValueError, TypeError):
                        task_uuid = None

                if created_at is not None and task_uuid is not None:
                    stmt = stmt.where(
                        or_(
                            AgentReviewTask.created_at < created_at,
                            and_(
                                AgentReviewTask.created_at == created_at,
                                AgentReviewTask.id < task_uuid,
                            ),
                        )
                    )

            stmt = stmt.limit(normalized_limit + 1)
            result = await db_session.execute(stmt)
            tasks = list(result.scalars())

        has_more = len(tasks) > normalized_limit
        page_items = tasks[:normalized_limit]

        next_cursor: str | None = None
        if has_more and page_items:
            last = page_items[-1]
            payload = {
                "created_at": last.created_at.isoformat(),
                "task_id": str(last.id),
            }
            next_cursor = AgentReviewService._encode_cursor(payload)

        return page_items, next_cursor

    @staticmethod
    async def resolve_task(
        *,
        task_id: UUID,
        resolved_by: str,
        status: ReviewTaskStatus,
        notes: str | None = None,
    ) -> AgentReviewTask | None:
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
        task_ids: list[UUID],
        status: ReviewTaskStatus | None = None,
        resolved_by: str | None = None,
        notes: str | None = None,
        escalated_to: str | None = None,
        due_at: datetime | None = None,
        priority: str | None = None,
        notification_channel: str | None = None,
        ticket_system: str | None = None,
        ticket_summary: str | None = None,
        ticket_metadata: dict[str, Any] | None = None,
    ) -> list[AgentReviewTask]:
        if not task_ids:
            return []

        post_notifications: list[tuple[UUID, str, dict[str, Any]]] = []
        post_tickets: list[tuple[UUID, str, str, dict[str, Any]]] = []

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
                    await AgentReviewService._record_policy_signal(
                        db_session, task, status
                    )

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

                    if (
                        ticket_system
                        and ticket_summary
                        and status
                        in {ReviewTaskStatus.ESCALATED, ReviewTaskStatus.PROMOTED}
                    ):
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
            task_match = next((t for t in tasks if t.id == task_id), None)
            if not task_match:
                continue
            task = task_match
            await NotificationService.enqueue(
                org_id=task.org_id,
                task_id=task.id,
                channel=channel,
                payload=payload,
            )

        for task_id, system, summary, metadata in post_tickets:
            task_match = next((t for t in tasks if t.id == task_id), None)
            if not task_match:
                continue
            task = task_match
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
        resolved_by: str | None,
        notes: str | None,
        escalated_to: str | None = None,
    ) -> None:
        task.status = status
        task.resolution_notes = notes
        task.resolved_at = datetime.now(UTC)
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

        expression = (
            payload.get("suggested_expression")
            or f'resource.tool_name == "{tool_name}"'
        )

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

        suggestion.last_seen = datetime.now(UTC)
        suggestion.details.setdefault("last_resolution_notes", task.resolution_notes)

    @staticmethod
    def _serialize_for_websocket(task: AgentReviewTask) -> dict[str, Any]:
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
            "updated_at": (
                task.updated_at or task.resolved_at or task.created_at
            ).isoformat(),
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
            await websocket_notifier.notify_review_task_event(
                str(task.org_id), event_type, payload
            )
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.warning("Failed to emit review task websocket event: %s", exc)

    @staticmethod
    async def assign_task(
        *,
        task_id: UUID,
        assigned_to: str,
        assigned_by: str,
    ) -> AgentReviewTask | None:
        """Assign a task to a user."""
        async with async_session_factory() as db_session:
            task = await db_session.get(AgentReviewTask, task_id)
            if not task:
                return None

            old_assignee = task.assigned_to
            task.assigned_to = assigned_to
            task.assigned_at = datetime.now(UTC)
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
        metadata: dict[str, Any] | None = None,
    ) -> AgentReviewComment | None:
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
    ) -> list[AgentReviewComment]:
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
    ) -> list[AgentReviewHistory]:
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
    async def summarize_queue(
        *,
        org_id: UUID,
        now: datetime | None = None,
        db_session: AsyncSession | None = None,
    ) -> dict[str, Any]:
        """Summarize review queue backlog for operator dashboards."""

        reference_time = now or datetime.now(UTC)

        if db_session is None:
            async with async_session_factory() as session:
                return await AgentReviewService._summarize_queue_internal(
                    session,
                    org_id=org_id,
                    reference_time=reference_time,
                )

        return await AgentReviewService._summarize_queue_internal(
            db_session,
            org_id=org_id,
            reference_time=reference_time,
        )

    @staticmethod
    async def _summarize_queue_internal(
        db_session: AsyncSession,
        *,
        org_id: UUID,
        reference_time: datetime,
    ) -> dict[str, Any]:
        status_stmt = (
            select(
                AgentReviewTask.status.label("status"),
                func.count().label("count"),
                func.sum(
                    case(
                        (AgentReviewTask.assigned_to.is_(None), 1),
                        else_=0,
                    )
                ).label("unassigned"),
                func.sum(
                    case(
                        (
                            and_(
                                AgentReviewTask.due_at.isnot(None),
                                AgentReviewTask.due_at <= reference_time,
                            ),
                            1,
                        ),
                        else_=0,
                    )
                ).label("overdue"),
                func.min(AgentReviewTask.created_at).label("oldest_created"),
                func.max(AgentReviewTask.created_at).label("newest_created"),
            )
            .where(AgentReviewTask.org_id == org_id)
            .group_by(AgentReviewTask.status)
        )

        status_rows = (await db_session.execute(status_stmt)).all()

        pending_stmt = select(
            func.count().label("total"),
            func.sum(
                case(
                    (AgentReviewTask.assigned_to.is_(None), 1),
                    else_=0,
                )
            ).label("unassigned"),
            func.sum(
                case(
                    (
                        and_(
                            AgentReviewTask.due_at.isnot(None),
                            AgentReviewTask.due_at <= reference_time,
                        ),
                        1,
                    ),
                    else_=0,
                )
            ).label("overdue"),
            func.min(AgentReviewTask.due_at).label("next_due"),
            func.min(AgentReviewTask.created_at).label("oldest_created"),
        ).where(
            AgentReviewTask.org_id == org_id,
            AgentReviewTask.status == ReviewTaskStatus.PENDING,
        )

        pending_row = await db_session.execute(pending_stmt)
        pending_summary = pending_row.one_or_none()

        priority_stmt = (
            select(
                AgentReviewTask.priority.label("priority"),
                func.count().label("count"),
            )
            .where(
                AgentReviewTask.org_id == org_id,
                AgentReviewTask.status == ReviewTaskStatus.PENDING,
                AgentReviewTask.priority.isnot(None),
            )
            .group_by(AgentReviewTask.priority)
        )

        priority_rows = (await db_session.execute(priority_stmt)).all()

        status_summary = [
            {
                "status": (
                    row.status.value
                    if hasattr(row.status, "value")
                    else str(row.status)
                ),
                "count": int(row.count or 0),
                "unassigned": int(row.unassigned or 0),
                "overdue": int(row.overdue or 0),
                "oldest_created": row.oldest_created,
                "newest_created": row.newest_created,
            }
            for row in status_rows
        ]

        priority_summary = [
            {
                "priority": row.priority,
                "count": int(row[1] or 0),  # type: ignore[arg-type]
            }
            for row in priority_rows
        ]

        if pending_summary is None:
            pending_data = {
                "total": 0,
                "unassigned": 0,
                "overdue": 0,
                "next_due": None,
                "oldest_created": None,
            }
        else:
            pending_data = {
                "total": int(pending_summary.total or 0),
                "unassigned": int(pending_summary.unassigned or 0),
                "overdue": int(pending_summary.overdue or 0),
                "next_due": pending_summary.next_due,
                "oldest_created": pending_summary.oldest_created,
            }

        return {
            "generated_at": reference_time,
            "status_counts": status_summary,
            "pending": pending_data,
            "priority_breakdown": priority_summary,
        }

    @staticmethod
    async def _record_history(
        db_session,
        *,
        task_id: UUID,
        changed_by: str,
        change_type: str,
        field_name: str | None = None,
        old_value: dict[str, Any] | None = None,
        new_value: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
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

    @staticmethod
    def _encode_cursor(payload: dict[str, Any]) -> str:
        serialized = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        token = base64.urlsafe_b64encode(serialized.encode("utf-8")).decode("ascii")
        return token.rstrip("=")

    @staticmethod
    def _decode_cursor(token: str) -> dict[str, Any]:
        padding = "=" * (-len(token) % 4)
        raw = token + padding
        try:
            decoded = base64.urlsafe_b64decode(raw.encode("ascii")).decode("utf-8")
            payload = json.loads(decoded)
        except (ValueError, json.JSONDecodeError):
            return {}

        if not isinstance(payload, dict):
            return {}
        return payload
