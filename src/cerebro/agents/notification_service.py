"""Notification helpers for agent review workflow."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select

from cerebro.agents.models import AgentReviewNotification, NotificationStatus
from cerebro.core.database import async_session_factory


class NotificationService:
    """Persist and retrieve human-in-loop notification events."""

    @staticmethod
    async def enqueue(
        *,
        org_id: UUID,
        task_id: UUID,
        channel: str,
        payload: dict[str, Any] | None = None,
    ) -> AgentReviewNotification:
        async with async_session_factory() as db_session:
            notification = AgentReviewNotification(
                org_id=org_id,
                task_id=task_id,
                channel=channel,
                payload=payload or {},
                status=NotificationStatus.PENDING,
            )
            db_session.add(notification)
            await db_session.commit()
            await db_session.refresh(notification)
            return notification

    @staticmethod
    async def list_notifications(
        *,
        org_id: UUID,
        status: NotificationStatus | str | None = None,
        limit: int = 100,
    ) -> list[AgentReviewNotification]:
        async with async_session_factory() as db_session:
            stmt = select(AgentReviewNotification).where(
                AgentReviewNotification.org_id == org_id
            )
            if status:
                status_enum = (
                    status
                    if isinstance(status, NotificationStatus)
                    else NotificationStatus(status)
                )
                stmt = stmt.where(AgentReviewNotification.status == status_enum)
            stmt = stmt.order_by(AgentReviewNotification.created_at.desc()).limit(limit)
            result = await db_session.execute(stmt)
            return list(result.scalars())

    @staticmethod
    async def mark_delivered(
        *, notification_id: UUID
    ) -> AgentReviewNotification | None:
        async with async_session_factory() as db_session:
            notification = await db_session.get(
                AgentReviewNotification, notification_id
            )
            if not notification:
                return None
            if notification.status != NotificationStatus.PENDING:
                raise ValueError("Notification is not pending")
            notification.status = NotificationStatus.DELIVERED
            notification.delivered_at = datetime.now(UTC)
            await db_session.commit()
            await db_session.refresh(notification)
            return notification
