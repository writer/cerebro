"""Notification and ticket helpers for agent workflows."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from prometheus_client import CollectorRegistry
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.agents.models import AgentReviewNotification, AgentReviewTicket, NotificationStatus, TicketStatus

from cerebro_sdk.agents.base import AsyncManagerBase
from cerebro_sdk.agents.repositories import NotificationRepository, TicketRepository
from cerebro_sdk.agents.types import (
    AgentInvalidStatusError,
    AgentNotificationRecord,
    AgentTicketRecord,
)


class AgentNotificationManager(AsyncManagerBase):
    """Manage notification and ticket records for agent workflows."""

    def __init__(self, db: AsyncSession, *, registry: CollectorRegistry | None = None) -> None:
        super().__init__(db)
        self._notifications = NotificationRepository(db, registry=registry)
        self._tickets = TicketRepository(db, registry=registry)

    async def enqueue_notification(
        self,
        *,
        org_id: UUID,
        task_id: UUID,
        channel: str,
        payload: Optional[dict[str, object]] = None,
    ) -> AgentNotificationRecord:
        async with self._transaction():
            notification = await self._notifications.create(
                org_id=org_id,
                task_id=task_id,
                channel=channel,
                payload=dict(payload or {}),
            )
        await self._db.refresh(notification)
        return self._notification_to_record(notification)

    async def list_notifications(
        self,
        *,
        org_id: UUID,
        status: NotificationStatus | str | None = None,
        limit: int = 100,
    ) -> list[AgentNotificationRecord]:
        status_enum: Optional[NotificationStatus] = None
        if status:
            try:
                status_enum = self._require_enum(
                    status,
                    NotificationStatus,
                    message=f"Invalid notification status '{status}'",
                )
            except AgentInvalidStatusError:
                return []
        notifications = await self._notifications.list(
            org_id=org_id,
            status=status_enum,
            limit=limit,
        )
        return [self._notification_to_record(notification) for notification in notifications]

    async def mark_delivered(self, notification_id: UUID) -> Optional[AgentNotificationRecord]:
        notification = await self._notifications.get(notification_id)
        if not notification:
            return None
        async with self._transaction():
            if notification.status != NotificationStatus.PENDING:
                raise AgentInvalidStatusError("Notification is not pending")
            notification.status = NotificationStatus.DELIVERED
            notification.delivered_at = datetime.now(timezone.utc)
        await self._db.refresh(notification)
        return self._notification_to_record(notification)

    async def create_ticket(
        self,
        *,
        org_id: UUID,
        task_id: UUID,
        system: str,
        summary: str,
        metadata: Optional[dict[str, object]] = None,
    ) -> AgentTicketRecord:
        details = dict(metadata or {})
        details.setdefault("summary", summary)
        async with self._transaction():
            ticket = await self._tickets.create(
                org_id=org_id,
                task_id=task_id,
                system=system,
                details=details,
            )
        await self._db.refresh(ticket)
        return self._ticket_to_record(ticket)

    async def close_ticket(
        self,
        *,
        ticket_id: UUID,
        external_id: Optional[str] = None,
    ) -> Optional[AgentTicketRecord]:
        ticket = await self._tickets.get(ticket_id)
        if not ticket:
            return None
        async with self._transaction():
            if ticket.status != TicketStatus.OPEN:
                raise AgentInvalidStatusError("Ticket is not open")
            ticket.status = TicketStatus.CLOSED
            ticket.updated_at = datetime.now(timezone.utc)
            if external_id:
                ticket.external_id = external_id
        await self._db.refresh(ticket)
        return self._ticket_to_record(ticket)

    async def list_tickets(self, *, task_id: UUID) -> list[AgentTicketRecord]:
        tickets = await self._tickets.list_for_task(task_id)
        return [self._ticket_to_record(ticket) for ticket in tickets]

    @staticmethod
    def _notification_to_record(notification: AgentReviewNotification) -> AgentNotificationRecord:
        return AgentNotificationRecord(
            notification_id=notification.id,
            task_id=notification.task_id,
            org_id=notification.org_id,
            channel=notification.channel,
            status=notification.status.value,
            payload=dict(notification.payload or {}),
            created_at=notification.created_at,
            delivered_at=notification.delivered_at,
        )

    @staticmethod
    def _ticket_to_record(ticket: AgentReviewTicket) -> AgentTicketRecord:
        return AgentTicketRecord(
            ticket_id=ticket.id,
            task_id=ticket.task_id,
            org_id=ticket.org_id,
            system=ticket.system,
            status=ticket.status.value,
            details=dict(ticket.details or {}),
            external_id=ticket.external_id,
            created_at=ticket.created_at,
            updated_at=ticket.updated_at,
        )
