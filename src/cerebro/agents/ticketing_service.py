"""Ticketing helpers for agent review workflows."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import UUID

from sqlalchemy import select

from cerebro.agents.models import AgentReviewTicket, TicketStatus
from cerebro.core.database import async_session_factory


class TicketingService:
    """Lightweight ticketing integration placeholder."""

    @staticmethod
    async def create_ticket(
        *,
        org_id: UUID,
        task_id: UUID,
        system: str,
        summary: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentReviewTicket:
        payload = metadata or {}
        payload.setdefault("summary", summary)

        async with async_session_factory() as db_session:
            ticket = AgentReviewTicket(
                org_id=org_id,
                task_id=task_id,
                system=system,
                details=payload,
                status=TicketStatus.OPEN,
            )
            db_session.add(ticket)
            await db_session.commit()
            await db_session.refresh(ticket)
            return ticket

    @staticmethod
    async def close_ticket(*, ticket_id: UUID, external_id: Optional[str] = None) -> Optional[AgentReviewTicket]:
        async with async_session_factory() as db_session:
            ticket = await db_session.get(AgentReviewTicket, ticket_id)
            if not ticket:
                return None
            if ticket.status != TicketStatus.OPEN:
                raise ValueError("Ticket is not open")
            ticket.status = TicketStatus.CLOSED
            if external_id:
                ticket.external_id = external_id
            ticket.updated_at = datetime.now(timezone.utc)
            await db_session.commit()
            await db_session.refresh(ticket)
            return ticket

    @staticmethod
    async def list_tickets(*, task_id: UUID) -> list[AgentReviewTicket]:
        async with async_session_factory() as db_session:
            stmt = select(AgentReviewTicket).where(AgentReviewTicket.task_id == task_id)
            result = await db_session.execute(stmt)
            return list(result.scalars())
