"""Ticketing helpers for agent review workflows."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select

from cerebro.agents.models import AgentReviewTicket, TicketStatus
from cerebro.core.database import async_session_factory
from cerebro.integrations.serval import ServalError
from cerebro.integrations.serval_ticket_service import ServalTicketService

logger = structlog.get_logger(__name__)

_SERVAL_SYSTEM = "serval"


class TicketingService:
    """Lightweight ticketing integration placeholder."""

    @staticmethod
    async def create_ticket(
        *,
        org_id: UUID,
        task_id: UUID,
        system: str,
        summary: str,
        metadata: dict[str, Any] | None = None,
    ) -> AgentReviewTicket:
        # Copy metadata to avoid mutating caller-owned dictionaries.
        payload = dict(metadata or {})
        if isinstance(payload.get("serval"), dict):
            payload["serval"] = dict(payload["serval"])
        payload.setdefault("summary", summary)

        normalized_system = system.lower()

        # Serval rejects requests without a description; reuse summary when omitted.
        if normalized_system == _SERVAL_SYSTEM and "description" not in payload:
            payload["description"] = summary

        async with async_session_factory() as db_session:
            ticket = AgentReviewTicket(
                org_id=org_id,
                task_id=task_id,
                system=normalized_system,
                details=payload,
                status=TicketStatus.OPEN,
            )
            db_session.add(ticket)

            if normalized_system == _SERVAL_SYSTEM:
                # Leverage per-ticket overrides if present, falling back to configured defaults.
                serval_overrides = dict(payload.get("serval") or {})
                ticket_name = str(serval_overrides.get("name") or summary).strip()
                description = str(
                    serval_overrides.get("description")
                    or payload.get("description")
                    or summary
                ).strip()

                serval_service = ServalTicketService(db_session)
                try:
                    result = await serval_service.create_ticket(
                        org_id=org_id,
                        name=ticket_name,
                        description=description,
                        overrides=serval_overrides,
                    )
                except ServalError:
                    logger.exception("Failed to create Serval ticket")
                    raise

                ticket.external_id = result.ticket_id
                serval_details = payload.setdefault("serval", {})
                # Preserve upstream payload and identifiers for agents and UI surfaces.
                serval_details.update(serval_overrides)
                serval_details.setdefault("team_id", serval_overrides.get("team_id"))
                serval_details.setdefault(
                    "friendly_identifier", result.payload.get("friendlyIdentifier")
                )
                serval_details["ticket"] = result.payload
                ticket.details = payload
            await db_session.commit()
            await db_session.refresh(ticket)
            return ticket

    @staticmethod
    async def close_ticket(
        *, ticket_id: UUID, external_id: str | None = None
    ) -> AgentReviewTicket | None:
        async with async_session_factory() as db_session:
            ticket = await db_session.get(AgentReviewTicket, ticket_id)
            if not ticket:
                return None
            if ticket.status != TicketStatus.OPEN:
                raise ValueError("Ticket is not open")
            ticket.status = TicketStatus.CLOSED
            if external_id:
                ticket.external_id = external_id
            ticket.updated_at = datetime.now(UTC)

            if ticket.system == _SERVAL_SYSTEM and ticket.external_id:
                # Propagate local closure to Serval so analysts see consistent state.
                serval_service = ServalTicketService(db_session)
                try:
                    await serval_service.update_ticket_status(
                        org_id=ticket.org_id,
                        ticket_id=ticket.external_id,
                        status_key="closed",
                    )
                except (ServalError, ValueError):
                    logger.exception(
                        "Failed to update Serval ticket status for %s",
                        ticket.external_id,
                    )

            await db_session.commit()
            await db_session.refresh(ticket)
            return ticket

    @staticmethod
    async def list_tickets(*, task_id: UUID) -> list[AgentReviewTicket]:
        async with async_session_factory() as db_session:
            stmt = select(AgentReviewTicket).where(AgentReviewTicket.task_id == task_id)
            result = await db_session.execute(stmt)
            return list(result.scalars())
