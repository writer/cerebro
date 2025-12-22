"""Higher-level ticket orchestration for Serval."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from cerebro.integrations.serval import ServalClient, ServalConfig
from cerebro.integrations.serval_service import (
    ServalIntegrationRepository,
    ServalIntegrationSettings,
)
from cerebro.agents.models import AgentReviewTicket, TicketStatus


@dataclass
class ServalTicketResult:
    ticket_id: str
    payload: Dict[str, Any]


class ServalTicketService:
    """Facade that ties together configuration repository and Serval client."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db
        self._repo = ServalIntegrationRepository(db)

    async def ensure_settings(self, org_id: UUID) -> ServalIntegrationSettings:
        """Return decrypted settings or raise when the org is not configured."""
        settings = await self._repo.get(org_id)
        if settings is None:
            raise ValueError(
                "Serval integration is not configured for this organization"
            )
        return settings

    async def create_ticket(
        self,
        *,
        org_id: UUID,
        name: str,
        description: str,
        overrides: Optional[Dict[str, Any]] = None,
    ) -> ServalTicketResult:
        """Create a Serval ticket using saved defaults plus optional overrides."""
        settings = await self.ensure_settings(org_id)
        override = overrides or {}

        team_id = override.get("team_id") or settings.team_id
        created_by_user_id = (
            override.get("created_by_user_id") or settings.default_created_by_user_id
        )
        requester_user_id = (
            override.get("requester_user_id") or settings.default_requester_user_id
        )
        assigned_to_user_id = (
            override.get("assigned_to_user_id") or settings.default_assigned_user_id
        )
        parent_ticket_id = override.get("parent_ticket_id")
        channel_sync_targets = override.get("channel_sync_targets")
        created_at = override.get("created_at")

        async with self._build_client(settings) as client:
            ticket_payload = await client.create_ticket(
                team_id=team_id,
                name=name,
                description=description,
                created_by_user_id=created_by_user_id,
                assigned_to_user_id=assigned_to_user_id,
                requester_user_id=requester_user_id,
                parent_ticket_id=parent_ticket_id,
                channel_sync_targets=channel_sync_targets,
                created_at=created_at,
            )

            ticket_id = ticket_payload.get("id")
            if not ticket_id:
                raise ValueError("Serval ticket response missing identifier")

            # Optionally apply configured status/priority immediately
            update_payload: Dict[str, Any] = {}
            if settings.status_map.get("open"):
                update_payload["statusId"] = settings.status_map["open"]
            if settings.priority_map.get("default"):
                update_payload["priorityId"] = settings.priority_map["default"]

            if update_payload:
                updated = await client.update_ticket(ticket_id, **update_payload)
                if isinstance(updated, dict):
                    ticket_payload = updated

            return ServalTicketResult(ticket_id=ticket_id, payload=ticket_payload)

    async def update_ticket_status(
        self,
        *,
        org_id: UUID,
        ticket_id: str,
        status_key: Optional[str] = None,
        priority_key: Optional[str] = None,
        assigned_to_user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Translate local status/priority keys to Serval IDs and send the update."""
        settings = await self.ensure_settings(org_id)
        body: Dict[str, Any] = {}

        if status_key:
            status_id = settings.status_map.get(status_key)
            if status_id:
                body["statusId"] = status_id
        if priority_key:
            priority_id = settings.priority_map.get(priority_key)
            if priority_id:
                body["priorityId"] = priority_id
        if assigned_to_user_id:
            body["assignedToUserId"] = assigned_to_user_id

        if not body:
            return {}

        async with self._build_client(settings) as client:
            return await client.update_ticket(ticket_id, **body)

    async def list_recent_tickets(
        self, org_id: UUID, since: Optional[datetime]
    ) -> list[dict[str, Any]]:
        """Return tickets updated since the provided timestamp for polling syncs."""
        settings = await self.ensure_settings(org_id)
        async with self._build_client(settings) as client:
            return await client.list_tickets(team_id=settings.team_id, since=since)

    async def synchronize_remote_ticket(
        self,
        *,
        org_id: UUID,
        ticket_payload: dict[str, Any],
    ) -> Optional[TicketStatus]:
        """Update the local ticket matching the Serval payload and return new status."""
        settings = await self.ensure_settings(org_id)
        external_id = ticket_payload.get("id")
        if not external_id:
            return None

        stmt = select(AgentReviewTicket).where(
            AgentReviewTicket.org_id == org_id,
            AgentReviewTicket.system == "serval",
            AgentReviewTicket.external_id == external_id,
        )
        result = await self._db.execute(stmt)
        ticket = result.scalar_one_or_none()
        if ticket is None:
            return None

        status_id = ticket_payload.get("statusId")
        status_key = (
            settings.status_reverse_map.get(str(status_id)) if status_id else None
        )

        new_status: Optional[TicketStatus] = None
        if status_key == "closed" and ticket.status != TicketStatus.CLOSED:
            ticket.status = TicketStatus.CLOSED
            ticket.updated_at = datetime.now(timezone.utc)
            new_status = TicketStatus.CLOSED
        elif status_key == "open" and ticket.status != TicketStatus.OPEN:
            ticket.status = TicketStatus.OPEN
            ticket.updated_at = datetime.now(timezone.utc)
            new_status = TicketStatus.OPEN

        details = dict(ticket.details or {})
        serval_details = dict(details.get("serval") or {})
        serval_details["ticket"] = ticket_payload
        details["serval"] = serval_details
        ticket.details = details

        await self._db.flush()
        return new_status

    async def list_statuses(self, org_id: UUID) -> list[dict[str, Any]]:
        settings = await self.ensure_settings(org_id)
        async with self._build_client(settings) as client:
            return await client.list_statuses(team_id=settings.team_id)

    async def list_priorities(self, org_id: UUID) -> list[dict[str, Any]]:
        settings = await self.ensure_settings(org_id)
        async with self._build_client(settings) as client:
            return await client.list_priorities(team_id=settings.team_id)

    def _build_client(self, settings: ServalIntegrationSettings) -> ServalClient:
        config = ServalConfig(
            base_url=settings.api_base_url,
            client_id=settings.client_id,
            client_secret=settings.client_secret,
            verify=True,
        )
        return ServalClient(config)
