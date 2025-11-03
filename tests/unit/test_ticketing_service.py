from uuid import uuid4

import pytest

from cerebro.agents import ticketing_service
from cerebro.agents.ticketing_service import TicketingService
from cerebro.integrations.serval_ticket_service import ServalTicketResult


pytestmark = pytest.mark.asyncio


class DummySession:
    def __init__(self) -> None:
        self.added = []
        self.committed = False
        self.refreshed = None
        self.storage = {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        pass

    def add(self, obj) -> None:
        self.added.append(obj)
        obj_id = getattr(obj, "id", None)
        if obj_id is None:
            obj_id = uuid4()
            setattr(obj, "id", obj_id)
        self.storage[obj_id] = obj

    async def commit(self) -> None:
        self.committed = True

    async def refresh(self, obj) -> None:
        self.refreshed = obj

    async def get(self, model, obj_id):
        return self.storage.get(obj_id)


class DummyServalTicketService:
    create_calls = []
    update_calls = []

    def __init__(self, db):
        self.db = db

    async def create_ticket(self, *, org_id, name, description, overrides=None):
        DummyServalTicketService.create_calls.append(
            {
                "org_id": org_id,
                "name": name,
                "description": description,
                "overrides": overrides or {},
            }
        )
        return ServalTicketResult(
            ticket_id="srv-123",
            payload={
                "id": "srv-123",
                "friendlyIdentifier": "SRV-123",
                "teamId": overrides.get("team_id") if overrides else None,
            },
        )

    async def update_ticket_status(self, *, org_id, ticket_id, status_key=None, priority_key=None, assigned_to_user_id=None):
        DummyServalTicketService.update_calls.append(
            {
                "org_id": org_id,
                "ticket_id": ticket_id,
                "status_key": status_key,
                "priority_key": priority_key,
                "assigned_to_user_id": assigned_to_user_id,
            }
        )
        return {}



async def test_ticketing_service_creates_serval_ticket(monkeypatch):
    session = DummySession()

    monkeypatch.setattr(ticketing_service, "async_session_factory", lambda: session)
    monkeypatch.setattr(ticketing_service, "ServalTicketService", DummyServalTicketService)
    DummyServalTicketService.create_calls.clear()
    DummyServalTicketService.update_calls.clear()

    metadata = {
        "description": "Detailed body",
        "serval": {
            "name": "Custom Serval Ticket",
            "assigned_to_user_id": "assign-1",
            "team_id": "team-default",
        },
    }

    ticket = await TicketingService.create_ticket(
        org_id=uuid4(),
        task_id=uuid4(),
        system="Serval",
        summary="Escalate issue",
        metadata=metadata,
    )

    assert session.committed is True
    assert ticket.external_id == "srv-123"
    assert ticket.system == "serval"
    assert ticket.details["serval"]["ticket"]["friendlyIdentifier"] == "SRV-123"
    assert ticket.details["serval"]["team_id"] == "team-default"
    assert DummyServalTicketService.create_calls[0]["overrides"]["assigned_to_user_id"] == "assign-1"


async def test_ticketing_service_closes_serval_ticket(monkeypatch):
    session = DummySession()
    monkeypatch.setattr(ticketing_service, "async_session_factory", lambda: session)
    monkeypatch.setattr(ticketing_service, "ServalTicketService", DummyServalTicketService)
    DummyServalTicketService.create_calls.clear()
    DummyServalTicketService.update_calls.clear()

    org_id = uuid4()
    task_id = uuid4()

    ticket = await TicketingService.create_ticket(
        org_id=org_id,
        task_id=task_id,
        system="serval",
        summary="Escalate",
        metadata={"serval": {"team_id": "team-default", "created_by_user_id": "creator"}},
    )

    assert ticket.external_id == "srv-123"
    assert ticket.id in session.storage

    DummyServalTicketService.update_calls.clear()

    await TicketingService.close_ticket(ticket_id=ticket.id, external_id=ticket.external_id)

    assert DummyServalTicketService.update_calls
    call = DummyServalTicketService.update_calls[0]
    assert call["ticket_id"] == ticket.external_id
    assert call["status_key"] == "closed"
