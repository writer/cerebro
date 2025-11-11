from __future__ import annotations

from datetime import UTC, datetime

from cerebro.tasks import serval_tasks


def test_sync_serval_tickets_updates_state(monkeypatch, test_db, test_org):
    # Validate the polling task records processed tickets even with mocked services.
    org_id = test_org.org_id

    async def _list_all(self):  # type: ignore[override]
        from cerebro.integrations.serval_service import ServalIntegrationSettings
        return [
            ServalIntegrationSettings(
                org_id=org_id,
                api_base_url="https://api.serval.test",
                team_id="team-1",
                client_id="client",
                client_secret="secret",
                default_status_id="status-open",
                default_priority_id="priority-default",
                default_created_by_user_id="creator",
                default_requester_user_id=None,
                default_assigned_user_id=None,
                status_map={"open": "status-open", "closed": "status-closed"},
                priority_map={"default": "priority-default"},
                status_reverse_map={"status-open": "open", "status-closed": "closed"},
                priority_reverse_map={"priority-default": "default"},
            )
        ]

    async def _list_recent_tickets(self, org_id, since):  # type: ignore[override]
        return [
            {
                "id": "ticket-1",
                "statusId": "status-closed",
                "updatedAt": datetime.now(UTC).isoformat(),
            }
        ]

    async def _sync_ticket(self, org_id, ticket_payload):  # type: ignore[override]
        return None

    monkeypatch.setattr(
        "cerebro.integrations.serval_service.ServalIntegrationRepository.list_all",
        _list_all,
    )
    monkeypatch.setattr(
        "cerebro.integrations.serval_ticket_service.ServalTicketService.list_recent_tickets",
        _list_recent_tickets,
    )
    monkeypatch.setattr(
        "cerebro.integrations.serval_ticket_service.ServalTicketService.synchronize_remote_ticket",
        _sync_ticket,
    )

    result = serval_tasks.sync_serval_tickets.apply().get()

    assert result["processed"] == 1
