from __future__ import annotations

from cerebro.integrations import serval_ticket_service


def test_upsert_and_get_serval_config(client, admin_token, test_db, test_org):
    # Ensure configuration can be persisted and subsequently retrieved.
    org_id = str(test_org.org_id)
    headers = {"Authorization": f"Bearer {admin_token}"}

    response = client.put(
        f"/api/v1/serval/{org_id}/config",
        json={
            "team_id": "team-1",
            "client_id": "client-abc",
            "client_secret": "secret-xyz",
            "default_created_by_user_id": "user-creator",
            "default_status_id": "status-open",
            "default_priority_id": "priority-default",
            "status_map": {"open": "status-open", "closed": "status-closed"},
            "priority_map": {"default": "priority-default"},
        },
        headers=headers,
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["team_id"] == "team-1"
    assert "client_secret" not in payload

    get_response = client.get(f"/api/v1/serval/{org_id}/config", headers=headers)
    assert get_response.status_code == 200
    fetched = get_response.json()
    assert fetched["status_map"]["closed"] == "status-closed"


def test_serval_metadata_endpoints(client, admin_token, monkeypatch, test_org):
    # Surface metadata even when live client calls are mocked.
    org_id = str(test_org.org_id)
    headers = {"Authorization": f"Bearer {admin_token}"}

    async def _list_statuses(self, org_id):  # type: ignore[override]
        return [{"id": "status-open", "name": "Open"}]

    async def _list_priorities(self, org_id):  # type: ignore[override]
        return [{"id": "priority-default", "priority": "DEFAULT"}]

    monkeypatch.setattr(serval_ticket_service.ServalTicketService, "list_statuses", _list_statuses)
    monkeypatch.setattr(serval_ticket_service.ServalTicketService, "list_priorities", _list_priorities)

    # Ensure config exists to satisfy lookups
    client.put(
        f"/api/v1/serval/{org_id}/config",
        json={
            "team_id": "team-1",
            "client_id": "client-abc",
            "client_secret": "secret-xyz",
            "default_created_by_user_id": "user-creator",
        },
        headers=headers,
    )

    status_response = client.get(f"/api/v1/serval/{org_id}/statuses", headers=headers)
    assert status_response.status_code == 200
    assert status_response.json()[0]["id"] == "status-open"

    priority_response = client.get(f"/api/v1/serval/{org_id}/priorities", headers=headers)
    assert priority_response.status_code == 200
    assert priority_response.json()[0]["id"] == "priority-default"
