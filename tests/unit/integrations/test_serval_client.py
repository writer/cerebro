import json

import httpx
import pytest

from cerebro.integrations.serval import ServalClient, ServalConfig


pytestmark = pytest.mark.asyncio


async def test_serval_client_caches_token() -> None:
    requests = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path))
        if request.url.path == "/v2/auth/token":
            return httpx.Response(
                200,
                json={
                    "access_token": "token-123",
                    "token_type": "Bearer",
                    "expires_in": 60,
                },
            )
        if request.url.path == "/v2/tickets":
            return httpx.Response(200, json={"data": []})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)

    async with httpx.AsyncClient(transport=transport, base_url="https://public.api.serval.com") as http_client:
        client = ServalClient(
            ServalConfig(
                base_url="https://public.api.serval.com",
                client_id="client",
                client_secret="secret",
            ),
            client=http_client,
        )
        async with client:
            await client.list_tickets()
            await client.list_tickets()

    token_requests = [req for req in requests if req[1] == "/v2/auth/token"]
    ticket_requests = [req for req in requests if req[1] == "/v2/tickets"]

    assert len(token_requests) == 1
    assert len(ticket_requests) == 2


async def test_serval_client_create_ticket_payload() -> None:
    captured_payload = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v2/auth/token":
            return httpx.Response(
                200,
                json={
                    "access_token": "token-abc",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )
        if request.url.path == "/v2/tickets":
            captured_payload.update(json.loads(request.content.decode()))
            return httpx.Response(
                200,
                json={
                    "data": {
                        "id": "srv-1",
                        "friendlyIdentifier": "SRV-1",
                        "teamId": captured_payload.get("teamId"),
                        "name": captured_payload.get("name"),
                        "description": captured_payload.get("description"),
                    }
                },
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)

    async with httpx.AsyncClient(transport=transport, base_url="https://public.api.serval.com") as http_client:
        client = ServalClient(
            ServalConfig(
                base_url="https://public.api.serval.com",
                client_id="client",
                client_secret="secret",
            ),
            client=http_client,
        )
        async with client:
            ticket = await client.create_ticket(
                team_id="team-1",
                name="Example Ticket",
                description="Test description",
                created_by_user_id="creator-1",
                assigned_to_user_id="assignee-1",
                requester_user_id="requester-1",
                channel_sync_targets=[{"email": {"targetUserType": "HUMAN"}}],
            )

    assert captured_payload["teamId"] == "team-1"
    assert captured_payload["assignedToUserId"] == "assignee-1"
    assert captured_payload["requesterUserId"] == "requester-1"
    assert isinstance(captured_payload["channelSyncTargets"], list)
    assert ticket["id"] == "srv-1"


async def test_serval_client_update_ticket() -> None:
    captured_payload = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v2/auth/token":
            return httpx.Response(
                200,
                json={
                    "access_token": "token-xyz",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )
        if request.url.path == "/v2/tickets/demo-ticket":
            captured_payload.update(json.loads(request.content.decode()))
            return httpx.Response(
                200,
                json={
                    "data": {
                        "id": "demo-ticket",
                        "statusId": captured_payload.get("statusId"),
                    }
                },
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)

    async with httpx.AsyncClient(transport=transport, base_url="https://public.api.serval.com") as http_client:
        client = ServalClient(
            ServalConfig(
                base_url="https://public.api.serval.com",
                client_id="client",
                client_secret="secret",
            ),
            client=http_client,
        )
        async with client:
            response = await client.update_ticket(
                "demo-ticket",
                statusId="status-123",
                priorityId="priority-1",
            )

    assert captured_payload == {"statusId": "status-123", "priorityId": "priority-1"}
    assert response["id"] == "demo-ticket"
    assert response["statusId"] == "status-123"
