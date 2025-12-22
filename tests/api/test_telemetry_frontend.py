import asyncio
from datetime import datetime
from uuid import UUID, uuid4

import pytest

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.models import FrontendObservationEvent, Organization
from cerebro.telemetry.schemas import FrontendObservationTelemetry
from cerebro.telemetry.services import TelemetryIngestionService


def test_frontend_observation_ingestion(
    client: TestClient,
    test_db: AsyncSession,
    test_org: Organization,
    test_token: str,
) -> None:
    response = client.post(
        "/api/v1/telemetry/frontend/observe",
        json={
            "event_type": "page_view",
            "component": "DashboardLayout",
            "context": {"pathname": "/agents"},
            "metadata": {"source": "unit-test"},
        },
        headers={"Authorization": f"Bearer {test_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "recorded"

    event_id = UUID(data["event_id"])

    loop = asyncio.get_event_loop()
    result = loop.run_until_complete(
        test_db.execute(
            select(FrontendObservationEvent).where(
                FrontendObservationEvent.event_id == event_id
            )
        )
    )
    stored_event = result.scalar_one()

    assert stored_event.component == "DashboardLayout"
    assert stored_event.context_data.get("pathname") == "/agents"
    assert stored_event.event_metadata.get("source") == "unit-test"


def test_frontend_observation_with_agent_session(
    client: TestClient,
    test_db: AsyncSession,
    test_org: Organization,
    test_token: str,
) -> None:
    session_id = str(uuid4())
    occurred_at = "2024-10-22T12:34:56+00:00"

    response = client.post(
        "/api/v1/telemetry/frontend/observe",
        json={
            "event_type": "filter_apply",
            "component": "RuntimeAnalyticsPanel",
            "agent_session_id": session_id,
            "context": {"filter": "tool_execution"},
            "metadata": {"source": "unit-test"},
            "occurred_at": occurred_at,
        },
        headers={"Authorization": f"Bearer {test_token}"},
    )

    assert response.status_code == 200
    data = response.json()

    event_id = UUID(data["event_id"])
    loop = asyncio.get_event_loop()
    result = loop.run_until_complete(
        test_db.execute(
            select(FrontendObservationEvent).where(
                FrontendObservationEvent.event_id == event_id
            )
        )
    )
    stored_event = result.scalar_one()

    assert str(stored_event.agent_session_id) == session_id
    assert stored_event.occurred_at.isoformat().startswith("2024-10-22T12:34:56")
    assert stored_event.context_data.get("filter") == "tool_execution"


@pytest.mark.asyncio
async def test_process_frontend_observation_normalizes_datetime(
    test_db: AsyncSession,
    test_org: Organization,
    test_admin_user,
):
    service = TelemetryIngestionService(test_db)
    payload = FrontendObservationTelemetry(
        event_type="page_view",
        component="DashboardLayout",
        occurred_at=datetime(2024, 10, 22, 13, 0, 0),
    )

    result = await service.process_frontend_observation(
        org_id=test_org.org_id,
        user_id=test_admin_user.user_id,
        payload=payload,
    )

    assert result["status"] == "recorded"
    event_id = UUID(result["event_id"])

    row = await test_db.execute(
        select(FrontendObservationEvent).where(
            FrontendObservationEvent.event_id == event_id
        )
    )
    stored_event = row.scalar_one()

    assert (
        stored_event.occurred_at.strftime("%Y-%m-%dT%H:%M:%S") == "2024-10-22T13:00:00"
    )
    assert stored_event.event_type == "page_view"
