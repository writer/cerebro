import asyncio
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.models import FrontendObservationEvent, Organization


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
            select(FrontendObservationEvent).where(FrontendObservationEvent.event_id == event_id)
        )
    )
    stored_event = result.scalar_one()

    assert stored_event.component == "DashboardLayout"
    assert stored_event.context_data.get("pathname") == "/agents"
    assert stored_event.event_metadata.get("source") == "unit-test"
