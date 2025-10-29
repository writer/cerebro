from __future__ import annotations

import asyncio
from typing import Any

import pytest

from cerebro.core.config import settings
from cerebro.integrations.state import IntegrationStateRepository
from cerebro.api.routers import integrations as integrations_router


def _run_async(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_list_integration_issues_surfaces_error(client, test_db, admin_token):
    async def _prepare_state():
        repo = IntegrationStateRepository(test_db)
        await repo.upsert_state(
            integration="kandji.devices",
            scope="acme",
            metadata={"last_status": "error", "last_error": "auth failure"},
        )
        await test_db.commit()

    _run_async(_prepare_state())

    headers = {"Authorization": f"Bearer {admin_token}"}
    response = client.get("/api/v1/integrations/status/issues", headers=headers)

    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 1
    issue = payload[0]
    assert issue["integration"] == "kandji.devices"
    assert issue["scope"] == "acme"
    assert issue["issue_type"] == "error"
    assert issue["severity"] == "critical"
    assert "auth failure" in issue["message"].lower()


def test_trigger_integration_sync_sentinelone(client, admin_token, monkeypatch):
    monkeypatch.setattr(settings, "sentinelone_enabled", True)
    monkeypatch.setattr(settings, "sentinelone_org_name", "acme")

    captured: dict[str, Any] = {}

    def _fake_apply_async(*, kwargs=None):  # type: ignore[override]
        captured["kwargs"] = kwargs or {}

        class _Result:
            id = "task-42"

        return _Result()

    monkeypatch.setattr(integrations_router.sync_sentinelone, "apply_async", _fake_apply_async)

    headers = {"Authorization": f"Bearer {admin_token}"}
    response = client.post(
        "/api/v1/integrations/sync",
        json={"integration": "sentinelone", "lookback_minutes": 45},
        headers=headers,
    )

    assert response.status_code == 202
    body = response.json()
    assert body["task_id"] == "task-42"
    assert body["integration"] == "sentinelone"
    assert body["scope"] == "acme"
    assert "queued_at" in body

    assert captured["kwargs"] == {"lookback_minutes": 45}


def test_trigger_integration_sync_kandji_rejects_lookback(client, admin_token, monkeypatch):
    monkeypatch.setattr(settings, "kandji_enabled", True)
    monkeypatch.setattr(integrations_router.sync_kandji, "apply_async", lambda: None)

    headers = {"Authorization": f"Bearer {admin_token}"}
    response = client.post(
        "/api/v1/integrations/sync",
        json={"integration": "kandji", "lookback_minutes": 15},
        headers=headers,
    )

    assert response.status_code == 422


@pytest.mark.parametrize("integration", ["sentinelone", "kandji"])
def test_trigger_integration_sync_respects_disabled(client, admin_token, monkeypatch, integration):
    monkeypatch.setattr(settings, f"{integration}_enabled", False)

    headers = {"Authorization": f"Bearer {admin_token}"}
    response = client.post(
        "/api/v1/integrations/sync",
        json={"integration": integration},
        headers=headers,
    )

    assert response.status_code == 400
