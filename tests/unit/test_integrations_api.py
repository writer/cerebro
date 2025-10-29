from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from cerebro.core.config import settings
from cerebro.automation.integration_sync import IntegrationIssue
from cerebro.integrations.state import IntegrationIssueEventRepository, IntegrationStateRepository
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


def test_integration_issue_history_endpoint(client, test_db, admin_token):
    now = datetime.now(timezone.utc)

    async def _prepare_history():
        repo = IntegrationIssueEventRepository(test_db)
        issue = IntegrationIssue(
            integration="sentinelone.activities",
            scope="acme",
            status="error",
            issue_type="error",
            severity="critical",
            message="api timeout",
            observed_at=now,
            last_timestamp=now - timedelta(minutes=10),
            age_seconds=600,
            metadata={"error": "timeout"},
        )
        await repo.record_issue_event(issue)
        await test_db.commit()

    _run_async(_prepare_history())

    headers = {"Authorization": f"Bearer {admin_token}"}
    response = client.get(
        "/api/v1/integrations/status/issues/history",
        params={"integration": "sentinelone.activities", "scope": "acme", "hours": 24},
        headers=headers,
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["events"]
    assert payload["events"][0]["integration"] == "sentinelone.activities"
    assert payload["buckets"]


def test_get_integration_sync_status_endpoint(client, admin_token, monkeypatch):
    finished_at = datetime.now(timezone.utc)

    class _Result:
        status = "SUCCESS"
        result = {"status": "ok"}
        date_done = finished_at

        @staticmethod
        def ready():
            return True

    monkeypatch.setattr(integrations_router.celery_app, "AsyncResult", lambda task_id: _Result())

    headers = {"Authorization": f"Bearer {admin_token}"}
    response = client.get("/api/v1/integrations/sync/task-xyz", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "SUCCESS"
    assert body["finished"] is True
    assert body["result"] == {"status": "ok"}
