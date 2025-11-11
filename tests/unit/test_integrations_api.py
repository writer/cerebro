from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

import pytest

from cerebro.api.routers import integrations as integrations_router
from cerebro.automation.integration_sync import IntegrationIssue
from cerebro.core.config import settings
from cerebro.core.models import Account
from cerebro.integrations.state import (
    IntegrationIssueEventRepository,
    IntegrationStateRepository,
)
UTC = timezone.utc

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

    monkeypatch.setattr(
        integrations_router.sync_sentinelone,
        "apply_async",
        _fake_apply_async,
    )

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


def test_trigger_integration_sync_kandji_rejects_lookback(
    client,
    admin_token,
    monkeypatch,
):
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
def test_trigger_integration_sync_respects_disabled(
    client,
    admin_token,
    monkeypatch,
    integration,
):
    monkeypatch.setattr(settings, f"{integration}_enabled", False)

    headers = {"Authorization": f"Bearer {admin_token}"}
    response = client.post(
        "/api/v1/integrations/sync",
        json={"integration": integration},
        headers=headers,
    )

    assert response.status_code == 400


def test_integration_issue_history_endpoint(client, test_db, admin_token):
    now = datetime.now(UTC)

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
    finished_at = datetime.now(UTC)

    class _Result:
        status: ClassVar[str] = "SUCCESS"
        result: ClassVar[dict[str, str]] = {"status": "ok"}
        date_done: ClassVar[datetime] = finished_at

        @staticmethod
        def ready():
            return True

    monkeypatch.setattr(
        integrations_router.celery_app,
        "AsyncResult",
        lambda task_id: _Result(),
    )

    headers = {"Authorization": f"Bearer {admin_token}"}
    response = client.get("/api/v1/integrations/sync/task-xyz", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "SUCCESS"
    assert body["finished"] is True
    assert body["result"] == {"status": "ok"}


def test_integration_coverage_endpoint(
    client,
    test_db,
    test_org,
    admin_token,
    monkeypatch,
):
    now = datetime.now(UTC)

    async def _seed_data():
        account = Account(
            org_id=test_org.org_id,
            provider="endpoint",
            external_id="endpoint-1",
            display_name="Endpoint Tenant",
        )
        test_db.add(account)

        repo = IntegrationStateRepository(test_db)
        await repo.upsert_state(
            integration="kandji",
            scope="tenant-a",
            last_timestamp=now,
            metadata={"last_status": "success"},
        )
        await repo.upsert_state(
            integration="kandji",
            scope="tenant-b",
            last_timestamp=now - timedelta(hours=4),
            metadata={"last_status": "error", "last_error": "token expired"},
        )

        await test_db.commit()

    _run_async(_seed_data())

    from cerebro.integrations import coverage as coverage_module

    monkeypatch.setattr(
        coverage_module,
        "INTEGRATION_PROVIDER_MAPPING",
        {"kandji": ["endpoint"], "sentinelone": ["endpoint"]},
    )

    headers = {"Authorization": f"Bearer {admin_token}"}
    response = client.get(
        "/api/v1/integrations/coverage",
        headers=headers,
        params={"stale_seconds": 3600},
    )

    assert response.status_code == 200, response.text

    payload = response.json()
    assert len(payload) >= 2

    kandji_summary = next(
        item for item in payload if item["integration"] == "kandji"
    )
    assert kandji_summary["status"] == "critical"
    assert kandji_summary["scopes"]["total"] == 2
    assert kandji_summary["scopes"]["healthy"] == 1
    assert kandji_summary["scopes"]["critical"] == 1
    assert pytest.approx(kandji_summary["coverage_ratio"], rel=1e-3) == 0.5

    sentinelone_summary = next(
        item for item in payload if item["integration"] == "sentinelone"
    )
    assert sentinelone_summary["status"] == "missing"
    assert sentinelone_summary["scopes"]["total"] == 0


def test_integration_admin_overview_endpoint(client, test_db, admin_token, monkeypatch):
    now = datetime.now(UTC)

    async def _seed_state():
        repo = IntegrationStateRepository(test_db)
        await repo.upsert_state(
            integration="sentinelone.activities",
            scope="acme",
            last_timestamp=now - timedelta(minutes=20),
            metadata={
                "last_status": "ok",
                "last_success_at": (now - timedelta(minutes=20)).isoformat(),
                "duration_samples": [45.0, 50.0],
                "recent_errors": [
                    {
                        "recorded_at": (now - timedelta(hours=5)).isoformat(),
                        "details": "timeout",
                    }
                ],
            },
        )
        await test_db.commit()

    _run_async(_seed_state())

    schedule_stub = {
        "sentinelone-test": {
            "task": "cerebro.tasks.integration.sync_sentinelone",
            "schedule": 600,
        }
    }
    monkeypatch.setattr(
        integrations_router.celery_app.conf,
        "beat_schedule",
        schedule_stub,
        raising=False,
    )

    headers = {"Authorization": f"Bearer {admin_token}"}
    response = client.get("/api/v1/integrations/admin/overview", headers=headers)

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload, "Expected at least one integration overview"

    overview = next(
        item
        for item in payload
        if item["integration"] == "sentinelone.activities"
    )
    assert overview["scope"] == "acme"
    assert overview["duration_samples"] == [45.0, 50.0]
    assert overview["confidence"] == "high"
    assert isinstance(overview.get("next_scheduled_sync_at"), str)
