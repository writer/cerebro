from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from cerebro.automation.integration_sync import IntegrationIssue, analyze_state, should_suppress_issue
from cerebro.core.models import IntegrationSyncState
from cerebro.core.config import settings
from cerebro.tasks.integration_monitor import _get_retry_task, _maybe_queue_auto_retry
from cerebro.tasks.integration_tasks import sync_kandji


def _make_state(**kwargs) -> IntegrationSyncState:
    defaults = {
        "integration": "sentinelone.activities",
        "scope": "default",
        "last_cursor": None,
        "last_timestamp": None,
        "state_metadata": {},
    }
    defaults.update(kwargs)
    return IntegrationSyncState(**defaults)


def test_analyze_state_returns_none_for_disabled() -> None:
    now = datetime.now(timezone.utc)
    state = _make_state(state_metadata={"last_status": "disabled"})
    assert analyze_state(state, now, stale_seconds=3600) is None


def test_analyze_state_flags_error_status() -> None:
    now = datetime.now(timezone.utc)
    state = _make_state(state_metadata={"last_status": "error", "last_error": "failure"})
    issue = analyze_state(state, now, stale_seconds=3600)
    assert issue is not None
    assert issue.issue_type == "error"
    assert issue.severity == "critical"


def test_analyze_state_marks_stale_when_threshold_exceeded() -> None:
    now = datetime.now(timezone.utc)
    state = _make_state(
        last_timestamp=now - timedelta(hours=2),
        state_metadata={"last_status": "ok"},
    )
    issue = analyze_state(state, now, stale_seconds=1800)
    assert issue is not None
    assert issue.issue_type == "stale"


def test_should_suppress_issue_honors_cooldown() -> None:
    now = datetime.now(timezone.utc)
    issue = IntegrationIssue(
        integration="sentinelone.activities",
        scope="default",
        status="error",
        issue_type="error",
        severity="critical",
        message="error",
        observed_at=now,
        last_timestamp=None,
        age_seconds=None,
        metadata={},
    )

    metadata = {
        "last_alert_issue_type": "error",
        "last_alert_status": "error",
        "last_alert_sent_at": (now - timedelta(seconds=60)).isoformat(),
    }

    assert should_suppress_issue(metadata, issue, now, cooldown_seconds=300) is True

    metadata["last_alert_sent_at"] = (now - timedelta(seconds=600)).isoformat()
    assert should_suppress_issue(metadata, issue, now, cooldown_seconds=300) is False


def test_get_retry_task_respects_settings(monkeypatch) -> None:
    monkeypatch.setattr(settings, "kandji_enabled", False)
    task, _ = _get_retry_task("kandji.vulnerabilities")
    assert task is None

    monkeypatch.setattr(settings, "kandji_enabled", True)
    task, kwargs = _get_retry_task("kandji.vulnerabilities")
    assert task is sync_kandji
    assert kwargs == {}


def test_maybe_queue_auto_retry(monkeypatch) -> None:
    now = datetime.now(timezone.utc)
    state = _make_state(integration="kandji.vulnerabilities")
    issue = IntegrationIssue(
        integration="kandji.vulnerabilities",
        scope="default",
        status="error",
        issue_type="error",
        severity="critical",
        message="sync failed",
        observed_at=now,
        last_timestamp=None,
        age_seconds=None,
        metadata={},
    )

    monkeypatch.setattr(settings, "kandji_enabled", True)
    monkeypatch.setattr(settings, "integration_sync_retry_enabled", True)
    monkeypatch.setattr(settings, "integration_sync_retry_cooldown_seconds", 0)

    calls: dict[str, Any] = {}

    def fake_apply_async(*, kwargs=None):  # type: ignore[override]
        calls["kwargs"] = kwargs or {}

        class _Result:
            id = "task-123"

        return _Result()

    monkeypatch.setattr(sync_kandji, "apply_async", fake_apply_async)

    metadata_update = _maybe_queue_auto_retry(state, issue, now, {})
    assert metadata_update.get("last_auto_retry_task_id") == "task-123"
    assert "last_auto_retry_at" in metadata_update

    # Cooldown prevents immediate subsequent retry
    monkeypatch.setattr(settings, "integration_sync_retry_cooldown_seconds", 3600)
    metadata_update_second = _maybe_queue_auto_retry(
        state,
        issue,
        now,
        {"last_auto_retry_at": now.isoformat()},
    )
    assert metadata_update_second == {}
