from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cerebro.automation.integration_sync import IntegrationIssue, analyze_state, should_suppress_issue
from cerebro.core.models import IntegrationSyncState


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
