"""Integration sync health evaluation and alerting."""

from __future__ import annotations

import dataclasses
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx

from cerebro.core.models import IntegrationSyncState

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class IntegrationIssue:
    integration: str
    scope: str
    status: str
    issue_type: str
    severity: str
    message: str
    observed_at: datetime
    last_timestamp: Optional[datetime]
    age_seconds: Optional[float]
    metadata: Dict[str, Any]


def _normalize_timestamp(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def analyze_state(
    state: IntegrationSyncState,
    now: datetime,
    stale_seconds: int,
) -> Optional[IntegrationIssue]:
    metadata = dict(state.state_metadata or {})
    status = str(metadata.get("last_status") or "unknown").lower()
    scope = state.scope or "default"
    last_timestamp = _normalize_timestamp(state.last_timestamp)

    age_seconds: Optional[float] = None
    if last_timestamp is not None:
        age_seconds = max((now - last_timestamp).total_seconds(), 0.0)

    # Disabled integrations are intentionally quiet.
    if status == "disabled":
        return None

    issue_message: Optional[str] = None
    issue_type: Optional[str] = None
    severity = "warning"

    if status == "error":
        issue_type = "error"
        severity = "critical"
        issue_message = metadata.get("last_error") or "Latest sync ended with an error"
    elif status == "skipped":
        issue_type = "skipped"
        issue_message = metadata.get("last_payload", {}).get("reason") if isinstance(metadata.get("last_payload"), dict) else None
        issue_message = issue_message or "Sync skipped due to missing prerequisites"
    elif last_timestamp is None:
        issue_type = "missing"
        issue_message = "No successful sync has been recorded"
    elif stale_seconds > 0 and age_seconds is not None and age_seconds > stale_seconds:
        issue_type = "stale"
        severity = "critical" if age_seconds > stale_seconds * 2 else "warning"
        minutes = int(age_seconds // 60)
        issue_message = f"Last successful sync is {minutes} minutes old"

    if issue_type is None:
        return None

    if issue_message is None:
        issue_message = "Integration sync health degraded"

    return IntegrationIssue(
        integration=state.integration,
        scope=scope,
        status=status,
        issue_type=issue_type,
        severity=severity,
        message=issue_message,
        observed_at=now,
        last_timestamp=last_timestamp,
        age_seconds=age_seconds,
        metadata=metadata,
    )


def should_suppress_issue(
    metadata: Dict[str, Any],
    issue: IntegrationIssue,
    now: datetime,
    cooldown_seconds: int,
) -> bool:
    last_issue_type = str(metadata.get("last_alert_issue_type") or "")
    last_issue_status = str(metadata.get("last_alert_status") or "")
    if last_issue_type != issue.issue_type or last_issue_status != issue.status:
        return False

    sent_at_raw = metadata.get("last_alert_sent_at")
    if not sent_at_raw:
        return False
    try:
        sent_at = datetime.fromisoformat(sent_at_raw)
    except Exception:  # pragma: no cover - defensive parse
        return False
    if sent_at.tzinfo is None:
        sent_at = sent_at.replace(tzinfo=timezone.utc)

    return (now - sent_at).total_seconds() < max(cooldown_seconds, 0)


def _format_metadata_summary(metadata: Dict[str, Any]) -> str:
    summary_parts: list[str] = []
    for key in ("last_status_at", "last_error", "last_event_count", "last_ingested_count"):
        if key in metadata and metadata[key] not in (None, ""):
            summary_parts.append(f"*{key.replace('_', ' ').title()}:* {metadata[key]}")

    if "last_payload" in metadata and isinstance(metadata["last_payload"], dict):
        payload = metadata["last_payload"]
        if payload:
            keys = list(payload.keys())[:5]
            summary_parts.append("*Payload keys:* " + ", ".join(keys))

    if "last_auto_retry_at" in metadata:
        summary_parts.append(f"*Last retry:* {metadata['last_auto_retry_at']}")

    return "\n".join(summary_parts) if summary_parts else "No additional metadata recorded."


def _format_slack_payload(issue: IntegrationIssue) -> Dict[str, Any]:
    age_text = "unknown"
    if issue.age_seconds is not None:
        minutes = int(issue.age_seconds // 60)
        seconds = int(issue.age_seconds % 60)
        age_text = f"{minutes}m {seconds}s"

    last_sync_text = issue.last_timestamp.isoformat() if issue.last_timestamp else "Never"

    color = {
        "critical": "#d32f2f",
        "warning": "#f57c00",
        "info": "#1976d2",
    }.get(issue.severity, "#9e9e9e")

    metadata_summary = _format_metadata_summary(issue.metadata)

    return {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"Integration sync alert — {issue.integration} ({issue.scope})",
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Status:*\\n{issue.status}"},
                            {"type": "mrkdwn", "text": f"*Issue:*\\n{issue.issue_type}"},
                            {"type": "mrkdwn", "text": f"*Severity:*\\n{issue.severity}"},
                            {"type": "mrkdwn", "text": f"*Last Sync:*\\n{last_sync_text}"},
                            {"type": "mrkdwn", "text": f"*Age:*\\n{age_text}"},
                        ],
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": issue.message},
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": metadata_summary,
                        },
                    },
                ],
            }
        ]
    }


async def send_integration_sync_alert(
    webhook_url: str,
    issue: IntegrationIssue,
    *,
    timeout: float = 10.0,
) -> None:
    payload = _format_slack_payload(issue)
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.post(webhook_url, json=payload)
        response.raise_for_status()
