"""
Slack Notification Service

Handles sending notifications to Slack via webhooks with:
- Retry logic with exponential backoff
- Rich message formatting with Block Kit
- Filtering by severity and event types
- Audit logging of all notifications
"""

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.database import async_session_factory
from cerebro.core.models import SlackWebhook, SlackNotification, Finding, Organization

logger = structlog.get_logger(__name__)


# ==================== Slack Message Formatter ====================

class SlackMessageFormatter:
    """Format security events into Slack Block Kit messages."""

    @staticmethod
    def format_finding_created(finding: Finding, org_name: str) -> Dict[str, Any]:
        """Format a new finding notification."""
        severity = finding.severity or "unknown"
        severity_emoji = {
            "critical": ":rotating_light:",
            "high": ":warning:",
            "medium": ":large_orange_diamond:",
            "low": ":information_source:",
        }.get(severity.lower(), ":grey_question:")

        # Color coding
        color = {
            "critical": "#d32f2f",
            "high": "#f57c00",
            "medium": "#fbc02d",
            "low": "#1976d2",
        }.get(severity.lower(), "#9e9e9e")

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{severity_emoji} New Security Finding: {severity.upper()}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Organization:*\n{org_name}"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{severity.upper()}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Rule:*\n{finding.rule_id or 'N/A'}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Status:*\n{finding.status}",
                    },
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Title:*\n{finding.title or 'Untitled Finding'}",
                },
            },
        ]

        # Add description if available
        description = getattr(finding, 'description', None)
        if description:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Description:*\n{description[:500]}",
                },
            })

        # Add resource/principal info if available
        resource_info = []
        if finding.resource_id:
            resource_info.append(f"Resource ID: {finding.resource_id}")
        if finding.principal_id:
            resource_info.append(f"Principal ID: {finding.principal_id}")

        if resource_info:
            blocks.append({
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": " | ".join(resource_info),
                    }
                ],
            })

        # Add timestamp
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"<!date^{int(finding.created_at.timestamp())}^{{date_short_pretty}} at {{time}}|{finding.created_at.isoformat()}>",
                }
            ],
        })

        return {
            "attachments": [
                {
                    "color": color,
                    "blocks": blocks,
                }
            ]
        }

    @staticmethod
    def format_compliance_failed(
        control_id: str, control_title: str, failure_count: int, org_name: str
    ) -> Dict[str, Any]:
        """Format a compliance failure notification."""
        return {
            "attachments": [
                {
                    "color": "#f57c00",
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": ":warning: Compliance Control Failed",
                            },
                        },
                        {
                            "type": "section",
                            "fields": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Organization:*\n{org_name}",
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Control ID:*\n{control_id}",
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Control:*\n{control_title}",
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Failures:*\n{failure_count}",
                                },
                            ],
                        },
                        {
                            "type": "context",
                            "elements": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"<!date^{int(datetime.now(timezone.utc).timestamp())}^{{date_short_pretty}} at {{time}}|Now>",
                                }
                            ],
                        },
                    ],
                }
            ]
        }

    @staticmethod
    def format_monitoring_alert(
        alert_title: str, alert_description: str, severity: str, org_name: str
    ) -> Dict[str, Any]:
        """Format a monitoring alert notification."""
        severity_emoji = {
            "critical": ":rotating_light:",
            "high": ":warning:",
            "medium": ":large_orange_diamond:",
            "low": ":information_source:",
        }.get(severity.lower(), ":grey_question:")

        color = {
            "critical": "#d32f2f",
            "high": "#f57c00",
            "medium": "#fbc02d",
            "low": "#1976d2",
        }.get(severity.lower(), "#9e9e9e")

        return {
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"{severity_emoji} Security Alert: {alert_title}",
                            },
                        },
                        {
                            "type": "section",
                            "fields": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Organization:*\n{org_name}",
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Severity:*\n{severity.upper()}",
                                },
                            ],
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": alert_description,
                            },
                        },
                        {
                            "type": "context",
                            "elements": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"<!date^{int(datetime.now(timezone.utc).timestamp())}^{{date_short_pretty}} at {{time}}|Now>",
                                }
                            ],
                        },
                    ],
                }
            ]
        }


# ==================== Slack Notification Service ====================

class SlackNotificationService:
    """Service for sending Slack notifications with retry logic."""

    def __init__(
        self,
        max_retries: int = 3,
        retry_delay_seconds: int = 2,
        timeout_seconds: int = 10,
    ):
        self.max_retries = max_retries
        self.retry_delay_seconds = retry_delay_seconds
        self.timeout_seconds = timeout_seconds
        self.client = httpx.AsyncClient(timeout=timeout_seconds)

    async def send_finding_notification(
        self, org_id: UUID, finding: Finding, db: AsyncSession
    ) -> None:
        """Send notification for a new finding to all matching webhooks."""
        try:
            # Get organization
            org_result = await db.execute(
                select(Organization).where(Organization.org_id == org_id)
            )
            org = org_result.scalar_one_or_none()
            if not org:
                logger.error("organization_not_found", org_id=str(org_id))
                return

            # Get active webhooks for this org that match the finding
            webhooks_result = await db.execute(
                select(SlackWebhook).where(
                    SlackWebhook.org_id == org_id,
                    SlackWebhook.enabled == True,
                )
            )
            webhooks = webhooks_result.scalars().all()

            if not webhooks:
                logger.debug(
                    "no_slack_webhooks_configured",
                    org_id=str(org_id),
                )
                return

            # Format message
            message = SlackMessageFormatter.format_finding_created(finding, org.name)

            # Send to each matching webhook
            for webhook in webhooks:
                if not self._should_send_finding(webhook, finding):
                    continue

                await self._send_with_retry(
                    webhook=webhook,
                    message=message,
                    event_type="finding_created",
                    finding_id=finding.finding_id,
                    severity=finding.severity,
                    db=db,
                )

        except Exception as e:
            logger.error(
                "send_finding_notification_failed",
                org_id=str(org_id),
                finding_id=str(finding.finding_id),
                error=str(e),
            )

    async def send_compliance_alert(
        self,
        org_id: UUID,
        control_id: str,
        control_title: str,
        failure_count: int,
        db: AsyncSession,
    ) -> None:
        """Send compliance failure notification."""
        try:
            # Get organization
            org_result = await db.execute(
                select(Organization).where(Organization.org_id == org_id)
            )
            org = org_result.scalar_one_or_none()
            if not org:
                return

            # Get webhooks that monitor compliance events
            webhooks_result = await db.execute(
                select(SlackWebhook).where(
                    SlackWebhook.org_id == org_id,
                    SlackWebhook.enabled == True,
                )
            )
            webhooks = webhooks_result.scalars().all()

            # Filter webhooks that have compliance_failed in event_types
            compliance_webhooks = [
                w for w in webhooks if "compliance_failed" in w.event_types
            ]

            if not compliance_webhooks:
                return

            message = SlackMessageFormatter.format_compliance_failed(
                control_id, control_title, failure_count, org.name
            )

            for webhook in compliance_webhooks:
                await self._send_with_retry(
                    webhook=webhook,
                    message=message,
                    event_type="compliance_failed",
                    finding_id=None,
                    severity="high",
                    db=db,
                )

        except Exception as e:
            logger.error(
                "send_compliance_alert_failed",
                org_id=str(org_id),
                control_id=control_id,
                error=str(e),
            )

    async def send_monitoring_alert(
        self,
        org_id: UUID,
        alert_title: str,
        alert_description: str,
        severity: str,
        db: AsyncSession,
    ) -> None:
        """Send monitoring alert notification."""
        try:
            # Get organization
            org_result = await db.execute(
                select(Organization).where(Organization.org_id == org_id)
            )
            org = org_result.scalar_one_or_none()
            if not org:
                return

            # Get webhooks that monitor alerts
            webhooks_result = await db.execute(
                select(SlackWebhook).where(
                    SlackWebhook.org_id == org_id,
                    SlackWebhook.enabled == True,
                )
            )
            webhooks = webhooks_result.scalars().all()

            # Filter webhooks that have monitoring_alert in event_types
            alert_webhooks = [
                w for w in webhooks if "monitoring_alert" in w.event_types
            ]

            if not alert_webhooks:
                return

            message = SlackMessageFormatter.format_monitoring_alert(
                alert_title, alert_description, severity, org.name
            )

            for webhook in alert_webhooks:
                if webhook.severity_filter and severity not in webhook.severity_filter:
                    continue

                await self._send_with_retry(
                    webhook=webhook,
                    message=message,
                    event_type="monitoring_alert",
                    finding_id=None,
                    severity=severity,
                    db=db,
                )

        except Exception as e:
            logger.error(
                "send_monitoring_alert_failed",
                org_id=str(org_id),
                alert_title=alert_title,
                error=str(e),
            )

    def _should_send_finding(self, webhook: SlackWebhook, finding: Finding) -> bool:
        """Check if a finding matches webhook filters."""
        # Check if finding_created is in event types
        if "finding_created" not in webhook.event_types:
            return False

        # Check severity filter
        if webhook.severity_filter:
            if not finding.severity or finding.severity not in webhook.severity_filter:
                return False

        # Check finding type filter (if implemented in future)
        # if webhook.finding_type_filter and finding.finding_type not in webhook.finding_type_filter:
        #     return False

        return True

    async def _send_with_retry(
        self,
        webhook: SlackWebhook,
        message: Dict[str, Any],
        event_type: str,
        finding_id: Optional[UUID],
        severity: Optional[str],
        db: AsyncSession,
    ) -> None:
        """Send message to Slack with exponential backoff retry."""
        notification_id = uuid4()
        retry_count = 0
        last_error = None

        # Decrypt webhook URL
        try:
            webhook_url = await webhook.get_webhook_url()
            if not webhook_url:
                raise ValueError("Failed to decrypt webhook URL")
            if not webhook_url.startswith('https://hooks.slack.com/'):
                raise ValueError(f"Invalid Slack webhook URL format")
        except Exception as e:
            logger.error(
                "webhook_url_decryption_failed",
                webhook_id=str(webhook.webhook_id),
                error=str(e),
            )
            # Log failure and abort
            notification = SlackNotification(
                notification_id=notification_id,
                webhook_id=webhook.webhook_id,
                org_id=webhook.org_id,
                event_type=event_type,
                finding_id=finding_id,
                severity=severity,
                payload=message,
                status="failed",
                error_message=f"Decryption error: {str(e)}",
                retry_count=0,
            )
            db.add(notification)
            await db.commit()
            return

        for attempt in range(self.max_retries + 1):
            try:
                response = await self.client.post(
                    webhook_url,
                    json=message,
                    headers={"Content-Type": "application/json"},
                )

                if response.status_code == 200:
                    # Success - log notification
                    notification = SlackNotification(
                        notification_id=notification_id,
                        webhook_id=webhook.webhook_id,
                        org_id=webhook.org_id,
                        event_type=event_type,
                        finding_id=finding_id,
                        severity=severity,
                        payload=message,
                        status="sent",
                        status_code=response.status_code,
                        retry_count=retry_count,
                        sent_at=datetime.now(timezone.utc),
                    )
                    db.add(notification)
                    await db.commit()

                    logger.info(
                        "slack_notification_sent",
                        webhook_id=str(webhook.webhook_id),
                        event_type=event_type,
                        retry_count=retry_count,
                    )
                    return

                else:
                    # Non-200 response
                    last_error = f"HTTP {response.status_code}: {response.text}"
                    logger.warning(
                        "slack_send_failed",
                        webhook_id=str(webhook.webhook_id),
                        status_code=response.status_code,
                        attempt=attempt + 1,
                        error=last_error,
                    )

            except Exception as e:
                last_error = str(e)
                logger.warning(
                    "slack_send_exception",
                    webhook_id=str(webhook.webhook_id),
                    attempt=attempt + 1,
                    error=last_error,
                )

            # Retry logic
            if attempt < self.max_retries:
                retry_count += 1
                delay = self.retry_delay_seconds * (2 ** attempt)  # Exponential backoff
                await asyncio.sleep(delay)

        # All retries failed - log failure
        notification = SlackNotification(
            notification_id=notification_id,
            webhook_id=webhook.webhook_id,
            org_id=webhook.org_id,
            event_type=event_type,
            finding_id=finding_id,
            severity=severity,
            payload=message,
            status="failed",
            error_message=last_error,
            retry_count=retry_count,
        )
        db.add(notification)
        await db.commit()

        logger.error(
            "slack_notification_failed_after_retries",
            webhook_id=str(webhook.webhook_id),
            event_type=event_type,
            retry_count=retry_count,
            error=last_error,
        )

    async def close(self) -> None:
        """Close HTTP client."""
        await self.client.aclose()


# Global service instance
_slack_service: Optional[SlackNotificationService] = None


def get_slack_service() -> SlackNotificationService:
    """Get or create the global Slack notification service."""
    global _slack_service
    if _slack_service is None:
        _slack_service = SlackNotificationService()
    return _slack_service