"""
Tests for Slack Integration

Tests webhook management, message formatting, and notification delivery.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from cerebro.core.models import Finding, Organization, SlackNotification, SlackWebhook
from cerebro.notifications.slack import (
    SlackMessageFormatter,
    SlackNotificationService,
)

# ==================== Fixtures ====================

UTC = timezone.utc


@pytest.fixture
def sample_org():
    """Sample organization for testing."""
    return Organization(
        org_id=uuid4(),
        name="Acme Corp",
        created_at=datetime.now(UTC),
    )


@pytest.fixture
def sample_webhook(sample_org):
    """Sample Slack webhook for testing."""
    return SlackWebhook(
        webhook_id=uuid4(),
        org_id=sample_org.org_id,
        name="Security Alerts",
        webhook_url="https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX",
        channel="#security-alerts",
        enabled=True,
        severity_filter=["critical", "high"],
        finding_type_filter=None,
        event_types=["finding_created", "monitoring_alert"],
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


@pytest.fixture
def sample_finding(sample_org):
    """Sample finding for testing."""
    finding = Finding(
        finding_id=uuid4(),
        org_id=sample_org.org_id,
        title="S3 Bucket Publicly Accessible",
        severity="critical",
        status="open",
    )
    # Manually set created_at after instantiation
    finding.created_at = datetime.now(UTC)
    return finding


# ==================== Message Formatter Tests ====================

class TestSlackMessageFormatter:
    """Tests for Slack message formatting."""

    def test_format_finding_created_critical(self, sample_finding, sample_org):
        """Test formatting a critical finding notification."""
        message = SlackMessageFormatter.format_finding_created(
            finding=sample_finding,
            org_name=sample_org.name,
        )

        # Check message structure
        assert "attachments" in message
        assert len(message["attachments"]) == 1
        attachment = message["attachments"][0]

        # Check color for critical
        assert attachment["color"] == "#d32f2f"

        # Check blocks exist
        assert "blocks" in attachment
        blocks = attachment["blocks"]
        assert len(blocks) >= 3  # Header, section, context

        # Verify header contains severity
        assert blocks[0]["type"] == "header"
        assert "CRITICAL" in blocks[0]["text"]["text"]

    def test_format_compliance_failed(self, sample_org):
        """Test formatting a compliance failure notification."""
        message = SlackMessageFormatter.format_compliance_failed(
            control_id="CIS-AWS-1.1",
            control_title="Ensure MFA is enabled for root account",
            failure_count=1,
            org_name=sample_org.name,
        )

        # Check message structure
        assert "attachments" in message
        attachment = message["attachments"][0]

        # Check compliance failure color (orange)
        assert attachment["color"] == "#f57c00"

        # Check blocks
        blocks = attachment["blocks"]
        assert len(blocks) >= 2

        # Verify control info present
        block_text = str(blocks)
        assert "CIS-AWS-1.1" in block_text
        assert "Ensure MFA is enabled" in block_text

    def test_format_monitoring_alert_high(self, sample_org):
        """Test formatting a high severity monitoring alert."""
        message = SlackMessageFormatter.format_monitoring_alert(
            alert_title="New Critical Findings Detected",
            alert_description="5 new critical findings detected in the last 5 minutes",
            severity="high",
            org_name=sample_org.name,
        )

        # Check message structure
        assert "attachments" in message
        attachment = message["attachments"][0]

        # Check high severity color
        assert attachment["color"] == "#f57c00"

        # Check alert content
        blocks = attachment["blocks"]
        assert len(blocks) >= 3

        # Verify alert title and description
        block_text = str(blocks)
        assert "New Critical Findings" in block_text
        assert "5 new critical findings" in block_text


# ==================== Notification Service Tests ====================

class TestSlackNotificationService:
    """Tests for Slack notification service."""

    @pytest.mark.asyncio
    async def test_send_with_retry_success(self, sample_webhook):
        """Test successful notification delivery on first try."""
        service = SlackNotificationService()

        async def fake_get_webhook_url():
            return "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX"

        # Mock HTTP client
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "ok"

        async def fake_post(url: str, **kwargs):
            return mock_response

        async def fake_commit():
            return None

        with patch.object(
            sample_webhook,
            "get_webhook_url",
            side_effect=fake_get_webhook_url,
        ), patch.object(service, "client") as mock_client:
            mock_client.post = AsyncMock(side_effect=fake_post)
            mock_db = MagicMock()
            mock_db.commit = AsyncMock(side_effect=fake_commit)

            await service._send_with_retry(
                webhook=sample_webhook,
                message={"text": "Test message"},
                event_type="finding_created",
                finding_id=uuid4(),
                severity="high",
                db=mock_db,
            )

            # Verify HTTP post was called once
            assert mock_client.post.await_count == 1

            # Verify notification was logged as sent
            assert mock_db.add.called
            notification = mock_db.add.call_args[0][0]
            assert isinstance(notification, SlackNotification)
            assert notification.status == "sent"
            assert notification.retry_count == 0

    @pytest.mark.asyncio
    async def test_send_with_retry_failure_exhausted(self, sample_webhook):
        """Test notification failure after all retries exhausted."""
        service = SlackNotificationService(max_retries=2, retry_delay_seconds=0.1)

        # Mock HTTP client to always fail
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"

        async def fake_post(url: str, **kwargs):
            return mock_response

        async def fake_commit():
            return None

        async def fake_get_webhook_url():
            return "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX"

        with patch.object(
            sample_webhook,
            "get_webhook_url",
            side_effect=fake_get_webhook_url,
        ), patch.object(service, "client") as mock_client:
            mock_client.post = AsyncMock(side_effect=fake_post)
            mock_db = MagicMock()
            mock_db.commit = AsyncMock(side_effect=fake_commit)

            await service._send_with_retry(
                webhook=sample_webhook,
                message={"text": "Test message"},
                event_type="finding_created",
                finding_id=uuid4(),
                severity="high",
                db=mock_db,
            )

            # Verify retries (initial + 2 retries = 3 total)
            assert mock_client.post.await_count == 3

            # Verify notification was logged as failed
            assert mock_db.add.called
            notification = mock_db.add.call_args[0][0]
            assert isinstance(notification, SlackNotification)
            assert notification.status == "failed"
            assert notification.retry_count == 2
            assert "500" in notification.error_message

    @pytest.mark.asyncio
    async def test_should_send_finding_severity_filter(
        self,
        sample_webhook,
        sample_finding,
    ):
        """Test severity filtering logic."""
        service = SlackNotificationService()

        # Webhook filters for critical and high
        sample_webhook.severity_filter = ["critical", "high"]

        # Critical finding should pass
        sample_finding.severity = "critical"
        assert service._should_send_finding(sample_webhook, sample_finding) is True

        # Medium finding should be filtered out
        sample_finding.severity = "medium"
        assert service._should_send_finding(sample_webhook, sample_finding) is False

    @pytest.mark.asyncio
    async def test_should_send_finding_event_type_filter(
        self,
        sample_webhook,
        sample_finding,
    ):
        """Test event type filtering logic."""
        service = SlackNotificationService()

        # Webhook only monitors finding_created
        sample_webhook.event_types = ["finding_created"]

        # Should send for finding_created
        assert service._should_send_finding(sample_webhook, sample_finding) is True

        # Should not send if finding_created not in event_types
        sample_webhook.event_types = ["monitoring_alert"]
        assert service._should_send_finding(sample_webhook, sample_finding) is False


# ==================== Integration Tests ====================

@pytest.mark.integration
class TestSlackIntegration:
    """Integration tests for Slack (requires actual Slack webhook or mock server)."""

    @pytest.mark.skip(reason="Requires actual Slack webhook URL")
    @pytest.mark.asyncio
    async def test_real_slack_webhook(self):
        """Test sending to a real Slack webhook (manual test)."""
        # This test is skipped by default
        # To run manually:
        # 1. Set SLACK_WEBHOOK_URL environment variable
        # 2. Run: pytest -m integration \
        #        tests/test_slack_integration.py::
        #        TestSlackIntegration::test_real_slack_webhook

        import os
        webhook_url = os.getenv("SLACK_WEBHOOK_URL")
        if not webhook_url:
            pytest.skip("SLACK_WEBHOOK_URL not set")

        service = SlackNotificationService()
        message = {
            "text": "Cerebro Test Notification",
            "attachments": [
                {
                    "color": "#36a64f",
                    "title": "Test Alert",
                    "text": "This is a test notification from Cerebro automated tests",
                    "footer": "Cerebro Security",
                }
            ],
        }

        response = await service.client.post(webhook_url, json=message)
        assert response.status_code == 200
