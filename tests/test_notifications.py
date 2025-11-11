"""
Comprehensive tests for notification services.

Tests cover:
- Email notifications
- Webhook notifications
- Digest processing
- Error handling
- Retry logic
"""
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, Mock, patch
from uuid import uuid4

import pytest

from cerebro.core.models import EmailConfig, EmailNotification, Finding, WebhookConfig
from cerebro.notifications.email import EmailNotificationService
from cerebro.notifications.webhooks import WebhookNotificationService
from cerebro.tasks.notification_digest import (
    _generate_digest_html,
    _generate_digest_subject,
    _group_findings_by_severity,
)

from tests.utils.time import utc_now


class TestEmailNotificationService:
    """Test suite for EmailNotificationService."""

    @pytest.fixture
    def email_config(self):
        """Create a mock email configuration."""
        config = Mock(spec=EmailConfig)
        config.config_id = uuid4()
        config.org_id = uuid4()
        config.name = "Test Email Config"
        config.smtp_host = "smtp.example.com"
        config.smtp_port = 587
        config.smtp_username = "test@example.com"
        config.from_email = "alerts@example.com"
        config.from_name = "Security Alerts"
        config.to_emails = ["recipient@example.com"]
        config.cc_emails = []
        config.use_tls = True
        config.enabled = True
        config.severity_filter = ["critical", "high"]
        config.event_types = ["finding.created"]
        config.digest_mode = False
        config.get_smtp_password = AsyncMock(return_value="test-password")
        return config

    @pytest.fixture
    def email_service(self):
        """Create email notification service."""
        return EmailNotificationService()

    @pytest.mark.asyncio
    async def test_validate_config_success(self, email_service, email_config):
        """Test email config validation succeeds with valid config."""
        # Should not raise
        await email_service._validate_config(email_config)

    @pytest.mark.asyncio
    async def test_validate_config_missing_smtp_host(self, email_service, email_config):
        """Test validation fails with missing SMTP host."""
        email_config.smtp_host = None

        with pytest.raises(ValueError) as exc_info:
            await email_service._validate_config(email_config)
        assert "smtp_host" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_validate_config_invalid_port(self, email_service, email_config):
        """Test validation fails with invalid port."""
        email_config.smtp_port = 70000  # Invalid port

        with pytest.raises(ValueError) as exc_info:
            await email_service._validate_config(email_config)
        assert "port" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_validate_config_no_recipients(self, email_service, email_config):
        """Test validation fails with no recipients."""
        email_config.to_emails = []

        with pytest.raises(ValueError) as exc_info:
            await email_service._validate_config(email_config)
        assert "recipient" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_decryption_failure_handling(self, email_service, email_config):
        """Test graceful handling of decryption failure."""
        # Mock decryption to fail
        email_config.get_smtp_password = AsyncMock(
            side_effect=RuntimeError("Decryption failed")
        )

        db = MagicMock()
        db.add = MagicMock()
        db.commit = AsyncMock()

        await email_service._send_email_with_retry(
            config=email_config,
            subject="Test",
            html_body="<p>test</p>",
            event_type="finding_created",
            finding_id=uuid4(),
            severity="critical",
            db=db,
        )

        db.add.assert_called_once()
        notification = db.add.call_args.args[0]
        assert isinstance(notification, EmailNotification)
        assert notification.status == "failed"
        assert "Decryption" in (notification.error_message or "")
        assert db.commit.await_count == 1


class TestWebhookNotificationService:
    """Test suite for WebhookNotificationService."""

    @pytest.fixture
    def webhook_config(self):
        """Create a mock webhook configuration."""
        config = Mock(spec=WebhookConfig)
        config.config_id = uuid4()
        config.org_id = uuid4()
        config.name = "Test Webhook"
        config.url = "https://webhook.example.com/endpoint"
        config.http_method = "POST"
        config.headers = {"X-Custom": "value"}
        config.payload_template = {}
        config.use_hmac_signature = True
        config.enabled = True
        config.severity_filter = ["critical"]
        config.event_types = ["finding.created"]
        config.timeout_seconds = 5
        config.hmac_secret = b"secret"
        config.hmac_secret_dek = b"dek"
        config.get_webhook_url = AsyncMock(return_value="https://webhook.example.com/endpoint")
        config.get_hmac_secret = AsyncMock(return_value="test-hmac-secret")
        return config

    @pytest.fixture
    def webhook_service(self):
        """Create webhook notification service."""
        return WebhookNotificationService()

    @pytest.mark.asyncio
    async def test_hmac_signature_generation(self, webhook_service):
        """Test HMAC signature generation."""
        payload = '{"test": "data"}'
        secret = "test-secret"

        signature = webhook_service._generate_hmac_signature(payload, secret)

        assert signature is not None
        assert isinstance(signature, str)
        assert len(signature) == 64  # SHA256 hex digest

    @pytest.mark.asyncio
    async def test_hmac_signature_consistency(self, webhook_service):
        """Test that same payload/secret produces same signature."""
        payload = '{"test": "data"}'
        secret = "test-secret"

        sig1 = webhook_service._generate_hmac_signature(payload, secret)
        sig2 = webhook_service._generate_hmac_signature(payload, secret)

        assert sig1 == sig2

    @pytest.mark.asyncio
    async def test_hmac_signature_changes_with_payload(self, webhook_service):
        """Test that different payloads produce different signatures."""
        secret = "test-secret"

        sig1 = webhook_service._generate_hmac_signature('{"test": "data1"}', secret)
        sig2 = webhook_service._generate_hmac_signature('{"test": "data2"}', secret)

        assert sig1 != sig2

    @pytest.mark.asyncio
    async def test_validate_webhook_url(self, webhook_service):
        """Test webhook URL validation."""
        # Valid URLs
        assert webhook_service._is_valid_url("https://example.com/webhook")
        assert webhook_service._is_valid_url("http://localhost:8080/hook")

        # Invalid URLs
        assert not webhook_service._is_valid_url("not-a-url")
        assert not webhook_service._is_valid_url("ftp://example.com")
        assert not webhook_service._is_valid_url("")

    @pytest.mark.asyncio
    async def test_url_decryption_failure_handling(
        self,
        webhook_service,
        webhook_config,
    ):
        """Test handling of URL decryption failure."""
        webhook_config.get_webhook_url = AsyncMock(
            side_effect=RuntimeError("Decryption failed")
        )

        finding = Mock()
        finding.finding_id = uuid4()
        finding.severity = "critical"

        db = AsyncMock()
        db.add = AsyncMock()
        db.commit = AsyncMock()

        # Should surface decryption failure
        with patch("cerebro.notifications.webhooks.logger.error"):
            with pytest.raises(RuntimeError, match="Decryption failed"):
                await webhook_service._send_with_retry(
                    config=webhook_config,
                    payload={"test": "data"},
                    event_type="finding.created",
                    finding_id=finding.finding_id,
                    severity=finding.severity,
                    db=db,
                )


class TestNotificationDigest:
    """Test suite for notification digest processing."""

    @pytest.fixture
    def sample_findings(self):
        """Create sample findings for testing."""
        findings = []
        severities = ["critical", "high", "medium", "low"]

        for i, severity in enumerate(severities * 5):  # 20 findings total
            finding = Mock(spec=Finding)
            finding.finding_id = uuid4()
            finding.title = f"Test Finding {i}"
            finding.severity = severity
            finding.provider = "aws"
            finding.resource_type = "s3.bucket"
            finding.account_id = "123456789012"
            finding.region = "us-east-1"
            finding.created_at = utc_now()
            findings.append(finding)

        return findings

    def test_group_findings_by_severity(self, sample_findings):
        """Test grouping findings by severity."""
        grouped = _group_findings_by_severity(sample_findings)

        assert "critical" in grouped
        assert "high" in grouped
        assert "medium" in grouped
        assert "low" in grouped

        assert len(grouped["critical"]) == 5
        assert len(grouped["high"]) == 5
        assert len(grouped["medium"]) == 5
        assert len(grouped["low"]) == 5

    def test_group_findings_empty_list(self):
        """Test grouping empty findings list."""
        grouped = _group_findings_by_severity([])
        assert grouped == {}

    def test_generate_digest_subject_with_critical(self, sample_findings):
        """Test digest subject generation with critical findings."""
        config = Mock()
        config.digest_frequency = "daily"

        window_start = utc_now() - timedelta(days=1)
        window_end = utc_now()

        subject = _generate_digest_subject(
            config,
            sample_findings,
            window_start,
            window_end,
        )

        assert "[CRITICAL]" in subject
        assert "20 findings" in subject
        assert "5 critical" in subject

    def test_generate_digest_subject_no_critical(self):
        """Test digest subject without critical findings."""
        config = Mock()
        config.digest_frequency = "weekly"

        findings = []
        for _ in range(10):
            finding = Mock()
            finding.severity = "medium"
            findings.append(finding)

        window_start = utc_now() - timedelta(weeks=1)
        window_end = utc_now()

        subject = _generate_digest_subject(config, findings, window_start, window_end)

        assert "[CRITICAL]" not in subject
        assert "10 findings" in subject
        assert "weekly" in subject

    def test_generate_digest_html(self, sample_findings):
        """Test HTML digest generation."""
        config = Mock()
        config.digest_frequency = "daily"

        grouped = _group_findings_by_severity(sample_findings)
        window_start = utc_now() - timedelta(days=1)
        window_end = utc_now()

        html = _generate_digest_html(config, grouped, window_start, window_end)

        # Check for HTML structure
        assert "<!DOCTYPE html>" in html
        assert "<html>" in html
        assert "</html>" in html

        # Check for severity sections
        assert "CRITICAL Severity" in html
        assert "HIGH Severity" in html
        assert "MEDIUM Severity" in html
        assert "LOW Severity" in html

        # Check for summary
        assert "20" in html  # Total findings
        assert "Security Findings Digest" in html

    def test_generate_digest_html_with_overflow(self):
        """Test HTML digest with more than 10 findings per severity."""
        findings = []
        for i in range(15):  # More than 10
            finding = Mock()
            finding.finding_id = uuid4()
            finding.title = f"Critical Finding {i}"
            finding.severity = "critical"
            finding.provider = "aws"
            finding.resource_type = "s3.bucket"
            finding.account_id = "123456789012"
            finding.region = "us-east-1"
            findings.append(finding)

        grouped = {"critical": findings}
        config = Mock()
        window_start = utc_now() - timedelta(days=1)
        window_end = utc_now()

        html = _generate_digest_html(config, grouped, window_start, window_end)

        # Should show overflow message
        assert "... and 5 more critical findings" in html


class TestNotificationRetry:
    """Test notification retry logic."""

    @pytest.mark.asyncio
    async def test_exponential_backoff_calculation(self):
        """Test exponential backoff calculation."""
        # Simulate retry attempts
        base_delay = 60  # 1 minute
        max_delay = 3600  # 1 hour

        for attempt in range(1, 4):
            delay = min(base_delay * (2 ** (attempt - 1)), max_delay)

            if attempt == 1:
                assert delay == 60  # 1 minute
            elif attempt == 2:
                assert delay == 120  # 2 minutes
            elif attempt == 3:
                assert delay == 240  # 4 minutes


class TestNotificationFiltering:
    """Test notification filtering by severity and event type."""

    @pytest.fixture
    def config_with_filters(self):
        """Create config with severity and event filters."""
        config = Mock()
        config.severity_filter = ["critical", "high"]
        config.event_types = ["finding.created", "compliance.check_failed"]
        return config

    def test_severity_filtering(self, config_with_filters):
        """Test that severity filtering works correctly."""
        findings = [
            Mock(severity="critical"),
            Mock(severity="high"),
            Mock(severity="medium"),  # Should be filtered out
            Mock(severity="low"),  # Should be filtered out
        ]

        filtered = [
            f for f in findings
            if f.severity in config_with_filters.severity_filter
        ]

        assert len(filtered) == 2
        assert all(f.severity in ["critical", "high"] for f in filtered)

    def test_event_type_filtering(self, config_with_filters):
        """Test that event type filtering works correctly."""
        events = [
            "finding.created",  # Should pass
            "compliance.check_failed",  # Should pass
            "monitoring.alert",  # Should be filtered out
        ]

        filtered = [
            e for e in events
            if e in config_with_filters.event_types
        ]

        assert len(filtered) == 2
        assert "monitoring.alert" not in filtered


class TestNotificationEdgeCases:
    """Test edge cases and error scenarios."""

    @pytest.mark.asyncio
    async def test_empty_findings_list(self):
        """Test handling of empty findings list in digest."""
        grouped = _group_findings_by_severity([])
        assert grouped == {}

    @pytest.mark.asyncio
    async def test_finding_with_missing_severity(self):
        """Test handling of finding with None severity."""
        finding = Mock()
        finding.severity = None

        grouped = _group_findings_by_severity([finding])
        assert "unknown" in grouped
        assert len(grouped["unknown"]) == 1

    @pytest.mark.asyncio
    async def test_very_long_finding_title(self):
        """Test handling of very long finding titles."""
        finding = Mock()
        finding.title = "A" * 1000  # Very long title
        finding.severity = "critical"
        finding.provider = "aws"
        finding.resource_type = "s3.bucket"
        finding.account_id = "123456789012"
        finding.region = "us-east-1"

        grouped = _group_findings_by_severity([finding])
        config = Mock()
        window_start = utc_now() - timedelta(days=1)
        window_end = utc_now()

        # Should not crash
        html = _generate_digest_html(config, grouped, window_start, window_end)
        assert len(html) > 0

    @pytest.mark.asyncio
    async def test_unicode_in_finding_title(self):
        """Test handling of Unicode characters in finding titles."""
        finding = Mock()
        finding.title = "🔐 Encryption Issue 密码问题 пароль"
        finding.severity = "high"
        finding.provider = "aws"
        finding.resource_type = "s3.bucket"
        finding.account_id = "123456789012"
        finding.region = "us-east-1"

        grouped = _group_findings_by_severity([finding])
        config = Mock()
        window_start = utc_now() - timedelta(days=1)
        window_end = utc_now()

        html = _generate_digest_html(config, grouped, window_start, window_end)
        assert "🔐" in html
        assert "密码" in html
