"""
Email Notification Service

Handles sending email notifications via SMTP with:
- Async SMTP client
- HTML email templates
- Retry logic with exponential backoff
- TLS support
- Audit logging
"""

import asyncio
import smtplib
from datetime import UTC, datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from uuid import UUID, uuid4

import structlog
from jinja2 import Template
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.models import EmailConfig, EmailNotification, Finding, Organization

logger = structlog.get_logger(__name__)


# ==================== Email Templates ====================


class EmailTemplates:
    """HTML email templates for security notifications."""

    @staticmethod
    def finding_created_template() -> str:
        """Template for new finding notification."""
        return """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: {% if severity == 'critical' %}#d32f2f{% elif severity == 'high' %}#f57c00{% elif severity == 'medium' %}#fbc02d{% else %}#1976d2{% endif %}; color: white; padding: 20px; border-radius: 5px 5px 0 0; }
        .content { background: #f5f5f5; padding: 20px; }
        .finding-details { background: white; padding: 15px; border-left: 4px solid {% if severity == 'critical' %}#d32f2f{% elif severity == 'high' %}#f57c00{% elif severity == 'medium' %}#fbc02d{% else %}#1976d2{% endif %}; margin: 10px 0; }
        .label { font-weight: bold; color: #666; }
        .value { color: #333; }
        .footer { background: #333; color: white; padding: 15px; text-align: center; border-radius: 0 0 5px 5px; font-size: 12px; }
        .severity-badge { display: inline-block; padding: 5px 10px; border-radius: 3px; color: white; font-weight: bold; background: {% if severity == 'critical' %}#d32f2f{% elif severity == 'high' %}#f57c00{% elif severity == 'medium' %}#fbc02d{% else %}#1976d2{% endif %}; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 New Security Finding</h1>
            <p>{{ org_name }}</p>
        </div>
        <div class="content">
            <div class="finding-details">
                <h2>{{ title }}</h2>
                <p><span class="severity-badge">{{ severity|upper }}</span></p>

                {% if description %}
                <p><span class="label">Description:</span><br>
                {{ description }}</p>
                {% endif %}

                <p><span class="label">Status:</span> <span class="value">{{ status }}</span></p>
                <p><span class="label">Rule ID:</span> <span class="value">{{ rule_id or 'N/A' }}</span></p>
                <p><span class="label">Finding ID:</span> <span class="value">{{ finding_id }}</span></p>
                <p><span class="label">Detected:</span> <span class="value">{{ created_at }}</span></p>
            </div>

            <p style="text-align: center; margin-top: 20px;">
                <a href="{{ cerebro_url }}/findings/{{ finding_id }}" style="background: #1976d2; color: white; padding: 10px 20px; text-decoration: none; border-radius: 3px;">View in Cerebro</a>
            </p>
        </div>
        <div class="footer">
            <p>Cerebro Security System of Record</p>
            <p>This is an automated security notification. Please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>
"""

    @staticmethod
    def compliance_failed_template() -> str:
        """Template for compliance failure notification."""
        return """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #f57c00; color: white; padding: 20px; border-radius: 5px 5px 0 0; }
        .content { background: #f5f5f5; padding: 20px; }
        .compliance-details { background: white; padding: 15px; border-left: 4px solid #f57c00; margin: 10px 0; }
        .label { font-weight: bold; color: #666; }
        .value { color: #333; }
        .footer { background: #333; color: white; padding: 15px; text-align: center; border-radius: 0 0 5px 5px; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚠️ Compliance Control Failed</h1>
            <p>{{ org_name }}</p>
        </div>
        <div class="content">
            <div class="compliance-details">
                <h2>{{ control_title }}</h2>
                <p><span class="label">Control ID:</span> <span class="value">{{ control_id }}</span></p>
                <p><span class="label">Failures:</span> <span class="value">{{ failure_count }}</span></p>
                <p><span class="label">Detected:</span> <span class="value">{{ timestamp }}</span></p>
            </div>

            <p style="text-align: center; margin-top: 20px;">
                <a href="{{ cerebro_url }}/compliance" style="background: #1976d2; color: white; padding: 10px 20px; text-decoration: none; border-radius: 3px;">View Compliance Dashboard</a>
            </p>
        </div>
        <div class="footer">
            <p>Cerebro Security System of Record</p>
            <p>This is an automated compliance notification. Please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>
"""

    @staticmethod
    def monitoring_alert_template() -> str:
        """Template for monitoring alert notification."""
        return """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: {% if severity == 'critical' %}#d32f2f{% elif severity == 'high' %}#f57c00{% else %}#1976d2{% endif %}; color: white; padding: 20px; border-radius: 5px 5px 0 0; }
        .content { background: #f5f5f5; padding: 20px; }
        .alert-details { background: white; padding: 15px; border-left: 4px solid {% if severity == 'critical' %}#d32f2f{% elif severity == 'high' %}#f57c00{% else %}#1976d2{% endif %}; margin: 10px 0; }
        .footer { background: #333; color: white; padding: 15px; text-align: center; border-radius: 0 0 5px 5px; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{ emoji }} {{ title }}</h1>
            <p>{{ org_name }}</p>
        </div>
        <div class="content">
            <div class="alert-details">
                <p>{{ description }}</p>
                <p><strong>Severity:</strong> {{ severity|upper }}</p>
                <p><strong>Time:</strong> {{ timestamp }}</p>
            </div>

            <p style="text-align: center; margin-top: 20px;">
                <a href="{{ cerebro_url }}" style="background: #1976d2; color: white; padding: 10px 20px; text-decoration: none; border-radius: 3px;">Open Cerebro</a>
            </p>
        </div>
        <div class="footer">
            <p>Cerebro Security System of Record</p>
            <p>This is an automated security alert. Please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>
"""


# ==================== Email Notification Service ====================


class EmailNotificationService:
    """Service for sending email notifications with retry logic."""

    def __init__(
        self,
        max_retries: int = 3,
        retry_delay_seconds: int = 2,
        cerebro_url: str = "https://cerebro.example.com",
    ):
        self.max_retries = max_retries
        self.retry_delay_seconds = retry_delay_seconds
        self.cerebro_url = cerebro_url

    async def _validate_config(self, config: EmailConfig) -> None:
        """Validate email configuration before attempting delivery."""
        if not config:
            raise ValueError("Email configuration is required")

        smtp_host = getattr(config, "smtp_host", None)
        if not smtp_host or not str(smtp_host).strip():
            raise ValueError("smtp_host is required for email notifications")

        port_raw = getattr(config, "smtp_port", None)
        if port_raw is None:
            raise ValueError("SMTP port must be configured")
        try:
            port = int(port_raw)
        except (TypeError, ValueError):
            raise ValueError("SMTP port must be a number between 1 and 65535") from None

        if not 1 <= port <= 65535:
            raise ValueError("SMTP port must be between 1 and 65535")
        config.smtp_port = port

        recipients = list(getattr(config, "to_emails", []) or [])
        recipients = [email for email in recipients if email]
        if not recipients:
            raise ValueError("At least one recipient email must be configured")

        if not getattr(config, "from_email", None):
            raise ValueError("from_email is required for email notifications")

        if getattr(config, "digest_mode", False) and not getattr(
            config, "digest_frequency", None
        ):
            raise ValueError("digest_frequency is required when digest_mode is enabled")

        config.to_emails = recipients

    async def send_finding_notification(
        self, org_id: UUID, finding: Finding, db: AsyncSession
    ) -> None:
        """Send email notification for a new finding."""
        try:
            # Get organization
            org_result = await db.execute(
                select(Organization).where(Organization.org_id == org_id)
            )
            org = org_result.scalar_one_or_none()
            if not org:
                logger.error("organization_not_found", org_id=str(org_id))
                return

            # Get active email configs
            configs_result = await db.execute(
                select(EmailConfig).where(
                    EmailConfig.org_id == org_id,
                    EmailConfig.enabled,
                )
            )
            configs = configs_result.scalars().all()

            if not configs:
                logger.debug("no_email_configs", org_id=str(org_id))
                return

            # Filter and send to matching configs
            for config in configs:
                if self._should_send_finding(config, finding):
                    await self._send_finding_email(config, finding, org, db)

        except (OSError, RuntimeError, ValueError) as e:
            logger.error("send_finding_notification_failed", error=str(e))

    async def send_compliance_alert(
        self,
        org_id: UUID,
        control_id: str,
        control_title: str,
        failure_count: int,
        db: AsyncSession,
    ) -> None:
        """Send compliance failure email notification."""
        try:
            # Get organization
            org_result = await db.execute(
                select(Organization).where(Organization.org_id == org_id)
            )
            org = org_result.scalar_one_or_none()
            if not org:
                return

            # Get configs that monitor compliance events
            configs_result = await db.execute(
                select(EmailConfig).where(
                    EmailConfig.org_id == org_id,
                    EmailConfig.enabled,
                )
            )
            configs = configs_result.scalars().all()

            compliance_configs = [
                c for c in configs if "compliance_failed" in c.event_types
            ]

            if not compliance_configs:
                return

            for config in compliance_configs:
                await self._send_compliance_email(
                    config, control_id, control_title, failure_count, org, db
                )

        except (OSError, RuntimeError, ValueError) as e:
            logger.error("send_compliance_alert_failed", error=str(e))

    async def send_monitoring_alert(
        self,
        org_id: UUID,
        alert_title: str,
        alert_description: str,
        severity: str,
        db: AsyncSession,
    ) -> None:
        """Send monitoring alert email notification."""
        try:
            # Get organization
            org_result = await db.execute(
                select(Organization).where(Organization.org_id == org_id)
            )
            org = org_result.scalar_one_or_none()
            if not org:
                return

            # Get configs that monitor alerts
            configs_result = await db.execute(
                select(EmailConfig).where(
                    EmailConfig.org_id == org_id,
                    EmailConfig.enabled,
                )
            )
            configs = configs_result.scalars().all()

            alert_configs = [c for c in configs if "monitoring_alert" in c.event_types]

            if not alert_configs:
                return

            for config in alert_configs:
                if config.severity_filter and severity not in config.severity_filter:
                    continue

                await self._send_monitoring_email(
                    config, alert_title, alert_description, severity, org, db
                )

        except (OSError, RuntimeError, ValueError) as e:
            logger.error("send_monitoring_alert_failed", error=str(e))

    def _should_send_finding(self, config: EmailConfig, finding: Finding) -> bool:
        """Check if finding matches config filters."""
        if "finding_created" not in config.event_types:
            return False

        if config.severity_filter:
            if not finding.severity or finding.severity not in config.severity_filter:
                return False

        return True

    async def _send_finding_email(
        self, config: EmailConfig, finding: Finding, org: Organization, db: AsyncSession
    ) -> None:
        """Send finding email with retry logic."""
        template = Template(EmailTemplates.finding_created_template())

        description = getattr(finding, "description", None)

        html_body = template.render(
            org_name=org.name,
            title=finding.title or "Untitled Finding",
            severity=finding.severity or "unknown",
            description=description,
            status=finding.status,
            rule_id=finding.rule_id,
            finding_id=str(finding.finding_id),
            created_at=finding.first_seen.strftime("%Y-%m-%d %H:%M:%S UTC") if finding.first_seen else "Unknown",
            cerebro_url=self.cerebro_url,
        )

        subject = f"[Cerebro] {finding.severity.upper() if finding.severity else 'UNKNOWN'}: {finding.title}"

        await self._send_email_with_retry(
            config=config,
            subject=subject,
            html_body=html_body,
            event_type="finding_created",
            finding_id=finding.finding_id,
            severity=finding.severity,
            db=db,
        )

    async def _send_compliance_email(
        self,
        config: EmailConfig,
        control_id: str,
        control_title: str,
        failure_count: int,
        org: Organization,
        db: AsyncSession,
    ) -> None:
        """Send compliance failure email."""
        template = Template(EmailTemplates.compliance_failed_template())

        html_body = template.render(
            org_name=org.name,
            control_id=control_id,
            control_title=control_title,
            failure_count=failure_count,
            timestamp=datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
            cerebro_url=self.cerebro_url,
        )

        subject = f"[Cerebro] Compliance Failed: {control_id}"

        await self._send_email_with_retry(
            config=config,
            subject=subject,
            html_body=html_body,
            event_type="compliance_failed",
            finding_id=None,
            severity="high",
            db=db,
        )

    async def _send_monitoring_email(
        self,
        config: EmailConfig,
        alert_title: str,
        alert_description: str,
        severity: str,
        org: Organization,
        db: AsyncSession,
    ) -> None:
        """Send monitoring alert email."""
        template = Template(EmailTemplates.monitoring_alert_template())

        emoji = {"critical": "🚨", "high": "⚠️", "medium": "🔔", "low": "ℹ️"}.get(
            severity.lower(), "🔔"
        )

        html_body = template.render(
            org_name=org.name,
            title=alert_title,
            description=alert_description,
            severity=severity,
            emoji=emoji,
            timestamp=datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
            cerebro_url=self.cerebro_url,
        )

        subject = f"[Cerebro] {severity.upper()}: {alert_title}"

        await self._send_email_with_retry(
            config=config,
            subject=subject,
            html_body=html_body,
            event_type="monitoring_alert",
            finding_id=None,
            severity=severity,
            db=db,
        )

    async def _send_email_with_retry(
        self,
        config: EmailConfig,
        subject: str,
        html_body: str,
        event_type: str,
        finding_id: UUID | None,
        severity: str | None,
        db: AsyncSession,
    ) -> None:
        """Send email with exponential backoff retry."""
        await self._validate_config(config)
        notification_id = uuid4()
        retry_count = 0
        last_error = None

        # Decrypt SMTP password if present
        smtp_password = None
        if config.smtp_password:
            try:
                smtp_password = await config.get_smtp_password()
                if not smtp_password and config.smtp_username:
                    raise ValueError("Failed to decrypt SMTP password")
            except (OSError, RuntimeError, ValueError) as e:
                logger.error(f"SMTP password decryption failed: {e}", exc_info=True)
                # Log failure and abort
                notification = EmailNotification(
                    notification_id=notification_id,
                    config_id=config.config_id,
                    org_id=config.org_id,
                    event_type=event_type,
                    finding_id=finding_id,
                    severity=severity,
                    subject=subject,
                    body_html=html_body,
                    to_emails=config.to_emails,
                    status="failed",
                    error_message=f"Decryption error: {e!s}",
                    retry_count=0,
                )
                db.add(notification)
                await db.commit()
                return

        for attempt in range(self.max_retries + 1):
            try:
                # Send email synchronously (wrap in executor for async)
                await asyncio.to_thread(
                    self._send_smtp_email,
                    config,
                    subject,
                    html_body,
                    smtp_password,
                )

                # Success - log notification
                notification = EmailNotification(
                    notification_id=notification_id,
                    config_id=config.config_id,
                    org_id=config.org_id,
                    event_type=event_type,
                    finding_id=finding_id,
                    severity=severity,
                    subject=subject,
                    body_html=html_body,
                    to_emails=config.to_emails,
                    status="sent",
                    status_code=250,  # SMTP success code
                    retry_count=retry_count,
                    sent_at=datetime.now(UTC),
                )
                db.add(notification)
                await db.commit()

                logger.info(
                    "email_notification_sent",
                    config_id=str(config.config_id),
                    event_type=event_type,
                    retry_count=retry_count,
                )
                return

            except (OSError, ConnectionError, TimeoutError) as e:
                last_error = str(e)
                logger.warning(
                    "email_send_failed",
                    config_id=str(config.config_id),
                    attempt=attempt + 1,
                    error=last_error,
                )

            # Retry logic
            if attempt < self.max_retries:
                retry_count += 1
                delay = self.retry_delay_seconds * (2**attempt)
                await asyncio.sleep(delay)

        # All retries failed - log failure
        notification = EmailNotification(
            notification_id=notification_id,
            config_id=config.config_id,
            org_id=config.org_id,
            event_type=event_type,
            finding_id=finding_id,
            severity=severity,
            subject=subject,
            body_html=html_body,
            to_emails=config.to_emails,
            status="failed",
            error_message=last_error,
            retry_count=retry_count,
        )
        db.add(notification)
        await db.commit()

        logger.error(
            "email_notification_failed_after_retries",
            config_id=str(config.config_id),
            event_type=event_type,
            error=last_error,
        )

    def _send_smtp_email(
        self,
        config: EmailConfig,
        subject: str,
        html_body: str,
        smtp_password: str | None = None,
    ) -> None:
        """Send email via SMTP (synchronous)."""
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = (
            f"{config.from_name} <{config.from_email}>"
            if config.from_name
            else config.from_email
        )
        msg["To"] = ", ".join(config.to_emails)
        if config.cc_emails:
            msg["Cc"] = ", ".join(config.cc_emails)

        # Attach HTML body
        html_part = MIMEText(html_body, "html")
        msg.attach(html_part)

        # Send via SMTP
        if config.use_tls:
            with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=10) as server:
                server.starttls()
                if config.smtp_username and smtp_password:
                    server.login(config.smtp_username, smtp_password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=10) as server:
                if config.smtp_username and smtp_password:
                    server.login(config.smtp_username, smtp_password)
                server.send_message(msg)


# Global service instance
_email_service: EmailNotificationService | None = None


def get_email_service() -> EmailNotificationService:
    """Get or create the global email notification service."""
    global _email_service
    if _email_service is None:
        _email_service = EmailNotificationService()
    return _email_service
