"""Notification digest processing tasks.

Aggregates notifications over time periods (daily, weekly) and sends them
as batched digests instead of individual messages.
"""
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from uuid import UUID

from celery import shared_task
from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.database import async_session_factory
from cerebro.core.models import EmailConfig, EmailNotification, Finding
from cerebro.notifications.email import get_email_service

logger = logging.getLogger(__name__)


@shared_task(name="process_email_digests")
def process_email_digests():
    """Process all pending email digests (Celery task wrapper)."""
    asyncio.run(_process_email_digests_async())


async def _process_email_digests_async():
    """Process all pending email digests asynchronously."""
    try:
        async with async_session_factory() as db:
            # Find all configs with digest mode enabled
            configs_result = await db.execute(
                select(EmailConfig).where(
                    EmailConfig.enabled == True,
                    EmailConfig.digest_mode == True,
                )
            )
            configs = configs_result.scalars().all()

            logger.info(f"Processing email digests for {len(configs)} configs")

            for config in configs:
                try:
                    await _process_config_digest(config, db)
                except Exception as e:
                    logger.error(
                        f"Failed to process digest for config {config.config_id}: {e}",
                        exc_info=True,
                    )

    except Exception as e:
        logger.error(f"Failed to process email digests: {e}", exc_info=True)
        raise


async def _process_config_digest(config: EmailConfig, db: AsyncSession):
    """Process digest for a single email configuration.

    Args:
        config: Email configuration with digest mode enabled
        db: Database session
    """
    # Determine time window based on digest frequency
    now = datetime.now(timezone.utc)
    if config.digest_frequency == "daily":
        window_start = now - timedelta(days=1)
    elif config.digest_frequency == "weekly":
        window_start = now - timedelta(weeks=1)
    else:
        logger.warning(f"Unknown digest frequency: {config.digest_frequency}")
        return

    # Find findings created in this window for this org
    findings_result = await db.execute(
        select(Finding).where(
            and_(
                Finding.org_id == config.org_id,
                Finding.created_at >= window_start,
                Finding.created_at <= now,
            )
        ).order_by(Finding.severity.desc(), Finding.created_at.desc())
    )
    findings = findings_result.scalars().all()

    if not findings:
        logger.info(f"No findings for digest config {config.config_id}")
        return

    # Filter findings by severity if configured
    if config.severity_filter:
        findings = [
            f for f in findings if f.severity and f.severity in config.severity_filter
        ]

    if not findings:
        logger.info(f"No findings matching severity filter for config {config.config_id}")
        return

    # Group findings by severity
    findings_by_severity = _group_findings_by_severity(findings)

    # Generate digest email
    subject = _generate_digest_subject(config, findings, window_start, now)
    html_body = _generate_digest_html(config, findings_by_severity, window_start, now)

    # Send digest email
    email_service = get_email_service()

    # Decrypt SMTP password
    smtp_password = None
    if config.smtp_password:
        try:
            smtp_password = await config.get_smtp_password()
        except Exception as e:
            logger.error(f"Failed to decrypt SMTP password: {e}")
            return

    try:
        # Send via executor (SMTP is sync)
        await asyncio.to_thread(
            email_service._send_smtp_email,
            config,
            subject,
            html_body,
            smtp_password,
        )

        # Log successful digest
        notification = EmailNotification(
            config_id=config.config_id,
            org_id=config.org_id,
            event_type="digest.sent",
            subject=subject,
            body_html=html_body,
            to_emails=config.to_emails,
            status="sent",
            status_code=250,
            retry_count=0,
            sent_at=now,
        )
        db.add(notification)
        await db.commit()

        logger.info(
            f"Sent email digest for config {config.config_id} with {len(findings)} findings"
        )

    except Exception as e:
        logger.error(f"Failed to send digest email: {e}", exc_info=True)

        # Log failed digest
        notification = EmailNotification(
            config_id=config.config_id,
            org_id=config.org_id,
            event_type="digest.failed",
            subject=subject,
            body_html=html_body,
            to_emails=config.to_emails,
            status="failed",
            error_message=str(e),
            retry_count=0,
        )
        db.add(notification)
        await db.commit()


def _group_findings_by_severity(findings: List[Finding]) -> Dict[str, List[Finding]]:
    """Group findings by severity level.

    Args:
        findings: List of findings

    Returns:
        Dictionary mapping severity to list of findings
    """
    grouped = {}
    for finding in findings:
        severity = finding.severity or "unknown"
        if severity not in grouped:
            grouped[severity] = []
        grouped[severity].append(finding)
    return grouped


def _generate_digest_subject(
    config: EmailConfig,
    findings: List[Finding],
    window_start: datetime,
    window_end: datetime,
) -> str:
    """Generate subject line for digest email.

    Args:
        config: Email configuration
        findings: List of findings in digest
        window_start: Start of time window
        window_end: End of time window

    Returns:
        Email subject line
    """
    frequency = config.digest_frequency or "periodic"
    critical_count = sum(1 for f in findings if f.severity == "critical")

    if critical_count > 0:
        return f"[CRITICAL] Security Digest: {len(findings)} findings ({critical_count} critical)"
    else:
        return f"Security Digest: {len(findings)} findings ({frequency})"


def _generate_digest_html(
    config: EmailConfig,
    findings_by_severity: Dict[str, List[Finding]],
    window_start: datetime,
    window_end: datetime,
) -> str:
    """Generate HTML body for digest email.

    Args:
        config: Email configuration
        findings_by_severity: Findings grouped by severity
        window_start: Start of time window
        window_end: End of time window

    Returns:
        HTML email body
    """
    total_findings = sum(len(findings) for findings in findings_by_severity.values())

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 800px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #1976d2; color: white; padding: 20px; border-radius: 5px 5px 0 0; }}
        .summary {{ background: #f5f5f5; padding: 15px; margin: 20px 0; border-left: 4px solid #1976d2; }}
        .severity-section {{ margin: 20px 0; }}
        .severity-header {{ padding: 10px; color: white; font-weight: bold; border-radius: 5px; }}
        .severity-critical {{ background: #d32f2f; }}
        .severity-high {{ background: #f57c00; }}
        .severity-medium {{ background: #fbc02d; }}
        .severity-low {{ background: #1976d2; }}
        .finding {{ background: white; padding: 15px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }}
        .finding-title {{ font-weight: bold; color: #333; }}
        .finding-meta {{ color: #666; font-size: 0.9em; margin-top: 5px; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 2px solid #ddd; color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Findings Digest</h1>
            <p>Period: {window_start.strftime('%Y-%m-%d %H:%M')} - {window_end.strftime('%Y-%m-%d %H:%M')} UTC</p>
        </div>

        <div class="summary">
            <h2>Summary</h2>
            <p><strong>{total_findings}</strong> security findings detected</p>
            <ul>
"""

    # Add severity counts to summary
    for severity in ["critical", "high", "medium", "low"]:
        if severity in findings_by_severity:
            count = len(findings_by_severity[severity])
            html += f"                <li><strong>{severity.upper()}:</strong> {count}</li>\n"

    html += """
            </ul>
        </div>
"""

    # Add findings grouped by severity
    for severity in ["critical", "high", "medium", "low"]:
        if severity not in findings_by_severity:
            continue

        findings = findings_by_severity[severity]

        html += f"""
        <div class="severity-section">
            <div class="severity-header severity-{severity}">
                {severity.upper()} Severity ({len(findings)} findings)
            </div>
"""

        # Show up to 10 findings per severity
        for finding in findings[:10]:
            html += f"""
            <div class="finding">
                <div class="finding-title">{finding.title}</div>
                <div class="finding-meta">
                    Provider: {finding.provider} | Resource: {finding.resource_type}
                    {f'| Account: {finding.account_id}' if finding.account_id else ''}
                    {f'| Region: {finding.region}' if finding.region else ''}
                </div>
            </div>
"""

        if len(findings) > 10:
            html += f"            <p><em>... and {len(findings) - 10} more {severity} findings</em></p>\n"

        html += "        </div>\n"

    html += """
        <div class="footer">
            <p>This is an automated security digest from Cerebro.</p>
            <p>To view full details and take action, please log in to your Cerebro dashboard.</p>
        </div>
    </div>
</body>
</html>
"""

    return html