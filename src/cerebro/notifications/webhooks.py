"""Generic webhook notification service with Jinja2 templating and HMAC signatures."""
import asyncio
import hashlib
import hmac
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

import httpx
from jinja2 import Template, TemplateSyntaxError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.models import (
    Finding,
    WebhookConfig,
    WebhookNotification,
    Organization,
)

logger = logging.getLogger(__name__)


class WebhookPayloadTemplates:
    """Default webhook payload templates for different event types."""

    @staticmethod
    def finding_created_template() -> Dict[str, Any]:
        """Default template for finding created events."""
        return {
            "event_type": "finding.created",
            "timestamp": "{{ timestamp }}",
            "organization": {
                "id": "{{ org_id }}",
                "name": "{{ org_name }}"
            },
            "finding": {
                "id": "{{ finding.finding_id }}",
                "title": "{{ finding.title }}",
                "severity": "{{ finding.severity }}",
                "status": "{{ finding.status }}",
                "provider": "{{ finding.provider }}",
                "resource_id": "{{ finding.resource_id }}",
                "resource_type": "{{ finding.resource_type }}",
                "account_id": "{{ finding.account_id }}",
                "region": "{{ finding.region }}",
                "compliance_frameworks": "{{ finding.compliance_frameworks | default([]) }}",
                "ocsf_data": "{{ finding.ocsf_data | default({}) }}",
                "created_at": "{{ finding.created_at }}"
            }
        }

    @staticmethod
    def compliance_failed_template() -> Dict[str, Any]:
        """Default template for compliance check failure events."""
        return {
            "event_type": "compliance.check_failed",
            "timestamp": "{{ timestamp }}",
            "organization": {
                "id": "{{ org_id }}",
                "name": "{{ org_name }}"
            },
            "compliance": {
                "framework": "{{ framework }}",
                "control_id": "{{ control_id }}",
                "control_title": "{{ control_title }}",
                "status": "{{ status }}",
                "severity": "{{ severity }}",
                "findings_count": "{{ findings_count }}",
                "account_id": "{{ account_id }}"
            }
        }

    @staticmethod
    def monitoring_alert_template() -> Dict[str, Any]:
        """Default template for monitoring alert events."""
        return {
            "event_type": "monitoring.alert",
            "timestamp": "{{ timestamp }}",
            "organization": {
                "id": "{{ org_id }}",
                "name": "{{ org_name }}"
            },
            "alert": {
                "title": "{{ alert_title }}",
                "description": "{{ alert_description }}",
                "severity": "{{ severity }}",
                "finding_id": "{{ finding_id | default('') }}",
                "metadata": "{{ metadata | default({}) }}"
            }
        }


class WebhookNotificationService:
    """Service for sending generic webhook notifications with templating and HMAC."""

    def __init__(self, max_retries: int = 3, retry_delay_seconds: int = 2):
        """Initialize webhook notification service.

        Args:
            max_retries: Maximum number of retry attempts
            retry_delay_seconds: Base delay between retries (exponential backoff)
        """
        self.max_retries = max_retries
        self.retry_delay_seconds = retry_delay_seconds
        self.client = httpx.AsyncClient(timeout=30.0)

    async def send_finding_notification(
        self, org_id: UUID, finding: Finding, db: AsyncSession
    ) -> None:
        """Send webhook notifications for a new finding.

        Args:
            org_id: Organization ID
            finding: Finding object
            db: Database session
        """
        try:
            # Get organization
            org_result = await db.execute(
                select(Organization).where(Organization.org_id == org_id)
            )
            org = org_result.scalar_one_or_none()
            if not org:
                logger.error(f"Organization {org_id} not found")
                return

            # Get active webhook configs for this org and event type
            configs_result = await db.execute(
                select(WebhookConfig).where(
                    WebhookConfig.org_id == org_id,
                    WebhookConfig.enabled == True,
                    WebhookConfig.event_types.contains(["finding.created"])
                )
            )
            configs = configs_result.scalars().all()

            if not configs:
                logger.debug(f"No webhook configs found for org {org_id} and event finding.created")
                return

            # Prepare context for template rendering
            context = {
                "timestamp": datetime.utcnow().isoformat(),
                "org_id": str(org_id),
                "org_name": org.name,
                "finding": finding,
            }

            # Send to each configured webhook
            for config in configs:
                # Check severity filter
                if config.severity_filter and finding.severity not in config.severity_filter:
                    logger.debug(
                        f"Skipping webhook {config.config_id} - severity {finding.severity} not in filter"
                    )
                    continue

                # Use custom template or default
                payload_template = config.payload_template or WebhookPayloadTemplates.finding_created_template()

                try:
                    payload = self._render_payload(payload_template, context)
                    await self._send_with_retry(
                        config=config,
                        payload=payload,
                        event_type="finding.created",
                        finding_id=finding.finding_id,
                        severity=finding.severity,
                        db=db,
                    )
                except Exception as e:
                    logger.error(
                        f"Failed to send webhook notification {config.config_id}: {e}",
                        exc_info=True,
                    )

        except Exception as e:
            logger.error(f"Error sending finding webhook notifications: {e}", exc_info=True)

    async def send_compliance_alert(
        self,
        org_id: UUID,
        framework: str,
        control_id: str,
        control_title: str,
        status: str,
        severity: str,
        findings_count: int,
        account_id: Optional[str],
        db: AsyncSession,
    ) -> None:
        """Send webhook notifications for compliance check failure.

        Args:
            org_id: Organization ID
            framework: Compliance framework (e.g., "SOC2", "CIS")
            control_id: Control identifier
            control_title: Control title
            status: Control status
            severity: Alert severity
            findings_count: Number of findings
            account_id: Account ID
            db: Database session
        """
        try:
            # Get organization
            org_result = await db.execute(
                select(Organization).where(Organization.org_id == org_id)
            )
            org = org_result.scalar_one_or_none()
            if not org:
                logger.error(f"Organization {org_id} not found")
                return

            # Get active webhook configs
            configs_result = await db.execute(
                select(WebhookConfig).where(
                    WebhookConfig.org_id == org_id,
                    WebhookConfig.enabled == True,
                    WebhookConfig.event_types.contains(["compliance.check_failed"])
                )
            )
            configs = configs_result.scalars().all()

            if not configs:
                logger.debug(f"No webhook configs found for org {org_id} and event compliance.check_failed")
                return

            # Prepare context
            context = {
                "timestamp": datetime.utcnow().isoformat(),
                "org_id": str(org_id),
                "org_name": org.name,
                "framework": framework,
                "control_id": control_id,
                "control_title": control_title,
                "status": status,
                "severity": severity,
                "findings_count": findings_count,
                "account_id": account_id or "",
            }

            # Send to each configured webhook
            for config in configs:
                # Check severity filter
                if config.severity_filter and severity not in config.severity_filter:
                    continue

                payload_template = config.payload_template or WebhookPayloadTemplates.compliance_failed_template()

                try:
                    payload = self._render_payload(payload_template, context)
                    await self._send_with_retry(
                        config=config,
                        payload=payload,
                        event_type="compliance.check_failed",
                        finding_id=None,
                        severity=severity,
                        db=db,
                    )
                except Exception as e:
                    logger.error(f"Failed to send webhook notification {config.config_id}: {e}", exc_info=True)

        except Exception as e:
            logger.error(f"Error sending compliance webhook notifications: {e}", exc_info=True)

    async def send_monitoring_alert(
        self,
        org_id: UUID,
        alert_title: str,
        alert_description: str,
        severity: str,
        finding_id: Optional[UUID] = None,
        metadata: Optional[Dict[str, Any]] = None,
        db: AsyncSession = None,
    ) -> None:
        """Send webhook notifications for monitoring alerts.

        Args:
            org_id: Organization ID
            alert_title: Alert title
            alert_description: Alert description
            severity: Alert severity
            finding_id: Optional finding ID
            metadata: Optional additional metadata
            db: Database session
        """
        try:
            # Get organization
            org_result = await db.execute(
                select(Organization).where(Organization.org_id == org_id)
            )
            org = org_result.scalar_one_or_none()
            if not org:
                logger.error(f"Organization {org_id} not found")
                return

            # Get active webhook configs
            configs_result = await db.execute(
                select(WebhookConfig).where(
                    WebhookConfig.org_id == org_id,
                    WebhookConfig.enabled == True,
                    WebhookConfig.event_types.contains(["monitoring.alert"])
                )
            )
            configs = configs_result.scalars().all()

            if not configs:
                logger.debug(f"No webhook configs found for org {org_id} and event monitoring.alert")
                return

            # Prepare context
            context = {
                "timestamp": datetime.utcnow().isoformat(),
                "org_id": str(org_id),
                "org_name": org.name,
                "alert_title": alert_title,
                "alert_description": alert_description,
                "severity": severity,
                "finding_id": str(finding_id) if finding_id else "",
                "metadata": metadata or {},
            }

            # Send to each configured webhook
            for config in configs:
                # Check severity filter
                if config.severity_filter and severity not in config.severity_filter:
                    continue

                payload_template = config.payload_template or WebhookPayloadTemplates.monitoring_alert_template()

                try:
                    payload = self._render_payload(payload_template, context)
                    await self._send_with_retry(
                        config=config,
                        payload=payload,
                        event_type="monitoring.alert",
                        finding_id=finding_id,
                        severity=severity,
                        db=db,
                    )
                except Exception as e:
                    logger.error(f"Failed to send webhook notification {config.config_id}: {e}", exc_info=True)

        except Exception as e:
            logger.error(f"Error sending monitoring webhook notifications: {e}", exc_info=True)

    def _render_payload(self, template: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Render Jinja2 template with context data.

        Args:
            template: Dictionary containing Jinja2 template strings
            context: Context data for rendering

        Returns:
            Rendered payload dictionary
        """
        def render_value(value: Any, context: Dict[str, Any]) -> Any:
            """Recursively render values in the template."""
            if isinstance(value, str):
                try:
                    # Render string as Jinja2 template
                    jinja_template = Template(value)
                    rendered = jinja_template.render(context)
                    # Try to parse as JSON if it looks like a JSON string
                    if rendered.startswith(("{", "[")):
                        try:
                            return json.loads(rendered)
                        except json.JSONDecodeError:
                            return rendered
                    return rendered
                except TemplateSyntaxError as e:
                    logger.warning(f"Template syntax error: {e}")
                    return value
            elif isinstance(value, dict):
                return {k: render_value(v, context) for k, v in value.items()}
            elif isinstance(value, list):
                return [render_value(item, context) for item in value]
            else:
                return value

        return render_value(template, context)

    def _generate_hmac_signature(self, payload_str: str, secret: str) -> str:
        """Generate HMAC-SHA256 signature for webhook payload.

        Args:
            payload_str: JSON string of the payload
            secret: HMAC secret key

        Returns:
            Hexadecimal HMAC signature
        """
        signature = hmac.new(
            key=secret.encode("utf-8"),
            msg=payload_str.encode("utf-8"),
            digestmod=hashlib.sha256,
        )
        return signature.hexdigest()

    async def _send_with_retry(
        self,
        config: WebhookConfig,
        payload: Dict[str, Any],
        event_type: str,
        finding_id: Optional[UUID],
        severity: Optional[str],
        db: AsyncSession,
    ) -> None:
        """Send webhook with retry logic and audit logging.

        Args:
            config: Webhook configuration
            payload: Payload to send
            event_type: Event type
            finding_id: Optional finding ID
            severity: Optional severity
            db: Database session
        """
        notification_id = uuid4()
        retry_count = 0
        last_error = None
        response_status = None
        response_body = None

        # Convert payload to JSON string
        payload_str = json.dumps(payload)

        # Prepare headers
        headers = {"Content-Type": "application/json"}
        if config.headers:
            headers.update(config.headers)

        # Add HMAC signature if configured
        if config.use_hmac_signature and config.hmac_secret:
            signature = self._generate_hmac_signature(payload_str, config.hmac_secret)
            headers["X-Webhook-Signature"] = f"sha256={signature}"

        # Retry loop
        for attempt in range(self.max_retries + 1):
            try:
                # Determine HTTP method
                method = config.http_method.upper() if config.http_method else "POST"

                # Send request
                if method == "POST":
                    response = await self.client.post(
                        config.url,
                        content=payload_str,
                        headers=headers,
                        timeout=config.timeout_seconds,
                    )
                elif method == "PUT":
                    response = await self.client.put(
                        config.url,
                        content=payload_str,
                        headers=headers,
                        timeout=config.timeout_seconds,
                    )
                elif method == "PATCH":
                    response = await self.client.patch(
                        config.url,
                        content=payload_str,
                        headers=headers,
                        timeout=config.timeout_seconds,
                    )
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")

                response_status = response.status_code
                response_body = response.text[:1000]  # Limit body size

                # Check if successful
                if 200 <= response.status_code < 300:
                    # Success - log and return
                    notification = WebhookNotification(
                        notification_id=notification_id,
                        config_id=config.config_id,
                        org_id=config.org_id,
                        event_type=event_type,
                        finding_id=finding_id,
                        severity=severity,
                        payload=payload,
                        response_status=response_status,
                        response_body=response_body,
                        status="sent",
                        error_message=None,
                        retry_count=retry_count,
                        sent_at=datetime.utcnow(),
                    )
                    db.add(notification)
                    await db.commit()
                    logger.info(f"Webhook notification sent successfully: {notification_id}")
                    return
                else:
                    last_error = f"HTTP {response.status_code}: {response.text[:200]}"
                    logger.warning(
                        f"Webhook request failed with status {response.status_code}: {config.url}"
                    )

            except httpx.TimeoutException as e:
                last_error = f"Timeout after {config.timeout_seconds}s: {str(e)}"
                logger.warning(f"Webhook request timeout: {config.url}")
            except Exception as e:
                last_error = str(e)
                logger.warning(f"Webhook request failed: {e}")

            # Retry logic
            retry_count = attempt
            if attempt < self.max_retries:
                delay = self.retry_delay_seconds * (2 ** attempt)  # Exponential backoff
                logger.info(f"Retrying webhook in {delay}s (attempt {attempt + 1}/{self.max_retries})")
                await asyncio.sleep(delay)

        # All retries failed - log failure
        notification = WebhookNotification(
            notification_id=notification_id,
            config_id=config.config_id,
            org_id=config.org_id,
            event_type=event_type,
            finding_id=finding_id,
            severity=severity,
            payload=payload,
            response_status=response_status,
            response_body=response_body,
            status="failed",
            error_message=last_error,
            retry_count=retry_count,
            sent_at=None,
        )
        db.add(notification)
        await db.commit()
        logger.error(f"Webhook notification failed after {retry_count} retries: {notification_id}")

    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()


# Global webhook service instance
_webhook_service: Optional[WebhookNotificationService] = None


def get_webhook_service() -> WebhookNotificationService:
    """Get global webhook notification service instance."""
    global _webhook_service
    if _webhook_service is None:
        _webhook_service = WebhookNotificationService()
    return _webhook_service