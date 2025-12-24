"""API endpoints for generic webhook notification configuration and management."""

import logging
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    ValidationInfo,
    field_validator,
)
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.api.auth import User, get_current_user
from cerebro.core.database import get_db
from cerebro.core.models import WebhookConfig, WebhookNotification
from cerebro.notifications.webhooks import WebhookPayloadTemplates, get_webhook_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["Generic Webhooks"])
limiter = Limiter(key_func=get_remote_address)


# Pydantic models for API
class WebhookConfigCreate(BaseModel):
    """Request model for creating webhook configuration."""

    name: str = Field(
        ..., min_length=1, max_length=255, description="Human-readable name"
    )
    url: HttpUrl = Field(..., description="Webhook URL endpoint")
    http_method: str = Field(
        default="POST", description="HTTP method (POST, PUT, PATCH)"
    )
    headers: dict[str, str] | None = Field(None, description="Custom HTTP headers")
    payload_template: dict[str, Any] = Field(
        ..., description="Jinja2 template for webhook payload"
    )
    authentication: dict[str, Any] | None = Field(
        None, description="Authentication configuration (Bearer token, etc.)"
    )
    use_hmac_signature: bool = Field(
        default=False, description="Add HMAC signature header"
    )
    hmac_secret: str | None = Field(None, description="HMAC secret key")
    enabled: bool = Field(default=True, description="Enable this webhook config")
    severity_filter: list[str] | None = Field(
        None, description="Filter by severity (critical, high, medium, low)"
    )
    event_types: list[str] = Field(
        ...,
        min_length=1,
        description="Event types to send (finding.created, compliance.check_failed, etc.)",
    )
    timeout_seconds: int = Field(
        default=10, ge=1, le=60, description="Request timeout in seconds"
    )
    webhook_metadata: dict[str, Any] | None = Field(
        None, description="Additional metadata"
    )

    @field_validator("http_method")
    @classmethod
    def validate_http_method(cls, v: str) -> str:
        """Validate HTTP method."""
        method = v.upper()
        if method not in ["POST", "PUT", "PATCH"]:
            raise ValueError("http_method must be POST, PUT, or PATCH")
        return method

    @field_validator("hmac_secret", mode="after")
    @classmethod
    def validate_hmac_secret(cls, v, info: ValidationInfo):
        """Validate HMAC secret is provided when use_hmac_signature is true."""
        if info.data.get("use_hmac_signature") and not v:
            raise ValueError("hmac_secret is required when use_hmac_signature is true")
        return v


class WebhookConfigUpdate(BaseModel):
    """Request model for updating webhook configuration."""

    name: str | None = Field(None, min_length=1, max_length=255)
    url: HttpUrl | None = None
    http_method: str | None = None
    headers: dict[str, str] | None = None
    payload_template: dict[str, Any] | None = None
    authentication: dict[str, Any] | None = None
    use_hmac_signature: bool | None = None
    hmac_secret: str | None = None
    enabled: bool | None = None
    severity_filter: list[str] | None = None
    event_types: list[str] | None = Field(None, min_length=1)
    timeout_seconds: int | None = Field(None, ge=1, le=60)
    webhook_metadata: dict[str, Any] | None = None


class WebhookConfigResponse(BaseModel):
    """Response model for webhook configuration."""

    config_id: UUID
    org_id: UUID
    name: str
    url: str  # Masked for security
    http_method: str
    headers: dict[str, str] | None
    payload_template: dict[str, Any]
    authentication: dict[str, Any] | None  # Masked for security
    use_hmac_signature: bool
    hmac_secret: str | None  # Masked
    enabled: bool
    severity_filter: list[str] | None
    event_types: list[str]
    timeout_seconds: int
    webhook_metadata: dict[str, Any] | None
    created_at: datetime
    updated_at: datetime
    created_by: str | None

    model_config = ConfigDict(from_attributes=True)


class WebhookNotificationResponse(BaseModel):
    """Response model for webhook notification."""

    notification_id: UUID
    config_id: UUID
    org_id: UUID
    event_type: str
    finding_id: UUID | None
    severity: str | None
    payload: dict[str, Any]
    response_status: int | None
    response_body: str | None
    response_time_ms: int | None
    status: str
    error_message: str | None
    retry_count: int
    sent_at: datetime | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class WebhookNotificationStatsResponse(BaseModel):
    """Response model for webhook notification statistics."""

    total_sent: int
    total_failed: int
    total_retrying: int
    success_rate: float
    avg_response_time_ms: float | None


def _mask_url(url: str) -> str:
    """Mask sensitive parts of URL for security."""
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        if parsed.password:
            return url.replace(parsed.password, "********")
        return url
    except Exception:
        return url


def _mask_authentication(auth: dict[str, Any] | None) -> dict[str, Any] | None:
    """Mask sensitive authentication values."""
    if not auth:
        return None

    masked = auth.copy()
    sensitive_keys = ["token", "secret", "password", "api_key", "bearer"]

    for key in masked:
        if any(sensitive in key.lower() for sensitive in sensitive_keys):
            masked[key] = "********"

    return masked


@router.post("/configs", response_model=WebhookConfigResponse, status_code=201)
@limiter.limit("10/minute")
async def create_webhook_config(
    request: Request,
    config_data: WebhookConfigCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new webhook notification configuration.

    Args:
        config_data: Webhook configuration data
        db: Database session
        current_user: Authenticated user

    Returns:
        Created webhook configuration
    """
    # Create webhook config
    webhook_config = WebhookConfig(
        config_id=uuid4(),
        org_id=current_user.org_id,
        name=config_data.name,
        url=str(config_data.url),
        http_method=config_data.http_method,
        headers=config_data.headers,
        payload_template=config_data.payload_template,
        authentication=config_data.authentication,
        use_hmac_signature=config_data.use_hmac_signature,
        enabled=config_data.enabled,
        severity_filter=config_data.severity_filter,
        event_types=config_data.event_types,
        timeout_seconds=config_data.timeout_seconds,
        webhook_metadata=config_data.webhook_metadata,
        created_by=current_user.username,
    )

    # Encrypt HMAC secret if provided
    if config_data.hmac_secret:
        await webhook_config.set_hmac_secret(config_data.hmac_secret)

    db.add(webhook_config)
    await db.commit()
    await db.refresh(webhook_config)

    # Mask sensitive data in response
    response_config = WebhookConfigResponse.model_validate(webhook_config)
    response_config.url = _mask_url(response_config.url)
    response_config.authentication = _mask_authentication(
        response_config.authentication
    )
    if response_config.hmac_secret:
        response_config.hmac_secret = "********"

    logger.info(
        f"Created webhook config {webhook_config.config_id} for org {current_user.org_id}"
    )
    return response_config


@router.get("/configs", response_model=list[WebhookConfigResponse])
async def list_webhook_configs(
    enabled: bool | None = Query(None, description="Filter by enabled status"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all webhook configurations for the current organization.

    Args:
        enabled: Optional filter by enabled status
        db: Database session
        current_user: Authenticated user

    Returns:
        List of webhook configurations
    """
    query = select(WebhookConfig).where(WebhookConfig.org_id == current_user.org_id)

    if enabled is not None:
        query = query.where(WebhookConfig.enabled == enabled)

    result = await db.execute(query.order_by(WebhookConfig.created_at.desc()))
    configs = result.scalars().all()

    # Mask sensitive data in response
    response_configs = [
        WebhookConfigResponse.model_validate(config) for config in configs
    ]
    for response_config in response_configs:
        response_config.url = _mask_url(response_config.url)
        response_config.authentication = _mask_authentication(
            response_config.authentication
        )
        if response_config.hmac_secret:
            response_config.hmac_secret = "********"

    return response_configs


@router.get("/configs/{config_id}", response_model=WebhookConfigResponse)
async def get_webhook_config(
    config_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a specific webhook configuration.

    Args:
        config_id: Webhook configuration ID
        db: Database session
        current_user: Authenticated user

    Returns:
        Webhook configuration
    """
    result = await db.execute(
        select(WebhookConfig).where(
            WebhookConfig.config_id == config_id,
            WebhookConfig.org_id == current_user.org_id,
        )
    )
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(status_code=404, detail="Webhook configuration not found")

    # Mask sensitive data in response
    response_config = WebhookConfigResponse.model_validate(config)
    response_config.url = _mask_url(response_config.url)
    response_config.authentication = _mask_authentication(
        response_config.authentication
    )
    if response_config.hmac_secret:
        response_config.hmac_secret = "********"

    return response_config


@router.patch("/configs/{config_id}", response_model=WebhookConfigResponse)
async def update_webhook_config(
    config_id: UUID,
    update_data: WebhookConfigUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update a webhook configuration.

    Args:
        config_id: Webhook configuration ID
        update_data: Fields to update
        db: Database session
        current_user: Authenticated user

    Returns:
        Updated webhook configuration
    """
    result = await db.execute(
        select(WebhookConfig).where(
            WebhookConfig.config_id == config_id,
            WebhookConfig.org_id == current_user.org_id,
        )
    )
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(status_code=404, detail="Webhook configuration not found")

    # Update fields
    update_dict = update_data.dict(exclude_unset=True)

    # Handle HMAC secret encryption separately
    hmac_secret = update_dict.pop("hmac_secret", None)

    for field, value in update_dict.items():
        if field == "url" and value:
            setattr(config, field, str(value))
        else:
            setattr(config, field, value)

    # Encrypt HMAC secret if provided
    if hmac_secret is not None:
        await config.set_hmac_secret(hmac_secret)

    config.updated_at = datetime.utcnow()

    await db.commit()
    await db.refresh(config)

    # Mask sensitive data in response
    response_config = WebhookConfigResponse.model_validate(config)
    response_config.url = _mask_url(response_config.url)
    response_config.authentication = _mask_authentication(
        response_config.authentication
    )
    if response_config.hmac_secret:
        response_config.hmac_secret = "********"

    logger.info(f"Updated webhook config {config_id}")
    return response_config


@router.delete("/configs/{config_id}", status_code=204)
async def delete_webhook_config(
    config_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a webhook configuration.

    Args:
        config_id: Webhook configuration ID
        db: Database session
        current_user: Authenticated user
    """
    result = await db.execute(
        select(WebhookConfig).where(
            WebhookConfig.config_id == config_id,
            WebhookConfig.org_id == current_user.org_id,
        )
    )
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(status_code=404, detail="Webhook configuration not found")

    await db.delete(config)
    await db.commit()

    logger.info(f"Deleted webhook config {config_id}")


@router.get("/templates", response_model=dict[str, dict[str, Any]])
async def get_default_templates():
    """Get default webhook payload templates.

    Returns:
        Dictionary of default templates by event type
    """
    return {
        "finding.created": WebhookPayloadTemplates.finding_created_template(),
        "compliance.check_failed": WebhookPayloadTemplates.compliance_failed_template(),
        "monitoring.alert": WebhookPayloadTemplates.monitoring_alert_template(),
    }


@router.post("/test/{config_id}", status_code=200)
async def test_webhook_config(
    config_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Send a test webhook using the specified configuration.

    Args:
        config_id: Webhook configuration ID
        db: Database session
        current_user: Authenticated user

    Returns:
        Success message with response details
    """
    result = await db.execute(
        select(WebhookConfig).where(
            WebhookConfig.config_id == config_id,
            WebhookConfig.org_id == current_user.org_id,
        )
    )
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(status_code=404, detail="Webhook configuration not found")

    try:
        webhook_service = get_webhook_service()

        # Prepare test context
        test_context = {
            "timestamp": datetime.utcnow().isoformat(),
            "org_id": str(current_user.org_id),
            "org_name": "Test Organization",
            "alert_title": "Test Webhook",
            "alert_description": "This is a test webhook notification from Cerebro",
            "severity": "info",
            "metadata": {"test": True},
        }

        # Render payload
        test_payload = webhook_service._render_payload(
            config.payload_template, test_context
        )

        # Send test webhook
        await webhook_service._send_with_retry(
            config=config,
            payload=test_payload,
            event_type="test.webhook",
            finding_id=None,
            severity="info",
            db=db,
        )

        return {"message": "Test webhook sent successfully", "payload": test_payload}

    except Exception:
        logger.exception(
            "Failed to send test webhook", extra={"config_id": str(config_id)}
        )
        raise HTTPException(status_code=500, detail="Failed to send test webhook")


@router.get("/notifications", response_model=list[WebhookNotificationResponse])
async def list_webhook_notifications(
    config_id: UUID | None = Query(None, description="Filter by config ID"),
    status: str | None = Query(
        None, description="Filter by status (sent, failed, retrying)"
    ),
    limit: int = Query(
        100, ge=1, le=1000, description="Number of notifications to return"
    ),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List webhook notifications for the current organization.

    Args:
        config_id: Optional filter by configuration ID
        status: Optional filter by status
        limit: Maximum number of results
        offset: Pagination offset
        db: Database session
        current_user: Authenticated user

    Returns:
        List of webhook notifications
    """
    query = select(WebhookNotification).where(
        WebhookNotification.org_id == current_user.org_id
    )

    if config_id:
        query = query.where(WebhookNotification.config_id == config_id)

    if status:
        query = query.where(WebhookNotification.status == status)

    result = await db.execute(
        query.order_by(WebhookNotification.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    notifications = result.scalars().all()

    return [
        WebhookNotificationResponse.model_validate(notif) for notif in notifications
    ]


@router.get("/notifications/stats", response_model=WebhookNotificationStatsResponse)
async def get_webhook_notification_stats(
    config_id: UUID | None = Query(None, description="Filter by config ID"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get webhook notification statistics for the current organization.

    Args:
        config_id: Optional filter by configuration ID
        db: Database session
        current_user: Authenticated user

    Returns:
        Webhook notification statistics
    """
    query = select(
        func.count(WebhookNotification.notification_id).label("total"),
        func.sum(func.cast(WebhookNotification.status == "sent", sa.Integer)).label(
            "sent"
        ),
        func.sum(func.cast(WebhookNotification.status == "failed", sa.Integer)).label(
            "failed"
        ),
        func.sum(func.cast(WebhookNotification.status == "retrying", sa.Integer)).label(
            "retrying"
        ),
        func.avg(WebhookNotification.response_time_ms).label("avg_response_time"),
    ).where(WebhookNotification.org_id == current_user.org_id)

    if config_id:
        query = query.where(WebhookNotification.config_id == config_id)

    result = await db.execute(query)
    row = result.one()

    total_sent = row.sent or 0
    total_failed = row.failed or 0
    total_retrying = row.retrying or 0
    total = row.total or 0
    avg_response_time = row.avg_response_time

    success_rate = (total_sent / total * 100) if total > 0 else 0.0

    return WebhookNotificationStatsResponse(
        total_sent=total_sent,
        total_failed=total_failed,
        total_retrying=total_retrying,
        success_rate=round(success_rate, 2),
        avg_response_time_ms=round(avg_response_time, 2) if avg_response_time else None,
    )
