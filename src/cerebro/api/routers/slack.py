"""
Slack Integration API Router

Endpoints for managing Slack webhooks and notification configurations.
"""

from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl, Field, ConfigDict
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

import structlog

from cerebro.core.config import settings
from cerebro.core.database import get_db
from cerebro.api.auth import get_current_user, User
from cerebro.core.models import SlackWebhook, SlackNotification
from cerebro.integrations.slack import (
    SlackCommandError,
    SlackCommandService,
    SlackRequestParser,
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/slack", tags=["slack"])
limiter = Limiter(key_func=get_remote_address)


# ==================== Request/Response Models ====================

class SlackWebhookCreate(BaseModel):
    """Request model for creating a Slack webhook."""

    name: str = Field(..., min_length=1, max_length=255, description="Human-readable webhook name")
    webhook_url: HttpUrl = Field(..., description="Slack incoming webhook URL")
    channel: Optional[str] = Field(None, max_length=255, description="Slack channel (e.g., #security-alerts)")
    enabled: bool = Field(True, description="Whether webhook is enabled")
    severity_filter: Optional[List[str]] = Field(
        None,
        description="Filter by severity: critical, high, medium, low. If null, all severities",
    )
    finding_type_filter: Optional[List[str]] = Field(
        None,
        description="Filter by finding types. If null, all types",
    )
    event_types: List[str] = Field(
        ...,
        min_length=1,
        description="Event types: finding_created, finding_updated, compliance_failed, monitoring_alert",
    )


class SlackWebhookUpdate(BaseModel):
    """Request model for updating a Slack webhook."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    webhook_url: Optional[HttpUrl] = None
    channel: Optional[str] = Field(None, max_length=255)
    enabled: Optional[bool] = None
    severity_filter: Optional[List[str]] = None
    finding_type_filter: Optional[List[str]] = None
    event_types: Optional[List[str]] = None


class SlackWebhookResponse(BaseModel):
    """Response model for Slack webhook."""

    webhook_id: UUID
    org_id: UUID
    name: str
    webhook_url: str  # Masked in response
    channel: Optional[str]
    enabled: bool
    severity_filter: Optional[List[str]]
    finding_type_filter: Optional[List[str]]
    event_types: List[str]
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str]

    model_config = ConfigDict(from_attributes=True)


class SlackNotificationResponse(BaseModel):
    """Response model for Slack notification log."""

    notification_id: UUID
    webhook_id: UUID
    event_type: str
    finding_id: Optional[UUID]
    severity: Optional[str]
    status: str
    status_code: Optional[int]
    error_message: Optional[str]
    retry_count: int
    sent_at: Optional[datetime]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SlackNotificationStats(BaseModel):
    """Statistics for Slack notifications."""

    total_sent: int
    total_failed: int
    last_24h_sent: int
    last_24h_failed: int
    by_severity: dict
    by_event_type: dict


# ==================== Endpoints ====================

@router.post("/webhooks", response_model=SlackWebhookResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
async def create_slack_webhook(
    request: Request,
    webhook_data: SlackWebhookCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Create a new Slack webhook configuration.

    **Permissions:** Requires authenticated user with org access
    """
    try:
        # Validate event types
        valid_event_types = {
            "finding_created",
            "finding_updated",
            "compliance_failed",
            "monitoring_alert",
        }
        for event_type in webhook_data.event_types:
            if event_type not in valid_event_types:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid event type: {event_type}",
                )

        # Create webhook
        webhook = SlackWebhook(
            webhook_id=uuid4(),
            org_id=current_user.org_id,
            name=webhook_data.name,
            channel=webhook_data.channel,
            enabled=webhook_data.enabled,
            severity_filter=webhook_data.severity_filter,
            finding_type_filter=webhook_data.finding_type_filter,
            event_types=webhook_data.event_types,
            created_by=current_user.email,
        )

        # Encrypt webhook URL
        await webhook.set_webhook_url(str(webhook_data.webhook_url))

        db.add(webhook)
        await db.commit()
        await db.refresh(webhook)

        logger.info(
            "slack_webhook_created",
            webhook_id=str(webhook.webhook_id),
            org_id=str(current_user.org_id),
            name=webhook_data.name,
        )

        # Mask webhook URL in response
        response_webhook = SlackWebhookResponse.from_orm(webhook)
        response_webhook.webhook_url = _mask_url(webhook.webhook_url)

        return response_webhook

    except Exception as e:
        logger.error("create_slack_webhook_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create Slack webhook",
        )


@router.get("/webhooks", response_model=List[SlackWebhookResponse])
async def list_slack_webhooks(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List all Slack webhooks for the current organization.

    **Permissions:** Requires authenticated user
    """
    try:
        result = await db.execute(
            select(SlackWebhook)
            .where(SlackWebhook.org_id == current_user.org_id)
            .order_by(SlackWebhook.created_at.desc())
        )
        webhooks = result.scalars().all()

        # Mask webhook URLs
        response_webhooks = []
        for webhook in webhooks:
            response_webhook = SlackWebhookResponse.from_orm(webhook)
            response_webhook.webhook_url = _mask_url(webhook.webhook_url)
            response_webhooks.append(response_webhook)

        return response_webhooks

    except Exception as e:
        logger.error("list_slack_webhooks_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list Slack webhooks",
        )


@router.get("/webhooks/{webhook_id}", response_model=SlackWebhookResponse)
async def get_slack_webhook(
    webhook_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get a specific Slack webhook by ID.

    **Permissions:** Requires authenticated user with org access
    """
    try:
        result = await db.execute(
            select(SlackWebhook).where(
                SlackWebhook.webhook_id == webhook_id,
                SlackWebhook.org_id == current_user.org_id,
            )
        )
        webhook = result.scalar_one_or_none()

        if not webhook:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Slack webhook not found",
            )

        response_webhook = SlackWebhookResponse.from_orm(webhook)
        response_webhook.webhook_url = _mask_url(webhook.webhook_url)

        return response_webhook

    except HTTPException:
        raise
    except Exception as e:
        logger.error("get_slack_webhook_failed", webhook_id=str(webhook_id), error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get Slack webhook",
        )


@router.patch("/webhooks/{webhook_id}", response_model=SlackWebhookResponse)
async def update_slack_webhook(
    webhook_id: UUID,
    webhook_data: SlackWebhookUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Update a Slack webhook configuration.

    **Permissions:** Requires authenticated user with org access
    """
    try:
        result = await db.execute(
            select(SlackWebhook).where(
                SlackWebhook.webhook_id == webhook_id,
                SlackWebhook.org_id == current_user.org_id,
            )
        )
        webhook = result.scalar_one_or_none()

        if not webhook:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Slack webhook not found",
            )

        # Update fields
        if webhook_data.name is not None:
            webhook.name = webhook_data.name
        if webhook_data.webhook_url is not None:
            await webhook.set_webhook_url(str(webhook_data.webhook_url))
        if webhook_data.channel is not None:
            webhook.channel = webhook_data.channel
        if webhook_data.enabled is not None:
            webhook.enabled = webhook_data.enabled
        if webhook_data.severity_filter is not None:
            webhook.severity_filter = webhook_data.severity_filter
        if webhook_data.finding_type_filter is not None:
            webhook.finding_type_filter = webhook_data.finding_type_filter
        if webhook_data.event_types is not None:
            webhook.event_types = webhook_data.event_types

        webhook.updated_at = datetime.now(timezone.utc)

        await db.commit()
        await db.refresh(webhook)

        logger.info(
            "slack_webhook_updated",
            webhook_id=str(webhook_id),
            org_id=str(current_user.org_id),
        )

        response_webhook = SlackWebhookResponse.from_orm(webhook)
        response_webhook.webhook_url = _mask_url(webhook.webhook_url)

        return response_webhook

    except HTTPException:
        raise
    except Exception as e:
        logger.error("update_slack_webhook_failed", webhook_id=str(webhook_id), error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update Slack webhook",
        )


@router.delete("/webhooks/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_slack_webhook(
    webhook_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Delete a Slack webhook.

    **Permissions:** Requires authenticated user with org access
    """
    try:
        result = await db.execute(
            select(SlackWebhook).where(
                SlackWebhook.webhook_id == webhook_id,
                SlackWebhook.org_id == current_user.org_id,
            )
        )
        webhook = result.scalar_one_or_none()

        if not webhook:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Slack webhook not found",
            )

        await db.delete(webhook)
        await db.commit()

        logger.info(
            "slack_webhook_deleted",
            webhook_id=str(webhook_id),
            org_id=str(current_user.org_id),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("delete_slack_webhook_failed", webhook_id=str(webhook_id), error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete Slack webhook",
        )


@router.get("/notifications", response_model=List[SlackNotificationResponse])
async def list_slack_notifications(
    webhook_id: Optional[UUID] = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List Slack notification logs for the current organization.

    **Query Parameters:**
    - webhook_id: Filter by specific webhook (optional)
    - limit: Maximum number of results (default 50, max 200)

    **Permissions:** Requires authenticated user
    """
    try:
        limit = min(limit, 200)  # Cap at 200

        query = select(SlackNotification).where(
            SlackNotification.org_id == current_user.org_id
        )

        if webhook_id:
            query = query.where(SlackNotification.webhook_id == webhook_id)

        query = query.order_by(SlackNotification.created_at.desc()).limit(limit)

        result = await db.execute(query)
        notifications = result.scalars().all()

        return [SlackNotificationResponse.from_orm(n) for n in notifications]

    except Exception as e:
        logger.error("list_slack_notifications_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list Slack notifications",
        )


@router.post("/commands")
async def handle_slack_command(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Handle Slack slash command requests."""

    parser = SlackRequestParser(signing_secret=settings.slack_signing_secret)
    try:
        command = await parser.parse(request)
    except SlackCommandError as exc:
        logger.warning("slack_command_parse_failed", error=str(exc))
        return JSONResponse(
            status_code=200,
            content={"response_type": "ephemeral", "text": str(exc)},
        )

    service = SlackCommandService(default_org_id=settings.slack_default_org_id)
    try:
        response = await service.handle_command(command, db)
    except SlackCommandError as exc:
        logger.warning("slack_command_handle_failed", error=str(exc))
        return JSONResponse(
            status_code=200,
            content={"response_type": "ephemeral", "text": str(exc)},
        )
    except Exception as exc:  # pragma: no cover - unexpected error path
        logger.exception("slack_command_unhandled_exception", error=str(exc))
        return JSONResponse(
            status_code=200,
            content={
                "response_type": "ephemeral",
                "text": "We hit an unexpected error while processing your command. Please try again shortly.",
            },
        )

    return JSONResponse(status_code=200, content=response.to_dict())


@router.get("/notifications/stats", response_model=SlackNotificationStats)
async def get_slack_notification_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get statistics about Slack notifications.

    **Permissions:** Requires authenticated user
    """
    try:
        # Total sent and failed
        total_sent_result = await db.execute(
            select(func.count(SlackNotification.notification_id)).where(
                SlackNotification.org_id == current_user.org_id,
                SlackNotification.status == "sent",
            )
        )
        total_sent = total_sent_result.scalar() or 0

        total_failed_result = await db.execute(
            select(func.count(SlackNotification.notification_id)).where(
                SlackNotification.org_id == current_user.org_id,
                SlackNotification.status == "failed",
            )
        )
        total_failed = total_failed_result.scalar() or 0

        # Last 24 hours
        last_24h = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

        last_24h_sent_result = await db.execute(
            select(func.count(SlackNotification.notification_id)).where(
                SlackNotification.org_id == current_user.org_id,
                SlackNotification.status == "sent",
                SlackNotification.created_at >= last_24h,
            )
        )
        last_24h_sent = last_24h_sent_result.scalar() or 0

        last_24h_failed_result = await db.execute(
            select(func.count(SlackNotification.notification_id)).where(
                SlackNotification.org_id == current_user.org_id,
                SlackNotification.status == "failed",
                SlackNotification.created_at >= last_24h,
            )
        )
        last_24h_failed = last_24h_failed_result.scalar() or 0

        # Group by severity
        severity_query = select(
            SlackNotification.severity,
            func.count(SlackNotification.notification_id).label("count")
        ).where(
            SlackNotification.org_id == current_user.org_id,
            SlackNotification.status == "sent"
        ).group_by(SlackNotification.severity)

        severity_result = await db.execute(severity_query)
        by_severity = {row.severity: row.count for row in severity_result if row.severity}

        # Group by event type
        event_type_query = select(
            SlackNotification.event_type,
            func.count(SlackNotification.notification_id).label("count")
        ).where(
            SlackNotification.org_id == current_user.org_id,
            SlackNotification.status == "sent"
        ).group_by(SlackNotification.event_type)

        event_type_result = await db.execute(event_type_query)
        by_event_type = {row.event_type: row.count for row in event_type_result}

        return SlackNotificationStats(
            total_sent=total_sent,
            total_failed=total_failed,
            last_24h_sent=last_24h_sent,
            last_24h_failed=last_24h_failed,
            by_severity=by_severity,
            by_event_type=by_event_type,
        )

    except Exception as e:
        logger.error("get_slack_notification_stats_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get Slack notification stats",
        )


# ==================== Helper Functions ====================

def _mask_url(url: str) -> str:
    """Mask webhook URL for security (show only last 8 chars)."""
    if len(url) <= 8:
        return "*" * len(url)
    return "*" * (len(url) - 8) + url[-8:]