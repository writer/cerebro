"""API endpoints for email notification configuration and management."""
import logging
from datetime import datetime
from typing import List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, EmailStr, Field, validator
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.api.auth import User, get_current_user
from cerebro.core.database import get_db
from cerebro.core.models import EmailConfig, EmailNotification
from cerebro.notifications.email import get_email_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/email", tags=["Email Notifications"])
limiter = Limiter(key_func=get_remote_address)


# Pydantic models for API
class EmailConfigCreate(BaseModel):
    """Request model for creating email configuration."""

    name: str = Field(..., min_length=1, max_length=255, description="Human-readable name")
    smtp_host: str = Field(..., min_length=1, max_length=255, description="SMTP server host")
    smtp_port: int = Field(default=587, ge=1, le=65535, description="SMTP server port")
    smtp_username: Optional[str] = Field(None, max_length=255, description="SMTP username")
    smtp_password: Optional[str] = Field(None, description="SMTP password (encrypted)")
    from_email: EmailStr = Field(..., description="Sender email address")
    from_name: Optional[str] = Field(None, max_length=255, description="Sender display name")
    to_emails: List[EmailStr] = Field(..., min_items=1, description="List of recipient emails")
    cc_emails: Optional[List[EmailStr]] = Field(None, description="CC recipient emails")
    use_tls: bool = Field(default=True, description="Use TLS for SMTP connection")
    enabled: bool = Field(default=True, description="Enable this email config")
    severity_filter: Optional[List[str]] = Field(
        None, description="Filter by severity (critical, high, medium, low)"
    )
    event_types: List[str] = Field(
        ..., min_items=1, description="Event types to send (finding.created, compliance.check_failed, etc.)"
    )
    digest_mode: bool = Field(default=False, description="Send digest instead of immediate")
    digest_frequency: Optional[str] = Field(
        None, description="Digest frequency (daily, weekly) if digest_mode=true"
    )
    email_metadata: Optional[dict] = Field(None, description="Additional configuration metadata")

    @validator("digest_frequency")
    def validate_digest_frequency(cls, v, values):
        """Validate digest_frequency is set when digest_mode is true."""
        if values.get("digest_mode") and not v:
            raise ValueError("digest_frequency is required when digest_mode is true")
        if v and v not in ["daily", "weekly"]:
            raise ValueError("digest_frequency must be 'daily' or 'weekly'")
        return v


class EmailConfigUpdate(BaseModel):
    """Request model for updating email configuration."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    smtp_host: Optional[str] = Field(None, min_length=1, max_length=255)
    smtp_port: Optional[int] = Field(None, ge=1, le=65535)
    smtp_username: Optional[str] = Field(None, max_length=255)
    smtp_password: Optional[str] = Field(None)
    from_email: Optional[EmailStr] = None
    from_name: Optional[str] = Field(None, max_length=255)
    to_emails: Optional[List[EmailStr]] = Field(None, min_items=1)
    cc_emails: Optional[List[EmailStr]] = None
    use_tls: Optional[bool] = None
    enabled: Optional[bool] = None
    severity_filter: Optional[List[str]] = None
    event_types: Optional[List[str]] = Field(None, min_items=1)
    digest_mode: Optional[bool] = None
    digest_frequency: Optional[str] = None
    email_metadata: Optional[dict] = None

    @validator("digest_frequency")
    def validate_digest_frequency(cls, v, values):
        """Validate digest_frequency is set when digest_mode is true."""
        if values.get("digest_mode") and not v:
            raise ValueError("digest_frequency is required when digest_mode is true")
        if v and v not in ["daily", "weekly"]:
            raise ValueError("digest_frequency must be 'daily' or 'weekly'")
        return v


class EmailConfigResponse(BaseModel):
    """Response model for email configuration."""

    config_id: UUID
    org_id: UUID
    name: str
    smtp_host: str
    smtp_port: int
    smtp_username: Optional[str]
    smtp_password: Optional[str]  # Masked
    from_email: str
    from_name: Optional[str]
    to_emails: List[str]
    cc_emails: Optional[List[str]]
    use_tls: bool
    enabled: bool
    severity_filter: Optional[List[str]]
    event_types: List[str]
    digest_mode: bool
    digest_frequency: Optional[str]
    email_metadata: Optional[dict]
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str]

    class Config:
        from_attributes = True


class EmailNotificationResponse(BaseModel):
    """Response model for email notification."""

    notification_id: UUID
    config_id: UUID
    org_id: UUID
    event_type: str
    finding_id: Optional[UUID]
    severity: Optional[str]
    subject: str
    to_emails: List[str]
    status: str
    status_code: Optional[int]
    error_message: Optional[str]
    retry_count: int
    sent_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class EmailNotificationStatsResponse(BaseModel):
    """Response model for email notification statistics."""

    total_sent: int
    total_failed: int
    total_retrying: int
    success_rate: float


@router.post("/configs", response_model=EmailConfigResponse, status_code=201)
@limiter.limit("10/minute")
async def create_email_config(
    request: Request,
    config_data: EmailConfigCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new email notification configuration.

    Args:
        config_data: Email configuration data
        db: Database session
        current_user: Authenticated user

    Returns:
        Created email configuration
    """
    # Create email config
    email_config = EmailConfig(
        config_id=uuid4(),
        org_id=current_user.org_id,
        name=config_data.name,
        smtp_host=config_data.smtp_host,
        smtp_port=config_data.smtp_port,
        smtp_username=config_data.smtp_username,
        from_email=config_data.from_email,
        from_name=config_data.from_name,
        to_emails=config_data.to_emails,
        cc_emails=config_data.cc_emails,
        use_tls=config_data.use_tls,
        enabled=config_data.enabled,
        severity_filter=config_data.severity_filter,
        event_types=config_data.event_types,
        digest_mode=config_data.digest_mode,
        digest_frequency=config_data.digest_frequency,
        email_metadata=config_data.email_metadata,
        created_by=current_user.username,
    )

    # Encrypt password if provided
    if config_data.smtp_password:
        await email_config.set_smtp_password(config_data.smtp_password)

    db.add(email_config)
    await db.commit()
    await db.refresh(email_config)

    # Mask password in response
    response_config = EmailConfigResponse.from_orm(email_config)
    if response_config.smtp_password:
        response_config.smtp_password = "********"

    logger.info(f"Created email config {email_config.config_id} for org {current_user.org_id}")
    return response_config


@router.get("/configs", response_model=List[EmailConfigResponse])
async def list_email_configs(
    enabled: Optional[bool] = Query(None, description="Filter by enabled status"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all email configurations for the current organization.

    Args:
        enabled: Optional filter by enabled status
        db: Database session
        current_user: Authenticated user

    Returns:
        List of email configurations
    """
    query = select(EmailConfig).where(EmailConfig.org_id == current_user.org_id)

    if enabled is not None:
        query = query.where(EmailConfig.enabled == enabled)

    result = await db.execute(query.order_by(EmailConfig.created_at.desc()))
    configs = result.scalars().all()

    # Mask passwords in response
    response_configs = [EmailConfigResponse.from_orm(config) for config in configs]
    for response_config in response_configs:
        if response_config.smtp_password:
            response_config.smtp_password = "********"

    return response_configs


@router.get("/configs/{config_id}", response_model=EmailConfigResponse)
async def get_email_config(
    config_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a specific email configuration.

    Args:
        config_id: Email configuration ID
        db: Database session
        current_user: Authenticated user

    Returns:
        Email configuration
    """
    result = await db.execute(
        select(EmailConfig).where(
            EmailConfig.config_id == config_id,
            EmailConfig.org_id == current_user.org_id,
        )
    )
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(status_code=404, detail="Email configuration not found")

    # Mask password in response
    response_config = EmailConfigResponse.from_orm(config)
    if response_config.smtp_password:
        response_config.smtp_password = "********"

    return response_config


@router.patch("/configs/{config_id}", response_model=EmailConfigResponse)
async def update_email_config(
    config_id: UUID,
    update_data: EmailConfigUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update an email configuration.

    Args:
        config_id: Email configuration ID
        update_data: Fields to update
        db: Database session
        current_user: Authenticated user

    Returns:
        Updated email configuration
    """
    result = await db.execute(
        select(EmailConfig).where(
            EmailConfig.config_id == config_id,
            EmailConfig.org_id == current_user.org_id,
        )
    )
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(status_code=404, detail="Email configuration not found")

    # Update fields
    update_dict = update_data.dict(exclude_unset=True)

    # Validate digest configuration before applying updates
    final_digest_mode = update_dict.get("digest_mode", config.digest_mode)
    final_digest_frequency = update_dict.get("digest_frequency", config.digest_frequency)

    if final_digest_mode and not final_digest_frequency:
        raise HTTPException(
            status_code=400,
            detail="digest_frequency is required when digest_mode is true"
        )

    # Handle password encryption separately
    smtp_password = update_dict.pop("smtp_password", None)

    for field, value in update_dict.items():
        setattr(config, field, value)

    # Encrypt password if provided
    if smtp_password is not None:
        await config.set_smtp_password(smtp_password)

    config.updated_at = datetime.utcnow()

    await db.commit()
    await db.refresh(config)

    # Mask password in response
    response_config = EmailConfigResponse.from_orm(config)
    if response_config.smtp_password:
        response_config.smtp_password = "********"

    logger.info(f"Updated email config {config_id}")
    return response_config


@router.delete("/configs/{config_id}", status_code=204)
async def delete_email_config(
    config_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete an email configuration.

    Args:
        config_id: Email configuration ID
        db: Database session
        current_user: Authenticated user
    """
    result = await db.execute(
        select(EmailConfig).where(
            EmailConfig.config_id == config_id,
            EmailConfig.org_id == current_user.org_id,
        )
    )
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(status_code=404, detail="Email configuration not found")

    await db.delete(config)
    await db.commit()

    logger.info(f"Deleted email config {config_id}")


@router.post("/test/{config_id}", status_code=200)
async def test_email_config(
    config_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Send a test email using the specified configuration.

    Args:
        config_id: Email configuration ID
        db: Database session
        current_user: Authenticated user

    Returns:
        Success message
    """
    result = await db.execute(
        select(EmailConfig).where(
            EmailConfig.config_id == config_id,
            EmailConfig.org_id == current_user.org_id,
        )
    )
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(status_code=404, detail="Email configuration not found")

    try:
        email_service = get_email_service()

        # Send test email
        test_subject = "Cerebro Test Email"
        test_html = f"""
        <html>
        <body>
            <h1>Test Email from Cerebro</h1>
            <p>This is a test email to verify your email configuration.</p>
            <p><strong>Configuration:</strong> {config.name}</p>
            <p><strong>Sent at:</strong> {datetime.utcnow().isoformat()}</p>
        </body>
        </html>
        """

        email_service._send_smtp_email(config, test_subject, test_html)

        return {"message": "Test email sent successfully"}

    except Exception as e:
        logger.error(f"Failed to send test email: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to send test email: {str(e)}")


@router.get("/notifications", response_model=List[EmailNotificationResponse])
async def list_email_notifications(
    config_id: Optional[UUID] = Query(None, description="Filter by config ID"),
    status: Optional[str] = Query(None, description="Filter by status (sent, failed, retrying)"),
    limit: int = Query(100, ge=1, le=1000, description="Number of notifications to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List email notifications for the current organization.

    Args:
        config_id: Optional filter by configuration ID
        status: Optional filter by status
        limit: Maximum number of results
        offset: Pagination offset
        db: Database session
        current_user: Authenticated user

    Returns:
        List of email notifications
    """
    query = select(EmailNotification).where(EmailNotification.org_id == current_user.org_id)

    if config_id:
        query = query.where(EmailNotification.config_id == config_id)

    if status:
        query = query.where(EmailNotification.status == status)

    result = await db.execute(
        query.order_by(EmailNotification.created_at.desc()).limit(limit).offset(offset)
    )
    notifications = result.scalars().all()

    return [EmailNotificationResponse.from_orm(notif) for notif in notifications]


@router.get("/notifications/stats", response_model=EmailNotificationStatsResponse)
async def get_email_notification_stats(
    config_id: Optional[UUID] = Query(None, description="Filter by config ID"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get email notification statistics for the current organization.

    Args:
        config_id: Optional filter by configuration ID
        db: Database session
        current_user: Authenticated user

    Returns:
        Email notification statistics
    """
    query = select(
        func.count(EmailNotification.notification_id).label("total"),
        func.sum(func.cast(EmailNotification.status == "sent", sa.Integer)).label("sent"),
        func.sum(func.cast(EmailNotification.status == "failed", sa.Integer)).label("failed"),
        func.sum(func.cast(EmailNotification.status == "retrying", sa.Integer)).label("retrying"),
    ).where(EmailNotification.org_id == current_user.org_id)

    if config_id:
        query = query.where(EmailNotification.config_id == config_id)

    result = await db.execute(query)
    row = result.one()

    total_sent = row.sent or 0
    total_failed = row.failed or 0
    total_retrying = row.retrying or 0
    total = row.total or 0

    success_rate = (total_sent / total * 100) if total > 0 else 0.0

    return EmailNotificationStatsResponse(
        total_sent=total_sent,
        total_failed=total_failed,
        total_retrying=total_retrying,
        success_rate=round(success_rate, 2),
    )