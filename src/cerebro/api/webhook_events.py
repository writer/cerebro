"""Webhook event definitions and schemas for Cerebro API.

This module defines all webhook event types and their payload schemas.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class WebhookEventType(str, Enum):
    """Available webhook event types."""

    # Finding events
    FINDING_CREATED = "finding.created"
    FINDING_UPDATED = "finding.updated"
    FINDING_RESOLVED = "finding.resolved"
    FINDING_SUPPRESSED = "finding.suppressed"
    FINDING_RISK_ACCEPTED = "finding.risk_accepted"
    FINDING_SEVERITY_CHANGED = "finding.severity_changed"

    # Resource events
    RESOURCE_DISCOVERED = "resource.discovered"
    RESOURCE_UPDATED = "resource.updated"
    RESOURCE_DELETED = "resource.deleted"

    # Compliance events
    COMPLIANCE_CHECK_COMPLETED = "compliance.check_completed"
    COMPLIANCE_VIOLATION = "compliance.violation"
    COMPLIANCE_REMEDIATED = "compliance.remediated"

    # Integration events
    INTEGRATION_SYNC_STARTED = "integration.sync_started"
    INTEGRATION_SYNC_COMPLETED = "integration.sync_completed"
    INTEGRATION_SYNC_FAILED = "integration.sync_failed"
    INTEGRATION_CONNECTED = "integration.connected"
    INTEGRATION_DISCONNECTED = "integration.disconnected"

    # Agent events
    AGENT_SESSION_STARTED = "agent.session_started"
    AGENT_SESSION_COMPLETED = "agent.session_completed"
    AGENT_ACTION_REQUIRED = "agent.action_required"
    AGENT_ACTION_COMPLETED = "agent.action_completed"

    # Alert events
    ALERT_TRIGGERED = "alert.triggered"
    ALERT_RESOLVED = "alert.resolved"
    ALERT_ESCALATED = "alert.escalated"

    # User events
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    USER_LOGIN = "user.login"
    USER_LOGIN_FAILED = "user.login_failed"

    # API key events
    API_KEY_CREATED = "api_key.created"
    API_KEY_REVOKED = "api_key.revoked"
    API_KEY_EXPIRED = "api_key.expired"

    # Organization events
    ORGANIZATION_CREATED = "organization.created"
    ORGANIZATION_UPDATED = "organization.updated"

    # Test event (for webhook verification)
    TEST = "test"


class WebhookEvent(BaseModel):
    """Base webhook event envelope."""

    id: str = Field(..., description="Unique event ID")
    type: WebhookEventType = Field(..., description="Event type")
    api_version: str = Field(default="1.0", description="API version")
    created_at: datetime = Field(..., description="Event timestamp")
    org_id: UUID = Field(..., description="Organization ID")
    data: dict[str, Any] = Field(..., description="Event-specific payload")
    metadata: dict[str, Any] | None = Field(None, description="Additional metadata")


# Event-specific payload schemas


class FindingEventData(BaseModel):
    """Payload for finding events."""

    finding_id: UUID
    title: str
    severity: str
    status: str
    provider: str
    rule_id: UUID | None = None
    resource_id: UUID | None = None
    resource_type: str | None = None
    previous_status: str | None = None
    previous_severity: str | None = None
    changed_by: UUID | None = None
    change_reason: str | None = None


class ResourceEventData(BaseModel):
    """Payload for resource events."""

    resource_id: UUID
    resource_type: str
    provider: str
    account_id: UUID | None = None
    name: str | None = None
    arn: str | None = None
    tags: dict[str, str] | None = None
    changes: dict[str, Any] | None = None


class ComplianceEventData(BaseModel):
    """Payload for compliance events."""

    framework: str
    control_id: str
    status: str
    score: float | None = None
    evidence_count: int | None = None
    resource_ids: list[UUID] | None = None
    finding_ids: list[UUID] | None = None


class IntegrationEventData(BaseModel):
    """Payload for integration events."""

    integration_type: str
    integration_id: UUID | None = None
    account_id: UUID | None = None
    status: str
    resources_synced: int | None = None
    findings_created: int | None = None
    error_message: str | None = None
    duration_seconds: float | None = None


class AgentEventData(BaseModel):
    """Payload for agent events."""

    session_id: UUID
    agent_type: str | None = None
    action_type: str | None = None
    action_id: UUID | None = None
    status: str
    summary: str | None = None
    requires_approval: bool = False
    finding_ids: list[UUID] | None = None


class AlertEventData(BaseModel):
    """Payload for alert events."""

    alert_id: UUID
    alert_type: str
    severity: str
    title: str
    description: str | None = None
    source: str
    threshold: float | None = None
    current_value: float | None = None
    escalation_level: int | None = None


class UserEventData(BaseModel):
    """Payload for user events."""

    user_id: UUID
    username: str
    email: str | None = None
    action: str
    ip_address: str | None = None
    user_agent: str | None = None
    changes: dict[str, Any] | None = None


class APIKeyEventData(BaseModel):
    """Payload for API key events."""

    key_id: UUID
    key_name: str
    key_prefix: str
    scopes: list[str]
    created_by: UUID | None = None
    revoked_by: UUID | None = None
    expiration_reason: str | None = None


class TestEventData(BaseModel):
    """Payload for test webhook events."""

    message: str = "This is a test webhook event"
    timestamp: datetime


# Event type to payload schema mapping
EVENT_PAYLOAD_SCHEMAS = {
    WebhookEventType.FINDING_CREATED: FindingEventData,
    WebhookEventType.FINDING_UPDATED: FindingEventData,
    WebhookEventType.FINDING_RESOLVED: FindingEventData,
    WebhookEventType.FINDING_SUPPRESSED: FindingEventData,
    WebhookEventType.FINDING_RISK_ACCEPTED: FindingEventData,
    WebhookEventType.FINDING_SEVERITY_CHANGED: FindingEventData,
    WebhookEventType.RESOURCE_DISCOVERED: ResourceEventData,
    WebhookEventType.RESOURCE_UPDATED: ResourceEventData,
    WebhookEventType.RESOURCE_DELETED: ResourceEventData,
    WebhookEventType.COMPLIANCE_CHECK_COMPLETED: ComplianceEventData,
    WebhookEventType.COMPLIANCE_VIOLATION: ComplianceEventData,
    WebhookEventType.COMPLIANCE_REMEDIATED: ComplianceEventData,
    WebhookEventType.INTEGRATION_SYNC_STARTED: IntegrationEventData,
    WebhookEventType.INTEGRATION_SYNC_COMPLETED: IntegrationEventData,
    WebhookEventType.INTEGRATION_SYNC_FAILED: IntegrationEventData,
    WebhookEventType.INTEGRATION_CONNECTED: IntegrationEventData,
    WebhookEventType.INTEGRATION_DISCONNECTED: IntegrationEventData,
    WebhookEventType.AGENT_SESSION_STARTED: AgentEventData,
    WebhookEventType.AGENT_SESSION_COMPLETED: AgentEventData,
    WebhookEventType.AGENT_ACTION_REQUIRED: AgentEventData,
    WebhookEventType.AGENT_ACTION_COMPLETED: AgentEventData,
    WebhookEventType.ALERT_TRIGGERED: AlertEventData,
    WebhookEventType.ALERT_RESOLVED: AlertEventData,
    WebhookEventType.ALERT_ESCALATED: AlertEventData,
    WebhookEventType.USER_CREATED: UserEventData,
    WebhookEventType.USER_UPDATED: UserEventData,
    WebhookEventType.USER_DELETED: UserEventData,
    WebhookEventType.USER_LOGIN: UserEventData,
    WebhookEventType.USER_LOGIN_FAILED: UserEventData,
    WebhookEventType.API_KEY_CREATED: APIKeyEventData,
    WebhookEventType.API_KEY_REVOKED: APIKeyEventData,
    WebhookEventType.API_KEY_EXPIRED: APIKeyEventData,
    WebhookEventType.TEST: TestEventData,
}


# Event categories for filtering
EVENT_CATEGORIES = {
    "findings": [
        WebhookEventType.FINDING_CREATED,
        WebhookEventType.FINDING_UPDATED,
        WebhookEventType.FINDING_RESOLVED,
        WebhookEventType.FINDING_SUPPRESSED,
        WebhookEventType.FINDING_RISK_ACCEPTED,
        WebhookEventType.FINDING_SEVERITY_CHANGED,
    ],
    "resources": [
        WebhookEventType.RESOURCE_DISCOVERED,
        WebhookEventType.RESOURCE_UPDATED,
        WebhookEventType.RESOURCE_DELETED,
    ],
    "compliance": [
        WebhookEventType.COMPLIANCE_CHECK_COMPLETED,
        WebhookEventType.COMPLIANCE_VIOLATION,
        WebhookEventType.COMPLIANCE_REMEDIATED,
    ],
    "integrations": [
        WebhookEventType.INTEGRATION_SYNC_STARTED,
        WebhookEventType.INTEGRATION_SYNC_COMPLETED,
        WebhookEventType.INTEGRATION_SYNC_FAILED,
        WebhookEventType.INTEGRATION_CONNECTED,
        WebhookEventType.INTEGRATION_DISCONNECTED,
    ],
    "agents": [
        WebhookEventType.AGENT_SESSION_STARTED,
        WebhookEventType.AGENT_SESSION_COMPLETED,
        WebhookEventType.AGENT_ACTION_REQUIRED,
        WebhookEventType.AGENT_ACTION_COMPLETED,
    ],
    "alerts": [
        WebhookEventType.ALERT_TRIGGERED,
        WebhookEventType.ALERT_RESOLVED,
        WebhookEventType.ALERT_ESCALATED,
    ],
    "users": [
        WebhookEventType.USER_CREATED,
        WebhookEventType.USER_UPDATED,
        WebhookEventType.USER_DELETED,
        WebhookEventType.USER_LOGIN,
        WebhookEventType.USER_LOGIN_FAILED,
    ],
    "api_keys": [
        WebhookEventType.API_KEY_CREATED,
        WebhookEventType.API_KEY_REVOKED,
        WebhookEventType.API_KEY_EXPIRED,
    ],
}


def get_event_schema(event_type: WebhookEventType) -> type[BaseModel]:
    """Get the payload schema class for an event type."""
    return EVENT_PAYLOAD_SCHEMAS.get(event_type, BaseModel)


def get_all_event_types() -> list[dict]:
    """Get documentation for all event types."""
    return [
        {
            "type": event_type.value,
            "category": next(
                (cat for cat, types in EVENT_CATEGORIES.items() if event_type in types),
                "other",
            ),
            "payload_schema": EVENT_PAYLOAD_SCHEMAS.get(event_type, BaseModel).__name__,
        }
        for event_type in WebhookEventType
    ]
