"""Shared dataclasses and error types for the SDK agent facades."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID


class AgentSDKError(Exception):
    """Base exception raised by the Cerebro SDK agent facades."""


class AgentNotFoundError(AgentSDKError):
    """Raised when a requested agent resource cannot be located."""


class AgentInvalidStatusError(AgentSDKError):
    """Raised when an invalid status transition or value is requested."""


class AgentValidationError(AgentSDKError):
    """Raised when user input cannot be coerced into the expected type."""


@dataclass
class AgentSessionRecord:
    session_id: UUID
    org_id: UUID
    agent_type: str
    created_at: datetime
    created_by: str
    title: str | None
    is_active: bool
    context: dict[str, Any]


@dataclass
class AgentMessageRecord:
    message_id: UUID
    session_id: UUID
    role: str
    content: dict[str, Any]
    created_at: datetime


@dataclass
class AgentMemoryRecord:
    entry_id: UUID
    session_id: UUID | None
    role: str | None
    summary: str | None
    decay_score: float
    last_accessed_at: datetime
    created_at: datetime
    scopes: list[dict[str, Any]]
    scope_labels: list[str]
    metadata: dict[str, Any]
    token_count: int
    content: str | None


@dataclass
class AgentMemoryStats:
    total_entries: int
    recent_entries: int
    presented_entries: int
    average_decay: float
    token_total: int
    role_distribution: dict[str, int]
    scope_distribution: dict[str, int]
    top_memories: list[dict[str, Any]]


@dataclass
class AgentReviewTaskRecord:
    task_id: UUID
    session_id: UUID
    org_id: UUID
    status: str
    title: str
    summary: str | None
    payload: dict[str, Any]
    promotion_target: str | None
    priority: str | None
    due_at: datetime | None
    escalated_to: str | None
    notification_channel: str | None
    ticket_reference: str | None
    created_by: str
    created_at: datetime
    resolved_by: str | None
    resolved_at: datetime | None
    resolution_notes: str | None
    assigned_to: str | None


@dataclass
class AgentReviewCommentRecord:
    comment_id: UUID
    task_id: UUID
    author: str
    content: str
    created_at: datetime
    metadata: dict[str, Any]


@dataclass
class AgentReviewHistoryRecord:
    history_id: UUID
    task_id: UUID
    changed_by: str
    change_type: str
    field_name: str | None
    old_value: dict[str, Any] | None
    new_value: dict[str, Any] | None
    created_at: datetime
    metadata: dict[str, Any]


@dataclass
class AgentEventRecord:
    event_id: UUID
    session_id: UUID
    event_type: str
    payload: dict[str, Any]
    created_at: datetime


@dataclass
class AgentEventSummary:
    event_type: str
    event_count: int
    first_seen: datetime | None
    last_seen: datetime | None


@dataclass
class AgentAnalyticsSummary:
    total_sessions: int
    active_sessions: int
    message_count: int
    event_count: int
    skill_tag_counts: dict[str, int]
    agent_type_counts: dict[str, int]


@dataclass
class ToolInvocationRecord:
    invocation_id: UUID
    session_id: UUID
    tool_name: str
    tool_version: str
    status: str
    started_at: datetime
    completed_at: datetime | None
    input_data: dict[str, Any]
    output_data: dict[str, Any] | None
    error_message: str | None
    error_code: str | None
    cel_policy_key: str | None
    cel_expression: str | None
    cel_result: bool | None
    cel_context: dict[str, Any] | None


@dataclass
class ToolApprovalRecord:
    approval_id: UUID
    org_id: UUID
    tool_invocation_id: UUID
    requested_by: str
    requested_at: datetime
    reason: str
    status: str
    decided_by: str | None
    decided_at: datetime | None
    decision_reason: str | None
    expires_at: datetime | None
    risk_assessment: dict[str, Any]


@dataclass
class AgentPolicySuggestionRecord:
    suggestion_id: UUID
    org_id: UUID
    tool_name: str
    cel_expression: str
    support_count: int
    reject_count: int
    details: dict[str, Any]
    last_seen: datetime
    created_at: datetime


@dataclass
class ToolInvocationSummary:
    tool_name: str
    status: str
    count: int


@dataclass
class AgentReviewExportRecord:
    task: AgentReviewTaskRecord
    comments: list[AgentReviewCommentRecord]
    history: list[AgentReviewHistoryRecord]


@dataclass
class AgentReviewStatusAggregate:
    status: str
    count: int
    unassigned: int
    overdue: int
    oldest_created: datetime | None
    newest_created: datetime | None


@dataclass
class AgentReviewPendingSummary:
    total: int
    unassigned: int
    overdue: int
    next_due: datetime | None
    oldest_created: datetime | None


@dataclass
class AgentReviewPriorityBucket:
    priority: str | None
    count: int


@dataclass
class AgentReviewQueueSummary:
    generated_at: datetime
    status_counts: list[AgentReviewStatusAggregate]
    pending: AgentReviewPendingSummary
    priority_breakdown: list[AgentReviewPriorityBucket]


@dataclass
class AgentNotificationRecord:
    notification_id: UUID
    task_id: UUID
    org_id: UUID
    channel: str
    status: str
    payload: dict[str, Any]
    created_at: datetime
    delivered_at: datetime | None


@dataclass
class AgentTicketRecord:
    ticket_id: UUID
    task_id: UUID
    org_id: UUID
    system: str
    status: str
    details: dict[str, Any]
    external_id: str | None
    created_at: datetime
    updated_at: datetime | None
