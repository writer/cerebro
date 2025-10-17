"""
SQLAlchemy models for Cerebro agents.

These models support the append-only, auditable architecture of Cerebro by tracking
all agent sessions, messages, tool invocations, and approval workflows.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    Enum as SqlEnum,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from cerebro.core.database_types import JSONType
from cerebro.core.models import Organization


class Base(DeclarativeBase):
    """Base class for all Cerebro agent models."""
    pass


class AgentType(str, Enum):
    """Types of security agents available in Cerebro."""
    SECURITY_ANALYST = "security_analyst"
    INCIDENT_RESPONDER = "incident_responder" 
    IDENTITY_ADVISOR = "identity_advisor"
    COMPLIANCE_ADVISOR = "compliance_advisor"
    ATTACK_PATH_ANALYST = "attack_path_analyst"


class MessageRole(str, Enum):
    """Role types for agent messages."""
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"
    SYSTEM = "system"


class ToolInvocationStatus(str, Enum):
    """Status of tool invocations."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    ERROR = "error"
    DRY_RUN = "dry_run"
    APPROVAL_REQUIRED = "approval_required"


class ApprovalStatus(str, Enum):
    """Status of approval requests."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class MemoryScope(str, Enum):
    """Scope levels for long-term agent memory."""

    ORGANIZATION = "organization"
    INCIDENT = "incident"
    FINDING = "finding"
    SESSION = "session"


class AgentSession(Base):
    """
    Represents an agent conversation session.
    
    Sessions are scoped to an organization and maintain context about the
    security scope (findings, incidents, etc.) that the agent is working with.
    """
    __tablename__ = "agent_sessions"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=func.gen_random_uuid(),
    )
    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(Organization.__table__.c.org_id),
        nullable=False,
        index=True,
    )
    agent_type: Mapped[AgentType] = mapped_column(SqlEnum(AgentType), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    context: Mapped[Dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    
    # Context may include:
    # - finding_ids: List[UUID] - findings being analyzed
    # - incident_id: UUID - incident being investigated  
    # - provider_scope: List[str] - providers to focus on
    # - time_window: dict - temporal analysis window
    # - compliance_frameworks: List[str] - frameworks to map to
    
    # Relationships
    messages: Mapped[list["AgentMessage"]] = relationship(
        "AgentMessage",
        back_populates="session",
        order_by="AgentMessage.created_at",
    )
    tool_invocations: Mapped[list["ToolInvocation"]] = relationship(
        "ToolInvocation",
        back_populates="session",
    )
    memory_entries: Mapped[list["AgentMemoryEntry"]] = relationship(
        "AgentMemoryEntry",
        back_populates="session",
        order_by="AgentMemoryEntry.created_at",
        cascade="all, delete-orphan",
    )
    conversation_items: Mapped[list["AgentConversationItem"]] = relationship(
        "AgentConversationItem",
        back_populates="session",
        order_by="AgentConversationItem.created_at",
        cascade="all, delete-orphan",
    )


class AgentMessage(Base):
    """
    Individual messages in an agent conversation.
    
    Messages are append-only and maintain the complete conversation history
    including tool calls, results, and assistant responses.
    """
    __tablename__ = "agent_messages"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=func.gen_random_uuid(),
    )
    session_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("agent_sessions.id"),
        nullable=False,
        index=True,
    )
    role: Mapped[MessageRole] = mapped_column(SqlEnum(MessageRole), nullable=False)
    content: Mapped[Dict[str, Any]] = mapped_column(JSONType, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )
    
    # Content structure varies by role:
    # - user/assistant: {"text": str, "attachments": [...]}
    # - tool: {"tool_name": str, "input": {...}, "output": {...}}
    # - system: {"instruction": str, "metadata": {...}}
    
    # Token usage tracking
    input_tokens: Mapped[Optional[int]] = mapped_column(nullable=True)
    output_tokens: Mapped[Optional[int]] = mapped_column(nullable=True)
    
    # Relationships
    session: Mapped["AgentSession"] = relationship("AgentSession", back_populates="messages")


class AgentConversationItem(Base):
    """Raw conversation items stored for agent session memory systems."""

    __tablename__ = "agent_conversation_items"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=func.gen_random_uuid(),
    )
    session_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("agent_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    item: Mapped[Dict[str, Any]] = mapped_column(JSONType, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    session: Mapped["AgentSession"] = relationship(
        "AgentSession",
        back_populates="conversation_items",
    )


class AgentMemoryEntry(Base):
    """Learned facts, summaries, and embeddings for long-term recall."""

    __tablename__ = "agent_memory_entries"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=func.gen_random_uuid(),
    )
    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(Organization.__table__.c.org_id, ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    session_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("agent_sessions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    agent_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    role: Mapped[Optional[MessageRole]] = mapped_column(SqlEnum(MessageRole), nullable=True)
    scopes: Mapped[List[Dict[str, Any]]] = mapped_column(JSONType, nullable=False, default=list)
    scope_priority: Mapped[int] = mapped_column(
        nullable=False,
        default=0,
        comment="Lower values indicate broader relevance (organization=0, session=2, etc.)",
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    content_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    token_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    embedding: Mapped[Optional[List[float]]] = mapped_column(JSONType, nullable=True)
    embedding_norm: Mapped[Optional[float]] = mapped_column(nullable=True)
    extra_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType, nullable=True, default=dict)
    decay_score: Mapped[float] = mapped_column(nullable=False, default=1.0)
    last_accessed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    session: Mapped[Optional["AgentSession"]] = relationship(
        "AgentSession",
        back_populates="memory_entries",
    )


class ToolInvocation(Base):
    """
    Detailed tracking of tool invocations by agents.
    
    This provides a detailed audit trail of all tool calls, their inputs/outputs,
    CEL policy evaluations, and approval workflows.
    """
    __tablename__ = "tool_invocations"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=func.gen_random_uuid(),
    )
    session_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("agent_sessions.id"),
        nullable=False,
        index=True,
    )
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    tool_version: Mapped[str] = mapped_column(String(20), nullable=False, default="1.0")
    
    # Tool execution details
    input_data: Mapped[Dict[str, Any]] = mapped_column(JSONType, nullable=False)
    output_data: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType, nullable=True)
    status: Mapped[ToolInvocationStatus] = mapped_column(
        SqlEnum(ToolInvocationStatus),
        nullable=False,
        default=ToolInvocationStatus.PENDING,
        index=True,
    )
    
    # Timing
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    
    # CEL policy enforcement
    cel_policy_key: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    cel_expression: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cel_result: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    cel_context: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType, nullable=True)
    
    # Error handling
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_code: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    
    # Celery task tracking (for async operations)
    celery_task_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    
    # Relationships
    session: Mapped["AgentSession"] = relationship("AgentSession", back_populates="tool_invocations")
    approval: Mapped[Optional["ToolApproval"]] = relationship(
        "ToolApproval",
        back_populates="tool_invocation",
        uselist=False,
    )


class ToolApproval(Base):
    """
    Human-in-the-loop approval workflow for potentially destructive tool actions.
    
    Certain tool invocations require human approval before execution, especially
    those that modify production systems or access sensitive data.
    """
    __tablename__ = "tool_approvals"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=func.gen_random_uuid(),
    )
    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(Organization.__table__.c.org_id),
        nullable=False,
        index=True,
    )
    tool_invocation_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("tool_invocations.id"),
        nullable=False,
        unique=True,
        index=True,
    )
    
    # Approval request details
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    risk_assessment: Mapped[Dict[str, Any]] = mapped_column(JSONType, nullable=False)
    
    # Approval decision
    status: Mapped[ApprovalStatus] = mapped_column(
        SqlEnum(ApprovalStatus),
        nullable=False,
        default=ApprovalStatus.PENDING,
        index=True,
    )
    decided_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    decided_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    decision_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Expiry
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )
    
    # Relationships  
    tool_invocation: Mapped["ToolInvocation"] = relationship(
        "ToolInvocation",
        back_populates="approval",
    )


class AgentSessionContext(Base):
    """
    Cross-session context and memory for agents.

    Stores learned facts, user preferences, corrections, and environment details
    that agents should remember across sessions for continuity and personalization.
    """
    __tablename__ = "agent_session_context"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=func.gen_random_uuid(),
    )
    session_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("agent_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(Organization.__table__.c.org_id, ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Context identification
    context_key: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Key identifying the context (e.g. prod_account_id, ceo_name)",
    )
    context_value: Mapped[Dict[str, Any]] = mapped_column(
        JSONType,
        nullable=False,
        comment="Value stored as JSON for flexibility",
    )
    context_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="Type: user_preference, learned_fact, correction, environment",
    )
    learned_from: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="Source: user_conversation, tool_execution, external_source",
    )

    # Confidence and expiry
    confidence: Mapped[Optional[float]] = mapped_column(
        nullable=True,
        comment="Confidence score 0-1 for learned facts",
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Optional expiration for temporary context",
    )

    # Tracking
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    context_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        "metadata",
        JSONType,
        nullable=True,
        comment="Additional metadata about the context",
    )


class AgentRecommendation(Base):
    """
    Security recommendations generated by agents.

    Agents can generate actionable recommendations for remediation, policy changes,
    or process improvements based on their analysis.
    """
    __tablename__ = "agent_recommendations"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=func.gen_random_uuid(),
    )
    session_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("agent_sessions.id"),
        nullable=False,
        index=True,
    )
    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(Organization.__table__.c.org_id),
        nullable=False,
        index=True,
    )
    
    # Recommendation details
    type: Mapped[str] = mapped_column(String(50), nullable=False)  # remediation, policy, rule, process
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    priority: Mapped[str] = mapped_column(String(20), nullable=False)  # critical, high, medium, low
    
    # Implementation guidance
    action_items: Mapped[list[Dict[str, Any]]] = mapped_column(JSONType, nullable=False, default=list)
    estimated_effort: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    implementation_timeline: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    
    # Framework mappings
    cis_controls: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)
    nist_controls: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)
    cwe_ids: Mapped[list[int]] = mapped_column(JSONType, nullable=False, default=list)
    
    # Tracking
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="draft",
        index=True,
    )  # draft, approved, implemented, rejected
