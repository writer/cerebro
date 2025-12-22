"""Pydantic models for agent DynamoDB entities.

These models replace SQLAlchemy ORM models with Pydantic models that include
DynamoDB serialization/deserialization methods.

Entity Types and Key Patterns (cerebro-agents table):
    - SESSION: PK=ORG#{org_id}, SK=SESSION#{session_id}
    - MESSAGE: PK=SESSION#{session_id}, SK=MESSAGE#{timestamp}#{message_id}
    - TOOL_INVOCATION: PK=SESSION#{session_id}, SK=TOOL#{timestamp}#{invocation_id}
    - TOOL_APPROVAL: PK=ORG#{org_id}, SK=APPROVAL#{approval_id}
    - REVIEW_TASK: PK=ORG#{org_id}, SK=REVIEW#{task_id}
    - MEMORY_ENTRY: PK=ORG#{org_id}, SK=MEMORY#{entry_id}
    - RECOMMENDATION: PK=SESSION#{session_id}, SK=RECOMMENDATION#{rec_id}

GSI1 (by session/type):
    - GSI1PK=SESSION#{session_id}, GSI1SK=MESSAGE#{timestamp}
    - GSI1PK=SESSION#{session_id}, GSI1SK=TOOL#{timestamp}

GSI2 (by status):
    - GSI2PK=ORG#{org_id}#STATUS#{status}, GSI2SK=CREATED#{timestamp}
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from cerebro.core.dynamodb import build_pk, build_sk


class AgentType(str, Enum):
    """Types of security agents."""

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


class ReviewTaskStatus(str, Enum):
    """Workflow states for human-in-the-loop review tasks."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    ESCALATED = "escalated"
    PROMOTED = "promoted"


class AgentEntityType(str, Enum):
    """Entity type prefixes for agent DynamoDB keys."""

    SESSION = "SESSION"
    MESSAGE = "MESSAGE"
    TOOL_INVOCATION = "TOOL"
    TOOL_APPROVAL = "APPROVAL"
    REVIEW_TASK = "REVIEW"
    MEMORY_ENTRY = "MEMORY"
    RECOMMENDATION = "RECOMMENDATION"
    CONVERSATION_ITEM = "CONV_ITEM"
    SESSION_CONTEXT = "CONTEXT"
    RUNTIME_EVENT = "RUNTIME_EVENT"


class DynamoDBAgentModel(BaseModel):
    """Base model for agent DynamoDB entities."""

    class Config:
        populate_by_name = True
        use_enum_values = True

    def to_dynamodb_item(self) -> Dict[str, Any]:
        """Convert model to DynamoDB item format with keys."""
        raise NotImplementedError("Subclasses must implement to_dynamodb_item")

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> "DynamoDBAgentModel":
        """Create model instance from DynamoDB item."""
        raise NotImplementedError("Subclasses must implement from_dynamodb_item")

    def get_pk(self) -> str:
        """Get partition key for this entity."""
        raise NotImplementedError("Subclasses must implement get_pk")

    def get_sk(self) -> str:
        """Get sort key for this entity."""
        raise NotImplementedError("Subclasses must implement get_sk")


class AgentSession(DynamoDBAgentModel):
    """Agent conversation session."""

    id: UUID = Field(default_factory=uuid4)
    org_id: UUID
    agent_type: AgentType
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str
    title: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)
    is_active: bool = True

    @property
    def session_id(self) -> UUID:
        return self.id

    def get_pk(self) -> str:
        return build_pk("ORG", self.org_id)

    def get_sk(self) -> str:
        return build_sk(AgentEntityType.SESSION.value, self.id)

    def to_dynamodb_item(self) -> Dict[str, Any]:
        agent_type_val = (
            self.agent_type.value
            if isinstance(self.agent_type, Enum)
            else self.agent_type
        )

        return {
            "PK": self.get_pk(),
            "SK": self.get_sk(),
            "entity_type": AgentEntityType.SESSION.value,
            "id": str(self.id),
            "org_id": str(self.org_id),
            "agent_type": agent_type_val,
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "title": self.title,
            "context": self.context,
            "is_active": self.is_active,
            # GSI1 for querying by agent type
            "GSI1PK": f"ORG#{self.org_id}#AGENT#{agent_type_val}",
            "GSI1SK": f"CREATED#{self.created_at.isoformat()}",
            # GSI2 for querying active sessions
            "GSI2PK": f"ORG#{self.org_id}#ACTIVE#{self.is_active}",
            "GSI2SK": f"CREATED#{self.created_at.isoformat()}",
        }

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> "AgentSession":
        return cls(
            id=UUID(item["id"]),
            org_id=UUID(item["org_id"]),
            agent_type=AgentType(item["agent_type"]),
            created_at=datetime.fromisoformat(item["created_at"]),
            created_by=item["created_by"],
            title=item.get("title"),
            context=item.get("context", {}),
            is_active=item.get("is_active", True),
        )


class AgentMessage(DynamoDBAgentModel):
    """Individual message in an agent conversation."""

    id: UUID = Field(default_factory=uuid4)
    session_id: UUID
    org_id: UUID
    role: MessageRole
    content: Dict[str, Any]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None

    @property
    def message_id(self) -> UUID:
        return self.id

    def get_pk(self) -> str:
        return build_pk(AgentEntityType.SESSION.value, self.session_id)

    def get_sk(self) -> str:
        return f"MESSAGE#{self.created_at.isoformat()}#{self.id}"

    def to_dynamodb_item(self) -> Dict[str, Any]:
        role_val = self.role.value if isinstance(self.role, Enum) else self.role

        return {
            "PK": self.get_pk(),
            "SK": self.get_sk(),
            "entity_type": AgentEntityType.MESSAGE.value,
            "id": str(self.id),
            "session_id": str(self.session_id),
            "org_id": str(self.org_id),
            "role": role_val,
            "content": self.content,
            "created_at": self.created_at.isoformat(),
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            # GSI1 for querying messages by session
            "GSI1PK": f"SESSION#{self.session_id}",
            "GSI1SK": f"MESSAGE#{self.created_at.isoformat()}",
        }

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> "AgentMessage":
        return cls(
            id=UUID(item["id"]),
            session_id=UUID(item["session_id"]),
            org_id=UUID(item["org_id"]),
            role=MessageRole(item["role"]),
            content=item["content"],
            created_at=datetime.fromisoformat(item["created_at"]),
            input_tokens=item.get("input_tokens"),
            output_tokens=item.get("output_tokens"),
        )


class ToolInvocation(DynamoDBAgentModel):
    """Detailed tracking of tool invocations by agents."""

    id: UUID = Field(default_factory=uuid4)
    session_id: UUID
    org_id: UUID
    tool_name: str
    tool_version: str = "1.0"
    input_data: Dict[str, Any]
    output_data: Optional[Dict[str, Any]] = None
    status: ToolInvocationStatus = ToolInvocationStatus.PENDING
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    cel_policy_key: Optional[str] = None
    cel_expression: Optional[str] = None
    cel_result: Optional[bool] = None
    cel_context: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    error_code: Optional[str] = None
    celery_task_id: Optional[str] = None

    @property
    def invocation_id(self) -> UUID:
        return self.id

    def get_pk(self) -> str:
        return build_pk(AgentEntityType.SESSION.value, self.session_id)

    def get_sk(self) -> str:
        return f"TOOL#{self.started_at.isoformat()}#{self.id}"

    def to_dynamodb_item(self) -> Dict[str, Any]:
        status_val = self.status.value if isinstance(self.status, Enum) else self.status

        return {
            "PK": self.get_pk(),
            "SK": self.get_sk(),
            "entity_type": AgentEntityType.TOOL_INVOCATION.value,
            "id": str(self.id),
            "session_id": str(self.session_id),
            "org_id": str(self.org_id),
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "input_data": self.input_data,
            "output_data": self.output_data,
            "status": status_val,
            "started_at": self.started_at.isoformat(),
            "completed_at": (
                self.completed_at.isoformat() if self.completed_at else None
            ),
            "cel_policy_key": self.cel_policy_key,
            "cel_expression": self.cel_expression,
            "cel_result": self.cel_result,
            "cel_context": self.cel_context,
            "error_message": self.error_message,
            "error_code": self.error_code,
            "celery_task_id": self.celery_task_id,
            # GSI1 for querying tools by session
            "GSI1PK": f"SESSION#{self.session_id}",
            "GSI1SK": f"TOOL#{self.started_at.isoformat()}",
            # GSI2 for querying by tool name and status
            "GSI2PK": f"ORG#{self.org_id}#TOOL#{self.tool_name}",
            "GSI2SK": f"STATUS#{status_val}#{self.started_at.isoformat()}",
        }

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> "ToolInvocation":
        return cls(
            id=UUID(item["id"]),
            session_id=UUID(item["session_id"]),
            org_id=UUID(item["org_id"]),
            tool_name=item["tool_name"],
            tool_version=item.get("tool_version", "1.0"),
            input_data=item["input_data"],
            output_data=item.get("output_data"),
            status=ToolInvocationStatus(item["status"]),
            started_at=datetime.fromisoformat(item["started_at"]),
            completed_at=(
                datetime.fromisoformat(item["completed_at"])
                if item.get("completed_at")
                else None
            ),
            cel_policy_key=item.get("cel_policy_key"),
            cel_expression=item.get("cel_expression"),
            cel_result=item.get("cel_result"),
            cel_context=item.get("cel_context"),
            error_message=item.get("error_message"),
            error_code=item.get("error_code"),
            celery_task_id=item.get("celery_task_id"),
        )


class ToolApproval(DynamoDBAgentModel):
    """Human-in-the-loop approval workflow for tool actions."""

    id: UUID = Field(default_factory=uuid4)
    org_id: UUID
    tool_invocation_id: UUID
    session_id: UUID
    requested_by: str
    requested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reason: str
    risk_assessment: Dict[str, Any]
    status: ApprovalStatus = ApprovalStatus.PENDING
    decided_by: Optional[str] = None
    decided_at: Optional[datetime] = None
    decision_reason: Optional[str] = None
    expires_at: Optional[datetime] = None

    def get_pk(self) -> str:
        return build_pk("ORG", self.org_id)

    def get_sk(self) -> str:
        return build_sk(AgentEntityType.TOOL_APPROVAL.value, self.id)

    def to_dynamodb_item(self) -> Dict[str, Any]:
        status_val = self.status.value if isinstance(self.status, Enum) else self.status

        return {
            "PK": self.get_pk(),
            "SK": self.get_sk(),
            "entity_type": AgentEntityType.TOOL_APPROVAL.value,
            "id": str(self.id),
            "org_id": str(self.org_id),
            "tool_invocation_id": str(self.tool_invocation_id),
            "session_id": str(self.session_id),
            "requested_by": self.requested_by,
            "requested_at": self.requested_at.isoformat(),
            "reason": self.reason,
            "risk_assessment": self.risk_assessment,
            "status": status_val,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
            "decision_reason": self.decision_reason,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            # GSI1 for querying by tool invocation
            "GSI1PK": f"TOOL_INVOCATION#{self.tool_invocation_id}",
            "GSI1SK": f"APPROVAL#{self.id}",
            # GSI2 for querying pending approvals
            "GSI2PK": f"ORG#{self.org_id}#APPROVAL_STATUS#{status_val}",
            "GSI2SK": f"REQUESTED#{self.requested_at.isoformat()}",
        }

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> "ToolApproval":
        return cls(
            id=UUID(item["id"]),
            org_id=UUID(item["org_id"]),
            tool_invocation_id=UUID(item["tool_invocation_id"]),
            session_id=UUID(item["session_id"]),
            requested_by=item["requested_by"],
            requested_at=datetime.fromisoformat(item["requested_at"]),
            reason=item["reason"],
            risk_assessment=item["risk_assessment"],
            status=ApprovalStatus(item["status"]),
            decided_by=item.get("decided_by"),
            decided_at=(
                datetime.fromisoformat(item["decided_at"])
                if item.get("decided_at")
                else None
            ),
            decision_reason=item.get("decision_reason"),
            expires_at=(
                datetime.fromisoformat(item["expires_at"])
                if item.get("expires_at")
                else None
            ),
        )


class AgentReviewTask(DynamoDBAgentModel):
    """Pending review items raised by agents for human decision."""

    id: UUID = Field(default_factory=uuid4)
    org_id: UUID
    session_id: UUID
    message_id: Optional[UUID] = None
    tool_invocation_id: Optional[UUID] = None
    title: str
    summary: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)
    priority: Optional[str] = None
    due_at: Optional[datetime] = None
    escalated_to: Optional[str] = None
    notification_channel: Optional[str] = None
    ticket_reference: Optional[str] = None
    status: ReviewTaskStatus = ReviewTaskStatus.PENDING
    created_by: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    promotion_target: Optional[str] = None
    resolution_notes: Optional[str] = None
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    assigned_to: Optional[str] = None
    assigned_at: Optional[datetime] = None
    assigned_by: Optional[str] = None

    def get_pk(self) -> str:
        return build_pk("ORG", self.org_id)

    def get_sk(self) -> str:
        return build_sk(AgentEntityType.REVIEW_TASK.value, self.id)

    def to_dynamodb_item(self) -> Dict[str, Any]:
        status_val = self.status.value if isinstance(self.status, Enum) else self.status

        return {
            "PK": self.get_pk(),
            "SK": self.get_sk(),
            "entity_type": AgentEntityType.REVIEW_TASK.value,
            "id": str(self.id),
            "org_id": str(self.org_id),
            "session_id": str(self.session_id),
            "message_id": str(self.message_id) if self.message_id else None,
            "tool_invocation_id": (
                str(self.tool_invocation_id) if self.tool_invocation_id else None
            ),
            "title": self.title,
            "summary": self.summary,
            "payload": self.payload,
            "priority": self.priority,
            "due_at": self.due_at.isoformat() if self.due_at else None,
            "escalated_to": self.escalated_to,
            "notification_channel": self.notification_channel,
            "ticket_reference": self.ticket_reference,
            "status": status_val,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat(),
            "promotion_target": self.promotion_target,
            "resolution_notes": self.resolution_notes,
            "resolved_by": self.resolved_by,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "assigned_to": self.assigned_to,
            "assigned_at": self.assigned_at.isoformat() if self.assigned_at else None,
            "assigned_by": self.assigned_by,
            # GSI1 for querying by session
            "GSI1PK": f"SESSION#{self.session_id}",
            "GSI1SK": f"REVIEW#{self.created_at.isoformat()}",
            # GSI2 for querying by status
            "GSI2PK": f"ORG#{self.org_id}#REVIEW_STATUS#{status_val}",
            "GSI2SK": f"CREATED#{self.created_at.isoformat()}",
        }

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> "AgentReviewTask":
        return cls(
            id=UUID(item["id"]),
            org_id=UUID(item["org_id"]),
            session_id=UUID(item["session_id"]),
            message_id=UUID(item["message_id"]) if item.get("message_id") else None,
            tool_invocation_id=(
                UUID(item["tool_invocation_id"])
                if item.get("tool_invocation_id")
                else None
            ),
            title=item["title"],
            summary=item.get("summary"),
            payload=item.get("payload", {}),
            priority=item.get("priority"),
            due_at=(
                datetime.fromisoformat(item["due_at"]) if item.get("due_at") else None
            ),
            escalated_to=item.get("escalated_to"),
            notification_channel=item.get("notification_channel"),
            ticket_reference=item.get("ticket_reference"),
            status=ReviewTaskStatus(item["status"]),
            created_by=item["created_by"],
            created_at=datetime.fromisoformat(item["created_at"]),
            promotion_target=item.get("promotion_target"),
            resolution_notes=item.get("resolution_notes"),
            resolved_by=item.get("resolved_by"),
            resolved_at=(
                datetime.fromisoformat(item["resolved_at"])
                if item.get("resolved_at")
                else None
            ),
            assigned_to=item.get("assigned_to"),
            assigned_at=(
                datetime.fromisoformat(item["assigned_at"])
                if item.get("assigned_at")
                else None
            ),
            assigned_by=item.get("assigned_by"),
        )


class AgentMemoryEntry(DynamoDBAgentModel):
    """Learned facts, summaries, and embeddings for long-term recall."""

    id: UUID = Field(default_factory=uuid4)
    org_id: UUID
    session_id: Optional[UUID] = None
    agent_type: Optional[str] = None
    role: Optional[MessageRole] = None
    scopes: List[Dict[str, Any]] = Field(default_factory=list)
    scope_priority: int = 0
    content: str
    summary: Optional[str] = None
    content_hash: Optional[str] = None
    token_count: int = 0
    embedding: Optional[List[float]] = None
    embedding_norm: Optional[float] = None
    extra_metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)
    decay_score: float = 1.0
    last_accessed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def get_pk(self) -> str:
        return build_pk("ORG", self.org_id)

    def get_sk(self) -> str:
        return build_sk(AgentEntityType.MEMORY_ENTRY.value, self.id)

    def to_dynamodb_item(self) -> Dict[str, Any]:
        role_val = self.role.value if isinstance(self.role, Enum) else self.role

        return {
            "PK": self.get_pk(),
            "SK": self.get_sk(),
            "entity_type": AgentEntityType.MEMORY_ENTRY.value,
            "id": str(self.id),
            "org_id": str(self.org_id),
            "session_id": str(self.session_id) if self.session_id else None,
            "agent_type": self.agent_type,
            "role": role_val,
            "scopes": self.scopes,
            "scope_priority": self.scope_priority,
            "content": self.content,
            "summary": self.summary,
            "content_hash": self.content_hash,
            "token_count": self.token_count,
            "embedding": self.embedding,
            "embedding_norm": self.embedding_norm,
            "extra_metadata": self.extra_metadata,
            "decay_score": self.decay_score,
            "last_accessed_at": self.last_accessed_at.isoformat(),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            # GSI1 for querying by session
            "GSI1PK": (
                f"SESSION#{self.session_id}"
                if self.session_id
                else f"ORG#{self.org_id}#GLOBAL"
            ),
            "GSI1SK": f"MEMORY#{self.created_at.isoformat()}",
            # GSI2 for querying by decay score (for pruning)
            "GSI2PK": f"ORG#{self.org_id}#MEMORY",
            "GSI2SK": f"DECAY#{self.decay_score:010.6f}#{self.id}",
        }

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> "AgentMemoryEntry":
        return cls(
            id=UUID(item["id"]),
            org_id=UUID(item["org_id"]),
            session_id=UUID(item["session_id"]) if item.get("session_id") else None,
            agent_type=item.get("agent_type"),
            role=MessageRole(item["role"]) if item.get("role") else None,
            scopes=item.get("scopes", []),
            scope_priority=item.get("scope_priority", 0),
            content=item["content"],
            summary=item.get("summary"),
            content_hash=item.get("content_hash"),
            token_count=item.get("token_count", 0),
            embedding=item.get("embedding"),
            embedding_norm=item.get("embedding_norm"),
            extra_metadata=item.get("extra_metadata", {}),
            decay_score=item.get("decay_score", 1.0),
            last_accessed_at=datetime.fromisoformat(item["last_accessed_at"]),
            created_at=datetime.fromisoformat(item["created_at"]),
            updated_at=datetime.fromisoformat(item["updated_at"]),
        )


class AgentRecommendation(DynamoDBAgentModel):
    """Security recommendations generated by agents."""

    id: UUID = Field(default_factory=uuid4)
    session_id: UUID
    org_id: UUID
    type: str  # remediation, policy, rule, process
    title: str
    description: str
    priority: str  # critical, high, medium, low
    action_items: List[Dict[str, Any]] = Field(default_factory=list)
    estimated_effort: Optional[str] = None
    implementation_timeline: Optional[str] = None
    cis_controls: List[str] = Field(default_factory=list)
    nist_controls: List[str] = Field(default_factory=list)
    cwe_ids: List[int] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "draft"  # draft, approved, implemented, rejected

    def get_pk(self) -> str:
        return build_pk(AgentEntityType.SESSION.value, self.session_id)

    def get_sk(self) -> str:
        return build_sk(AgentEntityType.RECOMMENDATION.value, self.id)

    def to_dynamodb_item(self) -> Dict[str, Any]:
        return {
            "PK": self.get_pk(),
            "SK": self.get_sk(),
            "entity_type": AgentEntityType.RECOMMENDATION.value,
            "id": str(self.id),
            "session_id": str(self.session_id),
            "org_id": str(self.org_id),
            "type": self.type,
            "title": self.title,
            "description": self.description,
            "priority": self.priority,
            "action_items": self.action_items,
            "estimated_effort": self.estimated_effort,
            "implementation_timeline": self.implementation_timeline,
            "cis_controls": self.cis_controls,
            "nist_controls": self.nist_controls,
            "cwe_ids": self.cwe_ids,
            "created_at": self.created_at.isoformat(),
            "status": self.status,
            # GSI1 for querying by org and status
            "GSI1PK": f"ORG#{self.org_id}#REC_STATUS#{self.status}",
            "GSI1SK": f"PRIORITY#{self.priority}#{self.created_at.isoformat()}",
        }

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> "AgentRecommendation":
        return cls(
            id=UUID(item["id"]),
            session_id=UUID(item["session_id"]),
            org_id=UUID(item["org_id"]),
            type=item["type"],
            title=item["title"],
            description=item["description"],
            priority=item["priority"],
            action_items=item.get("action_items", []),
            estimated_effort=item.get("estimated_effort"),
            implementation_timeline=item.get("implementation_timeline"),
            cis_controls=item.get("cis_controls", []),
            nist_controls=item.get("nist_controls", []),
            cwe_ids=item.get("cwe_ids", []),
            created_at=datetime.fromisoformat(item["created_at"]),
            status=item.get("status", "draft"),
        )
