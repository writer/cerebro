"""Agent session management endpoints using DynamoDB.

This is the DynamoDB version of the agents API.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from cerebro.api.dynamodb_dependencies import (
    message_repository,
    session_repository,
    tool_invocation_repository,
)
from cerebro.agents.repositories.dynamodb.session import (
    AgentSession,
    AgentSessionRepository,
    AgentType,
)
from cerebro.agents.repositories.dynamodb.message import (
    AgentMessage,
    AgentMessageRepository,
    MessageRole,
)
from cerebro.agents.repositories.dynamodb.tool_invocation import (
    ToolInvocation,
    ToolInvocationRepository,
    ToolInvocationStatus,
)


# Request/Response schemas

class SessionCreate(BaseModel):
    """Request schema for creating a session."""
    org_id: UUID
    agent_type: str = Field(..., pattern="^(security_analyst|incident_responder|identity_advisor|compliance_advisor|attack_path_analyst)$")
    created_by: str
    title: Optional[str] = None
    context: Optional[Dict[str, Any]] = None


class SessionUpdate(BaseModel):
    """Request schema for updating a session."""
    title: Optional[str] = None
    context: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None


class SessionResponse(BaseModel):
    """Response schema for session."""
    id: UUID
    org_id: UUID
    agent_type: str
    created_at: str
    created_by: str
    title: Optional[str] = None
    context: Dict[str, Any] = {}
    is_active: bool = True

    @classmethod
    def from_entity(cls, session: AgentSession) -> "SessionResponse":
        return cls(
            id=session.id,
            org_id=session.org_id,
            agent_type=session.agent_type.value if hasattr(session.agent_type, 'value') else session.agent_type,
            created_at=session.created_at.isoformat(),
            created_by=session.created_by,
            title=session.title,
            context=session.context,
            is_active=session.is_active,
        )


class MessageCreate(BaseModel):
    """Request schema for creating a message."""
    role: str = Field(..., pattern="^(user|assistant|tool|system)$")
    content: Dict[str, Any]


class MessageResponse(BaseModel):
    """Response schema for message."""
    id: UUID
    session_id: UUID
    role: str
    content: Dict[str, Any]
    created_at: str
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None

    @classmethod
    def from_entity(cls, message: AgentMessage) -> "MessageResponse":
        return cls(
            id=message.id,
            session_id=message.session_id,
            role=message.role.value if hasattr(message.role, 'value') else message.role,
            content=message.content,
            created_at=message.created_at.isoformat(),
            input_tokens=message.input_tokens,
            output_tokens=message.output_tokens,
        )


class ToolInvocationResponse(BaseModel):
    """Response schema for tool invocation."""
    id: UUID
    session_id: UUID
    tool_name: str
    tool_version: str
    input_data: Dict[str, Any]
    output_data: Optional[Dict[str, Any]] = None
    status: str
    started_at: str
    completed_at: Optional[str] = None
    error_message: Optional[str] = None
    duration_ms: Optional[int] = None

    @classmethod
    def from_entity(cls, inv: ToolInvocation) -> "ToolInvocationResponse":
        return cls(
            id=inv.id,
            session_id=inv.session_id,
            tool_name=inv.tool_name,
            tool_version=inv.tool_version,
            input_data=inv.input_data,
            output_data=inv.output_data,
            status=inv.status.value if hasattr(inv.status, 'value') else inv.status,
            started_at=inv.started_at.isoformat(),
            completed_at=inv.completed_at.isoformat() if inv.completed_at else None,
            error_message=inv.error_message,
            duration_ms=inv.duration_ms,
        )


class SessionListResponse(BaseModel):
    """Response for listing sessions with pagination."""
    sessions: List[SessionResponse]
    total: int


class TokenUsageResponse(BaseModel):
    """Response for token usage."""
    input_tokens: int
    output_tokens: int
    total_tokens: int


# Router

router = APIRouter(prefix="/agents", tags=["agents"])


# Session endpoints

@router.post("/sessions", response_model=SessionResponse, status_code=201)
async def create_session(
    data: SessionCreate,
    repo: AgentSessionRepository = Depends(session_repository),
) -> SessionResponse:
    """Create a new agent session."""
    session = AgentSession(
        org_id=data.org_id,
        agent_type=AgentType(data.agent_type),
        created_by=data.created_by,
        title=data.title,
        context=data.context or {},
    )
    created = await repo.create(session)
    return SessionResponse.from_entity(created)


@router.get("/sessions/org/{org_id}", response_model=SessionListResponse)
async def list_sessions(
    org_id: UUID,
    agent_type: Optional[str] = Query(None, pattern="^(security_analyst|incident_responder|identity_advisor|compliance_advisor|attack_path_analyst)$"),
    created_by: Optional[str] = None,
    active_only: bool = False,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    repo: AgentSessionRepository = Depends(session_repository),
) -> SessionListResponse:
    """List sessions for an organization."""
    agent_type_enum = AgentType(agent_type) if agent_type else None
    
    sessions, total = await repo.list_by_org(
        org_id=org_id,
        agent_type=agent_type_enum,
        created_by=created_by,
        active_only=active_only,
        limit=limit,
        offset=offset,
    )
    
    return SessionListResponse(
        sessions=[SessionResponse.from_entity(s) for s in sessions],
        total=total,
    )


@router.get("/sessions/{org_id}/{session_id}", response_model=SessionResponse)
async def get_session(
    org_id: UUID,
    session_id: UUID,
    repo: AgentSessionRepository = Depends(session_repository),
) -> SessionResponse:
    """Get a specific session."""
    session = await repo.get(session_id, org_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return SessionResponse.from_entity(session)


@router.patch("/sessions/{org_id}/{session_id}", response_model=SessionResponse)
async def update_session(
    org_id: UUID,
    session_id: UUID,
    data: SessionUpdate,
    repo: AgentSessionRepository = Depends(session_repository),
) -> SessionResponse:
    """Update a session."""
    updates = {k: v for k, v in data.model_dump().items() if v is not None}
    
    if not updates:
        raise HTTPException(status_code=400, detail="No updates provided")
    
    session = await repo.update(session_id, org_id, **updates)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return SessionResponse.from_entity(session)


@router.post("/sessions/{org_id}/{session_id}/deactivate", response_model=SessionResponse)
async def deactivate_session(
    org_id: UUID,
    session_id: UUID,
    repo: AgentSessionRepository = Depends(session_repository),
) -> SessionResponse:
    """Deactivate a session."""
    session = await repo.deactivate(session_id, org_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return SessionResponse.from_entity(session)


@router.delete("/sessions/{org_id}/{session_id}", status_code=204)
async def delete_session(
    org_id: UUID,
    session_id: UUID,
    repo: AgentSessionRepository = Depends(session_repository),
) -> None:
    """Delete a session and all its messages."""
    session = await repo.get(session_id, org_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    await repo.delete(session_id, org_id)


# Message endpoints

@router.post("/sessions/{org_id}/{session_id}/messages", response_model=MessageResponse, status_code=201)
async def create_message(
    org_id: UUID,
    session_id: UUID,
    data: MessageCreate,
    session_repo: AgentSessionRepository = Depends(session_repository),
    message_repo: AgentMessageRepository = Depends(message_repository),
) -> MessageResponse:
    """Add a message to a session."""
    # Verify session exists
    session = await session_repo.get(session_id, org_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    message = AgentMessage(
        session_id=session_id,
        org_id=org_id,
        role=MessageRole(data.role),
        content=data.content,
    )
    created = await message_repo.create(message)
    return MessageResponse.from_entity(created)


@router.get("/sessions/{org_id}/{session_id}/messages", response_model=List[MessageResponse])
async def list_messages(
    org_id: UUID,
    session_id: UUID,
    limit: Optional[int] = Query(None, ge=1, le=1000),
    session_repo: AgentSessionRepository = Depends(session_repository),
    message_repo: AgentMessageRepository = Depends(message_repository),
) -> List[MessageResponse]:
    """List messages in a session."""
    # Verify session exists
    session = await session_repo.get(session_id, org_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    messages = await message_repo.list_by_session(session_id, limit)
    return [MessageResponse.from_entity(m) for m in messages]


@router.get("/sessions/{org_id}/{session_id}/token-usage", response_model=TokenUsageResponse)
async def get_token_usage(
    org_id: UUID,
    session_id: UUID,
    session_repo: AgentSessionRepository = Depends(session_repository),
    message_repo: AgentMessageRepository = Depends(message_repository),
) -> TokenUsageResponse:
    """Get token usage for a session."""
    session = await session_repo.get(session_id, org_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    usage = await message_repo.get_token_usage(session_id)
    return TokenUsageResponse(**usage)


# Tool invocation endpoints

@router.get("/sessions/{org_id}/{session_id}/tools", response_model=List[ToolInvocationResponse])
async def list_tool_invocations(
    org_id: UUID,
    session_id: UUID,
    limit: Optional[int] = Query(None, ge=1, le=1000),
    session_repo: AgentSessionRepository = Depends(session_repository),
    tool_repo: ToolInvocationRepository = Depends(tool_invocation_repository),
) -> List[ToolInvocationResponse]:
    """List tool invocations in a session."""
    session = await session_repo.get(session_id, org_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    invocations = await tool_repo.list_by_session(session_id, limit)
    return [ToolInvocationResponse.from_entity(inv) for inv in invocations]


@router.get("/tools/org/{org_id}/{tool_name}", response_model=List[ToolInvocationResponse])
async def list_tool_invocations_by_name(
    org_id: UUID,
    tool_name: str,
    status: Optional[str] = Query(None, pattern="^(pending|running|success|error|dry_run|approval_required)$"),
    limit: int = Query(100, ge=1, le=1000),
    tool_repo: ToolInvocationRepository = Depends(tool_invocation_repository),
) -> List[ToolInvocationResponse]:
    """List tool invocations by tool name."""
    status_enum = ToolInvocationStatus(status) if status else None
    
    invocations = await tool_repo.list_by_tool_name(org_id, tool_name, status_enum, limit)
    return [ToolInvocationResponse.from_entity(inv) for inv in invocations]
