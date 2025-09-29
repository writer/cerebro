"""
FastAPI routers for Cerebro agent endpoints.

Provides HTTP API access to agent functionality including sessions,
conversations, tool approvals, and analytics.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

import structlog

from cerebro.api.auth import get_current_user, get_org_context
from cerebro.agents.service import (
    AgentSessionService,
    ToolApprovalService, 
    AgentAnalyticsService,
)
from cerebro.agents.models import AgentType, ApprovalStatus

logger = structlog.get_logger(__name__)

# Initialize services
agent_service = AgentSessionService()
approval_service = ToolApprovalService()
analytics_service = AgentAnalyticsService()

# Create router
router = APIRouter(prefix="/api/v1/agents", tags=["agents"])


# Request/Response Models

class CreateSessionRequest(BaseModel):
    """Request to create new agent session."""
    agent_type: str = Field(description="Type of agent to create")
    title: Optional[str] = Field(None, description="Optional session title")
    context: Dict[str, Any] = Field(default_factory=dict, description="Agent context data")


class CreateSessionResponse(BaseModel):
    """Response from creating agent session."""
    session_id: UUID
    agent_type: str
    title: Optional[str]
    context: Dict[str, Any]
    created_at: datetime


class SendMessageRequest(BaseModel):
    """Request to send message to agent."""
    message: str = Field(description="Message text to send to agent")
    stream: bool = Field(default=True, description="Whether to stream response")


class SessionListResponse(BaseModel):
    """Response for listing agent sessions."""
    sessions: List[Dict[str, Any]]
    total_count: int
    has_more: bool


class ApprovalRequest(BaseModel):
    """Request for tool approval decision."""
    decision_reason: str = Field(description="Reason for approval/rejection decision")


class ApprovalListResponse(BaseModel):
    """Response for listing tool approvals."""
    approvals: List[Dict[str, Any]]
    total_count: int
    has_more: bool


# Agent Session Endpoints

@router.post("/sessions", response_model=CreateSessionResponse)
async def create_agent_session(
    request: CreateSessionRequest,
    current_user = Depends(get_current_user),
    org_context = Depends(get_org_context),
):
    """Create a new agent session."""
    
    try:
        session = await agent_service.create_session(
            org_id=org_context.org_id,
            agent_type=request.agent_type,
            created_by=current_user.id,
            context=request.context,
            title=request.title,
        )
        
        return CreateSessionResponse(
            session_id=session.id,
            agent_type=session.agent_type.value,
            title=session.title,
            context=session.context,
            created_at=session.created_at,
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("Failed to create agent session", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to create session")


@router.get("/sessions", response_model=SessionListResponse)
async def list_agent_sessions(
    agent_type: Optional[str] = Query(None, description="Filter by agent type"),
    created_by: Optional[str] = Query(None, description="Filter by creator"),
    limit: int = Query(50, description="Maximum sessions to return", ge=1, le=200),
    offset: int = Query(0, description="Number of sessions to skip", ge=0),
    current_user = Depends(get_current_user),
    org_context = Depends(get_org_context),
):
    """List agent sessions for the organization."""
    
    try:
        sessions, total_count = await agent_service.list_sessions(
            org_id=org_context.org_id,
            agent_type=agent_type,
            created_by=created_by,
            limit=limit,
            offset=offset,
        )
        
        session_data = [
            {
                "id": str(session.id),
                "agent_type": session.agent_type.value,
                "title": session.title,
                "created_at": session.created_at.isoformat(),
                "created_by": session.created_by,
                "context": session.context,
            }
            for session in sessions
        ]
        
        return SessionListResponse(
            sessions=session_data,
            total_count=total_count,
            has_more=(offset + len(sessions)) < total_count,
        )
        
    except Exception as e:
        logger.exception("Failed to list agent sessions", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to list sessions")


@router.get("/sessions/{session_id}")
async def get_agent_session(
    session_id: UUID,
    include_messages: bool = Query(True, description="Include recent messages"),
    message_limit: int = Query(50, description="Number of messages to include", ge=1, le=200),
    current_user = Depends(get_current_user),
    org_context = Depends(get_org_context),
):
    """Get a specific agent session with optional message history."""
    
    try:
        if include_messages:
            session_data = await agent_service.get_session_with_messages(
                session_id=session_id,
                org_id=org_context.org_id,
                message_limit=message_limit,
            )
        else:
            session = await agent_service.get_session(session_id, org_context.org_id)
            if not session:
                raise HTTPException(status_code=404, detail="Session not found")
            
            session_data = {
                "session": {
                    "id": str(session.id),
                    "org_id": str(session.org_id),
                    "agent_type": session.agent_type.value,
                    "title": session.title,
                    "context": session.context,
                    "created_at": session.created_at.isoformat(),
                    "created_by": session.created_by,
                },
                "messages": [],
                "tool_invocations": [],
            }
        
        if not session_data:
            raise HTTPException(status_code=404, detail="Session not found")
        
        return session_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to get agent session", session_id=session_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get session")


@router.post("/sessions/{session_id}/messages")
async def send_message_to_agent(
    session_id: UUID,
    request: SendMessageRequest,
    current_user = Depends(get_current_user),
    org_context = Depends(get_org_context),
):
    """Send a message to an agent session."""
    
    if request.stream:
        # Return streaming response using Server-Sent Events
        async def generate_response():
            try:
                async for response_chunk in agent_service.send_message(
                    session_id=session_id,
                    message=request.message,
                    user_id=current_user.id,
                    org_id=org_context.org_id,
                    stream=True,
                ):
                    yield {
                        "event": response_chunk["type"],
                        "data": response_chunk,
                    }
                    
            except Exception as e:
                logger.exception(
                    "Streaming message failed",
                    session_id=session_id,
                    error=str(e),
                )
                yield {
                    "event": "error",
                    "data": {
                        "type": "error",
                        "content": {"message": "Message processing failed", "error": str(e)},
                        "metadata": {"session_id": str(session_id)},
                    },
                }
        
        return EventSourceResponse(generate_response())
        
    else:
        # Return complete response as JSON
        try:
            responses = []
            async for response_chunk in agent_service.send_message(
                session_id=session_id,
                message=request.message,
                user_id=current_user.id,
                org_id=org_context.org_id,
                stream=False,
            ):
                responses.append(response_chunk)
            
            return {
                "session_id": str(session_id),
                "responses": responses,
                "completed_at": datetime.utcnow().isoformat(),
            }
            
        except Exception as e:
            logger.exception("Failed to send message", session_id=session_id, error=str(e))
            raise HTTPException(status_code=500, detail="Failed to send message")


@router.get("/sessions/{session_id}/messages")
async def get_session_messages(
    session_id: UUID,
    limit: int = Query(100, description="Maximum messages to return", ge=1, le=500),
    offset: int = Query(0, description="Number of messages to skip", ge=0),
    current_user = Depends(get_current_user),
    org_context = Depends(get_org_context),
):
    """Get messages from an agent session."""
    
    try:
        messages = await agent_service.get_session_messages(
            session_id=session_id,
            org_id=org_context.org_id,
            limit=limit,
            offset=offset,
        )
        
        return {
            "session_id": str(session_id),
            "messages": messages,
            "count": len(messages),
            "has_more": len(messages) == limit,  # Rough estimate
        }
        
    except Exception as e:
        logger.exception("Failed to get session messages", session_id=session_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get messages")


@router.delete("/sessions/{session_id}")
async def delete_agent_session(
    session_id: UUID,
    current_user = Depends(get_current_user),
    org_context = Depends(get_org_context),
):
    """Delete an agent session."""
    
    try:
        success = await agent_service.delete_session(
            session_id=session_id,
            org_id=org_context.org_id,
            deleted_by=current_user.id,
        )
        
        if not success:
            raise HTTPException(status_code=404, detail="Session not found")
        
        return {"message": "Session deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to delete session", session_id=session_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to delete session")


# Tool Approval Endpoints

@router.get("/approvals", response_model=ApprovalListResponse)
async def list_pending_approvals(
    limit: int = Query(50, description="Maximum approvals to return", ge=1, le=200),
    offset: int = Query(0, description="Number of approvals to skip", ge=0),
    current_user = Depends(get_current_user),
    org_context = Depends(get_org_context),
):
    """List pending tool approvals for the organization."""
    
    try:
        approvals, total_count = await approval_service.list_pending_approvals(
            org_id=org_context.org_id,
            limit=limit,
            offset=offset,
        )
        
        approval_data = [
            {
                "id": str(approval.id),
                "tool_invocation_id": str(approval.tool_invocation_id),
                "tool_name": approval.tool_invocation.tool_name if approval.tool_invocation else None,
                "requested_by": approval.requested_by,
                "requested_at": approval.requested_at.isoformat(),
                "reason": approval.reason,
                "risk_assessment": approval.risk_assessment,
                "status": approval.status.value,
                "expires_at": approval.expires_at.isoformat() if approval.expires_at else None,
            }
            for approval in approvals
        ]
        
        return ApprovalListResponse(
            approvals=approval_data,
            total_count=total_count,
            has_more=(offset + len(approvals)) < total_count,
        )
        
    except Exception as e:
        logger.exception("Failed to list approvals", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to list approvals")


@router.get("/approvals/{approval_id}")
async def get_tool_approval(
    approval_id: UUID,
    current_user = Depends(get_current_user),
    org_context = Depends(get_org_context),
):
    """Get a specific tool approval."""
    
    try:
        approval = await approval_service.get_approval(approval_id, org_context.org_id)
        
        if not approval:
            raise HTTPException(status_code=404, detail="Approval not found")
        
        return {
            "id": str(approval.id),
            "tool_invocation_id": str(approval.tool_invocation_id),
            "tool_name": approval.tool_invocation.tool_name if approval.tool_invocation else None,
            "tool_input": approval.tool_invocation.input_data if approval.tool_invocation else None,
            "requested_by": approval.requested_by,
            "requested_at": approval.requested_at.isoformat(),
            "reason": approval.reason,
            "risk_assessment": approval.risk_assessment,
            "status": approval.status.value,
            "decided_by": approval.decided_by,
            "decided_at": approval.decided_at.isoformat() if approval.decided_at else None,
            "decision_reason": approval.decision_reason,
            "expires_at": approval.expires_at.isoformat() if approval.expires_at else None,
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to get approval", approval_id=approval_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get approval")


@router.post("/approvals/{approval_id}/approve")
async def approve_tool_invocation(
    approval_id: UUID,
    request: ApprovalRequest,
    current_user = Depends(get_current_user),
    org_context = Depends(get_org_context),
):
    """Approve a tool invocation."""
    
    try:
        approval = await approval_service.approve_tool_invocation(
            approval_id=approval_id,
            org_id=org_context.org_id,
            approved_by=current_user.id,
            decision_reason=request.decision_reason,
        )
        
        if not approval:
            raise HTTPException(
                status_code=404,
                detail="Approval not found or already processed"
            )
        
        return {
            "message": "Tool invocation approved",
            "approval_id": str(approval.id),
            "status": approval.status.value,
            "decided_at": approval.decided_at.isoformat(),
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to approve tool", approval_id=approval_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to approve tool")


@router.post("/approvals/{approval_id}/reject")
async def reject_tool_invocation(
    approval_id: UUID,
    request: ApprovalRequest,
    current_user = Depends(get_current_user),
    org_context = Depends(get_org_context),
):
    """Reject a tool invocation."""
    
    try:
        approval = await approval_service.reject_tool_invocation(
            approval_id=approval_id,
            org_id=org_context.org_id,
            rejected_by=current_user.id,
            decision_reason=request.decision_reason,
        )
        
        if not approval:
            raise HTTPException(
                status_code=404,
                detail="Approval not found or already processed"
            )
        
        return {
            "message": "Tool invocation rejected",
            "approval_id": str(approval.id),
            "status": approval.status.value,
            "decided_at": approval.decided_at.isoformat(),
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to reject tool", approval_id=approval_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to reject tool")


# Analytics Endpoints

@router.get("/analytics/usage")
async def get_agent_usage_analytics(
    days: int = Query(30, description="Number of days to analyze", ge=1, le=365),
    current_user = Depends(get_current_user),
    org_context = Depends(get_org_context),
):
    """Get agent usage analytics for the organization."""
    
    try:
        analytics = await analytics_service.get_org_agent_usage(
            org_id=org_context.org_id,
            days=days,
        )
        
        return analytics
        
    except Exception as e:
        logger.exception("Failed to get analytics", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get analytics")


# Health and Status Endpoints

@router.get("/health")
async def agent_health_check():
    """Health check endpoint for agent services."""
    
    try:
        # TODO: Add actual health checks for Claude SDK, database, etc.
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "services": {
                "claude_sdk": "available",
                "database": "connected",
                "tool_registry": "loaded",
            },
        }
        
    except Exception as e:
        logger.exception("Health check failed", error=str(e))
        raise HTTPException(status_code=503, detail="Service unhealthy")


@router.get("/agent-types")
async def list_agent_types():
    """List available agent types."""
    
    agent_types = [
        {
            "value": agent_type.value,
            "name": agent_type.value.replace("_", " ").title(),
            "description": _get_agent_description(agent_type),
        }
        for agent_type in AgentType
    ]
    
    return {"agent_types": agent_types}


def _get_agent_description(agent_type: AgentType) -> str:
    """Get description for agent type."""
    descriptions = {
        AgentType.SECURITY_ANALYST: "Analyzes security findings and provides triage recommendations",
        AgentType.INCIDENT_RESPONDER: "Assists with incident response and forensic analysis", 
        AgentType.IDENTITY_ADVISOR: "Reviews IAM configurations and identity governance",
        AgentType.COMPLIANCE_ADVISOR: "Maps findings to compliance frameworks and generates reports",
        AgentType.ATTACK_PATH_ANALYST: "Analyzes attack paths and recommends defensive measures",
    }
    return descriptions.get(agent_type, "Specialized security agent")
