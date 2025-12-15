"""Tool invocation repository for DynamoDB."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from cerebro.core.dynamodb_client import (
    TableName,
    pk,
    put_item,
    query,
    query_paginated,
    update_item,
)


class ToolInvocationStatus(str, Enum):
    """Status of tool invocations."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    ERROR = "error"
    DRY_RUN = "dry_run"
    APPROVAL_REQUIRED = "approval_required"


class ToolInvocation(BaseModel):
    """Tool invocation by an agent."""
    
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
    duration_ms: Optional[int] = None
    
    class Config:
        from_attributes = True
        use_enum_values = True
    
    @property
    def invocation_id(self) -> UUID:
        return self.id
    
    def to_item(self) -> Dict[str, Any]:
        """Convert to DynamoDB item."""
        invocation_id = str(self.id)
        session_id = str(self.session_id)
        org_id = str(self.org_id)
        status = self.status.value if isinstance(self.status, Enum) else self.status
        started_at = self.started_at.isoformat()
        
        return {
            "PK": pk("SESSION", session_id),
            "SK": f"TOOL#{started_at}#{invocation_id}",
            "entity_type": "TOOL_INVOCATION",
            "id": invocation_id,
            "session_id": session_id,
            "org_id": org_id,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "input_data": self.input_data,
            "output_data": self.output_data,
            "status": status,
            "started_at": started_at,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "cel_policy_key": self.cel_policy_key,
            "cel_expression": self.cel_expression,
            "cel_result": self.cel_result,
            "cel_context": self.cel_context,
            "error_message": self.error_message,
            "error_code": self.error_code,
            "celery_task_id": self.celery_task_id,
            "duration_ms": self.duration_ms,
            # GSI1 for querying tools by session
            "GSI1PK": f"SESSION#{session_id}",
            "GSI1SK": f"TOOL#{started_at}",
            # GSI2 for querying by tool name and status
            "GSI2PK": f"ORG#{org_id}#TOOL#{self.tool_name}",
            "GSI2SK": f"STATUS#{status}#{started_at}",
        }
    
    @classmethod
    def from_item(cls, item: Dict[str, Any]) -> "ToolInvocation":
        """Create from DynamoDB item."""
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
            completed_at=datetime.fromisoformat(item["completed_at"]) if item.get("completed_at") else None,
            cel_policy_key=item.get("cel_policy_key"),
            cel_expression=item.get("cel_expression"),
            cel_result=item.get("cel_result"),
            cel_context=item.get("cel_context"),
            error_message=item.get("error_message"),
            error_code=item.get("error_code"),
            celery_task_id=item.get("celery_task_id"),
            duration_ms=item.get("duration_ms"),
        )


class ToolInvocationRepository:
    """Repository for ToolInvocation operations."""
    
    _table = TableName.AGENTS
    
    async def get(self, invocation_id: UUID, session_id: UUID) -> Optional[ToolInvocation]:
        """Get tool invocation by ID.
        
        Note: Invocations use timestamp in SK, so we must scan. Consider adding
        a GSI on invocation_id for direct lookups if this becomes a bottleneck.
        """
        cursor = None
        while True:
            items, cursor = await query_paginated(
                self._table,
                pk("SESSION", str(session_id)),
                sk_prefix="TOOL#",
                limit=100,
                cursor=cursor,
            )
            for item in items:
                if item.get("id") == str(invocation_id):
                    return ToolInvocation.from_item(item)
            if not cursor:
                break
        return None
    
    async def create(self, invocation: ToolInvocation) -> ToolInvocation:
        """Create new tool invocation."""
        await put_item(self._table, invocation.to_item())
        return invocation
    
    async def update(
        self,
        invocation_id: UUID,
        session_id: UUID,
        org_id: UUID,
        **updates,
    ) -> Optional[ToolInvocation]:
        """Update tool invocation."""
        invocation = await self.get(invocation_id, session_id)
        if not invocation:
            return None
        
        # Calculate duration if completing
        if "status" in updates and updates["status"] in (
            ToolInvocationStatus.SUCCESS,
            ToolInvocationStatus.ERROR,
        ):
            updates["completed_at"] = datetime.now(timezone.utc).isoformat()
            duration = (datetime.now(timezone.utc) - invocation.started_at).total_seconds() * 1000
            updates["duration_ms"] = int(duration)
        
        # Update GSI2 if status changed
        status = updates.get("status", invocation.status)
        status_val = status.value if isinstance(status, Enum) else status
        started_at = invocation.started_at.isoformat()
        updates["GSI2SK"] = f"STATUS#{status_val}#{started_at}"
        
        # Need to find the SK
        pk_val = pk("SESSION", str(session_id))
        sk_val = f"TOOL#{started_at}#{invocation_id}"
        
        result = await update_item(self._table, pk_val, sk_val, updates)
        return ToolInvocation.from_item(result) if result else None
    
    async def list_by_session(
        self,
        session_id: UUID,
        limit: Optional[int] = None,
    ) -> List[ToolInvocation]:
        """List tool invocations for a session."""
        items = await query(
            self._table,
            pk("SESSION", str(session_id)),
            sk_prefix="TOOL#",
            limit=limit,
            forward=True,
        )
        return [ToolInvocation.from_item(item) for item in items]
    
    async def list_by_tool_name(
        self,
        org_id: UUID,
        tool_name: str,
        status: Optional[ToolInvocationStatus] = None,
        limit: int = 100,
    ) -> List[ToolInvocation]:
        """List tool invocations by tool name."""
        if status:
            status_val = status.value if isinstance(status, Enum) else status
            items = await query(
                self._table,
                f"ORG#{org_id}#TOOL#{tool_name}",
                sk_prefix=f"STATUS#{status_val}",
                index="GSI2",
                limit=limit,
                forward=False,
            )
        else:
            items = await query(
                self._table,
                f"ORG#{org_id}#TOOL#{tool_name}",
                index="GSI2",
                limit=limit,
                forward=False,
            )
        return [ToolInvocation.from_item(item) for item in items]
    
    async def mark_success(
        self,
        invocation_id: UUID,
        session_id: UUID,
        org_id: UUID,
        output_data: Dict[str, Any],
    ) -> Optional[ToolInvocation]:
        """Mark invocation as successful."""
        return await self.update(
            invocation_id,
            session_id,
            org_id,
            status=ToolInvocationStatus.SUCCESS,
            output_data=output_data,
        )
    
    async def mark_error(
        self,
        invocation_id: UUID,
        session_id: UUID,
        org_id: UUID,
        error_message: str,
        error_code: Optional[str] = None,
    ) -> Optional[ToolInvocation]:
        """Mark invocation as failed."""
        return await self.update(
            invocation_id,
            session_id,
            org_id,
            status=ToolInvocationStatus.ERROR,
            error_message=error_message,
            error_code=error_code,
        )
    
    async def get_stats_by_tool(self, org_id: UUID) -> Dict[str, Dict[str, Any]]:
        """Get statistics by tool name."""
        # This is expensive - would need a different access pattern for production
        stats: Dict[str, Dict[str, Any]] = {}
        
        # Query each known tool (would need to track tool names separately)
        # For now, return empty - this needs a scan or separate tracking
        return stats
