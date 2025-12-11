"""Agent session repository for DynamoDB."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from cerebro.core.dynamodb_client import (
    TableName,
    batch_write,
    delete_item,
    get_item,
    pk,
    put_item,
    query,
    query_paginated,
    sk,
    update_item,
)


class AgentType(str, Enum):
    """Types of security agents."""
    SECURITY_ANALYST = "security_analyst"
    INCIDENT_RESPONDER = "incident_responder"
    IDENTITY_ADVISOR = "identity_advisor"
    COMPLIANCE_ADVISOR = "compliance_advisor"
    ATTACK_PATH_ANALYST = "attack_path_analyst"


class AgentSession(BaseModel):
    """Agent conversation session."""
    
    id: UUID = Field(default_factory=uuid4)
    org_id: UUID
    agent_type: AgentType
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str
    title: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)
    is_active: bool = True
    
    class Config:
        from_attributes = True
        use_enum_values = True
    
    @property
    def session_id(self) -> UUID:
        return self.id
    
    def to_item(self) -> Dict[str, Any]:
        """Convert to DynamoDB item."""
        session_id = str(self.id)
        org_id = str(self.org_id)
        agent_type = self.agent_type.value if isinstance(self.agent_type, Enum) else self.agent_type
        created_at = self.created_at.isoformat()
        
        return {
            "PK": pk("ORG", org_id),
            "SK": sk("SESSION", session_id),
            "entity_type": "SESSION",
            "id": session_id,
            "org_id": org_id,
            "agent_type": agent_type,
            "created_at": created_at,
            "created_by": self.created_by,
            "title": self.title,
            "context": self.context,
            "is_active": self.is_active,
            # GSI1 for querying by agent type
            "GSI1PK": f"ORG#{org_id}#AGENT#{agent_type}",
            "GSI1SK": f"CREATED#{created_at}",
            # GSI2 for querying active sessions
            "GSI2PK": f"ORG#{org_id}#ACTIVE#{self.is_active}",
            "GSI2SK": f"CREATED#{created_at}",
        }
    
    @classmethod
    def from_item(cls, item: Dict[str, Any]) -> "AgentSession":
        """Create from DynamoDB item."""
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


class AgentSessionRepository:
    """Repository for AgentSession operations."""
    
    _table = TableName.AGENTS
    
    async def get(self, session_id: UUID, org_id: UUID) -> Optional[AgentSession]:
        """Get session by ID."""
        item = await get_item(
            self._table,
            pk("ORG", str(org_id)),
            sk("SESSION", str(session_id)),
        )
        return AgentSession.from_item(item) if item else None
    
    async def create(self, session: AgentSession) -> AgentSession:
        """Create new session."""
        await put_item(self._table, session.to_item())
        return session
    
    async def update(self, session_id: UUID, org_id: UUID, **updates) -> Optional[AgentSession]:
        """Update session."""
        # Update GSI2 if is_active changed
        current = await self.get(session_id, org_id)
        if current:
            is_active = updates.get("is_active", current.is_active)
            created_at = current.created_at.isoformat()
            updates["GSI2PK"] = f"ORG#{org_id}#ACTIVE#{is_active}"
            updates["GSI2SK"] = f"CREATED#{created_at}"
        
        result = await update_item(
            self._table,
            pk("ORG", str(org_id)),
            sk("SESSION", str(session_id)),
            updates,
        )
        return AgentSession.from_item(result) if result else None
    
    async def delete(self, session_id: UUID, org_id: UUID) -> bool:
        """Delete session and all related items (messages, tool invocations)."""
        delete_keys = []
        
        # Paginate through all items under this session
        cursor = None
        while True:
            items, cursor = await query_paginated(
                self._table,
                pk("SESSION", str(session_id)),
                limit=100,
                cursor=cursor,
            )
            delete_keys.extend([(item["PK"], item["SK"]) for item in items])
            if not cursor:
                break
        
        # Add the session itself
        delete_keys.append((pk("ORG", str(org_id)), sk("SESSION", str(session_id))))
        
        # Delete in batches
        if delete_keys:
            await batch_write(self._table, delete_keys=delete_keys)
        
        return True
    
    async def list_by_org(
        self,
        org_id: UUID,
        agent_type: Optional[AgentType] = None,
        created_by: Optional[str] = None,
        active_only: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[AgentSession], int]:
        """List sessions for an organization."""
        if agent_type:
            # Use GSI1 for agent type filtering
            agent_type_val = agent_type.value if isinstance(agent_type, Enum) else agent_type
            items = await query(
                self._table,
                f"ORG#{org_id}#AGENT#{agent_type_val}",
                index="GSI1",
                limit=limit + offset,
                forward=False,
            )
        elif active_only:
            # Use GSI2 for active filtering
            items = await query(
                self._table,
                f"ORG#{org_id}#ACTIVE#True",
                index="GSI2",
                limit=limit + offset,
                forward=False,
            )
        else:
            # Query all sessions for org
            items = await query(
                self._table,
                pk("ORG", str(org_id)),
                sk_prefix="SESSION#",
                limit=limit + offset,
                forward=False,
            )
        
        # Filter by created_by if specified
        if created_by:
            items = [i for i in items if i.get("created_by") == created_by]
        
        total = len(items)
        
        # Apply pagination
        items = items[offset:offset + limit]
        sessions = [AgentSession.from_item(item) for item in items]
        
        return sessions, total
    
    async def deactivate(self, session_id: UUID, org_id: UUID) -> Optional[AgentSession]:
        """Deactivate a session."""
        return await self.update(session_id, org_id, is_active=False)
    
    async def update_title(self, session_id: UUID, org_id: UUID, title: str) -> Optional[AgentSession]:
        """Update session title."""
        return await self.update(session_id, org_id, title=title)
    
    async def update_context(
        self,
        session_id: UUID,
        org_id: UUID,
        context: Dict[str, Any],
    ) -> Optional[AgentSession]:
        """Update session context."""
        return await self.update(session_id, org_id, context=context)
