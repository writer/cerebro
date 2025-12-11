"""Agent message repository for DynamoDB."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from cerebro.core.dynamodb_client import (
    TableName,
    batch_write,
    get_item,
    pk,
    put_item,
    query,
    query_paginated,
    sk,
)


class MessageRole(str, Enum):
    """Role types for agent messages."""
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"
    SYSTEM = "system"


class AgentMessage(BaseModel):
    """Individual message in an agent conversation."""
    
    id: UUID = Field(default_factory=uuid4)
    session_id: UUID
    org_id: UUID
    role: MessageRole
    content: Dict[str, Any]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    
    class Config:
        from_attributes = True
        use_enum_values = True
    
    @property
    def message_id(self) -> UUID:
        return self.id
    
    def to_item(self) -> Dict[str, Any]:
        """Convert to DynamoDB item."""
        message_id = str(self.id)
        session_id = str(self.session_id)
        org_id = str(self.org_id)
        role = self.role.value if isinstance(self.role, Enum) else self.role
        created_at = self.created_at.isoformat()
        
        return {
            "PK": pk("SESSION", session_id),
            "SK": f"MESSAGE#{created_at}#{message_id}",
            "entity_type": "MESSAGE",
            "id": message_id,
            "session_id": session_id,
            "org_id": org_id,
            "role": role,
            "content": self.content,
            "created_at": created_at,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            # GSI1 for querying messages by session
            "GSI1PK": f"SESSION#{session_id}",
            "GSI1SK": f"MESSAGE#{created_at}",
        }
    
    @classmethod
    def from_item(cls, item: Dict[str, Any]) -> "AgentMessage":
        """Create from DynamoDB item."""
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


class AgentMessageRepository:
    """Repository for AgentMessage operations."""
    
    _table = TableName.AGENTS
    
    async def get(self, message_id: UUID, session_id: UUID) -> Optional[AgentMessage]:
        """Get message by ID.
        
        Note: Messages use timestamp in SK, so we must scan. Consider adding
        a GSI on message_id for direct lookups if this becomes a bottleneck.
        """
        cursor = None
        while True:
            items, cursor = await query_paginated(
                self._table,
                pk("SESSION", str(session_id)),
                sk_prefix="MESSAGE#",
                limit=100,
                cursor=cursor,
            )
            for item in items:
                if item.get("id") == str(message_id):
                    return AgentMessage.from_item(item)
            if not cursor:
                break
        return None
    
    async def create(self, message: AgentMessage) -> AgentMessage:
        """Create new message."""
        await put_item(self._table, message.to_item())
        return message
    
    async def list_by_session(
        self,
        session_id: UUID,
        limit: Optional[int] = None,
        after: Optional[datetime] = None,
    ) -> List[AgentMessage]:
        """List messages for a session in chronological order."""
        if after:
            items = await query(
                self._table,
                pk("SESSION", str(session_id)),
                sk_between=(f"MESSAGE#{after.isoformat()}", "MESSAGE#~"),
                limit=limit,
                forward=True,
            )
        else:
            items = await query(
                self._table,
                pk("SESSION", str(session_id)),
                sk_prefix="MESSAGE#",
                limit=limit,
                forward=True,
            )
        
        return [AgentMessage.from_item(item) for item in items]
    
    async def list_by_session_desc(
        self,
        session_id: UUID,
        limit: Optional[int] = None,
    ) -> List[AgentMessage]:
        """List messages for a session in reverse chronological order."""
        items = await query(
            self._table,
            pk("SESSION", str(session_id)),
            sk_prefix="MESSAGE#",
            limit=limit,
            forward=False,
        )
        return [AgentMessage.from_item(item) for item in items]
    
    async def get_last_n_messages(
        self,
        session_id: UUID,
        n: int,
    ) -> List[AgentMessage]:
        """Get last N messages for a session."""
        messages = await self.list_by_session_desc(session_id, limit=n)
        return list(reversed(messages))
    
    async def count_by_session(self, session_id: UUID) -> int:
        """Count messages in a session using pagination."""
        count = 0
        cursor = None
        while True:
            items, cursor = await query_paginated(
                self._table,
                pk("SESSION", str(session_id)),
                sk_prefix="MESSAGE#",
                limit=100,
                cursor=cursor,
            )
            count += len(items)
            if not cursor:
                break
        return count
    
    async def get_token_usage(self, session_id: UUID) -> Dict[str, int]:
        """Get total token usage for a session using pagination."""
        input_tokens = 0
        output_tokens = 0
        cursor = None
        while True:
            items, cursor = await query_paginated(
                self._table,
                pk("SESSION", str(session_id)),
                sk_prefix="MESSAGE#",
                limit=100,
                cursor=cursor,
            )
            for item in items:
                input_tokens += item.get("input_tokens") or 0
                output_tokens += item.get("output_tokens") or 0
            if not cursor:
                break
        return {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
        }
    
    async def bulk_create(self, messages: List[AgentMessage]) -> int:
        """Bulk create messages."""
        items = [m.to_item() for m in messages]
        await batch_write(self._table, put_items=items)
        return len(messages)
