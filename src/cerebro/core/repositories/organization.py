"""Organization repository for DynamoDB."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from cerebro.core.dynamodb_client import (
    TableName,
    delete_item,
    get_item,
    now_iso,
    pk,
    put_item,
    query,
    query_paginated,
    sk,
    update_item,
)


class Organization(BaseModel):
    """Organization entity."""
    
    org_id: UUID = Field(default_factory=uuid4)
    name: str
    slack_config: Optional[Dict[str, Any]] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    class Config:
        from_attributes = True
    
    def to_item(self) -> Dict[str, Any]:
        """Convert to DynamoDB item."""
        org_id = str(self.org_id)
        created = self.created_at.isoformat()
        return {
            "PK": pk("ORG", org_id),
            "SK": sk("ORG", org_id),
            "entity_type": "ORG",
            "org_id": org_id,
            "name": self.name,
            "slack_config": self.slack_config,
            "created_at": created,
            "GSI3PK": "ORG#ALL",
            "GSI3SK": f"CREATED#{created}",
        }
    
    @classmethod
    def from_item(cls, item: Dict[str, Any]) -> "Organization":
        """Create from DynamoDB item."""
        return cls(
            org_id=UUID(item["org_id"]),
            name=item["name"],
            slack_config=item.get("slack_config"),
            created_at=datetime.fromisoformat(item["created_at"]),
        )


class OrganizationRepository:
    """Repository for Organization operations."""
    
    _table = TableName.CORE
    
    async def get(self, org_id: UUID) -> Optional[Organization]:
        """Get organization by ID."""
        item = await get_item(
            self._table,
            pk("ORG", str(org_id)),
            sk("ORG", str(org_id)),
        )
        return Organization.from_item(item) if item else None
    
    async def create(self, org: Organization) -> Organization:
        """Create new organization."""
        await put_item(
            self._table,
            org.to_item(),
            condition="attribute_not_exists(PK)",
        )
        return org
    
    async def update(self, org_id: UUID, **updates) -> Optional[Organization]:
        """Update organization."""
        result = await update_item(
            self._table,
            pk("ORG", str(org_id)),
            sk("ORG", str(org_id)),
            updates,
        )
        return Organization.from_item(result) if result else None
    
    async def delete(self, org_id: UUID) -> bool:
        """Delete organization."""
        return await delete_item(
            self._table,
            pk("ORG", str(org_id)),
            sk("ORG", str(org_id)),
        )
    
    async def list_all(self, limit: int = 100) -> List[Organization]:
        """List all organizations."""
        items = await query(
            self._table,
            "ORG#ALL",
            index="GSI3",
            limit=limit,
            forward=False,
        )
        return [Organization.from_item(item) for item in items]
    
    async def get_by_name(self, name: str) -> Optional[Organization]:
        """Get organization by name.
        
        Note: Scans all orgs. Consider adding GSI on name for better performance.
        """
        cursor = None
        while True:
            items, cursor = await query_paginated(
                self._table,
                "ORG#ALL",
                index="GSI3",
                limit=100,
                cursor=cursor,
            )
            for item in items:
                if item.get("name") == name:
                    return Organization.from_item(item)
            if not cursor:
                break
        return None
