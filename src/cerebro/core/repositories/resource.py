"""Resource repository for DynamoDB."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
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


class Resource(BaseModel):
    """Resource entity - cloud/SaaS objects."""
    
    resource_id: UUID = Field(default_factory=uuid4)
    account_id: UUID
    org_id: UUID
    provider: str
    resource_type: str
    external_id: str
    name: Optional[str] = None
    parent_external_id: Optional[str] = None
    region: Optional[str] = None
    tags: Optional[Dict[str, str]] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    class Config:
        from_attributes = True
    
    def to_item(self) -> Dict[str, Any]:
        """Convert to DynamoDB item."""
        resource_id = str(self.resource_id)
        account_id = str(self.account_id)
        org_id = str(self.org_id)
        
        return {
            "PK": pk("ORG", org_id),
            "SK": sk("RESOURCE", resource_id),
            "entity_type": "RESOURCE",
            "resource_id": resource_id,
            "account_id": account_id,
            "org_id": org_id,
            "provider": self.provider,
            "resource_type": self.resource_type,
            "external_id": self.external_id,
            "name": self.name,
            "parent_external_id": self.parent_external_id,
            "region": self.region,
            "tags": self.tags,
            "created_at": self.created_at.isoformat(),
            # GSI for querying by account
            "GSI1PK": f"ACCOUNT#{account_id}",
            "GSI1SK": f"RESOURCE#{resource_id}",
            # GSI2 for querying by type
            "GSI2PK": f"ORG#{org_id}#TYPE#{self.resource_type}",
            "GSI2SK": f"RESOURCE#{resource_id}",
        }
    
    @classmethod
    def from_item(cls, item: Dict[str, Any]) -> "Resource":
        """Create from DynamoDB item."""
        return cls(
            resource_id=UUID(item["resource_id"]),
            account_id=UUID(item["account_id"]),
            org_id=UUID(item["org_id"]),
            provider=item["provider"],
            resource_type=item["resource_type"],
            external_id=item["external_id"],
            name=item.get("name"),
            parent_external_id=item.get("parent_external_id"),
            region=item.get("region"),
            tags=item.get("tags"),
            created_at=datetime.fromisoformat(item["created_at"]) if item.get("created_at") else datetime.now(timezone.utc),
        )


class ResourceRepository:
    """Repository for Resource operations."""
    
    _table = TableName.CORE
    
    async def get(self, resource_id: UUID, org_id: UUID) -> Optional[Resource]:
        """Get resource by ID."""
        item = await get_item(
            self._table,
            pk("ORG", str(org_id)),
            sk("RESOURCE", str(resource_id)),
        )
        return Resource.from_item(item) if item else None
    
    async def create(self, resource: Resource) -> Resource:
        """Create new resource."""
        await put_item(self._table, resource.to_item())
        return resource
    
    async def update(self, resource_id: UUID, org_id: UUID, **updates) -> Optional[Resource]:
        """Update resource."""
        result = await update_item(
            self._table,
            pk("ORG", str(org_id)),
            sk("RESOURCE", str(resource_id)),
            updates,
        )
        return Resource.from_item(result) if result else None
    
    async def delete(self, resource_id: UUID, org_id: UUID) -> bool:
        """Delete resource."""
        return await delete_item(
            self._table,
            pk("ORG", str(org_id)),
            sk("RESOURCE", str(resource_id)),
        )
    
    async def list_by_org(self, org_id: UUID, limit: int = 100) -> List[Resource]:
        """List resources for an organization."""
        items = await query(
            self._table,
            pk("ORG", str(org_id)),
            sk_prefix="RESOURCE#",
            limit=limit,
        )
        return [Resource.from_item(item) for item in items]
    
    async def list_by_account(
        self,
        account_id: UUID,
        resource_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[Resource]:
        """List resources for an account."""
        items = await query(
            self._table,
            f"ACCOUNT#{account_id}",
            sk_prefix="RESOURCE#",
            index="GSI1",
            limit=limit,
        )
        
        resources = [Resource.from_item(item) for item in items]
        
        if resource_type:
            resources = [r for r in resources if r.resource_type == resource_type]
        
        return resources
    
    async def list_by_type(
        self,
        org_id: UUID,
        resource_type: str,
        limit: int = 100,
    ) -> List[Resource]:
        """List resources by type."""
        items = await query(
            self._table,
            f"ORG#{org_id}#TYPE#{resource_type}",
            index="GSI2",
            limit=limit,
        )
        return [Resource.from_item(item) for item in items]
    
    async def get_by_external_id(
        self,
        org_id: UUID,
        provider: str,
        resource_type: str,
        external_id: str,
    ) -> Optional[Resource]:
        """Get resource by external ID.
        
        Note: Scans resources of given type. Consider adding GSI on external_id.
        """
        cursor = None
        while True:
            items, cursor = await query_paginated(
                self._table,
                f"ORG#{org_id}#TYPE#{resource_type}",
                index="GSI2",
                limit=100,
                cursor=cursor,
            )
            for item in items:
                if item.get("provider") == provider and item.get("external_id") == external_id:
                    return Resource.from_item(item)
            if not cursor:
                break
        return None
    
    async def bulk_upsert(self, resources: List[Resource]) -> int:
        """Bulk upsert resources."""
        items = [r.to_item() for r in resources]
        await batch_write(self._table, put_items=items)
        return len(resources)
    
    async def count_by_type(self, org_id: UUID) -> Dict[str, int]:
        """Count resources by type.
        
        Uses paginated queries to handle large datasets efficiently.
        """
        counts: Dict[str, int] = {}
        cursor = None
        while True:
            items, cursor = await query_paginated(
                self._table,
                pk("ORG", str(org_id)),
                sk_prefix="RESOURCE#",
                limit=100,
                cursor=cursor,
            )
            for item in items:
                rt = item.get("resource_type", "unknown")
                counts[rt] = counts.get(rt, 0) + 1
            if not cursor:
                break
        return counts
