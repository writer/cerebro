"""Principal repository for DynamoDB."""

from datetime import datetime, timezone
from enum import Enum
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
    sk,
    update_item,
)


class PrincipalType(str, Enum):
    """Types of principals."""
    USER = "user"
    GROUP = "group"
    SERVICE_ACCOUNT = "service_account"
    APP = "app"
    ROLE = "role"


class Principal(BaseModel):
    """Principal entity - users, groups, service accounts."""
    
    principal_id: UUID = Field(default_factory=uuid4)
    account_id: UUID
    org_id: UUID
    provider: str
    principal_type: PrincipalType
    external_id: str
    email: Optional[str] = None
    display_name: Optional[str] = None
    is_human: Optional[bool] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    class Config:
        from_attributes = True
        use_enum_values = True
    
    def to_item(self) -> Dict[str, Any]:
        """Convert to DynamoDB item."""
        principal_id = str(self.principal_id)
        account_id = str(self.account_id)
        org_id = str(self.org_id)
        principal_type = self.principal_type.value if isinstance(self.principal_type, Enum) else self.principal_type
        
        return {
            "PK": pk("ORG", org_id),
            "SK": sk("PRINCIPAL", principal_id),
            "entity_type": "PRINCIPAL",
            "principal_id": principal_id,
            "account_id": account_id,
            "org_id": org_id,
            "provider": self.provider,
            "principal_type": principal_type,
            "external_id": self.external_id,
            "email": self.email,
            "display_name": self.display_name,
            "is_human": self.is_human,
            "created_at": self.created_at.isoformat(),
            # GSI for querying by account
            "GSI1PK": f"ACCOUNT#{account_id}",
            "GSI1SK": f"PRINCIPAL#{principal_id}",
        }
    
    @classmethod
    def from_item(cls, item: Dict[str, Any]) -> "Principal":
        """Create from DynamoDB item."""
        return cls(
            principal_id=UUID(item["principal_id"]),
            account_id=UUID(item["account_id"]),
            org_id=UUID(item["org_id"]),
            provider=item["provider"],
            principal_type=PrincipalType(item["principal_type"]),
            external_id=item["external_id"],
            email=item.get("email"),
            display_name=item.get("display_name"),
            is_human=item.get("is_human"),
            created_at=datetime.fromisoformat(item["created_at"]) if item.get("created_at") else datetime.now(timezone.utc),
        )


class PrincipalRepository:
    """Repository for Principal operations."""
    
    _table = TableName.CORE
    
    async def get(self, principal_id: UUID, org_id: UUID) -> Optional[Principal]:
        """Get principal by ID."""
        item = await get_item(
            self._table,
            pk("ORG", str(org_id)),
            sk("PRINCIPAL", str(principal_id)),
        )
        return Principal.from_item(item) if item else None
    
    async def create(self, principal: Principal) -> Principal:
        """Create new principal."""
        await put_item(self._table, principal.to_item())
        return principal
    
    async def update(self, principal_id: UUID, org_id: UUID, **updates) -> Optional[Principal]:
        """Update principal."""
        result = await update_item(
            self._table,
            pk("ORG", str(org_id)),
            sk("PRINCIPAL", str(principal_id)),
            updates,
        )
        return Principal.from_item(result) if result else None
    
    async def delete(self, principal_id: UUID, org_id: UUID) -> bool:
        """Delete principal."""
        return await delete_item(
            self._table,
            pk("ORG", str(org_id)),
            sk("PRINCIPAL", str(principal_id)),
        )
    
    async def list_by_org(self, org_id: UUID, limit: int = 100) -> List[Principal]:
        """List principals for an organization."""
        items = await query(
            self._table,
            pk("ORG", str(org_id)),
            sk_prefix="PRINCIPAL#",
            limit=limit,
        )
        return [Principal.from_item(item) for item in items]
    
    async def list_by_account(self, account_id: UUID, limit: int = 100) -> List[Principal]:
        """List principals for an account."""
        items = await query(
            self._table,
            f"ACCOUNT#{account_id}",
            sk_prefix="PRINCIPAL#",
            index="GSI1",
            limit=limit,
        )
        return [Principal.from_item(item) for item in items]
    
    async def get_by_external_id(
        self,
        org_id: UUID,
        provider: str,
        external_id: str,
    ) -> Optional[Principal]:
        """Get principal by external ID."""
        principals = await self.list_by_org(org_id, limit=10000)
        for principal in principals:
            if principal.provider == provider and principal.external_id == external_id:
                return principal
        return None
    
    async def get_by_email(self, org_id: UUID, email: str) -> Optional[Principal]:
        """Get principal by email."""
        principals = await self.list_by_org(org_id, limit=10000)
        for principal in principals:
            if principal.email == email:
                return principal
        return None
    
    async def bulk_upsert(self, principals: List[Principal]) -> int:
        """Bulk upsert principals."""
        items = [p.to_item() for p in principals]
        await batch_write(self._table, put_items=items)
        return len(principals)
    
    async def list_humans(self, org_id: UUID, limit: int = 100) -> List[Principal]:
        """List human principals."""
        principals = await self.list_by_org(org_id, limit=limit * 2)
        return [p for p in principals if p.is_human is True][:limit]
    
    async def list_service_accounts(self, org_id: UUID, limit: int = 100) -> List[Principal]:
        """List service accounts."""
        principals = await self.list_by_org(org_id, limit=limit * 2)
        return [p for p in principals if p.principal_type == PrincipalType.SERVICE_ACCOUNT][:limit]
