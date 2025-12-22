"""Account repository for DynamoDB."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from cerebro.core.dynamodb_client import (
    TableName,
    delete_item,
    get_item,
    pk,
    put_item,
    query,
    sk,
    update_item,
)


class Provider(str, Enum):
    """Cloud/SaaS providers."""

    GITHUB = "github"
    GOOGLE_WORKSPACE = "google_workspace"
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    RUNTIME = "runtime"
    ENDPOINT = "endpoint"


class Account(BaseModel):
    """Account entity - provider-specific account within an org."""

    account_id: UUID = Field(default_factory=uuid4)
    org_id: UUID
    provider: Provider
    external_id: str
    display_name: Optional[str] = None
    credentials_encrypted: Optional[bytes] = None
    credentials_dek: Optional[bytes] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        from_attributes = True
        use_enum_values = True

    def to_item(self) -> Dict[str, Any]:
        """Convert to DynamoDB item."""
        account_id = str(self.account_id)
        org_id = str(self.org_id)
        provider = (
            self.provider.value if isinstance(self.provider, Enum) else self.provider
        )

        item = {
            "PK": pk("ORG", org_id),
            "SK": sk("ACCOUNT", account_id),
            "entity_type": "ACCOUNT",
            "account_id": account_id,
            "org_id": org_id,
            "provider": provider,
            "external_id": self.external_id,
            "display_name": self.display_name,
            "created_at": self.created_at.isoformat(),
            "GSI1PK": f"PROVIDER#{provider}",
            "GSI1SK": f"ACCOUNT#{account_id}",
        }

        # Don't serialize credentials to DynamoDB item for security
        # They should be stored separately or encrypted

        return item

    @classmethod
    def from_item(cls, item: Dict[str, Any]) -> "Account":
        """Create from DynamoDB item."""
        return cls(
            account_id=UUID(item["account_id"]),
            org_id=UUID(item["org_id"]),
            provider=Provider(item["provider"]),
            external_id=item["external_id"],
            display_name=item.get("display_name"),
            created_at=(
                datetime.fromisoformat(item["created_at"])
                if item.get("created_at")
                else datetime.now(timezone.utc)
            ),
        )


class AccountRepository:
    """Repository for Account operations."""

    _table = TableName.CORE

    async def get(self, account_id: UUID, org_id: UUID) -> Optional[Account]:
        """Get account by ID."""
        item = await get_item(
            self._table,
            pk("ORG", str(org_id)),
            sk("ACCOUNT", str(account_id)),
        )
        return Account.from_item(item) if item else None

    async def create(self, account: Account) -> Account:
        """Create new account."""
        await put_item(self._table, account.to_item())
        return account

    async def update(
        self, account_id: UUID, org_id: UUID, **updates
    ) -> Optional[Account]:
        """Update account."""
        result = await update_item(
            self._table,
            pk("ORG", str(org_id)),
            sk("ACCOUNT", str(account_id)),
            updates,
        )
        return Account.from_item(result) if result else None

    async def delete(self, account_id: UUID, org_id: UUID) -> bool:
        """Delete account."""
        return await delete_item(
            self._table,
            pk("ORG", str(org_id)),
            sk("ACCOUNT", str(account_id)),
        )

    async def list_by_org(
        self,
        org_id: UUID,
        provider: Optional[Provider] = None,
        limit: int = 100,
    ) -> List[Account]:
        """List accounts for an organization."""
        items = await query(
            self._table,
            pk("ORG", str(org_id)),
            sk_prefix="ACCOUNT#",
            limit=limit,
        )

        accounts = [Account.from_item(item) for item in items]

        if provider:
            prov_val = provider.value if isinstance(provider, Provider) else provider
            accounts = [
                a
                for a in accounts
                if a.provider == prov_val or a.provider.value == prov_val
            ]

        return accounts

    async def list_by_provider(
        self,
        provider: Provider,
        limit: int = 100,
    ) -> List[Account]:
        """List accounts by provider across all orgs."""
        prov_val = provider.value if isinstance(provider, Provider) else provider
        items = await query(
            self._table,
            f"PROVIDER#{prov_val}",
            index="GSI1",
            limit=limit,
        )
        return [Account.from_item(item) for item in items]

    async def get_by_external_id(
        self,
        org_id: UUID,
        provider: Provider,
        external_id: str,
    ) -> Optional[Account]:
        """Get account by external ID."""
        accounts = await self.list_by_org(org_id, provider)
        for account in accounts:
            if account.external_id == external_id:
                return account
        return None
