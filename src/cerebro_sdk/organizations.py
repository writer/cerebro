"""Organization, account, and resource helpers for the Cerebro SDK."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.models import Account, Organization, Resource


@dataclass(slots=True)
class OrganizationRecord:
    org_id: UUID
    name: str


@dataclass(slots=True)
class AccountRecord:
    account_id: UUID
    org_id: UUID
    provider: str
    external_id: str
    display_name: Optional[str]


@dataclass(slots=True)
class ResourceRecord:
    resource_id: UUID
    account_id: UUID
    provider: str
    resource_type: str
    external_id: str
    name: Optional[str]


class OrganizationManager:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def list_organizations(self, *, limit: int = 100, offset: int = 0) -> list[OrganizationRecord]:
        stmt = (
            select(Organization)
            .order_by(Organization.created_at.asc())
            .offset(offset)
            .limit(limit)
        )
        rows = await self._db.scalars(stmt)
        return [self._organization_to_record(org) for org in rows]

    async def get_organization(self, org_id: UUID) -> Optional[OrganizationRecord]:
        stmt = select(Organization).where(Organization.org_id == org_id)
        org = await self._db.scalar(stmt)
        if not org:
            return None
        return self._organization_to_record(org)

    async def list_accounts(self, org_id: UUID) -> list[AccountRecord]:
        stmt = select(Account).where(Account.org_id == org_id).order_by(Account.provider.asc())
        accounts = await self._db.scalars(stmt)
        return [self._account_to_record(acct) for acct in accounts]

    async def list_resources(
        self,
        account_id: UUID,
        *,
        providers: Optional[Iterable[str]] = None,
        resource_types: Optional[Iterable[str]] = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[ResourceRecord]:
        stmt = select(Resource).where(Resource.account_id == account_id)
        if providers:
            stmt = stmt.where(Resource.provider.in_(list(providers)))
        if resource_types:
            stmt = stmt.where(Resource.resource_type.in_(list(resource_types)))
        stmt = stmt.order_by(Resource.created_at.desc()).offset(offset).limit(limit)

        resources = await self._db.scalars(stmt)
        return [self._resource_to_record(res) for res in resources]

    @staticmethod
    def _organization_to_record(org: Organization) -> OrganizationRecord:
        return OrganizationRecord(org_id=org.org_id, name=org.name)

    @staticmethod
    def _account_to_record(account: Account) -> AccountRecord:
        return AccountRecord(
            account_id=account.account_id,
            org_id=account.org_id,
            provider=account.provider,
            external_id=account.external_id,
            display_name=account.display_name,
        )

    @staticmethod
    def _resource_to_record(resource: Resource) -> ResourceRecord:
        return ResourceRecord(
            resource_id=resource.resource_id,
            account_id=resource.account_id,
            provider=resource.provider,
            resource_type=resource.resource_type,
            external_id=resource.external_id,
            name=resource.name,
        )
