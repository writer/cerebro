"""Database facade for gradual PostgreSQL to DynamoDB migration.

This module provides a unified interface that can use either SQLAlchemy/PostgreSQL
or DynamoDB as the backend, allowing gradual migration of the codebase.

Usage:
    from cerebro.core.db_facade import get_db_facade, DBFacade

    # Get the configured facade instance
    db = get_db_facade()

    # Use the same interface regardless of backend
    org = await db.organizations.get(org_id)
    findings = await db.findings.list_by_org(org_id, status="open")

Configuration:
    Set CEREBRO_DB_BACKEND environment variable:
    - "postgresql" (default during migration)
    - "dynamodb" (target state)
    - "dual" (write to both, read from DynamoDB)
"""

from __future__ import annotations

import os
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple, TypeVar, Generic
from uuid import UUID

logger = logging.getLogger(__name__)

T = TypeVar("T")


class DBBackend(str, Enum):
    """Database backend options."""

    POSTGRESQL = "postgresql"
    DYNAMODB = "dynamodb"
    DUAL = "dual"  # Write to both, read from DynamoDB


def get_db_backend() -> DBBackend:
    """Get configured database backend."""
    backend = os.environ.get("CEREBRO_DB_BACKEND", "postgresql").lower()
    try:
        return DBBackend(backend)
    except ValueError:
        logger.warning(f"Unknown DB backend '{backend}', defaulting to PostgreSQL")
        return DBBackend.POSTGRESQL


class OrganizationFacade:
    """Unified interface for Organization operations."""

    def __init__(self, backend: DBBackend):
        self._backend = backend
        self._pg_repo = None
        self._dynamo_repo = None

    def _get_pg_session(self):
        """Get PostgreSQL session."""
        from cerebro.core.database import async_session_factory
        return async_session_factory()

    def _get_dynamo_repo(self):
        """Get DynamoDB repository."""
        if self._dynamo_repo is None:
            from cerebro.core.dynamodb_repositories import OrganizationRepository
            self._dynamo_repo = OrganizationRepository()
        return self._dynamo_repo

    async def get(self, org_id: UUID) -> Optional[Any]:
        """Get organization by ID."""
        if self._backend == DBBackend.DYNAMODB:
            return await self._get_dynamo_repo().get(org_id)
        elif self._backend == DBBackend.DUAL:
            # Read from DynamoDB
            return await self._get_dynamo_repo().get(org_id)
        else:
            # PostgreSQL
            from cerebro.core.models import Organization
            from sqlalchemy import select
            async with self._get_pg_session() as session:
                result = await session.execute(
                    select(Organization).where(Organization.org_id == org_id)
                )
                return result.scalar_one_or_none()

    async def create(self, **kwargs) -> Any:
        """Create a new organization."""
        if self._backend == DBBackend.DYNAMODB:
            from cerebro.core.dynamodb_models import Organization
            org = Organization(**kwargs)
            return await self._get_dynamo_repo().create(org)
        elif self._backend == DBBackend.DUAL:
            # Write to both
            from cerebro.core.models import Organization as PgOrganization
            from cerebro.core.dynamodb_models import Organization as DynamoOrganization

            # PostgreSQL
            async with self._get_pg_session() as session:
                pg_org = PgOrganization(**kwargs)
                session.add(pg_org)
                await session.commit()

            # DynamoDB
            dynamo_org = DynamoOrganization(**kwargs)
            return await self._get_dynamo_repo().create(dynamo_org)
        else:
            # PostgreSQL only
            from cerebro.core.models import Organization
            async with self._get_pg_session() as session:
                org = Organization(**kwargs)
                session.add(org)
                await session.commit()
                await session.refresh(org)
                return org

    async def list_all(
        self,
        limit: int = 100,
        last_key: Optional[str] = None,
    ) -> Tuple[List[Any], Optional[str]]:
        """List all organizations."""
        if self._backend in (DBBackend.DYNAMODB, DBBackend.DUAL):
            return await self._get_dynamo_repo().list_all(limit, last_key)
        else:
            from cerebro.core.models import Organization
            from sqlalchemy import select
            async with self._get_pg_session() as session:
                result = await session.execute(
                    select(Organization).limit(limit)
                )
                return list(result.scalars()), None


class AccountFacade:
    """Unified interface for Account operations."""

    def __init__(self, backend: DBBackend):
        self._backend = backend
        self._dynamo_repo = None

    def _get_pg_session(self):
        from cerebro.core.database import async_session_factory
        return async_session_factory()

    def _get_dynamo_repo(self):
        if self._dynamo_repo is None:
            from cerebro.core.dynamodb_repositories import AccountRepository
            self._dynamo_repo = AccountRepository()
        return self._dynamo_repo

    async def get(self, account_id: UUID, org_id: UUID) -> Optional[Any]:
        """Get account by ID."""
        if self._backend in (DBBackend.DYNAMODB, DBBackend.DUAL):
            return await self._get_dynamo_repo().get(account_id, org_id)
        else:
            from cerebro.core.models import Account
            from sqlalchemy import select
            async with self._get_pg_session() as session:
                result = await session.execute(
                    select(Account).where(
                        Account.account_id == account_id,
                        Account.org_id == org_id,
                    )
                )
                return result.scalar_one_or_none()

    async def list_by_org(
        self,
        org_id: UUID,
        provider: Optional[str] = None,
        limit: int = 100,
    ) -> List[Any]:
        """List accounts for an organization."""
        if self._backend in (DBBackend.DYNAMODB, DBBackend.DUAL):
            from cerebro.core.dynamodb_models import Provider
            provider_enum = Provider(provider) if provider else None
            return await self._get_dynamo_repo().list_by_org(org_id, provider_enum, limit)
        else:
            from cerebro.core.models import Account
            from sqlalchemy import select
            async with self._get_pg_session() as session:
                query = select(Account).where(Account.org_id == org_id)
                if provider:
                    query = query.where(Account.provider == provider)
                query = query.limit(limit)
                result = await session.execute(query)
                return list(result.scalars())


class FindingFacade:
    """Unified interface for Finding operations."""

    def __init__(self, backend: DBBackend):
        self._backend = backend
        self._dynamo_repo = None

    def _get_pg_session(self):
        from cerebro.core.database import async_session_factory
        return async_session_factory()

    def _get_dynamo_repo(self):
        if self._dynamo_repo is None:
            from cerebro.core.dynamodb_repositories import FindingRepository
            self._dynamo_repo = FindingRepository()
        return self._dynamo_repo

    async def get(self, finding_id: UUID, org_id: UUID) -> Optional[Any]:
        """Get finding by ID."""
        if self._backend in (DBBackend.DYNAMODB, DBBackend.DUAL):
            return await self._get_dynamo_repo().get(finding_id, org_id)
        else:
            from cerebro.core.models import Finding
            from sqlalchemy import select
            async with self._get_pg_session() as session:
                result = await session.execute(
                    select(Finding).where(
                        Finding.finding_id == finding_id,
                        Finding.org_id == org_id,
                    )
                )
                return result.scalar_one_or_none()

    async def list_by_org(
        self,
        org_id: UUID,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[Any]:
        """List findings for an organization."""
        if self._backend in (DBBackend.DYNAMODB, DBBackend.DUAL):
            from cerebro.core.dynamodb_models import FindingStatus, Severity
            status_enum = FindingStatus(status) if status else None
            severity_enum = Severity(severity) if severity else None
            return await self._get_dynamo_repo().list_by_org(
                org_id, status_enum, severity_enum, limit
            )
        else:
            from cerebro.core.models import Finding
            from sqlalchemy import select
            async with self._get_pg_session() as session:
                query = select(Finding).where(Finding.org_id == org_id)
                if status:
                    query = query.where(Finding.status == status)
                if severity:
                    query = query.where(Finding.severity == severity)
                query = query.limit(limit)
                result = await session.execute(query)
                return list(result.scalars())

    async def create(self, **kwargs) -> Any:
        """Create a new finding."""
        if self._backend == DBBackend.DYNAMODB:
            from cerebro.core.dynamodb_models import Finding
            finding = Finding(**kwargs)
            return await self._get_dynamo_repo().create(finding)
        elif self._backend == DBBackend.DUAL:
            from cerebro.core.models import Finding as PgFinding
            from cerebro.core.dynamodb_models import Finding as DynamoFinding

            async with self._get_pg_session() as session:
                pg_finding = PgFinding(**kwargs)
                session.add(pg_finding)
                await session.commit()

            dynamo_finding = DynamoFinding(**kwargs)
            return await self._get_dynamo_repo().create(dynamo_finding)
        else:
            from cerebro.core.models import Finding
            async with self._get_pg_session() as session:
                finding = Finding(**kwargs)
                session.add(finding)
                await session.commit()
                await session.refresh(finding)
                return finding

    async def update(
        self,
        finding_id: UUID,
        org_id: UUID,
        **updates,
    ) -> Optional[Any]:
        """Update a finding."""
        if self._backend in (DBBackend.DYNAMODB, DBBackend.DUAL):
            result = await self._get_dynamo_repo().update(finding_id, org_id, **updates)
            if self._backend == DBBackend.DUAL:
                # Also update PostgreSQL
                from cerebro.core.models import Finding
                from sqlalchemy import update
                async with self._get_pg_session() as session:
                    await session.execute(
                        update(Finding)
                        .where(Finding.finding_id == finding_id, Finding.org_id == org_id)
                        .values(**updates)
                    )
                    await session.commit()
            return result
        else:
            from cerebro.core.models import Finding
            from sqlalchemy import update
            async with self._get_pg_session() as session:
                await session.execute(
                    update(Finding)
                    .where(Finding.finding_id == finding_id, Finding.org_id == org_id)
                    .values(**updates)
                )
                await session.commit()
                return await self.get(finding_id, org_id)


class RuleFacade:
    """Unified interface for Rule operations."""

    def __init__(self, backend: DBBackend):
        self._backend = backend
        self._dynamo_repo = None

    def _get_pg_session(self):
        from cerebro.core.database import async_session_factory
        return async_session_factory()

    def _get_dynamo_repo(self):
        if self._dynamo_repo is None:
            from cerebro.core.dynamodb_repositories import RuleRepository
            self._dynamo_repo = RuleRepository()
        return self._dynamo_repo

    async def get(self, rule_id: UUID) -> Optional[Any]:
        """Get rule by ID."""
        if self._backend in (DBBackend.DYNAMODB, DBBackend.DUAL):
            return await self._get_dynamo_repo().get(rule_id)
        else:
            from cerebro.core.models import Rule
            from sqlalchemy import select
            async with self._get_pg_session() as session:
                result = await session.execute(
                    select(Rule).where(Rule.rule_id == rule_id)
                )
                return result.scalar_one_or_none()

    async def list_active(
        self,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[Any]:
        """List active rules."""
        if self._backend in (DBBackend.DYNAMODB, DBBackend.DUAL):
            from cerebro.core.dynamodb_models import Severity
            severity_enum = Severity(severity) if severity else None
            return await self._get_dynamo_repo().list_active(severity_enum, limit)
        else:
            from cerebro.core.models import Rule
            from sqlalchemy import select
            async with self._get_pg_session() as session:
                query = select(Rule).where(Rule.is_active == True)
                if severity:
                    query = query.where(Rule.severity == severity)
                query = query.limit(limit)
                result = await session.execute(query)
                return list(result.scalars())


class AgentSessionFacade:
    """Unified interface for AgentSession operations."""

    def __init__(self, backend: DBBackend):
        self._backend = backend
        self._dynamo_repo = None

    def _get_pg_session(self):
        from cerebro.core.database import async_session_factory
        return async_session_factory()

    def _get_dynamo_repo(self):
        if self._dynamo_repo is None:
            from cerebro.agents.repositories.dynamodb_session_repository import (
                DynamoDBAgentSessionRepository,
            )
            self._dynamo_repo = DynamoDBAgentSessionRepository()
        return self._dynamo_repo

    async def get(self, session_id: UUID, org_id: Optional[UUID] = None) -> Optional[Any]:
        """Get session by ID."""
        if self._backend in (DBBackend.DYNAMODB, DBBackend.DUAL):
            return await self._get_dynamo_repo().get_session(session_id, org_id)
        else:
            from cerebro.agents.models import AgentSession
            from sqlalchemy import select
            async with self._get_pg_session() as session:
                query = select(AgentSession).where(AgentSession.id == session_id)
                if org_id:
                    query = query.where(AgentSession.org_id == org_id)
                result = await session.execute(query)
                return result.scalar_one_or_none()

    async def list_sessions(
        self,
        org_id: UUID,
        agent_type: Optional[str] = None,
        created_by: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Any], int]:
        """List sessions for an organization."""
        if self._backend in (DBBackend.DYNAMODB, DBBackend.DUAL):
            from cerebro.agents.dynamodb_models import AgentType
            agent_type_enum = AgentType(agent_type) if agent_type else None
            return await self._get_dynamo_repo().list_sessions(
                org_id=org_id,
                agent_type=agent_type_enum,
                created_by=created_by,
                limit=limit,
                offset=offset,
            )
        else:
            from cerebro.agents.models import AgentSession
            from sqlalchemy import select, func
            async with self._get_pg_session() as session:
                filters = [AgentSession.org_id == org_id]
                if agent_type:
                    filters.append(AgentSession.agent_type == agent_type)
                if created_by:
                    filters.append(AgentSession.created_by == created_by)

                query = (
                    select(AgentSession)
                    .where(*filters)
                    .order_by(AgentSession.created_at.desc())
                    .limit(limit)
                    .offset(offset)
                )
                result = await session.execute(query)
                sessions = list(result.scalars())

                count_query = select(func.count(AgentSession.id)).where(*filters)
                count_result = await session.execute(count_query)
                total = count_result.scalar_one()

                return sessions, total


class DBFacade:
    """Unified database facade providing access to all entity facades."""

    def __init__(self, backend: Optional[DBBackend] = None):
        self._backend = backend or get_db_backend()
        self._organizations = None
        self._accounts = None
        self._findings = None
        self._rules = None
        self._agent_sessions = None

    @property
    def backend(self) -> DBBackend:
        """Get current backend."""
        return self._backend

    @property
    def organizations(self) -> OrganizationFacade:
        """Get organization facade."""
        if self._organizations is None:
            self._organizations = OrganizationFacade(self._backend)
        return self._organizations

    @property
    def accounts(self) -> AccountFacade:
        """Get account facade."""
        if self._accounts is None:
            self._accounts = AccountFacade(self._backend)
        return self._accounts

    @property
    def findings(self) -> FindingFacade:
        """Get finding facade."""
        if self._findings is None:
            self._findings = FindingFacade(self._backend)
        return self._findings

    @property
    def rules(self) -> RuleFacade:
        """Get rule facade."""
        if self._rules is None:
            self._rules = RuleFacade(self._backend)
        return self._rules

    @property
    def agent_sessions(self) -> AgentSessionFacade:
        """Get agent session facade."""
        if self._agent_sessions is None:
            self._agent_sessions = AgentSessionFacade(self._backend)
        return self._agent_sessions


# Global facade instance
_db_facade: Optional[DBFacade] = None


def get_db_facade() -> DBFacade:
    """Get the global database facade instance."""
    global _db_facade
    if _db_facade is None:
        _db_facade = DBFacade()
    return _db_facade


def reset_db_facade() -> None:
    """Reset the global facade (useful for testing)."""
    global _db_facade
    _db_facade = None


@asynccontextmanager
async def db_facade_context(backend: Optional[DBBackend] = None) -> AsyncGenerator[DBFacade, None]:
    """Context manager for database operations with specific backend."""
    facade = DBFacade(backend)
    try:
        yield facade
    finally:
        pass
