"""Unified Cerebro SDK facade for application developers."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from typing import Optional

from prometheus_client import CollectorRegistry
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cerebro_sdk.agents import (
    AgentAnalyticsClient,
    AgentManager,
    AgentNotificationManager,
    AgentPlaybook,
    AgentReviewManager,
    AgentToolingManager,
)
from cerebro_sdk.analytics import (
    IntegrationCoverageClient,
    RuntimeHealthClient,
)
from cerebro_sdk.auth import AuthSession
from cerebro_sdk.findings import FindingService
from cerebro_sdk.integrations import IntegrationService
from cerebro_sdk.organizations import OrganizationManager
from cerebro_sdk.tasks import TaskManager
from cerebro_sdk.users import UserManager


@dataclass
class AgentFacades:
    manager: AgentManager
    review: AgentReviewManager
    analytics: AgentAnalyticsClient
    tooling: AgentToolingManager
    notifications: AgentNotificationManager
    playbooks: AgentPlaybook


@dataclass
class AnalyticsFacades:
    runtime_health: RuntimeHealthClient
    integration_coverage: IntegrationCoverageClient


class UnifiedCerebroSDK:
    """Aggregate entrypoint bundling common Cerebro SDK facades."""

    def __init__(
        self,
        session: AsyncSession,
        *,
        registry: CollectorRegistry | None = None,
        celery_app=None,
    ) -> None:
        self._session = session
        self._registry = registry
        self._celery_app = celery_app

    @property
    def session(self) -> AsyncSession:
        return self._session

    @cached_property
    def auth(self) -> AuthSession:
        return AuthSession(self._session)

    @cached_property
    def users(self) -> UserManager:
        return UserManager(self._session)

    @cached_property
    def organizations(self) -> OrganizationManager:
        return OrganizationManager(self._session)

    @cached_property
    def findings(self) -> FindingService:
        return FindingService(self._session)

    @cached_property
    def integrations(self) -> IntegrationService:
        return IntegrationService(self._session)

    @cached_property
    def agents(self) -> AgentFacades:
        registry = self._registry
        return AgentFacades(
            manager=AgentManager(self._session),
            review=AgentReviewManager(self._session),
            analytics=AgentAnalyticsClient(self._session),
            tooling=AgentToolingManager(self._session, registry=registry),
            notifications=AgentNotificationManager(self._session, registry=registry),
            playbooks=AgentPlaybook(self._session, registry=registry),
        )

    @cached_property
    def analytics(self) -> AnalyticsFacades:
        return AnalyticsFacades(
            runtime_health=RuntimeHealthClient(self._session),
            integration_coverage=IntegrationCoverageClient(self._session),
        )

    @cached_property
    def tasks(self) -> TaskManager:
        return TaskManager(app=self._celery_app)

    @classmethod
    def from_session_factory(
        cls,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        registry: CollectorRegistry | None = None,
        celery_app=None,
    ) -> "UnifiedCerebroSDKContext":
        return UnifiedCerebroSDKContext(
            session_factory,
            registry=registry,
            celery_app=celery_app,
        )


class UnifiedCerebroSDKContext:
    """Async context manager producing a unified SDK bound to a session factory."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        registry: CollectorRegistry | None = None,
        celery_app=None,
    ) -> None:
        self._session_factory = session_factory
        self._registry = registry
        self._celery_app = celery_app
        self._session_manager = None
        self._active_session: Optional[AsyncSession] = None

    async def __aenter__(self) -> UnifiedCerebroSDK:
        manager = self._session_factory()
        self._session_manager = manager
        if hasattr(manager, "__aenter__"):
            session = await manager.__aenter__()
        else:
            session = manager
        self._active_session = session
        return UnifiedCerebroSDK(session, registry=self._registry, celery_app=self._celery_app)

    async def __aexit__(self, exc_type, exc, tb) -> None:
        manager = self._session_manager
        if manager and hasattr(manager, "__aexit__"):
            await manager.__aexit__(exc_type, exc, tb)
        elif self._active_session and hasattr(self._active_session, "close"):
            await self._active_session.close()


__all__ = [
    "UnifiedCerebroSDK",
    "UnifiedCerebroSDKContext",
    "AgentFacades",
    "AnalyticsFacades",
]
