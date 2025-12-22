"""Repository factory for DynamoDB repositories.

This module provides a factory pattern for creating repository instances,
making it easy to switch between implementations or mock for testing.
"""

from typing import Optional

from cerebro.core.repositories.account import AccountRepository
from cerebro.core.repositories.agents import (
    AgentMessageRepository,
    AgentSessionRepository,
    ToolInvocationRepository,
)
from cerebro.core.repositories.finding import FindingRepository
from cerebro.core.repositories.organization import OrganizationRepository
from cerebro.core.repositories.principal import PrincipalRepository
from cerebro.core.repositories.resource import ResourceRepository
from cerebro.core.repositories.rule import RuleRepository


class RepositoryFactory:
    """Factory for creating DynamoDB repository instances.

    Uses singleton pattern for repository instances since they're stateless.
    """

    _instance: Optional["RepositoryFactory"] = None

    def __init__(self):
        self._org_repo: Optional[OrganizationRepository] = None
        self._account_repo: Optional[AccountRepository] = None
        self._finding_repo: Optional[FindingRepository] = None
        self._rule_repo: Optional[RuleRepository] = None
        self._principal_repo: Optional[PrincipalRepository] = None
        self._resource_repo: Optional[ResourceRepository] = None
        self._session_repo: Optional[AgentSessionRepository] = None
        self._message_repo: Optional[AgentMessageRepository] = None
        self._tool_repo: Optional[ToolInvocationRepository] = None

    @classmethod
    def get_instance(cls) -> "RepositoryFactory":
        """Get singleton factory instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset factory instance (for testing)."""
        cls._instance = None

    @property
    def organizations(self) -> OrganizationRepository:
        """Get organization repository."""
        if self._org_repo is None:
            self._org_repo = OrganizationRepository()
        return self._org_repo

    @property
    def accounts(self) -> AccountRepository:
        """Get account repository."""
        if self._account_repo is None:
            self._account_repo = AccountRepository()
        return self._account_repo

    @property
    def findings(self) -> FindingRepository:
        """Get finding repository."""
        if self._finding_repo is None:
            self._finding_repo = FindingRepository()
        return self._finding_repo

    @property
    def rules(self) -> RuleRepository:
        """Get rule repository."""
        if self._rule_repo is None:
            self._rule_repo = RuleRepository()
        return self._rule_repo

    @property
    def principals(self) -> PrincipalRepository:
        """Get principal repository."""
        if self._principal_repo is None:
            self._principal_repo = PrincipalRepository()
        return self._principal_repo

    @property
    def resources(self) -> ResourceRepository:
        """Get resource repository."""
        if self._resource_repo is None:
            self._resource_repo = ResourceRepository()
        return self._resource_repo

    @property
    def agent_sessions(self) -> AgentSessionRepository:
        """Get agent session repository."""
        if self._session_repo is None:
            self._session_repo = AgentSessionRepository()
        return self._session_repo

    @property
    def agent_messages(self) -> AgentMessageRepository:
        """Get agent message repository."""
        if self._message_repo is None:
            self._message_repo = AgentMessageRepository()
        return self._message_repo

    @property
    def tool_invocations(self) -> ToolInvocationRepository:
        """Get tool invocation repository."""
        if self._tool_repo is None:
            self._tool_repo = ToolInvocationRepository()
        return self._tool_repo


# Convenience function
def get_repositories() -> RepositoryFactory:
    """Get repository factory instance."""
    return RepositoryFactory.get_instance()


# Direct access shortcuts
def get_org_repo() -> OrganizationRepository:
    """Get organization repository."""
    return get_repositories().organizations


def get_finding_repo() -> FindingRepository:
    """Get finding repository."""
    return get_repositories().findings


def get_account_repo() -> AccountRepository:
    """Get account repository."""
    return get_repositories().accounts


def get_rule_repo() -> RuleRepository:
    """Get rule repository."""
    return get_repositories().rules


def get_principal_repo() -> PrincipalRepository:
    """Get principal repository."""
    return get_repositories().principals


def get_resource_repo() -> ResourceRepository:
    """Get resource repository."""
    return get_repositories().resources


def get_session_repo() -> AgentSessionRepository:
    """Get agent session repository."""
    return get_repositories().agent_sessions


def get_message_repo() -> AgentMessageRepository:
    """Get agent message repository."""
    return get_repositories().agent_messages


def get_tool_repo() -> ToolInvocationRepository:
    """Get tool invocation repository."""
    return get_repositories().tool_invocations
