"""DynamoDB repositories for Cerebro core entities."""

from cerebro.core.repositories.account import Account, AccountRepository
from cerebro.core.repositories.agents import (
    AgentMessage,
    AgentMessageRepository,
    AgentSession,
    AgentSessionRepository,
    AgentType,
    MessageRole,
    ToolInvocation,
    ToolInvocationRepository,
    ToolInvocationStatus,
)
from cerebro.core.repositories.factory import (
    RepositoryFactory,
    get_account_repo,
    get_finding_repo,
    get_message_repo,
    get_org_repo,
    get_principal_repo,
    get_repositories,
    get_resource_repo,
    get_rule_repo,
    get_session_repo,
    get_tool_repo,
)
from cerebro.core.repositories.finding import (
    Finding,
    FindingRepository,
    FindingStatus,
    Severity,
)
from cerebro.core.repositories.organization import Organization, OrganizationRepository
from cerebro.core.repositories.principal import Principal, PrincipalRepository
from cerebro.core.repositories.resource import Resource, ResourceRepository
from cerebro.core.repositories.rule import Rule, RuleRepository

__all__ = [
    # Models
    "Organization",
    "Account", 
    "Finding",
    "FindingStatus",
    "Severity",
    "Rule",
    "Principal",
    "Resource",
    "AgentSession",
    "AgentType",
    "AgentMessage",
    "MessageRole",
    "ToolInvocation",
    "ToolInvocationStatus",
    # Repositories
    "OrganizationRepository",
    "AccountRepository",
    "FindingRepository",
    "RuleRepository",
    "PrincipalRepository",
    "ResourceRepository",
    "AgentSessionRepository",
    "AgentMessageRepository",
    "ToolInvocationRepository",
    # Factory
    "RepositoryFactory",
    "get_repositories",
    "get_org_repo",
    "get_finding_repo",
    "get_account_repo",
    "get_rule_repo",
    "get_principal_repo",
    "get_resource_repo",
    "get_session_repo",
    "get_message_repo",
    "get_tool_repo",
]
