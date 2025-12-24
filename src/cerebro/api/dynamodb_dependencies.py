"""FastAPI dependencies for DynamoDB repositories.

These dependencies provide DynamoDB repository instances for API routes.
They can be used alongside or instead of the SQLAlchemy-based dependencies.
"""

from cerebro.core.repositories import (
    AccountRepository,
    AgentMessageRepository,
    AgentSessionRepository,
    FindingRepository,
    OrganizationRepository,
    PrincipalRepository,
    ResourceRepository,
    RuleRepository,
    ToolInvocationRepository,
)

# Singleton instances (repositories are stateless)
_org_repo: OrganizationRepository | None = None
_account_repo: AccountRepository | None = None
_finding_repo: FindingRepository | None = None
_rule_repo: RuleRepository | None = None
_principal_repo: PrincipalRepository | None = None
_resource_repo: ResourceRepository | None = None
_session_repo: AgentSessionRepository | None = None
_message_repo: AgentMessageRepository | None = None
_tool_repo: ToolInvocationRepository | None = None


def get_org_repository() -> OrganizationRepository:
    """Get organization repository."""
    global _org_repo
    if _org_repo is None:
        _org_repo = OrganizationRepository()
    return _org_repo


def get_account_repository() -> AccountRepository:
    """Get account repository."""
    global _account_repo
    if _account_repo is None:
        _account_repo = AccountRepository()
    return _account_repo


def get_finding_repository() -> FindingRepository:
    """Get finding repository."""
    global _finding_repo
    if _finding_repo is None:
        _finding_repo = FindingRepository()
    return _finding_repo


def get_rule_repository() -> RuleRepository:
    """Get rule repository."""
    global _rule_repo
    if _rule_repo is None:
        _rule_repo = RuleRepository()
    return _rule_repo


def get_principal_repository() -> PrincipalRepository:
    """Get principal repository."""
    global _principal_repo
    if _principal_repo is None:
        _principal_repo = PrincipalRepository()
    return _principal_repo


def get_resource_repository() -> ResourceRepository:
    """Get resource repository."""
    global _resource_repo
    if _resource_repo is None:
        _resource_repo = ResourceRepository()
    return _resource_repo


def get_session_repository() -> AgentSessionRepository:
    """Get agent session repository."""
    global _session_repo
    if _session_repo is None:
        _session_repo = AgentSessionRepository()
    return _session_repo


def get_message_repository() -> AgentMessageRepository:
    """Get agent message repository."""
    global _message_repo
    if _message_repo is None:
        _message_repo = AgentMessageRepository()
    return _message_repo


def get_tool_invocation_repository() -> ToolInvocationRepository:
    """Get tool invocation repository."""
    global _tool_repo
    if _tool_repo is None:
        _tool_repo = ToolInvocationRepository()
    return _tool_repo


# FastAPI dependency versions
async def org_repository() -> OrganizationRepository:
    """FastAPI dependency for organization repository."""
    return get_org_repository()


async def account_repository() -> AccountRepository:
    """FastAPI dependency for account repository."""
    return get_account_repository()


async def finding_repository() -> FindingRepository:
    """FastAPI dependency for finding repository."""
    return get_finding_repository()


async def rule_repository() -> RuleRepository:
    """FastAPI dependency for rule repository."""
    return get_rule_repository()


async def principal_repository() -> PrincipalRepository:
    """FastAPI dependency for principal repository."""
    return get_principal_repository()


async def resource_repository() -> ResourceRepository:
    """FastAPI dependency for resource repository."""
    return get_resource_repository()


async def session_repository() -> AgentSessionRepository:
    """FastAPI dependency for agent session repository."""
    return get_session_repository()


async def message_repository() -> AgentMessageRepository:
    """FastAPI dependency for agent message repository."""
    return get_message_repository()


async def tool_invocation_repository() -> ToolInvocationRepository:
    """FastAPI dependency for tool invocation repository."""
    return get_tool_invocation_repository()


def reset_repositories() -> None:
    """Reset all repository singletons (for testing)."""
    global _org_repo, _account_repo, _finding_repo, _rule_repo
    global _principal_repo, _resource_repo, _session_repo, _message_repo, _tool_repo

    _org_repo = None
    _account_repo = None
    _finding_repo = None
    _rule_repo = None
    _principal_repo = None
    _resource_repo = None
    _session_repo = None
    _message_repo = None
    _tool_repo = None
