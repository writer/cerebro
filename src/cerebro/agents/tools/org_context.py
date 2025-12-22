"""
Organization Context Tool

Provides agents with immediate understanding of the organization's setup,
repositories, providers, and system architecture without requiring user explanation.

This is the "quick win" implementation that gives agents baseline knowledge
before full RAG/vector search system is implemented.
"""

from typing import Any, Dict, List, Optional
from uuid import UUID
from pydantic import BaseModel, Field
from pathlib import Path

from .base import StructuredTool, AgentContext, ToolResult, ToolPermissionLevel
from cerebro.core.database import async_session_factory
from cerebro.core.models import Organization, Account, Principal, Resource
from sqlalchemy import select, func, distinct
import structlog

logger = structlog.get_logger(__name__)


class OrgContextInput(BaseModel):
    """Input for organization context retrieval."""

    include_repositories: bool = Field(
        default=True, description="Include repository metadata"
    )
    include_providers: bool = Field(
        default=True, description="Include connected provider information"
    )
    include_statistics: bool = Field(
        default=True, description="Include resource/principal counts"
    )
    include_tools: bool = Field(
        default=True, description="Include available agent tools"
    )


class RepositoryInfo(BaseModel):
    """Repository metadata."""

    name: str
    path: str
    type: str
    primary_language: str
    framework: str
    description: str
    key_modules: List[str]


class ProviderInfo(BaseModel):
    """Provider connection info."""

    provider: str
    account_count: int
    resource_count: int
    principal_count: int
    last_collected: Optional[str]


class OrgContextOutput(BaseModel):
    """Organization context output."""

    org_name: str
    org_id: str

    # Repositories
    repositories: Optional[List[RepositoryInfo]] = None

    # Providers & Integrations
    providers_connected: Optional[List[ProviderInfo]] = None
    providers_supported: Optional[List[str]] = None

    # Agent Tools
    agent_tools_count: Optional[int] = None
    agent_tools_available: Optional[List[str]] = None

    # Statistics
    statistics: Optional[Dict[str, int]] = None

    # System Info
    system_info: Optional[Dict[str, Any]] = None


class GetOrgContextTool(StructuredTool):
    """
    Provide agents with organizational context and system understanding.

    This tool gives agents immediate awareness of:
    - Repository structure and tech stack
    - Connected cloud/SaaS providers
    - Available security tools and capabilities
    - Current resource/principal inventory
    - System architecture overview

    This eliminates the need for users to repeatedly explain the setup
    and allows agents to provide contextual, specific responses.

    Example uses:
    - "What providers are we connected to?"
    - "Show me the repo structure"
    - "What tools do I have available?"
    - "Give me an overview of the environment"
    """

    tool_name = "get_org_context"
    tool_description = (
        "Get organizational context including repos, providers, tools, and system info"
    )
    tool_version = "1.0.0"
    input_model = OrgContextInput
    output_model = OrgContextOutput

    # Read-only, safe for all agents
    required_permission = ToolPermissionLevel.READ_ONLY

    async def _run(
        self,
        context: AgentContext,
        include_repositories: bool = True,
        include_providers: bool = True,
        include_statistics: bool = True,
        include_tools: bool = True,
    ) -> ToolResult:
        """
        Execute organization context retrieval.

        Args:
            context: Agent execution context
            include_repositories: Include repo metadata
            include_providers: Include provider info
            include_statistics: Include stats
            include_tools: Include tool list

        Returns:
            ToolResult with comprehensive org context
        """
        try:
            logger.info(
                "Organization context requested",
                org_id=context.org_id,
                session_id=context.session_id,
            )

            async with async_session_factory() as db_session:
                # Get organization
                org = await db_session.get(Organization, context.org_id)
                if not org:
                    return ToolResult(
                        success=False, error=f"Organization {context.org_id} not found"
                    )

                output_data = {
                    "org_name": org.name,
                    "org_id": str(org.org_id),
                }

                # 1. Repository Information
                if include_repositories:
                    output_data["repositories"] = await self._get_repository_info()

                # 2. Provider Information
                if include_providers:
                    provider_info = await self._get_provider_info(
                        db_session, context.org_id
                    )
                    output_data["providers_connected"] = provider_info
                    output_data["providers_supported"] = [
                        "AWS",
                        "GitHub",
                        "Okta",
                        "Google Workspace",
                        "Microsoft 365",
                        "GCP",
                        "Azure",
                    ]

                # 3. Statistics
                if include_statistics:
                    output_data["statistics"] = await self._get_statistics(
                        db_session, context.org_id
                    )

                # 4. Agent Tools
                if include_tools:
                    from cerebro.agents.tools import tool_registry

                    tools = tool_registry.list_tools()
                    output_data["agent_tools_count"] = len(tools)
                    output_data["agent_tools_available"] = [t.name for t in tools]

                # 5. System Info
                output_data["system_info"] = await self._get_system_info()

                output = OrgContextOutput(**output_data)

                logger.info(
                    "Organization context retrieved",
                    org_id=context.org_id,
                    repos=len(output_data.get("repositories", [])),
                    providers=len(output_data.get("providers_connected", [])),
                )

                return ToolResult(
                    success=True,
                    data=output.model_dump(),
                    metadata={
                        "org_id": str(context.org_id),
                        "context_complete": True,
                    },
                )

        except Exception as e:
            logger.error("Failed to get org context", error=str(e), exc_info=True)
            return ToolResult(
                success=False,
                error=f"Failed to retrieve organization context: {str(e)}",
            )

    async def _get_repository_info(self) -> List[Dict[str, Any]]:
        """Get repository metadata from filesystem analysis."""

        repos = []

        # Backend Repository
        backend_path = Path("/app") if Path("/app").exists() else Path.cwd()
        if (backend_path / "src" / "cerebro").exists():
            repos.append(
                {
                    "name": "cerebro",
                    "path": str(backend_path),
                    "type": "backend",
                    "primary_language": "Python",
                    "framework": "FastAPI",
                    "description": "Enterprise security system of record with AI agent integration",
                    "key_modules": [
                        "agents/ - AI security agents with curated core toolset",
                        "api/ - REST API endpoints",
                        "collectors/ - Multi-provider data collection",
                        "rules/ - CEL policy engine",
                        "query/ - Zero-ETL security analytics",
                        "analytics/ - Runtime telemetry & observability",
                        "memory/ - Long-term contextual memory",
                        "analysis/ - Timeline reconstruction & risk insights",
                    ],
                }
            )

        # Check for frontend (common paths)
        frontend_paths = [
            Path("/app/cerebro-frontend"),
            Path.cwd().parent / "cerebro-frontend",
            Path.cwd() / "../cerebro-frontend",
        ]

        for frontend_path in frontend_paths:
            if frontend_path.exists() and (frontend_path / "src" / "app").exists():
                repos.append(
                    {
                        "name": "cerebro-frontend",
                        "path": str(frontend_path),
                        "type": "frontend",
                        "primary_language": "TypeScript",
                        "framework": "Next.js 15 + React 19",
                        "description": "Modern web interface with real-time agent chat and security modules",
                        "key_modules": [
                            "app/agents - AI agent chat interface with SSE streaming",
                            "app/dashboard - Security posture overview",
                            "app/findings - Finding management",
                            "app/identity - Identity governance",
                            "app/compliance - Compliance hub",
                            "app/investigation - Forensic investigation",
                            "app/oauth-risk - OAuth risk center",
                            "app/vendors - Vendor management",
                        ],
                    }
                )
                break

        return repos

    async def _get_provider_info(
        self, db_session, org_id: UUID
    ) -> List[Dict[str, Any]]:
        """Get connected provider information from database."""

        # Query accounts by provider
        provider_query = (
            select(
                Account.provider,
                func.count(distinct(Account.account_id)).label("account_count"),
            )
            .where(Account.org_id == org_id)
            .group_by(Account.provider)
        )

        result = await db_session.execute(provider_query)
        provider_accounts = {row.provider: row.account_count for row in result}

        # Get resource counts per provider
        resource_query = (
            select(
                Resource.provider,
                func.count(distinct(Resource.resource_id)).label("resource_count"),
            )
            .where(Resource.org_id == org_id)
            .group_by(Resource.provider)
        )

        result = await db_session.execute(resource_query)
        provider_resources = {row.provider: row.resource_count for row in result}

        # Get principal counts per provider
        principal_query = (
            select(
                Principal.provider,
                func.count(distinct(Principal.principal_id)).label("principal_count"),
            )
            .where(Principal.org_id == org_id)
            .group_by(Principal.provider)
        )

        result = await db_session.execute(principal_query)
        provider_principals = {row.provider: row.principal_count for row in result}

        # Combine into provider info
        providers = []
        all_providers = (
            set(provider_accounts.keys())
            | set(provider_resources.keys())
            | set(provider_principals.keys())
        )

        for provider in all_providers:
            providers.append(
                {
                    "provider": provider,
                    "account_count": provider_accounts.get(provider, 0),
                    "resource_count": provider_resources.get(provider, 0),
                    "principal_count": provider_principals.get(provider, 0),
                    "last_collected": None,  # TODO: Add from collection metadata
                }
            )

        return sorted(providers, key=lambda x: x["resource_count"], reverse=True)

    async def _get_statistics(self, db_session, org_id: UUID) -> Dict[str, int]:
        """Get resource/principal statistics."""

        stats = {}

        # Total accounts
        account_count = await db_session.scalar(
            select(func.count(Account.account_id)).where(Account.org_id == org_id)
        )
        stats["total_accounts"] = account_count or 0

        # Total resources
        resource_count = await db_session.scalar(
            select(func.count(Resource.resource_id)).where(Resource.org_id == org_id)
        )
        stats["total_resources"] = resource_count or 0

        # Total principals
        principal_count = await db_session.scalar(
            select(func.count(Principal.principal_id)).where(Principal.org_id == org_id)
        )
        stats["total_principals"] = principal_count or 0

        # Total findings
        from cerebro.core.models import Finding

        finding_count = await db_session.scalar(
            select(func.count(Finding.finding_id)).where(Finding.org_id == org_id)
        )
        stats["total_findings"] = finding_count or 0

        # Open findings
        open_finding_count = await db_session.scalar(
            select(func.count(Finding.finding_id)).where(
                Finding.org_id == org_id, Finding.status == "open"
            )
        )
        stats["open_findings"] = open_finding_count or 0

        return stats

    async def _get_system_info(self) -> Dict[str, Any]:
        """Get system/platform information."""

        return {
            "platform": "Cerebro Security System of Record",
            "version": "1.0.0",
            "capabilities": [
                "AI Security Agents (15+ tools)",
                "Forensic Replay & Time Travel",
                "Attack Path Simulation",
                "Compliance Testing (SOC2, ISO27001, CIS, NIST CSF)",
                "Zero-ETL SQL Query Engine",
                "Identity Anomaly Detection",
                "OAuth Risk Management",
                "Vendor Risk Intelligence",
                "CEL Policy Engine",
                "Cryptographic Audit Trail",
            ],
            "deployment_type": "self-hosted",
            "data_sovereignty": "full",
            "audit_trail": "append-only with cryptographic integrity",
        }
