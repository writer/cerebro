"""
System Context Tool

Provides agents with runtime system information including deployment environment,
database status, provider connectivity, and operational health.

This complements get_org_context by adding infrastructure/ops awareness.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import os
import sys
from datetime import datetime, timezone

from .base import StructuredTool, AgentContext, ToolResult, ToolPermissionLevel
from cerebro.core.database import async_session_factory, engine
from cerebro.core.models import Organization, Account, Resource, ConfigSnapshot
from sqlalchemy import func, select, text
import structlog

logger = structlog.get_logger(__name__)


class SystemContextInput(BaseModel):
    """Input for system context retrieval."""

    include_database: bool = Field(
        default=True, description="Include database connectivity and status"
    )
    include_environment: bool = Field(
        default=True, description="Include deployment environment info"
    )
    include_providers: bool = Field(
        default=True, description="Include provider connectivity status"
    )
    include_health: bool = Field(
        default=True, description="Include system health metrics"
    )


class DatabaseInfo(BaseModel):
    """Database connection info."""

    connected: bool
    database_url_masked: str
    pg_version: Optional[str]
    connection_pool_size: Optional[int]
    extensions: Optional[List[str]]


class EnvironmentInfo(BaseModel):
    """Deployment environment info."""

    python_version: str
    deployment_type: str  # docker, k8s, bare-metal, dev
    environment: str  # production, staging, development
    base_url: Optional[str]
    redis_configured: bool
    anthropic_api_configured: bool


class ProviderHealth(BaseModel):
    """Provider connectivity health."""

    provider: str
    status: str  # healthy, degraded, offline
    last_collection: Optional[str]
    error_rate: Optional[float]


class SystemHealthMetrics(BaseModel):
    """System health metrics."""

    uptime_seconds: Optional[float]
    memory_usage_mb: Optional[float]
    active_agent_sessions: int
    total_organizations: int
    background_tasks_running: int


class SystemContextOutput(BaseModel):
    """System context output."""

    timestamp: str
    database: Optional[DatabaseInfo] = None
    environment: Optional[EnvironmentInfo] = None
    provider_health: Optional[List[ProviderHealth]] = None
    health_metrics: Optional[SystemHealthMetrics] = None


class GetSystemContextTool(StructuredTool):
    """
    Provide agents with system/infrastructure context.

    This tool gives agents runtime awareness of:
    - Database connectivity and status
    - Deployment environment (Docker, K8s, dev)
    - Provider health (AWS, GitHub, Okta)
    - System health metrics
    - Configuration status

    This helps agents understand operational state and troubleshoot
    issues related to connectivity, configuration, or system health.

    Example uses:
    - "What's the database status?"
    - "Are we running in production or development?"
    - "Check provider connectivity"
    - "System health check"
    """

    tool_name = "get_system_context"
    tool_description = (
        "Get system/infrastructure context including database, environment, and health"
    )
    tool_version = "1.0.0"
    input_model = SystemContextInput
    output_model = SystemContextOutput

    # Read-only, safe for all agents
    required_permission = ToolPermissionLevel.READ_ONLY

    async def _run(
        self,
        context: AgentContext,
        include_database: bool = True,
        include_environment: bool = True,
        include_providers: bool = True,
        include_health: bool = True,
    ) -> ToolResult:
        """
        Execute system context retrieval.

        Args:
            context: Agent execution context
            include_database: Include DB info
            include_environment: Include env info
            include_providers: Include provider health
            include_health: Include health metrics

        Returns:
            ToolResult with system context
        """
        try:
            logger.info(
                "System context requested",
                session_id=context.session_id,
            )

            output_data = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }

            # 1. Database Info
            if include_database:
                output_data["database"] = await self._get_database_info()

            # 2. Environment Info
            if include_environment:
                output_data["environment"] = await self._get_environment_info()

            # 3. Provider Health
            if include_providers:
                output_data["provider_health"] = await self._get_provider_health(
                    context.org_id
                )

            # 4. Health Metrics
            if include_health:
                output_data["health_metrics"] = await self._get_health_metrics()

            output = SystemContextOutput(**output_data)

            logger.info("System context retrieved successfully")

            return ToolResult(
                success=True,
                data=output.model_dump(),
                metadata={
                    "timestamp": output_data["timestamp"],
                },
            )

        except Exception:
            logger.exception(
                "Failed to get system context",
                session_id=context.session_id,
            )
            return ToolResult(
                success=False,
                error="Failed to retrieve system context",
            )

    async def _get_database_info(self) -> Dict[str, Any]:
        """Get database connectivity and status."""

        try:
            async with async_session_factory() as db_session:
                dialect = engine.url.get_backend_name()

                # Test connection
                await db_session.execute(text("SELECT 1"))

                pg_version: Optional[str] = None
                extensions: Optional[List[str]] = None
                if dialect == "postgresql":
                    pg_version_result = await db_session.execute(
                        text("SELECT version()")
                    )
                    pg_version_row = pg_version_result.fetchone()
                    pg_version = pg_version_row[0] if pg_version_row else None

                    ext_result = await db_session.execute(
                        text("SELECT extname FROM pg_extension ORDER BY extname")
                    )
                    extensions = [row[0] for row in ext_result.fetchall()]
                elif dialect == "sqlite":
                    sqlite_version_result = await db_session.execute(
                        text("select sqlite_version()")
                    )
                    sqlite_row = sqlite_version_result.fetchone()
                    pg_version = f"sqlite {sqlite_row[0]}" if sqlite_row else "sqlite"

                # Mask database URL for security
                db_url = os.getenv("DATABASE_URL", "")
                if "@" in db_url:
                    # postgresql://user:pass@host:port/db -> postgresql://***@host:port/db
                    parts = db_url.split("@")
                    masked_url = f"{parts[0].split('://')[0]}://***@{parts[1]}"
                else:
                    masked_url = "***"

                return {
                    "connected": True,
                    "database_url_masked": masked_url,
                    "pg_version": pg_version,
                    "connection_pool_size": None,
                    "extensions": extensions,
                }

        except Exception as e:
            logger.error("Database check failed", error=str(e))
            return {
                "connected": False,
                "database_url_masked": "***",
                "pg_version": None,
                "connection_pool_size": None,
                "extensions": None,
            }

    async def _get_environment_info(self) -> Dict[str, Any]:
        """Get deployment environment information."""

        # Detect deployment type
        deployment_type = "development"
        if os.path.exists("/.dockerenv"):
            deployment_type = "docker"
        elif os.getenv("KUBERNETES_SERVICE_HOST"):
            deployment_type = "kubernetes"

        # Detect environment
        environment = os.getenv("ENVIRONMENT", os.getenv("ENV", "development"))

        return {
            "python_version": sys.version.split()[0],
            "deployment_type": deployment_type,
            "environment": environment,
            "base_url": os.getenv("API_BASE_URL", os.getenv("BASE_URL")),
            "redis_configured": bool(os.getenv("REDIS_URL")),
            "anthropic_api_configured": bool(os.getenv("ANTHROPIC_API_KEY")),
        }

    async def _get_provider_health(self, org_id) -> List[Dict[str, Any]]:
        """Get provider connectivity health."""

        provider_health = []

        try:
            async with async_session_factory() as db_session:
                provider_query = (
                    select(
                        Account.provider,
                        func.count(func.distinct(Account.account_id)).label(
                            "account_count"
                        ),
                        func.max(ConfigSnapshot.captured_at).label("last_collection"),
                    )
                    .select_from(Account)
                    .outerjoin(Resource, Resource.account_id == Account.account_id)
                    .outerjoin(
                        ConfigSnapshot,
                        ConfigSnapshot.resource_id == Resource.resource_id,
                    )
                    .where(Account.org_id == org_id)
                    .group_by(Account.provider)
                )

                result = await db_session.execute(provider_query)

                for row in result:
                    # Determine health status
                    status = "healthy"
                    if not row.last_collection:
                        status = "offline"
                    else:
                        now = datetime.now(timezone.utc)
                        last_collection = row.last_collection
                        if last_collection.tzinfo is None:
                            last_collection = last_collection.replace(
                                tzinfo=timezone.utc
                            )

                        time_since_collection = now - last_collection
                        if time_since_collection.days > 1:
                            status = "degraded"

                    provider_health.append(
                        {
                            "provider": row.provider,
                            "status": status,
                            "last_collection": (
                                row.last_collection.isoformat()
                                if row.last_collection
                                else None
                            ),
                            "error_rate": None,  # TODO: Calculate from audit events
                        }
                    )

        except Exception as e:
            logger.error("Provider health check failed", error=str(e))

        return provider_health

    async def _get_health_metrics(self) -> Dict[str, Any]:
        """Get system health metrics."""

        try:
            async with async_session_factory() as db_session:
                # Count active agent sessions
                from cerebro.agents.models import AgentSession

                active_sessions = await db_session.scalar(
                    select(func.count(AgentSession.id)).where(
                        AgentSession.is_active.is_(True)
                    )
                )

                # Count total organizations
                total_orgs = await db_session.scalar(
                    select(func.count(Organization.org_id))
                )

                # Get memory usage (rough estimate)
                try:
                    import psutil

                    process = psutil.Process()
                    memory_usage_mb = process.memory_info().rss / 1024 / 1024
                except ImportError:
                    memory_usage_mb = None

                return {
                    "uptime_seconds": None,  # TODO: Track from app start
                    "memory_usage_mb": memory_usage_mb,
                    "active_agent_sessions": active_sessions or 0,
                    "total_organizations": total_orgs or 0,
                    "background_tasks_running": 0,  # TODO: Query from Celery
                }

        except Exception as e:
            logger.error("Health metrics collection failed", error=str(e))
            return {
                "uptime_seconds": None,
                "memory_usage_mb": None,
                "active_agent_sessions": 0,
                "total_organizations": 0,
                "background_tasks_running": 0,
            }
