"""
Query tools for Cerebro agents.

Provides secure access to Cerebro's temporal query capabilities for investigating
configuration changes and audit trails over time.
"""

from typing import Any, Dict, List
from datetime import datetime, timezone
from uuid import UUID

import structlog
from pydantic import BaseModel, Field


from .base import Tool, ToolResult, AgentContext, ToolPermissionLevel

logger = structlog.get_logger(__name__)


# Input/Output Schemas

class RunQueryInput(BaseModel):
    """Input for running a query."""
    query_name: str = Field(description="Name of predefined query to run")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Query parameters")
    limit: int = Field(default=100, description="Maximum results to return", ge=1, le=1000)


class RunQueryOutput(BaseModel):
    """Output from query execution."""
    query_name: str
    results: List[Dict[str, Any]]
    result_count: int
    execution_time_ms: float
    parameters_used: Dict[str, Any]


class QueryTool(Tool):
    """Tool for running predefined temporal queries."""
    
    @property
    def name(self) -> str:
        return "query"
    
    @property
    def description(self) -> str:
        return "Execute predefined temporal queries against configuration and audit data"
    
    @property
    def input_schema(self) -> type:
        return RunQueryInput
    
    @property
    def output_schema(self) -> type:
        return RunQueryOutput
    
    @property
    def permission_level(self) -> ToolPermissionLevel:
        return ToolPermissionLevel.READ_ONLY
    
    async def execute(self, inputs: BaseModel, context: AgentContext) -> ToolResult:
        """Execute a predefined query."""
        query_inputs = RunQueryInput(**inputs.model_dump())
        
        try:
            import time
            from sqlalchemy import select
            from cerebro.core.models import Finding, ConfigSnapshot, AuditEvent
            
            start_time = time.time()
            
            from cerebro.core.database import async_session_factory
            async with async_session_factory() as session:
                results = []
                
                # Execute predefined queries based on query name
                if query_inputs.query_name == "recent_config_changes":
                    # Query recent configuration changes - must join through resource to get org
                    from cerebro.core.models import Resource, Account

                    query = (
                        select(ConfigSnapshot, Resource)
                        .join(Resource, ConfigSnapshot.resource_id == Resource.resource_id)
                        .join(Account, Resource.account_id == Account.account_id)
                        .where(Account.org_id == context.org_id)
                        .order_by(ConfigSnapshot.captured_at.desc())
                        .limit(query_inputs.limit)
                    )

                    result = await session.execute(query)
                    rows = result.all()

                    results = [
                        {
                            "snapshot_id": str(snap.snapshot_id),
                            "provider": resource.provider,
                            "resource_type": resource.resource_type,
                            "resource_name": resource.name or "unnamed",
                            "captured_at": snap.captured_at.isoformat(),
                            "change_summary": f"Config captured for {resource.resource_type}",
                        }
                        for snap, resource in rows
                    ]
                
                elif query_inputs.query_name == "audit_events":
                    # Query audit events with parameters
                    hours_back = query_inputs.parameters.get("hours_back", 24)
                    action_filter = query_inputs.parameters.get("action")

                    # Note: AuditEvent schema uses different field names than expected:
                    # - occurred_at instead of timestamp
                    # - action instead of event_type
                    # - actor_external_id instead of actor
                    # - resource_external_id instead of resource_id
                    # - raw instead of details
                    # - account_id instead of org_id (must join through Account)

                    from datetime import timedelta
                    time_threshold = datetime.now(timezone.utc) - timedelta(hours=hours_back)

                    from cerebro.core.models import Account

                    query = (
                        select(AuditEvent, Account)
                        .join(Account, AuditEvent.account_id == Account.account_id)
                        .where(Account.org_id == context.org_id)
                        .where(AuditEvent.occurred_at >= time_threshold)
                    )

                    if action_filter:
                        query = query.where(AuditEvent.action == action_filter)

                    query = query.order_by(AuditEvent.occurred_at.desc()).limit(query_inputs.limit)

                    result = await session.execute(query)
                    rows = result.all()

                    results = [
                        {
                            "event_id": str(event.event_id),
                            "action": event.action,
                            "actor": event.actor_external_id or "system",
                            "resource": event.resource_external_id,
                            "provider": event.provider,
                            "occurred_at": event.occurred_at.isoformat(),
                            "raw_event": event.raw,
                        }
                        for event, account in rows
                    ]
                
                elif query_inputs.query_name == "iam_permissions":
                    # Query IAM permission edges - Note: IamEdge uses edge_id not iam_edge_id
                    # and effective_at not effective_date, and has account_id not org_id
                    principal_id_param = query_inputs.parameters.get("principal_id")

                    from cerebro.core.models import Account, IamEdge

                    query = (
                        select(IamEdge)
                        .join(Account, IamEdge.account_id == Account.account_id)
                        .where(Account.org_id == context.org_id)
                    )

                    if principal_id_param:
                        try:
                            principal_uuid = UUID(principal_id_param)
                            query = query.where(IamEdge.principal_id == principal_uuid)
                        except (ValueError, TypeError):
                            logger.warning("Invalid principal_id format", principal_id=principal_id_param)

                    query = query.order_by(IamEdge.effective_at.desc()).limit(query_inputs.limit)

                    result = await session.execute(query)
                    edges = result.scalars().all()

                    results = [
                        {
                            "edge_id": str(edge.edge_id),
                            "principal_id": str(edge.principal_id),
                            "resource_id": str(edge.resource_id) if edge.resource_id else None,
                            "permission": edge.permission,
                            "provider": edge.provider,
                            "effective_at": edge.effective_at.isoformat(),
                            "expires_at": edge.expires_at.isoformat() if edge.expires_at else None,
                            "is_admin": edge.is_admin,
                            "via": edge.via,
                        }
                        for edge in edges
                    ]
                
                elif query_inputs.query_name == "findings_timeline":
                    # Query findings over time
                    days_back = query_inputs.parameters.get("days_back", 30)

                    from datetime import timedelta
                    from sqlalchemy import func
                    time_threshold = datetime.now(timezone.utc) - timedelta(days=days_back)

                    date_expr = func.date(Finding.first_seen)

                    query = (
                        select(
                            date_expr.label('date'),
                            Finding.severity,
                            Finding.provider,
                            func.count(Finding.finding_id).label('count')
                        )
                        .where(Finding.org_id == context.org_id)
                        .where(Finding.first_seen >= time_threshold)
                        .group_by(date_expr, Finding.severity, Finding.provider)
                        .order_by(date_expr.desc())
                        .limit(query_inputs.limit)
                    )

                    result = await session.execute(query)

                    results = [
                        {
                            "date": (
                                row.date
                                if isinstance(row.date, str)
                                else (
                                    row.date.isoformat()
                                    if hasattr(row.date, "isoformat")
                                    else str(row.date)
                                )
                            ),
                            "severity": row.severity,
                            "count": row.count,
                            "provider": row.provider,
                        }
                        for row in result
                    ]
                
                else:
                    return ToolResult(
                        success=False,
                        error=f"Unknown query: {query_inputs.query_name}. Available queries: recent_config_changes, audit_events, iam_permissions, findings_timeline",
                    )
                
                execution_time = (time.time() - start_time) * 1000
                
                output = RunQueryOutput(
                    query_name=query_inputs.query_name,
                    results=results,
                    result_count=len(results),
                    execution_time_ms=execution_time,
                    parameters_used=query_inputs.parameters,
                )
                
                return ToolResult(
                    success=True,
                    data=output.model_dump(),
                    metadata={
                        "query_type": "temporal",
                        "org_scoped": True,
                        "execution_time_ms": execution_time,
                        "available_queries": ["recent_config_changes", "audit_events", "iam_permissions", "findings_timeline"],
                    },
                )
                
        except Exception as e:
            logger.exception("Query execution failed", query_name=query_inputs.query_name, error=str(e))
            return ToolResult(
                success=False,
                error=f"Query execution error: {str(e)}",
            )
