"""
Query tools for Cerebro agents.

Provides secure access to Cerebro's temporal query capabilities for investigating
configuration changes and audit trails over time.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime
from uuid import UUID

import structlog
from pydantic import BaseModel, Field

from cerebro.core.database import get_db

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
            from sqlalchemy import select, text
            from cerebro.core.models import Finding, ConfigSnapshot, AuditEvent, IAMEdge
            
            start_time = time.time()
            
            from cerebro.core.database import async_session_factory
            async with async_session_factory() as session:
                results = []
                
                # Execute predefined queries based on query name
                if query_inputs.query_name == "recent_config_changes":
                    # Query recent configuration changes
                    query = select(ConfigSnapshot).where(
                        ConfigSnapshot.org_id == context.org_id
                    ).order_by(ConfigSnapshot.collected_at.desc()).limit(query_inputs.limit)
                    
                    result = await session.execute(query)
                    snapshots = result.scalars().all()
                    
                    results = [
                        {
                            "snapshot_id": str(snap.config_snapshot_id),
                            "provider": snap.provider,
                            "resource_type": snap.resource_type,
                            "collected_at": snap.collected_at.isoformat(),
                            "change_summary": f"Config collected for {snap.resource_type}",
                        }
                        for snap in snapshots
                    ]
                
                elif query_inputs.query_name == "audit_events":
                    # Query audit events with parameters
                    hours_back = query_inputs.parameters.get("hours_back", 24)
                    event_type = query_inputs.parameters.get("event_type")
                    
                    # Use raw SQL for audit events
                    sql = text("""
                        SELECT event_id, event_type, actor, resource_id, timestamp, details
                        FROM audit_events 
                        WHERE org_id = :org_id 
                        AND timestamp >= NOW() - INTERVAL ':hours_back hours'
                        AND (:event_type IS NULL OR event_type = :event_type)
                        ORDER BY timestamp DESC
                        LIMIT :limit
                    """)
                    
                    result = await session.execute(sql, {
                        "org_id": context.org_id,
                        "hours_back": hours_back,
                        "event_type": event_type,
                        "limit": query_inputs.limit
                    })
                    
                    results = [
                        {
                            "event_id": str(row.event_id),
                            "event_type": row.event_type,
                            "actor": row.actor,
                            "resource_id": row.resource_id,
                            "timestamp": row.timestamp.isoformat(),
                            "details": row.details,
                        }
                        for row in result
                    ]
                
                elif query_inputs.query_name == "iam_permissions":
                    # Query IAM permission edges
                    principal_id = query_inputs.parameters.get("principal_id")
                    
                    query = select(IAMEdge).where(IAMEdge.org_id == context.org_id)
                    if principal_id:
                        query = query.where(IAMEdge.principal_id == principal_id)
                    query = query.limit(query_inputs.limit)
                    
                    result = await session.execute(query)
                    edges = result.scalars().all()
                    
                    results = [
                        {
                            "edge_id": str(edge.iam_edge_id),
                            "principal_id": str(edge.principal_id),
                            "resource_id": str(edge.resource_id),
                            "permission": edge.permission,
                            "provider": edge.provider,
                            "effective_date": edge.effective_date.isoformat(),
                        }
                        for edge in edges
                    ]
                
                elif query_inputs.query_name == "findings_timeline":
                    # Query findings over time
                    days_back = query_inputs.parameters.get("days_back", 30)
                    
                    sql = text("""
                        SELECT 
                            DATE(first_seen) as date,
                            severity,
                            COUNT(*) as count,
                            provider
                        FROM findings 
                        WHERE org_id = :org_id 
                        AND first_seen >= NOW() - INTERVAL ':days_back days'
                        GROUP BY DATE(first_seen), severity, provider
                        ORDER BY date DESC
                        LIMIT :limit
                    """)
                    
                    result = await session.execute(sql, {
                        "org_id": context.org_id,
                        "days_back": days_back,
                        "limit": query_inputs.limit
                    })
                    
                    results = [
                        {
                            "date": row.date.isoformat(),
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
