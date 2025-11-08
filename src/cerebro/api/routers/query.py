"""
Query API endpoints for SQL-based security data queries.

Provides REST endpoints for executing SQL queries against security tables.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, Field

from sqlalchemy.ext.asyncio import AsyncSession

from ...query.engine import QueryResult
from ...query.bootstrap import get_query_engine
from ..schemas.base import BaseResponse
from ..auth import get_current_user, require_scopes, require_read_findings, User
from ...core.database import get_db
from ...integrations.freshness import IntegrationFreshnessService

router = APIRouter(prefix="/query", tags=["Query"], dependencies=[Depends(get_current_user)])

# Initialize shared query engine
query_engine = get_query_engine()


class QueryRequest(BaseModel):
    """SQL query request."""
    sql: str = Field(..., description="SQL query to execute", json_schema_extra={"example": "SELECT * FROM aws_ec2_instance LIMIT 10"})
    timeout: Optional[int] = Field(30, description="Query timeout in seconds", ge=1, le=300)


class QueryResponse(BaseResponse):
    """SQL query response."""
    data: Dict[str, Any] = Field(..., description="Query result data")


class TableInfo(BaseModel):
    """Security table information."""
    name: str
    provider: str
    description: str
    columns: int
    filterable_columns: int


class TableDetailInfo(BaseModel):
    """Detailed security table information."""
    name: str
    provider: str
    description: str
    columns: List[Dict[str, Any]]
    indexes: List[Dict[str, Any]]


class TablesResponse(BaseResponse):
    """List of available tables response."""
    data: List[TableInfo] = Field(..., description="Available security tables")


class TableDetailResponse(BaseResponse):
    """Table detail response."""
    data: TableDetailInfo = Field(..., description="Table schema details")


@router.post("/execute", response_model=QueryResponse, summary="Execute SQL Query")
async def execute_sql_query(
    request: QueryRequest,
    current_user: User = Depends(require_scopes("query:execute")),
    db: AsyncSession = Depends(get_db),
) -> QueryResponse:
    """
    Execute a SQL query against security tables.
    
    Supports SELECT queries with WHERE, ORDER BY, and LIMIT clauses.
    Query results are returned with execution metadata.
    """
    try:
        result = await query_engine.execute_query(request.sql)
        
        if result.errors:
            raise HTTPException(
                status_code=400,
                detail={
                    "message": "Query execution failed",
                    "errors": result.errors
                }
            )
        
        providers = _derive_providers(result)
        freshness_service = IntegrationFreshnessService(db)
        provider_freshness = await freshness_service.provider_freshness(providers)
        freshness_payload = {
            provider: {
                "last_synced_at": summary.last_synced_at.isoformat() if summary.last_synced_at else None,
                "age_seconds": summary.age_seconds,
                "age_human": summary.age_human,
                "status": summary.status,
                "sources": summary.sources,
                "confidence": summary.confidence,
            }
            for provider, summary in provider_freshness.items()
        }
        warnings = [summary.warning for summary in provider_freshness.values() if summary.warning]

        return QueryResponse(
            success=True,
            message=f"Query executed successfully, returned {result.total_rows} rows",
            data={
                "columns": result.columns,
                "rows": result.rows,
                "total_rows": result.total_rows,
                "execution_time_ms": result.execution_time_ms,
                "tables_queried": result.tables_queried,
                "freshness": freshness_payload,
                "warnings": warnings,
            }
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"message": "Internal server error", "error": str(e)}
        )


@router.get("/tables", response_model=TablesResponse, summary="List Security Tables")
async def list_security_tables(
    provider: Optional[str] = Query(None, description="Filter by provider (aws, okta, github, etc.)"),
    current_user: User = Depends(get_current_user)
) -> TablesResponse:
    """
    List all available security tables.
    
    Returns table metadata including name, provider, description, and column counts.
    """
    try:
        tables = await query_engine.list_tables(provider=provider)
        
        table_info = [
            TableInfo(
                name=table["name"],
                provider=table["provider"], 
                description=table["description"],
                columns=table["columns"],
                filterable_columns=table["filterable_columns"]
            )
            for table in tables
        ]
        
        return TablesResponse(
            success=True,
            message=f"Found {len(table_info)} security tables",
            data=table_info
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"message": "Failed to list tables", "error": str(e)}
        )


@router.get("/tables/{table_name}", response_model=TableDetailResponse, summary="Get Table Schema")
async def get_table_schema(table_name: str) -> TableDetailResponse:
    """
    Get detailed schema information for a specific table.
    
    Returns complete column definitions, data types, and index information.
    """
    try:
        table_info = await query_engine.describe_table(table_name)
        
        if not table_info:
            raise HTTPException(
                status_code=404,
                detail={"message": f"Table '{table_name}' not found"}
            )
        
        detail_info = TableDetailInfo(
            name=table_info["name"],
            provider=table_info["provider"],
            description=table_info["description"], 
            columns=table_info["columns"],
            indexes=table_info["indexes"]
        )
        
        return TableDetailResponse(
            success=True,
            message=f"Retrieved schema for table '{table_name}'",
            data=detail_info
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"message": "Failed to get table schema", "error": str(e)}
        )


@router.get("/health", summary="Query Engine Health Check")
async def query_engine_health():
    """Check health status of the query engine."""
    try:
        health_info = await query_engine.health_check()
        return {
            "success": True,
            "message": "Query engine is healthy",
            "data": health_info
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"message": "Query engine health check failed", "error": str(e)}
        )


# Common query examples endpoint
@router.get("/examples", summary="Get Query Examples")
async def get_query_examples(current_user: User = Depends(get_current_user)):
    """
    Get example SQL queries for different security use cases.
    """
    examples = [
        {
            "name": "List AWS EC2 instances",
            "description": "Get all EC2 instances with basic information",
            "sql": "SELECT instance_id, instance_type, state, public_ip FROM aws_ec2_instance LIMIT 10"
        },
        {
            "name": "Find inactive Okta users", 
            "description": "List Okta users that haven't logged in recently",
            "sql": "SELECT username, email, status, last_login FROM okta_user WHERE status = 'inactive' ORDER BY last_login DESC"
        },
        {
            "name": "High severity vulnerability alerts",
            "description": "Find high/critical vulnerability alerts across GitHub repos",
            "sql": "SELECT repository, state, security_advisory FROM github_vulnerability_alert WHERE severity IN ('high', 'critical')"
        },
        {
            "name": "AWS security groups with wide access",
            "description": "Find security groups allowing access from anywhere", 
            "sql": "SELECT group_id, group_name, ingress_rules FROM aws_security_group WHERE ingress_rules LIKE '%0.0.0.0/0%'"
        },
        {
            "name": "Cross-provider user analysis",
            "description": "Compare user counts across different providers",
            "sql": "SELECT provider, COUNT(*) as user_count FROM (SELECT provider FROM okta_user UNION ALL SELECT provider FROM aws_iam_user) GROUP BY provider"
        },
        {
            "name": "Recent security events",
            "description": "Get recent security alerts and vulnerabilities",
            "sql": "SELECT provider, 'alert' as event_type, created_at FROM github_vulnerability_alert WHERE created_at > '2024-01-01' ORDER BY created_at DESC LIMIT 20"
        }
    ]
    
    return {
        "success": True,
        "message": f"Retrieved {len(examples)} query examples",
        "data": {"examples": examples}
    }


# Convenience endpoints for common queries

@router.get("/alerts", summary="Query Security Alerts")
async def query_security_alerts(
    provider: Optional[str] = Query(None, description="Filter by provider"),
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low)"),
    since: Optional[str] = Query(None, description="Filter by creation date (ISO format)"),
    limit: int = Query(100, description="Maximum results to return", ge=1, le=1000),
    current_user: User = Depends(require_read_findings),
    db: AsyncSession = Depends(get_db),
):
    """Query security alerts with common filters."""
    
    # Input validation
    if provider and not provider.isalnum():
        raise HTTPException(status_code=400, detail="Invalid provider parameter")
    if severity and severity not in ["critical", "high", "medium", "low"]:
        raise HTTPException(status_code=400, detail="Invalid severity parameter")
    
    # Build parameterized query safely
    base_sql = "SELECT alert_id, repository_name, severity, created_at, title, description FROM github_vulnerability_alert"
    conditions = []
    params = []
    param_count = 0
    
    if provider:
        param_count += 1
        conditions.append(f"provider = ${param_count}")
        params.append(provider)
    if severity:
        param_count += 1
        conditions.append(f"severity = ${param_count}")
        params.append(severity)
    if since:
        param_count += 1
        conditions.append(f"created_at >= ${param_count}")
        params.append(since)
    
    where_clause = f" WHERE {' AND '.join(conditions)}" if conditions else ""
    param_count += 1
    sql = f"{base_sql}{where_clause} ORDER BY created_at DESC LIMIT ${param_count}"
    params.append(limit)
    
    try:
        result = await query_engine.execute_query(sql, params)

        providers = _derive_providers(result)
        freshness_service = IntegrationFreshnessService(db)
        provider_freshness = await freshness_service.provider_freshness(providers)
        warnings = [summary.warning for summary in provider_freshness.values() if summary.warning]
        freshness_payload = {
            provider: {
                "last_synced_at": summary.last_synced_at.isoformat() if summary.last_synced_at else None,
                "age_seconds": summary.age_seconds,
                "age_human": summary.age_human,
                "status": summary.status,
                "sources": summary.sources,
                "confidence": summary.confidence,
            }
            for provider, summary in provider_freshness.items()
        }
        
        return {
            "success": True,
            "message": f"Found {result.total_rows} security alerts",
            "data": {
                "alerts": result.rows,
                "execution_time_ms": result.execution_time_ms,
                "freshness": freshness_payload,
                "warnings": warnings,
            }
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"message": "Failed to query alerts", "error": str(e)}
        )


@router.get("/users", summary="Query User Identities")
async def query_users(
    provider: Optional[str] = Query(None, description="Filter by provider"),
    status: Optional[str] = Query(None, description="Filter by status"),
    mfa_enabled: Optional[bool] = Query(None, description="Filter by MFA status"),
    limit: int = Query(100, description="Maximum results to return", ge=1, le=1000),
    current_user: User = Depends(require_read_findings),
    db: AsyncSession = Depends(get_db),
):
    """Query user identities across providers."""
    
    # Input validation
    if provider and not provider.isalnum():
        raise HTTPException(status_code=400, detail="Invalid provider parameter")
    if status and not status.replace('_', '').isalnum():
        raise HTTPException(status_code=400, detail="Invalid status parameter")
    
    # Build parameterized query safely
    base_sql = "SELECT username, email, status, last_login, mfa_enabled FROM okta_user"
    conditions = []
    params = []
    param_count = 0
    
    if provider:
        param_count += 1
        conditions.append(f"provider = ${param_count}")
        params.append(provider)
    if status:
        param_count += 1
        conditions.append(f"status = ${param_count}")
        params.append(status)
    if mfa_enabled is not None:
        param_count += 1
        conditions.append(f"mfa_enabled = ${param_count}")
        params.append(mfa_enabled)
    
    where_clause = f" WHERE {' AND '.join(conditions)}" if conditions else ""
    param_count += 1
    sql = f"{base_sql}{where_clause} ORDER BY last_login DESC LIMIT ${param_count}"
    params.append(limit)
    
    try:
        result = await query_engine.execute_query(sql, params)

        providers = _derive_providers(result)
        freshness_service = IntegrationFreshnessService(db)
        provider_freshness = await freshness_service.provider_freshness(providers)
        warnings = [summary.warning for summary in provider_freshness.values() if summary.warning]
        freshness_payload = {
            provider: {
                "last_synced_at": summary.last_synced_at.isoformat() if summary.last_synced_at else None,
                "age_seconds": summary.age_seconds,
                "age_human": summary.age_human,
                "status": summary.status,
                "sources": summary.sources,
                "confidence": summary.confidence,
            }
            for provider, summary in provider_freshness.items()
        }
        
        return {
            "success": True, 
            "message": f"Found {result.total_rows} users",
            "data": {
                "users": result.rows,
                "execution_time_ms": result.execution_time_ms,
                "freshness": freshness_payload,
                "warnings": warnings,
            }
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"message": "Failed to query users", "error": str(e)}
        )


def _derive_providers(result: QueryResult) -> List[str]:
    providers: List[str] = []
    if not result.tables_queried:
        return providers
    seen = set()
    registry = query_engine.registry
    for table in result.tables_queried:
        info = registry.get_table_info(table)
        provider = (info or {}).get("provider") if info else None
        if provider and provider not in seen:
            providers.append(provider)
            seen.add(provider)
    return providers
