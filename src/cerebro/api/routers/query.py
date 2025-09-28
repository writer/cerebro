"""
Query API endpoints for SQL-based security data queries.

Provides REST endpoints for executing SQL queries against security tables.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, Field

from ...query.engine import QueryEngine, QueryResult
from ...query.registry import get_registry
from ...providers.tables import register_all_provider_tables
from ..schemas.base import BaseResponse

router = APIRouter(prefix="/query", tags=["Query"])

# Initialize query engine
query_engine = QueryEngine()

# Register all provider tables on startup  
register_all_provider_tables()


class QueryRequest(BaseModel):
    """SQL query request."""
    sql: str = Field(..., description="SQL query to execute", example="SELECT * FROM aws_ec2_instance LIMIT 10")
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
async def execute_sql_query(request: QueryRequest) -> QueryResponse:
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
        
        return QueryResponse(
            success=True,
            message=f"Query executed successfully, returned {result.total_rows} rows",
            data={
                "columns": result.columns,
                "rows": result.rows,
                "total_rows": result.total_rows,
                "execution_time_ms": result.execution_time_ms,
                "tables_queried": result.tables_queried,
            }
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"message": "Internal server error", "error": str(e)}
        )


@router.get("/tables", response_model=TablesResponse, summary="List Security Tables")
async def list_security_tables(
    provider: Optional[str] = Query(None, description="Filter by provider (aws, okta, github, etc.)")
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
async def get_query_examples():
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
    limit: int = Query(100, description="Maximum results to return", ge=1, le=1000)
):
    """Query security alerts with common filters."""
    
    # Build SQL query dynamically
    conditions = []
    if provider:
        conditions.append(f"provider = '{provider}'")
    if severity:
        conditions.append(f"severity = '{severity}'")
    if since:
        conditions.append(f"created_at >= '{since}'")
    
    where_clause = f" WHERE {' AND '.join(conditions)}" if conditions else ""
    
    # Query multiple alert tables (simplified - would need UNION in full implementation)
    sql = f"SELECT * FROM github_vulnerability_alert{where_clause} ORDER BY created_at DESC LIMIT {limit}"
    
    try:
        result = await query_engine.execute_query(sql)
        
        return {
            "success": True,
            "message": f"Found {result.total_rows} security alerts",
            "data": {
                "alerts": result.rows,
                "execution_time_ms": result.execution_time_ms
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
    limit: int = Query(100, description="Maximum results to return", ge=1, le=1000)
):
    """Query user identities across providers."""
    
    conditions = []
    if provider:
        conditions.append(f"provider = '{provider}'")
    if status:
        conditions.append(f"status = '{status}'")
    if mfa_enabled is not None:
        conditions.append(f"mfa_enabled = {str(mfa_enabled).lower()}")
    
    where_clause = f" WHERE {' AND '.join(conditions)}" if conditions else ""
    
    # Default to Okta users (would expand for multi-provider queries)
    sql = f"SELECT username, email, status, last_login, mfa_enabled FROM okta_user{where_clause} ORDER BY last_login DESC LIMIT {limit}"
    
    try:
        result = await query_engine.execute_query(sql)
        
        return {
            "success": True, 
            "message": f"Found {result.total_rows} users",
            "data": {
                "users": result.rows,
                "execution_time_ms": result.execution_time_ms
            }
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"message": "Failed to query users", "error": str(e)}
        )
