# Agent Tool Development Guide

This guide explains how to develop custom tools for Cerebro's AI agents, from basic implementation to advanced patterns.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Tool Architecture](#tool-architecture)
3. [Input/Output Schemas](#inputoutput-schemas)
4. [Security Features](#security-features)
5. [Testing Tools](#testing-tools)
6. [Advanced Patterns](#advanced-patterns)
7. [Common Patterns](#common-patterns)

## Quick Start

### Minimal Tool Example

```python
from cerebro.agents.tools.base import Tool, AgentContext, ToolResult, ToolPermissionLevel
from pydantic import BaseModel, Field

# 1. Define input schema
class EchoInput(BaseModel):
    message: str = Field(description="Message to echo back")

# 2. Define output schema
class EchoOutput(BaseModel):
    echoed_message: str
    char_count: int

# 3. Implement tool
class EchoTool(Tool):
    @property
    def name(self) -> str:
        return "echo"

    @property
    def description(self) -> str:
        return "Echo a message back with character count"

    @property
    def input_schema(self) -> type[BaseModel]:
        return EchoInput

    @property
    def output_schema(self) -> type[BaseModel]:
        return EchoOutput

    @property
    def permission_level(self) -> ToolPermissionLevel:
        return ToolPermissionLevel.READ_ONLY

    async def execute(
        self,
        inputs: EchoInput,
        context: AgentContext,
    ) -> ToolResult:
        # Tool logic
        message = inputs.message
        count = len(message)

        return ToolResult(
            success=True,
            data={
                "echoed_message": message,
                "char_count": count,
            }
        )

# 4. Register tool
from cerebro.agents.tools import tool_registry
tool_registry.register(EchoTool())
```

## Tool Architecture

### Tool Lifecycle

```
User Query → Claude → Tool Decision → Tool Execution
                ↓                         ↓
         Tool Metadata              ToolExecutor
                ↓                         ↓
         Input Schema      ┌──────────────┴─────────────┐
                           │                            │
                           ▼                            ▼
                    Permission Check            CEL Policy Check
                           │                            │
                           └──────────┬─────────────────┘
                                      ▼
                                 execute()
                                      │
                                      ▼
                              ToolResult
                                      │
                                      ▼
                        ┌─────────────┴─────────────┐
                        │                           │
                        ▼                           ▼
                  Audit Logging              Format for Claude
```

### Key Components

#### 1. Tool Base Class

All tools inherit from `Tool`:

```python
class Tool(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique tool identifier"""

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description for Claude"""

    @property
    @abstractmethod
    def input_schema(self) -> Type[BaseModel]:
        """Pydantic model for input validation"""

    @property
    @abstractmethod
    def output_schema(self) -> Type[BaseModel]:
        """Pydantic model for output validation"""

    @property
    def permission_level(self) -> ToolPermissionLevel:
        """Required permission level (default: READ_ONLY)"""

    @property
    def cel_policy_key(self) -> Optional[str]:
        """CEL policy key for authorization"""

    @property
    def cel_expression(self) -> Optional[str]:
        """Default CEL expression"""

    @abstractmethod
    async def execute(self, inputs: BaseModel, context: AgentContext) -> ToolResult:
        """Execute tool logic"""
```

#### 2. Agent Context

Execution context provided to every tool:

```python
@dataclass
class AgentContext:
    # Session info
    session_id: UUID
    org_id: UUID
    user_id: str
    agent_type: str

    # Security context
    provider_scope: List[str]        # ["aws", "gcp"]
    finding_ids: List[UUID]          # Pre-loaded findings
    incident_id: Optional[UUID]      # Linked incident
    permission_level: ToolPermissionLevel
    cel_context: Dict[str, Any]      # CEL variables

    # Execution controls
    dry_run: bool = True             # Safety first!
    roles: List[str]                 # User roles
```

#### 3. Tool Result

Standardized return format:

```python
@dataclass
class ToolResult:
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    warnings: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None

    # Dry-run support
    dry_run: bool = False
    preview: Optional[Dict[str, Any]] = None

    # Approval workflow
    requires_approval: bool = False
    approval_id: Optional[UUID] = None
```

## Input/Output Schemas

### Pydantic Models

Use Pydantic for type-safe schemas:

```python
from pydantic import BaseModel, Field, validator
from typing import List, Optional
from uuid import UUID

class FindingUpdateInput(BaseModel):
    finding_id: UUID = Field(
        description="UUID of the finding to update"
    )
    new_status: str = Field(
        description="New status: open, investigating, resolved, false_positive"
    )
    reason: Optional[str] = Field(
        default=None,
        description="Reason for status change"
    )

    @validator('new_status')
    def validate_status(cls, v):
        valid_statuses = ['open', 'investigating', 'resolved', 'false_positive']
        if v not in valid_statuses:
            raise ValueError(f'Status must be one of: {valid_statuses}')
        return v
```

### Field Descriptions

Claude uses descriptions to understand parameters:

```python
class QueryInput(BaseModel):
    query_type: str = Field(
        description="Type of query: 'recent_config_changes' | 'audit_events' | 'iam_permissions' | 'findings_timeline'"
    )
    timeframe: str = Field(
        default="7d",
        description="Time window: '1h', '24h', '7d', '30d', or '90d'"
    )
    filters: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional filters: {'severity': 'high', 'provider': 'aws'}"
    )
```

### Complex Types

Handle nested structures:

```python
from typing import List, Dict, Optional
from enum import Enum

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class FindingFilter(BaseModel):
    severities: List[Severity]
    providers: Optional[List[str]] = None
    tags: Optional[Dict[str, str]] = None

class QueryInput(BaseModel):
    finding_filter: Optional[FindingFilter] = None
    limit: int = Field(default=100, ge=1, le=1000)
```

## Security Features

### 1. Permission Levels

Four levels of access:

```python
class PermissionLevelExample(Tool):
    @property
    def permission_level(self) -> ToolPermissionLevel:
        # READ_ONLY: Query data only
        return ToolPermissionLevel.READ_ONLY

        # WRITE_SAFE: Non-destructive updates (add tags, comments)
        return ToolPermissionLevel.WRITE_SAFE

        # WRITE_DESTRUCTIVE: Can modify/delete (requires approval)
        return ToolPermissionLevel.WRITE_DESTRUCTIVE

        # ADMIN: Full system access
        return ToolPermissionLevel.ADMIN
```

### 2. Dry-Run Mode

Check `context.dry_run` before mutations:

```python
async def execute(self, inputs: Input, context: AgentContext) -> ToolResult:
    # Always check dry_run for destructive actions
    if context.dry_run:
        # Return preview of what would happen
        return ToolResult(
            success=True,
            dry_run=True,
            preview={
                "action": "delete_finding",
                "finding_id": str(inputs.finding_id),
                "current_status": current_finding.status,
                "warning": "This action is irreversible"
            },
            data=None  # No actual data in dry-run
        )

    # Real execution
    await db_session.delete(finding)
    await db_session.commit()

    return ToolResult(
        success=True,
        data={"deleted": True, "finding_id": str(inputs.finding_id)}
    )
```

### 3. CEL Policies

Define authorization rules:

```python
class FindingDeleteTool(Tool):
    @property
    def cel_policy_key(self) -> str:
        return "finding_delete"

    @property
    def cel_expression(self) -> str:
        return """
        // Only allow deletion if:
        // 1. User has admin role OR
        // 2. Finding severity is low AND user owns it
        has(principal.roles) && 'admin' in principal.roles ||
        (
            resource.severity == 'low' &&
            resource.created_by == principal.user_id
        )
        """
```

### 4. Provider Scope

Respect provider restrictions:

```python
async def execute(self, inputs: Input, context: AgentContext) -> ToolResult:
    # Check if requested providers are in scope
    requested_providers = inputs.providers or []

    if context.provider_scope:
        # Filter to allowed providers
        allowed = set(context.provider_scope)
        requested = set(requested_providers)

        if not requested.issubset(allowed):
            return ToolResult(
                success=False,
                error=f"Access denied to providers: {requested - allowed}"
            )

    # Continue with filtered providers
    providers = list(allowed & requested) if context.provider_scope else requested_providers
```

## Testing Tools

### Unit Tests

Test tools in isolation:

```python
import pytest
from cerebro.agents.tools.base import AgentContext, ToolPermissionLevel
from cerebro.agents.tools.my_tool import MyTool

@pytest.fixture
def mock_context():
    return AgentContext(
        session_id=UUID("00000000-0000-0000-0000-000000000000"),
        org_id=UUID("11111111-1111-1111-1111-111111111111"),
        user_id="test@example.com",
        agent_type="security_analyst",
        provider_scope=["aws"],
        permission_level=ToolPermissionLevel.READ_ONLY,
        dry_run=True,
    )

@pytest.mark.asyncio
async def test_my_tool_success(mock_context):
    tool = MyTool()

    # Test input validation
    inputs = tool.input_schema(param1="value1", param2="value2")

    # Execute tool
    result = await tool.execute(inputs, mock_context)

    # Assert results
    assert result.success
    assert result.data is not None
    assert "expected_key" in result.data

@pytest.mark.asyncio
async def test_my_tool_dry_run(mock_context):
    tool = MyTool()
    inputs = tool.input_schema(action="delete")

    # Ensure dry_run context
    mock_context.dry_run = True

    result = await tool.execute(inputs, mock_context)

    # Verify dry-run behavior
    assert result.success
    assert result.dry_run is True
    assert result.preview is not None
    assert result.data is None  # No real changes
```

### Integration Tests

Test with real database:

```python
@pytest.mark.asyncio
async def test_tool_with_database(test_org, test_finding):
    from cerebro.agents.tools import ToolExecutor

    tool = MyDatabaseTool()
    executor = ToolExecutor()

    context = AgentContext(
        session_id=uuid4(),
        org_id=test_org.org_id,
        user_id="test@example.com",
        agent_type="security_analyst",
        permission_level=ToolPermissionLevel.WRITE_SAFE,
        dry_run=False,
    )

    inputs = tool.input_schema(
        finding_id=test_finding.finding_id,
        action="update"
    )

    # Execute via executor (includes CEL checks, audit logging)
    result = await executor.execute_tool(tool, inputs.dict(), context)

    assert result.success

    # Verify database changes
    from cerebro.core.database import async_session_factory
    async with async_session_factory() as session:
        updated_finding = await session.get(Finding, test_finding.finding_id)
        assert updated_finding.status == "investigating"
```

## Advanced Patterns

### 1. Paginated Results

Handle large result sets:

```python
class PaginatedQueryInput(BaseModel):
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=500)

class PaginatedOutput(BaseModel):
    items: List[Dict[str, Any]]
    total_count: int
    page: int
    page_size: int
    has_more: bool

async def execute(self, inputs: PaginatedQueryInput, context: AgentContext) -> ToolResult:
    offset = (inputs.page - 1) * inputs.page_size

    # Query with pagination
    query = select(Finding).where(Finding.org_id == context.org_id)
    total_count = await session.scalar(select(func.count()).select_from(query.subquery()))

    results = await session.execute(
        query.offset(offset).limit(inputs.page_size)
    )
    items = results.scalars().all()

    return ToolResult(
        success=True,
        data={
            "items": [item.to_dict() for item in items],
            "total_count": total_count,
            "page": inputs.page,
            "page_size": inputs.page_size,
            "has_more": offset + len(items) < total_count
        }
    )
```

### 2. Batch Operations

Process multiple items:

```python
class BatchUpdateInput(BaseModel):
    finding_ids: List[UUID] = Field(max_items=100)
    new_status: str

async def execute(self, inputs: BatchUpdateInput, context: AgentContext) -> ToolResult:
    if context.dry_run:
        return ToolResult(
            success=True,
            dry_run=True,
            preview={
                "would_update": len(inputs.finding_ids),
                "new_status": inputs.new_status,
                "finding_ids": [str(f) for f in inputs.finding_ids]
            }
        )

    results = {"updated": [], "failed": []}

    for finding_id in inputs.finding_ids:
        try:
            finding = await session.get(Finding, finding_id)
            if finding and finding.org_id == context.org_id:
                finding.status = inputs.new_status
                results["updated"].append(str(finding_id))
            else:
                results["failed"].append({
                    "finding_id": str(finding_id),
                    "reason": "not_found_or_unauthorized"
                })
        except Exception as e:
            results["failed"].append({
                "finding_id": str(finding_id),
                "reason": str(e)
            })

    await session.commit()

    return ToolResult(
        success=len(results["failed"]) == 0,
        data=results,
        warnings=[f"{len(results['failed'])} items failed"] if results["failed"] else None
    )
```

### 3. Long-Running Operations

For operations that take time:

```python
from cerebro.agents.models import ToolInvocation, ToolInvocationStatus

async def execute(self, inputs: Input, context: AgentContext) -> ToolResult:
    # Create invocation record
    invocation = ToolInvocation(
        session_id=context.session_id,
        tool_name=self.name,
        status=ToolInvocationStatus.RUNNING,
        input_data=inputs.dict()
    )
    session.add(invocation)
    await session.commit()

    try:
        # Long operation
        result_data = await perform_long_operation()

        invocation.status = ToolInvocationStatus.SUCCESS
        invocation.output_data = result_data
        await session.commit()

        return ToolResult(success=True, data=result_data)

    except Exception as e:
        invocation.status = ToolInvocationStatus.ERROR
        invocation.error_message = str(e)
        await session.commit()

        return ToolResult(success=False, error=str(e))
```

### 4. External API Calls

Integrate with external services:

```python
import httpx

class ExternalAPITool(Tool):
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=30.0)

    async def execute(self, inputs: Input, context: AgentContext) -> ToolResult:
        try:
            response = await self.client.get(
                "https://api.example.com/data",
                headers={"Authorization": f"Bearer {get_api_key()}"},
                params={"org_id": str(context.org_id)}
            )
            response.raise_for_status()

            return ToolResult(
                success=True,
                data=response.json(),
                metadata={"api_latency_ms": response.elapsed.total_seconds() * 1000}
            )

        except httpx.HTTPError as e:
            return ToolResult(
                success=False,
                error=f"API request failed: {str(e)}",
                metadata={"status_code": e.response.status_code if e.response else None}
            )
```

## Common Patterns

### Error Handling

Always return ToolResult:

```python
async def execute(self, inputs: Input, context: AgentContext) -> ToolResult:
    try:
        # Tool logic
        result = await do_something()
        return ToolResult(success=True, data=result)

    except ValueError as e:
        # User error - inform Claude
        return ToolResult(
            success=False,
            error=f"Invalid input: {str(e)}"
        )

    except PermissionError as e:
        # Authorization error
        return ToolResult(
            success=False,
            error=f"Access denied: {str(e)}",
            metadata={"error_type": "permission_denied"}
        )

    except Exception as e:
        # Unexpected error - log and return generic message
        logger.exception("Tool execution failed", tool_name=self.name)
        return ToolResult(
            success=False,
            error="An unexpected error occurred. Please contact support.",
            metadata={"error_id": str(uuid4())}
        )
```

### Logging

Use structured logging:

```python
import structlog

logger = structlog.get_logger(__name__)

async def execute(self, inputs: Input, context: AgentContext) -> ToolResult:
    logger.info(
        "Tool execution started",
        tool_name=self.name,
        session_id=context.session_id,
        org_id=context.org_id,
        dry_run=context.dry_run,
    )

    start_time = time.time()

    result = await perform_operation()

    execution_time = time.time() - start_time

    logger.info(
        "Tool execution completed",
        tool_name=self.name,
        session_id=context.session_id,
        success=result.success,
        execution_time_ms=execution_time * 1000,
    )

    return result
```

### Database Queries

Use SQLAlchemy async patterns:

```python
from sqlalchemy import select
from cerebro.core.database import async_session_factory

async def execute(self, inputs: Input, context: AgentContext) -> ToolResult:
    async with async_session_factory() as session:
        # Build query
        stmt = (
            select(Finding)
            .where(Finding.org_id == context.org_id)
            .where(Finding.severity == inputs.severity)
            .order_by(Finding.first_seen.desc())
            .limit(100)
        )

        # Execute
        result = await session.execute(stmt)
        findings = result.scalars().all()

        # Format results
        return ToolResult(
            success=True,
            data={
                "findings": [f.to_dict() for f in findings],
                "count": len(findings)
            }
        )
```

## Best Practices

1. **Always validate inputs**: Use Pydantic validators
2. **Respect dry-run mode**: Never mutate in dry-run
3. **Provide good descriptions**: Claude reads them
4. **Return structured data**: Dict with clear keys
5. **Log appropriately**: Structured logging for debugging
6. **Handle errors gracefully**: Never raise unhandled exceptions
7. **Test thoroughly**: Unit + integration tests
8. **Document edge cases**: Comments for tricky logic
9. **Respect org isolation**: Always filter by org_id
10. **Audit trail**: Rely on ToolExecutor for automatic auditing

## Tool Registration

Register in `tools/__init__.py`:

```python
from .my_tool import MyTool

tool_registry.register(MyTool())
```

That's it! Tool is now available to all agents.

---

**Need Help?**
- See existing tools in `src/cerebro/agents/tools/`
- Check [Agent Architecture Docs](../architecture/claude-sdk-integration.md)
- Review [Test Examples](../../tests/agents/test_agent_integration.py)