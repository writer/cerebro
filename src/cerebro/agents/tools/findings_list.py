"""
List findings tool for Cerebro agents.

Provides secure, read-only access to listing security findings with filtering,
pagination, and provider scope enforcement.
"""

from typing import Any
from uuid import UUID

import structlog
from pydantic import BaseModel, Field

from cerebro.core.database import async_session_factory
from cerebro.core.models import Finding, Resource

from .base import AgentContext, Tool, ToolPermissionLevel, ToolResult

logger = structlog.get_logger(__name__)


class ListFindingsInput(BaseModel):
    """Input for listing findings."""

    org_id: UUID | None = Field(
        None, description="Organization ID (defaults to context org)"
    )
    limit: int = Field(
        50, description="Maximum number of findings to return", ge=1, le=500
    )
    offset: int = Field(0, description="Number of findings to skip", ge=0)
    severity: list[str] | None = Field(None, description="Filter by severity levels")
    status: list[str] | None = Field(None, description="Filter by finding status")
    provider: list[str] | None = Field(None, description="Filter by provider")
    created_after: str | None = Field(
        None, description="Filter findings created after this ISO timestamp"
    )
    created_before: str | None = Field(
        None, description="Filter findings created before this ISO timestamp"
    )
    rule_id: str | None = Field(None, description="Filter by specific rule ID")
    resource_type: str | None = Field(None, description="Filter by resource type")


class FindingSummary(BaseModel):
    """Summary representation of a finding."""

    id: str
    title: str
    description: str
    severity: str
    status: str
    provider: str
    resource_type: str
    resource_id: str
    rule_id: str
    created_at: str  # ISO format
    updated_at: str  # ISO format
    evidence: dict[str, Any]
    compliance_mappings: dict[str, Any]


class ListFindingsOutput(BaseModel):
    """Output for listing findings."""

    findings: list[FindingSummary]
    total_count: int
    has_more: bool
    filters_applied: dict[str, Any]


class FindingsListTool(Tool):
    """Tool for listing security findings with filtering and pagination."""

    @property
    def name(self) -> str:
        return "findings_list"

    @property
    def description(self) -> str:
        return "List security findings with filtering by severity, status, provider, and time range"

    @property
    def input_schema(self) -> type:
        return ListFindingsInput

    @property
    def output_schema(self) -> type:
        return ListFindingsOutput

    @property
    def permission_level(self) -> ToolPermissionLevel:
        return ToolPermissionLevel.READ_ONLY

    @property
    def cel_policy_key(self) -> str | None:
        return "tools.findings.list"

    @property
    def cel_expression(self) -> str | None:
        return "org_id == context.org_id && (size(provider_scope) == 0 || provider in provider_scope)"

    async def execute(self, inputs: BaseModel, context: AgentContext) -> ToolResult:
        """List findings with comprehensive filtering and provider scope enforcement."""

        try:
            list_inputs = ListFindingsInput(**inputs.model_dump())

            # Use context org if not specified
            org_id = list_inputs.org_id or context.org_id

            # Enforce provider scope security
            provider_filter = list_inputs.provider or []
            if context.provider_scope:
                # Intersect requested providers with allowed scope
                provider_filter = (
                    [p for p in provider_filter if p in context.provider_scope]
                    if provider_filter
                    else context.provider_scope
                )

            async with async_session_factory() as session:
                # Build comprehensive query using SQLAlchemy
                from datetime import datetime

                from sqlalchemy import and_, func, select
                from sqlalchemy.orm import selectinload

                # Base query with joins for related data
                query = (
                    select(Finding)
                    .options(
                        selectinload(Finding.rule),
                        selectinload(Finding.resource),
                        selectinload(Finding.principal),
                        selectinload(Finding.account),
                    )
                    .where(Finding.org_id == org_id)
                )

                # Apply filters with proper validation
                conditions: list[Any] = []

                if list_inputs.severity:
                    # Validate severity values
                    valid_severities = ["critical", "high", "medium", "low"]
                    filtered_severities = [
                        s for s in list_inputs.severity if s in valid_severities
                    ]
                    if filtered_severities:
                        conditions.append(Finding.severity.in_(filtered_severities))

                if list_inputs.status:
                    # Validate status values
                    valid_statuses = ["open", "suppressed", "accepted_risk", "fixed"]
                    filtered_statuses = [
                        s for s in list_inputs.status if s in valid_statuses
                    ]
                    if filtered_statuses:
                        conditions.append(Finding.status.in_(filtered_statuses))

                if provider_filter:
                    conditions.append(Finding.provider.in_(provider_filter))

                if list_inputs.created_after:
                    try:
                        after_dt = datetime.fromisoformat(
                            list_inputs.created_after.replace("Z", "+00:00")
                        )
                        conditions.append(Finding.first_seen >= after_dt)
                    except ValueError:
                        return ToolResult(
                            success=False,
                            error=f"Invalid created_after timestamp: {list_inputs.created_after}",
                        )

                if list_inputs.created_before:
                    try:
                        before_dt = datetime.fromisoformat(
                            list_inputs.created_before.replace("Z", "+00:00")
                        )
                        conditions.append(Finding.first_seen <= before_dt)
                    except ValueError:
                        return ToolResult(
                            success=False,
                            error=f"Invalid created_before timestamp: {list_inputs.created_before}",
                        )

                if list_inputs.rule_id:
                    try:
                        rule_uuid = UUID(list_inputs.rule_id)
                        conditions.append(Finding.rule_id == rule_uuid)
                    except ValueError:
                        return ToolResult(
                            success=False,
                            error=f"Invalid rule_id format: {list_inputs.rule_id}",
                        )

                if list_inputs.resource_type:
                    # Join with resource table for type filtering
                    query = query.join(
                        Resource, Finding.resource_id == Resource.resource_id
                    )
                    conditions.append(
                        Resource.resource_type == list_inputs.resource_type
                    )

                if conditions:
                    query = query.where(and_(*conditions))

                # Add pagination and ordering
                query = query.order_by(Finding.last_seen.desc())
                paginated_query = query.limit(list_inputs.limit).offset(
                    list_inputs.offset
                )

                # Execute query
                result = await session.execute(paginated_query)
                findings = result.scalars().all()

                # Get total count efficiently - match same conditions as main query
                count_query = select(func.count(Finding.finding_id)).where(
                    Finding.org_id == org_id
                )
                if list_inputs.resource_type:
                    count_query = count_query.join(
                        Resource, Finding.resource_id == Resource.resource_id
                    )
                if conditions:
                    count_query = count_query.where(and_(*conditions))

                count_result = await session.execute(count_query)
                total_count = count_result.scalar() or 0

                # Convert to summary format with full relationships
                finding_summaries = []
                for f in findings:
                    # Get resource type from relationship if available
                    resource_type = "unknown"
                    resource_id = ""
                    if f.resource:
                        resource_type = getattr(f.resource, "resource_type", "resource")
                        resource_id = str(f.resource.resource_id)
                    elif f.resource_id:
                        resource_id = str(f.resource_id)

                    # Get compliance mappings from rule if available
                    compliance_mappings = {}
                    if f.rule:
                        # Extract compliance framework mappings from rule
                        if hasattr(f.rule, "cis_controls") and f.rule.cis_controls:
                            compliance_mappings["cis"] = f.rule.cis_controls
                        if hasattr(f.rule, "nist_controls") and f.rule.nist_controls:
                            compliance_mappings["nist"] = f.rule.nist_controls
                        if hasattr(f.rule, "cwe_ids") and f.rule.cwe_ids:
                            compliance_mappings["cwe"] = f.rule.cwe_ids

                    finding_summaries.append(
                        FindingSummary(
                            id=str(f.finding_id),
                            title=f.title,
                            description=f.summary or f.title,
                            severity=f.severity,
                            status=f.status,
                            provider=f.provider,
                            resource_type=resource_type,
                            resource_id=resource_id,
                            rule_id=str(f.rule_id),
                            created_at=f.first_seen.isoformat(),
                            updated_at=f.last_seen.isoformat(),
                            evidence=f.evidence or {},
                            compliance_mappings=compliance_mappings,
                        )
                    )

                output = ListFindingsOutput(
                    findings=finding_summaries,
                    total_count=total_count,
                    has_more=(list_inputs.offset + len(findings)) < total_count,
                    filters_applied={
                        "severity": list_inputs.severity,
                        "status": list_inputs.status,
                        "provider": provider_filter,  # Show actual applied provider filter
                        "rule_id": list_inputs.rule_id,
                        "resource_type": list_inputs.resource_type,
                        "date_range": {
                            "after": list_inputs.created_after,
                            "before": list_inputs.created_before,
                        },
                        "provider_scope_enforced": len(context.provider_scope or []) > 0,
                    },
                )

                return ToolResult(
                    success=True,
                    data=output.model_dump(),
                    metadata={
                        "findings_count": len(findings),
                        "total_available": total_count,
                        "org_id": str(org_id),
                        "provider_scope_applied": provider_filter,
                        "query_performance": "optimized_with_relationships",
                        "security_enforced": True,
                    },
                )

        except Exception as e:
            logger.exception("List findings failed", org_id=org_id, error=str(e))
            return ToolResult(
                success=False,
                error=f"Failed to list findings: {e!s}",
            )
