"""
Findings management tools for Cerebro agents.

These tools provide secure access to finding data, allowing agents to query,
analyze, update, and manage security findings with proper audit trails.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

import structlog
from pydantic import BaseModel, Field

from cerebro.core.database import get_db
from cerebro.core.models import Finding
from cerebro.core.repositories import FindingRepository

from .base import Tool, ToolResult, AgentContext, ToolPermissionLevel

logger = structlog.get_logger(__name__)


# Input/Output Schemas

class ListFindingsInput(BaseModel):
    """Input for listing findings."""
    org_id: Optional[UUID] = Field(None, description="Organization ID (defaults to context org)")
    limit: int = Field(50, description="Maximum number of findings to return", ge=1, le=500)
    offset: int = Field(0, description="Number of findings to skip", ge=0)
    severity: Optional[List[str]] = Field(None, description="Filter by severity levels")
    status: Optional[List[str]] = Field(None, description="Filter by finding status")
    provider: Optional[List[str]] = Field(None, description="Filter by provider")
    created_after: Optional[datetime] = Field(None, description="Filter findings created after this timestamp")
    created_before: Optional[datetime] = Field(None, description="Filter findings created before this timestamp")
    rule_id: Optional[str] = Field(None, description="Filter by specific rule ID")
    resource_type: Optional[str] = Field(None, description="Filter by resource type")


class FindingSummary(BaseModel):
    """Summary representation of a finding."""
    id: UUID
    title: str
    description: str
    severity: str
    status: str
    provider: str
    resource_type: str
    resource_id: str
    rule_id: str
    created_at: datetime
    updated_at: datetime
    evidence: Dict[str, Any]
    compliance_mappings: Dict[str, Any]


class ListFindingsOutput(BaseModel):
    """Output for listing findings."""
    findings: List[FindingSummary]
    total_count: int
    has_more: bool
    filters_applied: Dict[str, Any]


class GetFindingInput(BaseModel):
    """Input for getting a specific finding."""
    finding_id: UUID = Field(description="Finding ID to retrieve")
    include_history: bool = Field(False, description="Include finding status change history")
    include_evidence: bool = Field(True, description="Include detailed evidence")


class GetFindingOutput(BaseModel):
    """Output for getting a specific finding."""
    finding: FindingSummary
    history: Optional[List[Dict[str, Any]]] = None
    related_findings: Optional[List[FindingSummary]] = None


class UpdateFindingStatusInput(BaseModel):
    """Input for updating finding status."""
    finding_id: UUID = Field(description="Finding ID to update")
    status: str = Field(description="New status for the finding")
    comment: str = Field(description="Comment explaining the status change")
    assignee: Optional[str] = Field(None, description="User to assign the finding to")


class UpdateFindingStatusOutput(BaseModel):
    """Output for updating finding status."""
    finding_id: UUID
    old_status: str
    new_status: str
    comment: str
    updated_at: datetime
    updated_by: str


class ClusterFindingsInput(BaseModel):
    """Input for clustering similar findings."""
    finding_ids: Optional[List[UUID]] = Field(None, description="Specific findings to cluster")
    similarity_threshold: float = Field(0.8, description="Similarity threshold for clustering", ge=0.0, le=1.0)
    max_clusters: int = Field(10, description="Maximum number of clusters to create", ge=1, le=50)
    clustering_criteria: List[str] = Field(
        ["rule_id", "resource_type", "provider"],
        description="Criteria to use for clustering"
    )


class FindingCluster(BaseModel):
    """A cluster of similar findings."""
    cluster_id: str
    finding_count: int
    primary_finding: FindingSummary
    cluster_summary: str
    severity_distribution: Dict[str, int]
    provider_distribution: Dict[str, int]
    estimated_remediation_time: str
    sample_findings: List[FindingSummary]


class ClusterFindingsOutput(BaseModel):
    """Output for clustering findings."""
    clusters: List[FindingCluster]
    unclustered_findings: List[FindingSummary]
    clustering_metadata: Dict[str, Any]


# Tools Implementation

class FindingsTool(Tool):
    """Tool for managing security findings in Cerebro."""
    
    @property
    def name(self) -> str:
        return "findings"
    
    @property
    def description(self) -> str:
        return "Query, analyze, and manage security findings with filtering and clustering capabilities"
    
    @property
    def input_schema(self) -> type:
        # This tool supports multiple operations, so we'll handle routing in execute()
        return BaseModel
    
    @property
    def output_schema(self) -> type:
        return BaseModel
    
    @property
    def permission_level(self) -> ToolPermissionLevel:
        return ToolPermissionLevel.READ_ONLY
    
    async def execute(self, inputs: BaseModel, context: AgentContext) -> ToolResult:
        """Execute findings operations based on input type."""
        
        # Route to appropriate handler based on input data
        raw_data = inputs.model_dump() if hasattr(inputs, 'model_dump') else inputs
        operation = raw_data.get('operation', 'list')
        
        try:
            if operation == 'list':
                return await self._list_findings(raw_data, context)
            elif operation == 'get':
                return await self._get_finding(raw_data, context)
            elif operation == 'update_status':
                return await self._update_finding_status(raw_data, context)
            elif operation == 'cluster':
                return await self._cluster_findings(raw_data, context)
            else:
                return ToolResult(
                    success=False,
                    error=f"Unknown operation: {operation}",
                )
        except Exception as e:
            logger.exception("Findings tool execution failed", operation=operation, error=str(e))
            return ToolResult(
                success=False,
                error=f"Findings operation failed: {str(e)}",
            )
    
    async def _list_findings(self, raw_data: Dict[str, Any], context: AgentContext) -> ToolResult:
        """List findings with filtering."""
        inputs = ListFindingsInput(**raw_data)
        
        # Use context org if not specified
        org_id = inputs.org_id or context.org_id
        
        from cerebro.core.database import async_session_factory
        async with async_session_factory() as session:
            finding_repo = FindingRepository(session)
            
            # Build comprehensive query using SQLAlchemy
            from sqlalchemy import select, and_, func
            from sqlalchemy.orm import selectinload
            
            # Base query with joins for related data
            query = (
                select(Finding)
                .options(
                    selectinload(Finding.rule),
                    selectinload(Finding.resource),
                    selectinload(Finding.principal)
                )
                .where(Finding.org_id == org_id)
            )
            
            # Apply filters
            conditions = []
            if inputs.severity:
                conditions.append(Finding.severity.in_(inputs.severity))
            if inputs.status:
                conditions.append(Finding.status.in_(inputs.status))
            if inputs.provider:
                conditions.append(Finding.provider.in_(inputs.provider))
            if inputs.created_after:
                conditions.append(Finding.first_seen >= inputs.created_after)
            if inputs.created_before:
                conditions.append(Finding.first_seen <= inputs.created_before)
            if inputs.rule_id:
                conditions.append(Finding.rule_id == inputs.rule_id)
            if inputs.resource_type:
                # Join with resource table for type filtering
                from cerebro.core.models import Resource
                from sqlalchemy.orm import join
                
                query = query.join(Resource, Finding.resource_id == Resource.resource_id)
                conditions.append(Resource.resource_type == inputs.resource_type)
            
            if conditions:
                query = query.where(and_(*conditions))
            
            # Add pagination and ordering
            query = query.order_by(Finding.last_seen.desc())
            paginated_query = query.limit(inputs.limit).offset(inputs.offset)
            
            # Execute query
            result = await session.execute(paginated_query)
            findings = result.scalars().all()
            
            # Get total count efficiently
            count_query = select(func.count(Finding.finding_id)).where(Finding.org_id == org_id)
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
                    resource_type = getattr(f.resource, 'resource_type', 'resource')
                    resource_id = str(f.resource.resource_id)
                elif f.resource_id:
                    resource_id = str(f.resource_id)
                
                # Get compliance mappings from rule if available
                compliance_mappings = {}
                if f.rule:
                    # Rule model should have compliance framework mappings
                    if hasattr(f.rule, 'cis_controls'):
                        compliance_mappings['cis'] = getattr(f.rule, 'cis_controls', [])
                    if hasattr(f.rule, 'nist_controls'):
                        compliance_mappings['nist'] = getattr(f.rule, 'nist_controls', [])
                    if hasattr(f.rule, 'cwe_ids'):
                        compliance_mappings['cwe'] = getattr(f.rule, 'cwe_ids', [])
                
                finding_summaries.append(FindingSummary(
                    id=f.finding_id,
                    title=f.title,
                    description=f.summary or f.title,
                    severity=f.severity,
                    status=f.status,
                    provider=f.provider,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    rule_id=str(f.rule_id),
                    created_at=f.first_seen,
                    updated_at=f.last_seen,
                    evidence=f.evidence or {},
                    compliance_mappings=compliance_mappings,
                ))
            
            output = ListFindingsOutput(
                findings=finding_summaries,
                total_count=total_count,
                has_more=(inputs.offset + len(findings)) < total_count,
                filters_applied={
                    "severity": inputs.severity,
                    "status": inputs.status,  
                    "provider": inputs.provider,
                    "rule_id": str(inputs.rule_id) if inputs.rule_id else None,
                    "date_range": {
                        "after": inputs.created_after.isoformat() if inputs.created_after else None,
                        "before": inputs.created_before.isoformat() if inputs.created_before else None,
                    }
                },
            )
            
            return ToolResult(
                success=True,
                data=output.model_dump(),
                metadata={
                    "findings_count": len(findings),
                    "total_available": total_count,
                    "org_id": str(org_id),
                    "query_performance": "optimized_with_relationships",
                },
            )
    
    async def _get_finding(self, raw_data: Dict[str, Any], context: AgentContext) -> ToolResult:
        """Get a specific finding with optional history."""
        inputs = GetFindingInput(**raw_data)
        
        from cerebro.core.database import async_session_factory
        async with async_session_factory() as session:
            from sqlalchemy import select
            from sqlalchemy.orm import selectinload
            
            # Query finding with all relationships
            query = (
                select(Finding)
                .options(
                    selectinload(Finding.rule),
                    selectinload(Finding.resource),
                    selectinload(Finding.principal),
                    selectinload(Finding.account),
                    selectinload(Finding.evidence_artifacts)
                )
                .where(
                    Finding.finding_id == inputs.finding_id,
                    Finding.org_id == context.org_id
                )
            )
            
            result = await session.execute(query)
            finding = result.scalar_one_or_none()
            
            if not finding:
                return ToolResult(
                    success=False,
                    error=f"Finding {inputs.finding_id} not found or access denied",
                )
            
            # Build comprehensive finding summary
            resource_type = "unknown"
            resource_id = ""
            if finding.resource:
                resource_type = getattr(finding.resource, 'resource_type', 'resource')
                resource_id = str(finding.resource.resource_id)
            elif finding.resource_id:
                resource_id = str(finding.resource_id)
            
            # Get compliance mappings from rule
            compliance_mappings = {}
            if finding.rule:
                if hasattr(finding.rule, 'cis_controls'):
                    compliance_mappings['cis'] = getattr(finding.rule, 'cis_controls', [])
                if hasattr(finding.rule, 'nist_controls'):
                    compliance_mappings['nist'] = getattr(finding.rule, 'nist_controls', [])
                if hasattr(finding.rule, 'cwe_ids'):
                    compliance_mappings['cwe'] = getattr(finding.rule, 'cwe_ids', [])
            
            # Enhanced evidence with artifacts if requested
            evidence = finding.evidence or {}
            if inputs.include_evidence and finding.evidence_artifacts:
                evidence['artifacts'] = [
                    {
                        "artifact_id": str(artifact.artifact_id),
                        "captured_at": artifact.captured_at.isoformat(),
                        "artifact_type": getattr(artifact, 'artifact_type', 'unknown'),
                        "size_bytes": getattr(artifact, 'size_bytes', 0),
                    }
                    for artifact in finding.evidence_artifacts
                ]
            
            finding_summary = FindingSummary(
                id=finding.finding_id,
                title=finding.title,
                description=finding.summary or finding.title,
                severity=finding.severity,
                status=finding.status,
                provider=finding.provider,
                resource_type=resource_type,
                resource_id=resource_id,
                rule_id=str(finding.rule_id),
                created_at=finding.first_seen,
                updated_at=finding.last_seen,
                evidence=evidence,
                compliance_mappings=compliance_mappings,
            )
            
            # Get history if requested - query actual audit events
            history = []
            if inputs.include_history:
                from cerebro.core.models import AuditEvent
                from sqlalchemy import select
                
                # Query audit events for this finding
                audit_query = select(AuditEvent).where(
                    AuditEvent.org_id == context.org_id,
                    AuditEvent.resource_id == str(finding.finding_id)
                ).order_by(AuditEvent.timestamp.asc())
                
                audit_result = await session.execute(audit_query)
                audit_events = audit_result.scalars().all()
                
                # Convert to history format
                history = [
                    {
                        "timestamp": event.timestamp.isoformat(),
                        "event": event.event_type,
                        "actor": event.actor,
                        "details": event.details or {}
                    }
                    for event in audit_events
                ]
                
                # If no audit events, add the creation event
                if not history:
                    history = [
                        {
                            "timestamp": finding.first_seen.isoformat(),
                            "event": "finding_created",
                            "actor": "rule_engine",
                            "details": {
                                "initial_status": finding.status,
                                "severity": finding.severity,
                                "rule_id": str(finding.rule_id)
                            }
                        }
                    ]
            
            # Get related findings (same rule, different resources)
            related_findings = []
            if finding.rule_id:
                related_query = (
                    select(Finding)
                    .options(selectinload(Finding.resource))
                    .where(
                        Finding.org_id == context.org_id,
                        Finding.rule_id == finding.rule_id,
                        Finding.finding_id != finding.finding_id
                    )
                    .limit(5)
                    .order_by(Finding.last_seen.desc())
                )
                
                related_result = await session.execute(related_query)
                related_list = related_result.scalars().all()
                
                related_findings = [
                    FindingSummary(
                        id=f.finding_id,
                        title=f.title,
                        description=f.summary or f.title,
                        severity=f.severity,
                        status=f.status,
                        provider=f.provider,
                        resource_type=getattr(f.resource, 'resource_type', 'resource') if f.resource else 'unknown',
                        resource_id=str(f.resource_id) if f.resource_id else "",
                        rule_id=str(f.rule_id),
                        created_at=f.first_seen,
                        updated_at=f.last_seen,
                        evidence={},  # Don't include full evidence for related findings
                        compliance_mappings=compliance_mappings,  # Same rule, same mappings
                    )
                    for f in related_list
                ]
            
            output = GetFindingOutput(
                finding=finding_summary,
                history=history if inputs.include_history else None,
                related_findings=related_findings if related_findings else None,
            )
            
            return ToolResult(
                success=True,
                data=output.model_dump(),
                metadata={
                    "finding_id": str(inputs.finding_id),
                    "related_count": len(related_findings),
                    "evidence_artifacts": len(finding.evidence_artifacts) if finding.evidence_artifacts else 0,
                    "rule_name": finding.rule.name if finding.rule else None,
                },
            )
    
    async def _update_finding_status(self, raw_data: Dict[str, Any], context: AgentContext) -> ToolResult:
        """Update finding status with audit trail and dry-run support."""
        inputs = UpdateFindingStatusInput(**raw_data)

        from cerebro.core.database import async_session_factory
        async with async_session_factory() as session:
            from sqlalchemy import select
            from datetime import datetime, timezone

            # Get the current finding
            query = select(Finding).where(
                Finding.finding_id == inputs.finding_id,
                Finding.org_id == context.org_id
            )

            result = await session.execute(query)
            finding = result.scalar_one_or_none()

            if not finding:
                return ToolResult(
                    success=False,
                    error=f"Finding {inputs.finding_id} not found or access denied",
                )

            old_status = finding.status

            # Validate new status (using Cerebro's status values)
            valid_statuses = ['open', 'suppressed', 'accepted_risk', 'fixed']
            if inputs.status not in valid_statuses:
                return ToolResult(
                    success=False,
                    error=f"Invalid status: {inputs.status}. Valid statuses: {valid_statuses}",
                )

            # DRY-RUN: If dry_run is enabled, return preview without making changes
            if context.dry_run:
                logger.info(
                    "DRY RUN: Would update finding status",
                    finding_id=inputs.finding_id,
                    old_status=old_status,
                    new_status=inputs.status,
                    user_id=context.user_id
                )

                return ToolResult(
                    success=True,
                    dry_run=True,
                    preview={
                        "action": "update_finding_status",
                        "finding_id": str(finding.finding_id),
                        "finding_title": finding.title,
                        "current_status": old_status,
                        "new_status": inputs.status,
                        "comment": inputs.comment,
                        "assignee": inputs.assignee,
                        "would_create_audit_event": True,
                    },
                    data={
                        "message": "DRY RUN: No changes made. Set dry_run=False to execute.",
                        "preview_only": True,
                    },
                    metadata={
                        "dry_run": True,
                        "finding_severity": finding.severity,
                    }
                )

            # REAL EXECUTION: Update finding
            finding.status = inputs.status
            finding.last_seen = datetime.now(timezone.utc)  # Update timestamp

            # Set resolved timestamp if marking as fixed
            if inputs.status == 'fixed' and old_status != 'fixed':
                if hasattr(finding, 'resolved_at'):
                    finding.resolved_at = datetime.now(timezone.utc)

            try:
                await session.commit()
                await session.refresh(finding)
                
                # Create audit event for status change
                from cerebro.core.models import AuditEvent
                from uuid import uuid4
                
                audit_event = AuditEvent(
                    event_id=uuid4(),
                    org_id=context.org_id,
                    event_type='finding_status_changed',
                    actor=context.user_id,
                    resource_id=str(finding.finding_id),
                    timestamp=finding.last_seen,
                    details={
                        "old_status": old_status,
                        "new_status": finding.status,
                        "comment": inputs.comment,
                        "assignee": inputs.assignee,
                        "finding_id": str(finding.finding_id),
                        "rule_id": str(finding.rule_id),
                        "severity": finding.severity,
                    }
                )
                session.add(audit_event)
                await session.commit()
                
                output = UpdateFindingStatusOutput(
                    finding_id=finding.finding_id,
                    old_status=old_status,
                    new_status=finding.status,
                    comment=inputs.comment,
                    updated_at=finding.last_seen,
                    updated_by=context.user_id,
                )
                
                return ToolResult(
                    success=True,
                    data=output.model_dump(),
                    metadata={
                        "status_change": f"{old_status} -> {finding.status}",
                        "audit_trail": True,
                        "resolved": finding.status == 'fixed',
                        "assignee": inputs.assignee,
                    },
                )
                
            except Exception as e:
                await session.rollback()
                logger.exception("Failed to update finding status", finding_id=inputs.finding_id, error=str(e))
                return ToolResult(
                    success=False,
                    error=f"Database error updating finding: {str(e)}",
                )
    
    async def _cluster_findings(self, raw_data: Dict[str, Any], context: AgentContext) -> ToolResult:
        """Cluster similar findings to reduce alert fatigue."""
        inputs = ClusterFindingsInput(**raw_data)
        
        from cerebro.core.database import async_session_factory
        async with async_session_factory() as session:
            from sqlalchemy import select
            from sqlalchemy.orm import selectinload
            from collections import defaultdict
            
            # Get findings to cluster
            if inputs.finding_ids:
                # Cluster specific findings
                query = (
                    select(Finding)
                    .options(selectinload(Finding.rule))
                    .where(
                        Finding.finding_id.in_(inputs.finding_ids),
                        Finding.org_id == context.org_id
                    )
                )
            else:
                # Get recent open findings for clustering
                query = (
                    select(Finding)
                    .options(selectinload(Finding.rule))
                    .where(
                        Finding.org_id == context.org_id,
                        Finding.status.in_(['open'])  # Only cluster open findings
                    )
                    .order_by(Finding.last_seen.desc())
                    .limit(200)  # Reasonable limit for clustering
                )
            
            result = await session.execute(query)
            findings = result.scalars().all()
            
            if not findings:
                return ToolResult(
                    success=True,
                    data=ClusterFindingsOutput(
                        clusters=[],
                        unclustered_findings=[],
                        clustering_metadata={"message": "No findings available for clustering"},
                    ).model_dump(),
                )
            
            # Advanced clustering by multiple criteria
            clusters_dict = defaultdict(list)
            unclustered = []
            
            # Severity priority for primary finding selection
            severity_priority = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
            
            for finding in findings:
                # Create cluster key based on criteria
                cluster_key_parts = []
                for criteria in inputs.clustering_criteria:
                    if criteria == 'rule_id':
                        cluster_key_parts.append(str(finding.rule_id))
                    elif criteria == 'resource_type':
                        # Get resource type from relationship
                        resource_type = "unknown"
                        if finding.resource and hasattr(finding.resource, 'resource_type'):
                            resource_type = finding.resource.resource_type
                        cluster_key_parts.append(resource_type)
                    elif criteria == 'provider':
                        cluster_key_parts.append(finding.provider)
                    elif criteria == 'severity':
                        cluster_key_parts.append(finding.severity)
                
                cluster_key = '|'.join(cluster_key_parts)
                clusters_dict[cluster_key].append(finding)
            
            # Convert to cluster objects with advanced analysis
            clusters = []
            cluster_id = 1
            
            for cluster_key, cluster_findings in clusters_dict.items():
                if len(cluster_findings) < 2:
                    # Single finding clusters go to unclustered
                    unclustered.extend(cluster_findings)
                    continue
                
                # Calculate detailed distributions
                severity_dist = defaultdict(int)
                provider_dist = defaultdict(int)
                resource_types = set()
                
                for f in cluster_findings:
                    severity_dist[f.severity] += 1
                    provider_dist[f.provider] += 1
                    if f.resource and hasattr(f.resource, 'resource_type'):
                        resource_types.add(f.resource.resource_type)
                
                # Estimate remediation time with business logic
                critical_count = severity_dist.get('critical', 0)
                high_count = severity_dist.get('high', 0)
                total_count = len(cluster_findings)
                
                if critical_count > 0:
                    est_time = f"{critical_count * 1}-{critical_count * 2} hours (critical priority)"
                elif high_count > 0:
                    est_time = f"{high_count * 2}-{high_count * 4} hours (high priority)"
                else:
                    est_time = f"{total_count * 0.5:.1f}-{total_count} hours (batch remediation)"
                
                # Select primary finding (highest severity, most recent)
                primary_finding = max(
                    cluster_findings, 
                    key=lambda f: (severity_priority.get(f.severity, 0), f.last_seen)
                )
                
                # Create intelligent cluster summary
                key_parts = cluster_key.split('|')
                criteria_names = inputs.clustering_criteria
                summary_parts = []
                for i, part in enumerate(key_parts):
                    if i < len(criteria_names):
                        criteria = criteria_names[i]
                        if criteria == 'rule_id' and primary_finding.rule:
                            summary_parts.append(f"rule '{primary_finding.rule.name if hasattr(primary_finding.rule, 'name') else part}'")
                        else:
                            summary_parts.append(f"{criteria} '{part}'")
                
                cluster_summary = f"{total_count} findings with {' and '.join(summary_parts)}"
                
                # Build comprehensive cluster
                cluster = FindingCluster(
                    cluster_id=f"cluster_{cluster_id}",
                    finding_count=total_count,
                    primary_finding=FindingSummary(
                        id=primary_finding.finding_id,
                        title=primary_finding.title,
                        description=primary_finding.summary or primary_finding.title,
                        severity=primary_finding.severity,
                        status=primary_finding.status,
                        provider=primary_finding.provider,
                        resource_type=getattr(primary_finding.resource, 'resource_type', 'unknown') if primary_finding.resource else 'unknown',
                        resource_id=str(primary_finding.resource_id) if primary_finding.resource_id else "",
                        rule_id=str(primary_finding.rule_id),
                        created_at=primary_finding.first_seen,
                        updated_at=primary_finding.last_seen,
                        evidence={},
                        compliance_mappings={},  # Would get from rule relationship
                    ),
                    cluster_summary=cluster_summary,
                    severity_distribution=dict(severity_dist),
                    provider_distribution=dict(provider_dist),
                    estimated_remediation_time=est_time,
                    sample_findings=[
                        FindingSummary(
                            id=f.finding_id,
                            title=f.title,
                            description=f.summary or f.title,
                            severity=f.severity,
                            status=f.status,
                            provider=f.provider,
                            resource_type=getattr(f.resource, 'resource_type', 'unknown') if f.resource else 'unknown',
                            resource_id=str(f.resource_id) if f.resource_id else "",
                            rule_id=str(f.rule_id),
                            created_at=f.first_seen,
                            updated_at=f.last_seen,
                            evidence={},
                            compliance_mappings={},
                        )
                        for f in sorted(cluster_findings, key=lambda x: (severity_priority.get(x.severity, 0), x.last_seen), reverse=True)[:3]
                    ],
                )
                
                clusters.append(cluster)
                cluster_id += 1
                
                if len(clusters) >= inputs.max_clusters:
                    # Move remaining clustered findings to unclustered
                    for remaining_key, remaining_findings in list(clusters_dict.items())[inputs.max_clusters:]:
                        unclustered.extend(remaining_findings)
                    break
            
            # Convert unclustered findings
            unclustered_summaries = [
                FindingSummary(
                    id=f.finding_id,
                    title=f.title,
                    description=f.summary or f.title,
                    severity=f.severity,
                    status=f.status,
                    provider=f.provider,
                    resource_type=getattr(f.resource, 'resource_type', 'unknown') if f.resource else 'unknown',
                    resource_id=str(f.resource_id) if f.resource_id else "",
                    rule_id=str(f.rule_id),
                    created_at=f.first_seen,
                    updated_at=f.last_seen,
                    evidence={},
                    compliance_mappings={},
                )
                for f in unclustered
            ]
            
            # Calculate clustering efficiency metrics
            total_findings = len(findings)
            clustered_findings = sum(cluster.finding_count for cluster in clusters)
            clustering_efficiency = (clustered_findings / total_findings * 100) if total_findings > 0 else 0
            
            output = ClusterFindingsOutput(
                clusters=clusters,
                unclustered_findings=unclustered_summaries,
                clustering_metadata={
                    "total_findings_analyzed": total_findings,
                    "clusters_created": len(clusters),
                    "unclustered_count": len(unclustered),
                    "clustering_criteria": inputs.clustering_criteria,
                    "similarity_threshold": inputs.similarity_threshold,
                    "clustering_efficiency_percent": round(clustering_efficiency, 1),
                    "avg_cluster_size": round(clustered_findings / len(clusters), 1) if clusters else 0,
                    "resource_types_found": len(resource_types) if 'resource_types' in locals() else 0,
                },
            )
            
            return ToolResult(
                success=True,
                data=output.model_dump(),
                metadata={
                    "clusters_found": len(clusters),
                    "total_findings": total_findings,
                    "clustering_efficiency": f"{clustering_efficiency:.1f}%",
                    "largest_cluster_size": max([c.finding_count for c in clusters]) if clusters else 0,
                },
            )
