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

from cerebro.core.database import get_db_session
from cerebro.findings.models import Finding, FindingStatus
from cerebro.findings.service import FindingsService

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
        
        async with get_db_session() as session:
            findings_service = FindingsService(session)
            
            # Build filters
            filters = {}
            if inputs.severity:
                filters['severity__in'] = inputs.severity
            if inputs.status:
                filters['status__in'] = inputs.status
            if inputs.provider:
                filters['provider__in'] = inputs.provider
            if inputs.created_after:
                filters['created_at__gte'] = inputs.created_after
            if inputs.created_before:
                filters['created_at__lte'] = inputs.created_before
            if inputs.rule_id:
                filters['rule_id'] = inputs.rule_id
            if inputs.resource_type:
                filters['resource_type'] = inputs.resource_type
            
            # Query findings
            findings, total_count = await findings_service.list_findings(
                org_id=org_id,
                limit=inputs.limit,
                offset=inputs.offset,
                filters=filters,
            )
            
            # Convert to summary format
            finding_summaries = [
                FindingSummary(
                    id=f.id,
                    title=f.title,
                    description=f.description,
                    severity=f.severity,
                    status=f.status.value,
                    provider=f.provider,
                    resource_type=f.resource_type,
                    resource_id=f.resource_id,
                    rule_id=f.rule_id,
                    created_at=f.created_at,
                    updated_at=f.updated_at,
                    evidence=f.evidence,
                    compliance_mappings=f.compliance_mappings or {},
                )
                for f in findings
            ]
            
            output = ListFindingsOutput(
                findings=finding_summaries,
                total_count=total_count,
                has_more=(inputs.offset + len(findings)) < total_count,
                filters_applied=filters,
            )
            
            return ToolResult(
                success=True,
                data=output.model_dump(),
                metadata={
                    "findings_count": len(findings),
                    "total_available": total_count,
                    "org_id": str(org_id),
                },
            )
    
    async def _get_finding(self, raw_data: Dict[str, Any], context: AgentContext) -> ToolResult:
        """Get a specific finding with optional history."""
        inputs = GetFindingInput(**raw_data)
        
        async with get_db_session() as session:
            findings_service = FindingsService(session)
            
            # Get the finding
            finding = await findings_service.get_finding(
                finding_id=inputs.finding_id,
                org_id=context.org_id,
            )
            
            if not finding:
                return ToolResult(
                    success=False,
                    error=f"Finding {inputs.finding_id} not found or access denied",
                )
            
            # Convert to summary
            finding_summary = FindingSummary(
                id=finding.id,
                title=finding.title,
                description=finding.description,
                severity=finding.severity,
                status=finding.status.value,
                provider=finding.provider,
                resource_type=finding.resource_type,
                resource_id=finding.resource_id,
                rule_id=finding.rule_id,
                created_at=finding.created_at,
                updated_at=finding.updated_at,
                evidence=finding.evidence if inputs.include_evidence else {},
                compliance_mappings=finding.compliance_mappings or {},
            )
            
            # Get history if requested
            history = None
            if inputs.include_history:
                history = await findings_service.get_finding_history(inputs.finding_id)
            
            # Get related findings (same rule, different resources)
            related_findings = []
            if finding.rule_id:
                related, _ = await findings_service.list_findings(
                    org_id=context.org_id,
                    limit=5,
                    filters={'rule_id': finding.rule_id},
                )
                related_findings = [
                    FindingSummary(
                        id=f.id,
                        title=f.title,
                        description=f.description,
                        severity=f.severity,
                        status=f.status.value,
                        provider=f.provider,
                        resource_type=f.resource_type,
                        resource_id=f.resource_id,
                        rule_id=f.rule_id,
                        created_at=f.created_at,
                        updated_at=f.updated_at,
                        evidence={},  # Don't include full evidence in related
                        compliance_mappings=f.compliance_mappings or {},
                    )
                    for f in related if f.id != finding.id
                ]
            
            output = GetFindingOutput(
                finding=finding_summary,
                history=history,
                related_findings=related_findings,
            )
            
            return ToolResult(
                success=True,
                data=output.model_dump(),
                metadata={
                    "finding_id": str(inputs.finding_id),
                    "related_count": len(related_findings),
                },
            )
    
    async def _update_finding_status(self, raw_data: Dict[str, Any], context: AgentContext) -> ToolResult:
        """Update finding status with audit trail."""
        inputs = UpdateFindingStatusInput(**raw_data)
        
        async with get_db_session() as session:
            findings_service = FindingsService(session)
            
            # Get current finding
            finding = await findings_service.get_finding(
                finding_id=inputs.finding_id,
                org_id=context.org_id,
            )
            
            if not finding:
                return ToolResult(
                    success=False,
                    error=f"Finding {inputs.finding_id} not found or access denied",
                )
            
            old_status = finding.status.value
            
            # Validate new status
            try:
                new_status = FindingStatus(inputs.status)
            except ValueError:
                return ToolResult(
                    success=False,
                    error=f"Invalid status: {inputs.status}",
                )
            
            # Update finding
            updated_finding = await findings_service.update_finding_status(
                finding_id=inputs.finding_id,
                status=new_status,
                comment=inputs.comment,
                updated_by=context.user_id,
                assignee=inputs.assignee,
            )
            
            output = UpdateFindingStatusOutput(
                finding_id=updated_finding.id,
                old_status=old_status,
                new_status=updated_finding.status.value,
                comment=inputs.comment,
                updated_at=updated_finding.updated_at,
                updated_by=context.user_id,
            )
            
            return ToolResult(
                success=True,
                data=output.model_dump(),
                metadata={
                    "status_change": f"{old_status} -> {updated_finding.status.value}",
                    "audit_trail": True,
                },
            )
    
    async def _cluster_findings(self, raw_data: Dict[str, Any], context: AgentContext) -> ToolResult:
        """Cluster similar findings to reduce alert fatigue."""
        inputs = ClusterFindingsInput(**raw_data)
        
        async with get_db_session() as session:
            findings_service = FindingsService(session)
            
            # Get findings to cluster
            if inputs.finding_ids:
                findings = []
                for finding_id in inputs.finding_ids:
                    finding = await findings_service.get_finding(finding_id, context.org_id)
                    if finding:
                        findings.append(finding)
            else:
                # Get recent open findings
                findings, _ = await findings_service.list_findings(
                    org_id=context.org_id,
                    limit=200,
                    filters={'status__in': ['new', 'investigating', 'in_progress']},
                )
            
            if not findings:
                return ToolResult(
                    success=True,
                    data=ClusterFindingsOutput(
                        clusters=[],
                        unclustered_findings=[],
                        clustering_metadata={"message": "No findings available for clustering"},
                    ).model_dump(),
                )
            
            # Simple clustering by rule_id and resource_type
            clusters_dict = {}
            unclustered = []
            
            for finding in findings:
                # Create cluster key based on criteria
                cluster_key_parts = []
                for criteria in inputs.clustering_criteria:
                    if criteria == 'rule_id':
                        cluster_key_parts.append(finding.rule_id or 'unknown')
                    elif criteria == 'resource_type':
                        cluster_key_parts.append(finding.resource_type or 'unknown')
                    elif criteria == 'provider':
                        cluster_key_parts.append(finding.provider or 'unknown')
                
                cluster_key = '|'.join(cluster_key_parts)
                
                if cluster_key not in clusters_dict:
                    clusters_dict[cluster_key] = []
                clusters_dict[cluster_key].append(finding)
            
            # Convert to cluster objects
            clusters = []
            cluster_id = 1
            
            for cluster_key, cluster_findings in clusters_dict.items():
                if len(cluster_findings) < 2:
                    # Single finding clusters go to unclustered
                    unclustered.extend(cluster_findings)
                    continue
                
                # Calculate distributions
                severity_dist = {}
                provider_dist = {}
                for f in cluster_findings:
                    severity_dist[f.severity] = severity_dist.get(f.severity, 0) + 1
                    provider_dist[f.provider] = provider_dist.get(f.provider, 0) + 1
                
                # Estimate remediation time based on severity and count
                high_severity_count = sum(
                    severity_dist.get(sev, 0) for sev in ['critical', 'high']
                )
                if high_severity_count > 0:
                    est_time = f"{high_severity_count * 2}-{high_severity_count * 4} hours"
                else:
                    est_time = f"{len(cluster_findings) * 0.5}-{len(cluster_findings)} hours"
                
                # Create cluster summary
                primary_finding = max(cluster_findings, key=lambda f: f.severity)
                cluster_summary = f"{len(cluster_findings)} similar {cluster_key.replace('|', ' + ')} findings"
                
                cluster = FindingCluster(
                    cluster_id=f"cluster_{cluster_id}",
                    finding_count=len(cluster_findings),
                    primary_finding=FindingSummary(
                        id=primary_finding.id,
                        title=primary_finding.title,
                        description=primary_finding.description,
                        severity=primary_finding.severity,
                        status=primary_finding.status.value,
                        provider=primary_finding.provider,
                        resource_type=primary_finding.resource_type,
                        resource_id=primary_finding.resource_id,
                        rule_id=primary_finding.rule_id,
                        created_at=primary_finding.created_at,
                        updated_at=primary_finding.updated_at,
                        evidence={},
                        compliance_mappings=primary_finding.compliance_mappings or {},
                    ),
                    cluster_summary=cluster_summary,
                    severity_distribution=severity_dist,
                    provider_distribution=provider_dist,
                    estimated_remediation_time=est_time,
                    sample_findings=[
                        FindingSummary(
                            id=f.id,
                            title=f.title,
                            description=f.description,
                            severity=f.severity,
                            status=f.status.value,
                            provider=f.provider,
                            resource_type=f.resource_type,
                            resource_id=f.resource_id,
                            rule_id=f.rule_id,
                            created_at=f.created_at,
                            updated_at=f.updated_at,
                            evidence={},
                            compliance_mappings=f.compliance_mappings or {},
                        )
                        for f in cluster_findings[:3]  # Show up to 3 samples
                    ],
                )
                
                clusters.append(cluster)
                cluster_id += 1
                
                if len(clusters) >= inputs.max_clusters:
                    break
            
            # Convert unclustered findings
            unclustered_summaries = [
                FindingSummary(
                    id=f.id,
                    title=f.title,
                    description=f.description,
                    severity=f.severity,
                    status=f.status.value,
                    provider=f.provider,
                    resource_type=f.resource_type,
                    resource_id=f.resource_id,
                    rule_id=f.rule_id,
                    created_at=f.created_at,
                    updated_at=f.updated_at,
                    evidence={},
                    compliance_mappings=f.compliance_mappings or {},
                )
                for f in unclustered
            ]
            
            output = ClusterFindingsOutput(
                clusters=clusters,
                unclustered_findings=unclustered_summaries,
                clustering_metadata={
                    "total_findings_analyzed": len(findings),
                    "clusters_created": len(clusters),
                    "unclustered_count": len(unclustered),
                    "clustering_criteria": inputs.clustering_criteria,
                    "similarity_threshold": inputs.similarity_threshold,
                },
            )
            
            return ToolResult(
                success=True,
                data=output.model_dump(),
                metadata={
                    "clusters_found": len(clusters),
                    "total_findings": len(findings),
                },
            )
