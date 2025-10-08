"""
Update finding status tool for Cerebro agents.

Provides secure, audited access to updating finding status with proper RBAC,
dry-run support, and audit trail creation.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import UUID, uuid4

import structlog
from pydantic import BaseModel, Field
from sqlalchemy import select

from cerebro.core.database import async_session_factory
from cerebro.core.models import Finding, AuditEvent
from cerebro.core.repositories import FindingRepository

from .base import Tool, ToolResult, AgentContext, ToolPermissionLevel

logger = structlog.get_logger(__name__)


class UpdateFindingStatusInput(BaseModel):
    """Input for updating finding status."""
    finding_id: str = Field(description="Finding ID to update")
    status: str = Field(description="New status for the finding")
    comment: str = Field(description="Comment explaining the status change")
    assignee: Optional[str] = Field(None, description="User to assign the finding to")


class UpdateFindingStatusOutput(BaseModel):
    """Output for updating finding status."""
    finding_id: UUID
    old_status: str
    new_status: str
    comment: str
    updated_at: str  # ISO format
    updated_by: str
    dry_run: bool
    audit_event_id: Optional[UUID] = None


class FindingStatusUpdateTool(Tool):
    """Tool for updating finding status with audit trails and RBAC."""
    
    @property
    def name(self) -> str:
        return "finding_update_status"
    
    @property
    def description(self) -> str:
        return "Update security finding status with audit trail and approval workflow"
    
    @property
    def input_schema(self) -> type:
        return UpdateFindingStatusInput
    
    @property
    def output_schema(self) -> type:
        return UpdateFindingStatusOutput
    
    @property
    def permission_level(self) -> ToolPermissionLevel:
        return ToolPermissionLevel.WRITE_SAFE
    
    @property
    def cel_policy_key(self) -> Optional[str]:
        return "tools.findings.update_status"
    
    @property
    def cel_expression(self) -> Optional[str]:
        # Require security analyst role and proper org ownership
        return """
        has(roles) && ('security_analyst' in roles || 'security_admin' in roles) &&
        org_id == context.org_id &&
        (inputs.status != 'accepted_risk' || has(approval))
        """
    
    @property
    def requires_approval(self) -> bool:
        # Require approval for accepting risk
        return True
    
    async def execute(self, inputs: BaseModel, context: AgentContext) -> ToolResult:
        """Update finding status with comprehensive validation and audit trail."""
        
        try:
            update_inputs = UpdateFindingStatusInput(**inputs.model_dump())
            
            # Validate finding ID format
            try:
                finding_uuid = UUID(update_inputs.finding_id)
            except ValueError:
                return ToolResult(
                    success=False,
                    error=f"Invalid finding ID format: {update_inputs.finding_id}",
                )
            
            # Validate status value
            valid_statuses = ['open', 'suppressed', 'accepted_risk', 'fixed']
            if update_inputs.status not in valid_statuses:
                return ToolResult(
                    success=False,
                    error=f"Invalid status: {update_inputs.status}. Valid statuses: {valid_statuses}",
                )
            
            # Enforce provider scope if specified
            provider_allowed = True
            if context.provider_scope:
                # Need to check finding's provider is in scope
                async with async_session_factory() as session:
                    finding_provider_query = select(Finding.provider).where(
                        Finding.finding_id == finding_uuid,
                        Finding.org_id == context.org_id
                    )
                    result = await session.execute(finding_provider_query)
                    finding_provider = result.scalar_one_or_none()
                    
                    if finding_provider and finding_provider not in context.provider_scope:
                        return ToolResult(
                            success=False,
                            error=f"Finding provider '{finding_provider}' not in authorized scope: {context.provider_scope}",
                        )
            
            # Single transaction for all operations
            async with async_session_factory() as session:
                # Get the current finding
                query = select(Finding).where(
                    Finding.finding_id == finding_uuid,
                    Finding.org_id == context.org_id
                )
                
                result = await session.execute(query)
                finding = result.scalar_one_or_none()
                
                if not finding:
                    return ToolResult(
                        success=False,
                        error=f"Finding {update_inputs.finding_id} not found or access denied",
                    )
                
                old_status = finding.status
                
                # Check if status change is actually needed
                if old_status == update_inputs.status:
                    return ToolResult(
                        success=True,
                        data=UpdateFindingStatusOutput(
                            finding_id=finding.finding_id,
                            old_status=old_status,
                            new_status=finding.status,
                            comment=update_inputs.comment,
                            updated_at=finding.last_seen.isoformat(),
                            updated_by=context.user_id,
                            dry_run=context.dry_run,
                        ).model_dump(),
                        metadata={
                            "no_change_needed": True,
                            "status": old_status,
                        },
                    )
                
                # Handle dry-run mode
                if context.dry_run:
                    return ToolResult(
                        success=True,
                        data=UpdateFindingStatusOutput(
                            finding_id=finding.finding_id,
                            old_status=old_status,
                            new_status=update_inputs.status,
                            comment=update_inputs.comment,
                            updated_at=datetime.now(timezone.utc).isoformat(),
                            updated_by=context.user_id,
                            dry_run=True,
                        ).model_dump(),
                        dry_run=True,
                        preview={
                            "would_change_status": f"{old_status} -> {update_inputs.status}",
                            "would_update_timestamp": True,
                            "would_create_audit_event": True,
                            "assignee_change": update_inputs.assignee,
                        },
                        metadata={
                            "dry_run_preview": True,
                            "finding_title": finding.title,
                            "finding_severity": finding.severity,
                        },
                    )
                
                # Perform actual update
                finding.status = update_inputs.status
                finding.last_seen = datetime.now(timezone.utc)
                
                # Set resolved timestamp if marking as fixed
                if update_inputs.status == 'fixed' and old_status != 'fixed':
                    if hasattr(finding, 'resolved_at'):
                        finding.resolved_at = datetime.now(timezone.utc)
                
                # Create comprehensive agent audit event
                from cerebro.agents.audit import log_agent_event

                audit_event = await log_agent_event(
                    org_id=context.org_id,
                    session_id=context.session_id,
                    event_type="finding_status_changed",
                    actor=context.user_id,
                    agent_type=context.agent_type,
                    tool_name=self.name,
                    resource_type="finding",
                    resource_id=str(finding.finding_id),
                    event_data={
                        "finding_title": finding.title,
                        "old_status": old_status,
                        "new_status": finding.status,
                        "comment": update_inputs.comment,
                        "assignee": update_inputs.assignee,
                        "severity": finding.severity,
                        "provider": finding.provider,
                        "rule_id": str(finding.rule_id),
                    },
                    success=True,
                )
                
                # Commit all changes atomically
                await session.commit()
                await session.refresh(finding)

                output = UpdateFindingStatusOutput(
                    finding_id=finding.finding_id,
                    old_status=old_status,
                    new_status=finding.status,
                    comment=update_inputs.comment,
                    updated_at=finding.last_seen.isoformat(),
                    updated_by=context.user_id,
                    dry_run=False,
                    audit_event_id=audit_event.event_id,
                )
                
                return ToolResult(
                    success=True,
                    data=output.model_dump(),
                    metadata={
                        "status_change": f"{old_status} -> {finding.status}",
                        "audit_trail": True,
                        "resolved": finding.status == 'fixed',
                        "assignee": update_inputs.assignee,
                        "finding_title": finding.title,
                        "severity": finding.severity,
                        "provider": finding.provider,
                        "atomic_transaction": True,
                    },
                )
                
        except Exception as e:
            logger.exception("Update finding status failed", finding_id=update_inputs.finding_id, error=str(e))
            return ToolResult(
                success=False,
                error=f"Failed to update finding status: {str(e)}",
                metadata={
                    "error_type": "database_error",
                    "finding_id": update_inputs.finding_id,
                },
            )
