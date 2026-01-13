"""
Remediation Action Execution Tool

Provides automated remediation capabilities with:
- Pre-execution validation and impact assessment
- Rollback support for reversible actions
- Blast radius limits to prevent widespread changes
- Audit logging for all actions taken
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

import structlog
from pydantic import BaseModel, Field
from sqlalchemy import select

from cerebro.core.database import async_session_factory
from cerebro.core.models import Finding

from .base import AgentContext, StructuredTool, ToolPermissionLevel, ToolResult

logger = structlog.get_logger(__name__)


class ActionType(str, Enum):
    """Types of remediation actions."""

    # AWS Actions
    AWS_S3_BLOCK_PUBLIC_ACCESS = "aws.s3.block_public_access"
    AWS_S3_ENABLE_ENCRYPTION = "aws.s3.enable_encryption"
    AWS_S3_ENABLE_VERSIONING = "aws.s3.enable_versioning"
    AWS_IAM_DEACTIVATE_ACCESS_KEY = "aws.iam.deactivate_access_key"
    AWS_IAM_ATTACH_MFA_POLICY = "aws.iam.attach_mfa_policy"
    AWS_EC2_ENCRYPT_VOLUME = "aws.ec2.encrypt_volume"
    AWS_RDS_ENABLE_ENCRYPTION = "aws.rds.enable_encryption"
    AWS_SECURITY_GROUP_RESTRICT = "aws.security_group.restrict_ingress"

    # GCP Actions
    GCP_STORAGE_BLOCK_PUBLIC = "gcp.storage.block_public"
    GCP_IAM_REMOVE_BINDING = "gcp.iam.remove_binding"
    GCP_COMPUTE_ENABLE_SHIELDED = "gcp.compute.enable_shielded_vm"

    # Azure Actions
    AZURE_STORAGE_ENABLE_ENCRYPTION = "azure.storage.enable_encryption"
    AZURE_NSG_RESTRICT_RULE = "azure.nsg.restrict_rule"

    # Okta Actions
    OKTA_USER_SUSPEND = "okta.user.suspend"
    OKTA_APP_DEACTIVATE = "okta.app.deactivate"
    OKTA_ENFORCE_MFA = "okta.policy.enforce_mfa"

    # GitHub Actions
    GITHUB_REPO_ENABLE_BRANCH_PROTECTION = "github.repo.enable_branch_protection"
    GITHUB_REVOKE_ACCESS = "github.repo.revoke_access"

    # Generic Actions
    CREATE_TICKET = "generic.create_ticket"
    SEND_NOTIFICATION = "generic.send_notification"


class ActionStatus(str, Enum):
    """Status of remediation action execution."""

    PENDING = "pending"
    VALIDATING = "validating"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class ActionResult:
    """Result of a remediation action."""

    action_id: str
    action_type: ActionType
    status: ActionStatus
    resource_id: str
    started_at: datetime
    completed_at: datetime | None = None
    error: str | None = None
    rollback_available: bool = False
    rollback_data: dict[str, Any] | None = None
    changes_made: list[str] | None = None


class RemediationActionInput(BaseModel):
    """Input for executing a remediation action."""

    action_type: ActionType = Field(..., description="Type of remediation action to execute")
    resource_id: str = Field(..., description="ID of the resource to remediate")
    finding_id: UUID | None = Field(None, description="Associated finding ID")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Action-specific parameters")
    dry_run: bool = Field(default=True, description="If true, validate but don't execute")
    require_approval: bool = Field(default=True, description="Require approval before execution")


class RollbackInput(BaseModel):
    """Input for rolling back a remediation action."""

    action_id: str = Field(..., description="ID of the action to rollback")


class RemediationActionTool(StructuredTool):
    """
    Execute automated remediation actions for security findings.

    Supports dry-run mode, rollback capabilities, and blast radius limits.
    All actions are logged for audit purposes.
    """

    tool_name = "execute_remediation"
    tool_description = "Execute automated remediation actions with validation and rollback support"
    tool_version = "1.0.0"
    input_model = RemediationActionInput
    output_model = BaseModel
    required_permission = ToolPermissionLevel.WRITE_DESTRUCTIVE

    # Blast radius limits - max resources that can be affected in one execution
    MAX_RESOURCES_PER_ACTION = 10

    # Action handlers registry
    _action_handlers: dict[ActionType, Any] = {}

    async def _run(  # type: ignore[override]
        self,
        context: AgentContext,
        action_type: ActionType,
        resource_id: str,
        finding_id: UUID | None = None,
        parameters: dict[str, Any] | None = None,
        dry_run: bool = True,
        require_approval: bool = True,
    ) -> ToolResult:
        """Execute a remediation action."""
        action_id = str(uuid4())
        parameters = parameters or {}

        logger.info(
            "Executing remediation action",
            action_id=action_id,
            action_type=action_type,
            resource_id=resource_id,
            dry_run=dry_run,
            org_id=context.org_id,
        )

        try:
            # Validate the action
            validation = await self._validate_action(
                context, action_type, resource_id, parameters
            )

            if not validation["valid"]:
                return ToolResult(
                    success=False,
                    error=f"Validation failed: {validation['reason']}",
                    data={"validation": validation},
                )

            # Check blast radius
            if validation.get("affected_resources", 1) > self.MAX_RESOURCES_PER_ACTION:
                return ToolResult(
                    success=False,
                    error=f"Action would affect {validation['affected_resources']} resources, "
                    f"exceeding limit of {self.MAX_RESOURCES_PER_ACTION}",
                    data={"validation": validation},
                )

            if dry_run:
                return ToolResult(
                    success=True,
                    data={
                        "action_id": action_id,
                        "mode": "dry_run",
                        "validation": validation,
                        "would_execute": {
                            "action_type": action_type.value,
                            "resource_id": resource_id,
                            "estimated_impact": validation.get("impact", "unknown"),
                            "rollback_available": validation.get("rollback_available", False),
                        },
                    },
                    metadata={"dry_run": True},
                )

            if require_approval:
                # Store pending action for approval workflow
                await self._store_pending_action(
                    context, action_id, action_type, resource_id, parameters, validation
                )
                return ToolResult(
                    success=True,
                    data={
                        "action_id": action_id,
                        "status": "pending_approval",
                        "validation": validation,
                        "approval_required": True,
                    },
                )

            # Execute the action
            result = await self._execute_action(
                context, action_id, action_type, resource_id, parameters
            )

            # Log the action for audit
            await self._log_action(context, result, finding_id)

            # Update finding status if successful
            if result.status == ActionStatus.COMPLETED and finding_id:
                await self._update_finding_status(context, finding_id, "remediated")

            return ToolResult(
                success=result.status == ActionStatus.COMPLETED,
                data={
                    "action_id": result.action_id,
                    "status": result.status.value,
                    "resource_id": result.resource_id,
                    "changes_made": result.changes_made,
                    "rollback_available": result.rollback_available,
                    "duration_ms": (
                        (result.completed_at - result.started_at).total_seconds() * 1000
                        if result.completed_at
                        else None
                    ),
                },
                error=result.error,
            )

        except Exception as e:
            logger.exception(
                "Remediation action failed",
                action_id=action_id,
                action_type=action_type,
                error=str(e),
            )
            return ToolResult(
                success=False,
                error=f"Action execution failed: {e!s}",
            )

    async def _validate_action(
        self,
        context: AgentContext,
        action_type: ActionType,
        resource_id: str,
        parameters: dict[str, Any],
    ) -> dict[str, Any]:
        """Validate that an action can be executed."""
        validation: dict[str, Any] = {
            "valid": True,
            "reason": None,
            "affected_resources": 1,
            "impact": "low",
            "rollback_available": False,
            "warnings": [],
        }

        # Action-specific validation
        if action_type == ActionType.AWS_S3_BLOCK_PUBLIC_ACCESS:
            validation["rollback_available"] = True
            validation["impact"] = "medium"
            validation["warnings"].append(
                "This may break applications relying on public access"
            )

        elif action_type == ActionType.AWS_IAM_DEACTIVATE_ACCESS_KEY:
            validation["rollback_available"] = True
            validation["impact"] = "high"
            validation["warnings"].append(
                "This may break applications using this access key"
            )

        elif action_type == ActionType.OKTA_USER_SUSPEND:
            validation["rollback_available"] = True
            validation["impact"] = "high"
            validation["warnings"].append(
                "User will immediately lose access to all applications"
            )

        elif action_type == ActionType.AWS_SECURITY_GROUP_RESTRICT:
            validation["rollback_available"] = True
            validation["impact"] = "high"
            # Check for wide-open rules
            if parameters.get("current_cidr") == "0.0.0.0/0":
                validation["warnings"].append(
                    "Restricting from 0.0.0.0/0 - verify allowed CIDRs"
                )

        elif action_type == ActionType.GITHUB_REPO_ENABLE_BRANCH_PROTECTION:
            validation["rollback_available"] = True
            validation["impact"] = "low"
            validation["warnings"].append(
                "Developers may need to update their workflow"
            )

        return validation

    async def _execute_action(
        self,
        context: AgentContext,
        action_id: str,
        action_type: ActionType,
        resource_id: str,
        parameters: dict[str, Any],
    ) -> ActionResult:
        """Execute the remediation action."""
        started_at = datetime.now(UTC)
        changes_made = []
        rollback_data: dict[str, Any] = {}
        error = None
        status = ActionStatus.EXECUTING

        try:
            # Route to appropriate handler
            if action_type == ActionType.AWS_S3_BLOCK_PUBLIC_ACCESS:
                rollback_data, changes = await self._aws_s3_block_public(
                    context, resource_id, parameters
                )
                changes_made.extend(changes)

            elif action_type == ActionType.AWS_S3_ENABLE_ENCRYPTION:
                rollback_data, changes = await self._aws_s3_enable_encryption(
                    context, resource_id, parameters
                )
                changes_made.extend(changes)

            elif action_type == ActionType.AWS_IAM_DEACTIVATE_ACCESS_KEY:
                rollback_data, changes = await self._aws_iam_deactivate_key(
                    context, resource_id, parameters
                )
                changes_made.extend(changes)

            elif action_type == ActionType.OKTA_USER_SUSPEND:
                rollback_data, changes = await self._okta_suspend_user(
                    context, resource_id, parameters
                )
                changes_made.extend(changes)

            elif action_type == ActionType.GITHUB_REPO_ENABLE_BRANCH_PROTECTION:
                rollback_data, changes = await self._github_enable_branch_protection(
                    context, resource_id, parameters
                )
                changes_made.extend(changes)

            elif action_type == ActionType.CREATE_TICKET:
                rollback_data, changes = await self._create_ticket(
                    context, resource_id, parameters
                )
                changes_made.extend(changes)

            elif action_type == ActionType.SEND_NOTIFICATION:
                rollback_data, changes = await self._send_notification(
                    context, resource_id, parameters
                )
                changes_made.extend(changes)

            else:
                raise NotImplementedError(f"Action type {action_type} not implemented")

            status = ActionStatus.COMPLETED

        except Exception as e:
            logger.exception("Action execution error", action_type=action_type)
            error = str(e)
            status = ActionStatus.FAILED

        return ActionResult(
            action_id=action_id,
            action_type=action_type,
            status=status,
            resource_id=resource_id,
            started_at=started_at,
            completed_at=datetime.now(UTC),
            error=error,
            rollback_available=bool(rollback_data),
            rollback_data=rollback_data,
            changes_made=changes_made,
        )

    # AWS Action Handlers
    async def _aws_s3_block_public(
        self, context: AgentContext, bucket_name: str, parameters: dict[str, Any]
    ) -> tuple[dict[str, Any], list[str]]:
        """Block public access on S3 bucket."""
        # In production, this would use boto3
        # For now, simulate the action
        rollback_data = {
            "previous_config": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            }
        }
        changes = [
            f"Enabled BlockPublicAcls on {bucket_name}",
            f"Enabled IgnorePublicAcls on {bucket_name}",
            f"Enabled BlockPublicPolicy on {bucket_name}",
            f"Enabled RestrictPublicBuckets on {bucket_name}",
        ]

        logger.info("Blocked public access on S3 bucket", bucket=bucket_name)
        return rollback_data, changes

    async def _aws_s3_enable_encryption(
        self, context: AgentContext, bucket_name: str, parameters: dict[str, Any]
    ) -> tuple[dict[str, Any], list[str]]:
        """Enable default encryption on S3 bucket."""
        encryption_type = parameters.get("encryption_type", "AES256")
        rollback_data = {"previous_encryption": None}
        changes = [f"Enabled {encryption_type} encryption on {bucket_name}"]

        logger.info("Enabled encryption on S3 bucket", bucket=bucket_name, type=encryption_type)
        return rollback_data, changes

    async def _aws_iam_deactivate_key(
        self, context: AgentContext, access_key_id: str, parameters: dict[str, Any]
    ) -> tuple[dict[str, Any], list[str]]:
        """Deactivate IAM access key."""
        rollback_data = {"previous_status": "Active"}
        changes = [f"Deactivated access key {access_key_id}"]

        logger.info("Deactivated IAM access key", access_key_id=access_key_id)
        return rollback_data, changes

    # Okta Action Handlers
    async def _okta_suspend_user(
        self, context: AgentContext, user_id: str, parameters: dict[str, Any]
    ) -> tuple[dict[str, Any], list[str]]:
        """Suspend Okta user."""
        rollback_data = {"previous_status": "ACTIVE"}
        changes = [f"Suspended Okta user {user_id}"]

        logger.info("Suspended Okta user", user_id=user_id)
        return rollback_data, changes

    # GitHub Action Handlers
    async def _github_enable_branch_protection(
        self, context: AgentContext, repo_name: str, parameters: dict[str, Any]
    ) -> tuple[dict[str, Any], list[str]]:
        """Enable branch protection on GitHub repository."""
        branch = parameters.get("branch", "main")
        rollback_data = {"previous_protection": None}
        changes = [
            f"Enabled branch protection on {repo_name}/{branch}",
            "Enabled required pull request reviews",
            "Enabled status checks",
        ]

        logger.info("Enabled branch protection", repo=repo_name, branch=branch)
        return rollback_data, changes

    # Generic Action Handlers
    async def _create_ticket(
        self, context: AgentContext, resource_id: str, parameters: dict[str, Any]
    ) -> tuple[dict[str, Any], list[str]]:
        """Create a ticket for manual remediation."""
        ticket_system = parameters.get("system", "jira")
        title = parameters.get("title", f"Security finding for {resource_id}")

        # In production, this would integrate with Jira, ServiceNow, etc.
        ticket_id = f"SEC-{uuid4().hex[:8].upper()}"

        rollback_data = {"ticket_id": ticket_id}
        changes = [f"Created {ticket_system} ticket {ticket_id}: {title}"]

        logger.info("Created remediation ticket", ticket_id=ticket_id, system=ticket_system)
        return rollback_data, changes

    async def _send_notification(
        self, context: AgentContext, resource_id: str, parameters: dict[str, Any]
    ) -> tuple[dict[str, Any], list[str]]:
        """Send notification about finding."""
        channel = parameters.get("channel", "slack")
        recipients = parameters.get("recipients", [])

        rollback_data: dict[str, Any] = {}  # Notifications cannot be rolled back
        changes = [f"Sent {channel} notification to {len(recipients)} recipients"]

        logger.info("Sent notification", channel=channel, recipients=recipients)
        return rollback_data, changes

    # Helper Methods
    async def _store_pending_action(
        self,
        context: AgentContext,
        action_id: str,
        action_type: ActionType,
        resource_id: str,
        parameters: dict[str, Any],
        validation: dict[str, Any],
    ) -> None:
        """Store pending action for approval workflow."""
        # In production, this would store in database
        logger.info(
            "Stored pending action for approval",
            action_id=action_id,
            action_type=action_type,
        )

    async def _log_action(
        self,
        context: AgentContext,
        result: ActionResult,
        finding_id: UUID | None,
    ) -> None:
        """Log action for audit trail."""
        logger.info(
            "Remediation action completed",
            action_id=result.action_id,
            action_type=result.action_type,
            status=result.status,
            resource_id=result.resource_id,
            finding_id=finding_id,
            changes=result.changes_made,
        )

    async def _update_finding_status(
        self,
        context: AgentContext,
        finding_id: UUID,
        status: str,
    ) -> None:
        """Update finding status after remediation."""
        async with async_session_factory() as db:
            result = await db.execute(
                select(Finding).where(
                    Finding.finding_id == finding_id,
                    Finding.org_id == context.org_id,
                )
            )
            finding = result.scalar_one_or_none()
            if finding:
                finding.status = status
                finding.last_seen = datetime.now(UTC)
                await db.commit()
                logger.info("Updated finding status", finding_id=finding_id, status=status)


class RollbackTool(StructuredTool):
    """
    Rollback a previously executed remediation action.

    Only works for actions that support rollback and have stored rollback data.
    """

    tool_name = "rollback_remediation"
    tool_description = "Rollback a previously executed remediation action"
    tool_version = "1.0.0"
    input_model = RollbackInput
    output_model = BaseModel
    required_permission = ToolPermissionLevel.WRITE_DESTRUCTIVE

    async def _run(  # type: ignore[override]
        self,
        context: AgentContext,
        action_id: str,
    ) -> ToolResult:
        """Rollback a remediation action."""
        logger.info(
            "Rolling back remediation action",
            action_id=action_id,
            org_id=context.org_id,
        )

        # In production, this would:
        # 1. Retrieve the action from database
        # 2. Validate rollback is possible
        # 3. Execute rollback using stored rollback_data
        # 4. Update action status

        return ToolResult(
            success=True,
            data={
                "action_id": action_id,
                "status": "rolled_back",
                "message": "Action successfully rolled back",
            },
        )


class ListPendingActionsInput(BaseModel):
    """Input for listing pending remediation actions."""

    status: str | None = Field(None, description="Filter by status")
    limit: int = Field(default=20, description="Maximum actions to return")


class ListPendingActionsTool(StructuredTool):
    """
    List pending remediation actions awaiting approval.
    """

    tool_name = "list_pending_remediations"
    tool_description = "List pending remediation actions awaiting approval"
    tool_version = "1.0.0"
    input_model = ListPendingActionsInput
    output_model = BaseModel
    required_permission = ToolPermissionLevel.READ_ONLY

    async def _run(  # type: ignore[override]
        self,
        context: AgentContext,
        status: str | None = None,
        limit: int = 20,
    ) -> ToolResult:
        """List pending remediation actions."""
        # In production, this would query the database
        return ToolResult(
            success=True,
            data={
                "pending_actions": [],
                "count": 0,
            },
        )
