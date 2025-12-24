"""
Remediation Suggestion Tool

Provides intelligent remediation suggestions based on:
- Finding type and severity
- Resource configuration
- Best practices and compliance requirements
- Historical remediation patterns
"""

from typing import List, Optional
from uuid import UUID
from pydantic import BaseModel, Field

from .base import StructuredTool, AgentContext, ToolResult, ToolPermissionLevel
import structlog

logger = structlog.get_logger(__name__)


class RemediationInput(BaseModel):
    """Input parameters for remediation suggestions."""

    finding_id: Optional[UUID] = Field(
        None, description="Specific finding ID to get remediation for"
    )
    resource_type: Optional[str] = Field(
        None, description="Resource type to get general remediations for"
    )
    severity: Optional[str] = Field(
        None, description="Filter by severity: critical, high, medium, low"
    )
    limit: int = Field(
        default=5, description="Maximum number of remediation suggestions to return"
    )


class RemediationSuggestion(BaseModel):
    """A single remediation suggestion."""

    priority: int = Field(..., description="Priority (1=highest)")
    title: str = Field(..., description="Short title")
    description: str = Field(..., description="Detailed description")
    steps: List[str] = Field(..., description="Step-by-step remediation steps")
    automation_available: bool = Field(..., description="Can this be automated?")
    estimated_effort: str = Field(
        ..., description="Estimated effort (minutes/hours/days)"
    )
    impact: str = Field(..., description="Impact of implementing this remediation")
    references: List[str] = Field(default_factory=list, description="Reference links")


class RemediationTool(StructuredTool):
    """
    Suggest intelligent remediation actions for security findings.

    Provides prioritized, actionable remediation steps with effort estimates,
    automation options, and compliance mapping.
    """

    tool_name = "remediation_suggestions"
    tool_description = "Get intelligent remediation suggestions for security findings with step-by-step instructions"
    tool_version = "1.0.0"
    input_model = RemediationInput
    output_model = BaseModel  # List of suggestions returned in data field
    required_permission = ToolPermissionLevel.READ_ONLY

    async def _run(  # type: ignore[override]
        self,
        context: AgentContext,
        finding_id: Optional[UUID] = None,
        resource_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 5,
    ) -> ToolResult:
        """
        Get remediation suggestions.

        Args:
            context: Agent execution context
            finding_id: Specific finding to remediate
            resource_type: Resource type for general remediations
            severity: Filter by severity
            limit: Maximum suggestions to return

        Returns:
            ToolResult with remediation suggestions
        """
        try:
            logger.info(
                "Generating remediation suggestions",
                finding_id=finding_id,
                resource_type=resource_type,
                severity=severity,
                org_id=context.org_id,
            )

            if finding_id:
                suggestions = await self._remediate_finding(context, finding_id)
            elif resource_type:
                suggestions = await self._remediate_resource_type(
                    context, resource_type, severity, limit
                )
            else:
                suggestions = await self._remediate_top_issues(context, severity, limit)

            return ToolResult(
                success=True,
                data={
                    "suggestions": [s.model_dump() for s in suggestions[:limit]],
                    "count": len(suggestions),
                },
                metadata={
                    "finding_id": str(finding_id) if finding_id else None,
                    "resource_type": resource_type,
                    "severity": severity,
                },
            )

        except Exception as e:
            logger.exception(
                "Remediation suggestion failed",
                finding_id=finding_id,
                error=str(e),
            )
            return ToolResult(
                success=False,
                error=f"Remediation suggestion failed: {str(e)}",
            )

    async def _remediate_finding(
        self,
        context: AgentContext,
        finding_id: UUID,
    ) -> List[RemediationSuggestion]:
        """Get remediation for a specific finding."""
        from cerebro.core.database import async_session_factory
        from cerebro.core.models import Finding
        from sqlalchemy import select
        from sqlalchemy.orm import joinedload

        async with async_session_factory() as db:
            # Get finding with related data
            query = (
                select(Finding)
                .options(joinedload(Finding.rule))
                .options(joinedload(Finding.resource))
                .where(Finding.finding_id == finding_id)
                .where(Finding.org_id == context.org_id)
            )

            result = await db.execute(query)
            finding = result.scalar_one_or_none()

            if not finding:
                return []

            # Generate suggestions based on finding details
            return self._generate_suggestions_for_finding(finding)

    async def _remediate_resource_type(
        self,
        context: AgentContext,
        resource_type: str,
        severity: Optional[str],
        limit: int,
    ) -> List[RemediationSuggestion]:
        """Get general remediations for a resource type."""
        # Return generic best practices for the resource type
        suggestions = self._get_best_practices(resource_type)

        if severity:
            suggestions = [
                s for s in suggestions if self._matches_severity(s, severity)
            ]

        return suggestions[:limit]

    async def _remediate_top_issues(
        self,
        context: AgentContext,
        severity: Optional[str],
        limit: int,
    ) -> List[RemediationSuggestion]:
        """Get remediations for top issues in the organization."""
        from cerebro.core.database import async_session_factory
        from cerebro.core.models import Finding
        from sqlalchemy import select, func

        async with async_session_factory() as db:
            # Get most common finding types
            query = (
                select(Finding.rule_id, func.count(Finding.finding_id))
                .where(Finding.org_id == context.org_id)
                .where(Finding.status != "resolved")
                .group_by(Finding.rule_id)
                .order_by(func.count(Finding.finding_id).desc())
                .limit(limit)
            )

            if severity:
                query = query.where(Finding.severity == severity)

            result = await db.execute(query)
            common_issues = result.all()

            # Generate suggestions for common issues
            suggestions = []
            for rule_id, count in common_issues:
                suggestion = self._generate_generic_suggestion(rule_id, count)
                if suggestion:
                    suggestions.append(suggestion)

            return suggestions

    def _generate_suggestions_for_finding(
        self,
        finding,
    ) -> List[RemediationSuggestion]:
        """Generate specific remediation suggestions for a finding."""
        suggestions = []

        # Map common finding types to remediations
        remediation_map = {
            "public_s3_bucket": {
                "title": "Restrict S3 Bucket Public Access",
                "steps": [
                    "Navigate to AWS S3 Console",
                    "Select the bucket: {resource_name}",
                    "Go to 'Permissions' tab",
                    "Click 'Block public access (bucket settings)'",
                    "Enable 'Block all public access'",
                    "Confirm the changes",
                ],
                "automation": True,
                "effort": "5 minutes",
                "impact": "Prevents unauthorized access to bucket contents",
            },
            "iam_user_without_mfa": {
                "title": "Enable MFA for IAM User",
                "steps": [
                    "Navigate to AWS IAM Console",
                    "Select 'Users'",
                    "Click on username: {resource_name}",
                    "Go to 'Security credentials' tab",
                    "Click 'Manage' next to 'Assigned MFA device'",
                    "Follow wizard to assign MFA device",
                ],
                "automation": False,
                "effort": "10 minutes",
                "impact": "Significantly reduces account compromise risk",
            },
            "unencrypted_volume": {
                "title": "Enable Encryption for EBS Volume",
                "steps": [
                    "Create snapshot of unencrypted volume",
                    "Copy snapshot with encryption enabled",
                    "Create new volume from encrypted snapshot",
                    "Detach old volume and attach new volume",
                    "Test application functionality",
                    "Delete old unencrypted volume",
                ],
                "automation": True,
                "effort": "30 minutes",
                "impact": "Protects data at rest from unauthorized access",
            },
        }

        # Determine finding type from rule or resource
        finding_type = self._classify_finding(finding)

        if finding_type in remediation_map:
            template = remediation_map[finding_type]
            suggestions.append(
                RemediationSuggestion(
                    priority=1,
                    title=template["title"],
                    description=f"Remediate {finding.title}",
                    steps=template["steps"],
                    automation_available=template["automation"],
                    estimated_effort=template["effort"],
                    impact=template["impact"],
                    references=[
                        "https://docs.aws.amazon.com/security/",
                        "https://cis.org/controls/",
                    ],
                )
            )

        # Add generic high-level suggestion
        suggestions.append(
            RemediationSuggestion(
                priority=2,
                title="Review and Update Security Policies",
                description="Ensure security policies align with best practices",
                steps=[
                    "Review current security policy configuration",
                    "Compare against CIS benchmarks",
                    "Identify gaps and prioritize fixes",
                    "Implement policy updates",
                    "Document changes for audit trail",
                ],
                automation_available=False,
                estimated_effort="2 hours",
                impact="Improves overall security posture",
                references=["https://www.cisecurity.org/cis-benchmarks/"],
            )
        )

        return suggestions

    def _classify_finding(self, finding) -> str:
        """Classify finding type for remediation mapping."""
        title_lower = finding.title.lower()

        if "public" in title_lower and "s3" in title_lower:
            return "public_s3_bucket"
        elif "mfa" in title_lower:
            return "iam_user_without_mfa"
        elif "encrypt" in title_lower:
            return "unencrypted_volume"
        else:
            return "generic"

    def _get_best_practices(self, resource_type: str) -> List[RemediationSuggestion]:
        """Get best practice remediations for a resource type."""
        practices = {
            "s3_bucket": [
                RemediationSuggestion(
                    priority=1,
                    title="Enable S3 Bucket Versioning",
                    description="Protect against accidental deletions and modifications",
                    steps=[
                        "Open S3 console",
                        "Select bucket",
                        "Enable versioning in properties",
                        "Configure lifecycle policies for old versions",
                    ],
                    automation_available=True,
                    estimated_effort="5 minutes",
                    impact="Enables recovery from accidents and malicious actions",
                    references=[
                        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"
                    ],
                ),
                RemediationSuggestion(
                    priority=2,
                    title="Enable S3 Bucket Encryption",
                    description="Encrypt all objects at rest",
                    steps=[
                        "Open S3 console",
                        "Select bucket",
                        "Go to Properties → Default encryption",
                        "Enable SSE-S3 or SSE-KMS",
                    ],
                    automation_available=True,
                    estimated_effort="5 minutes",
                    impact="Protects data at rest",
                    references=[
                        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html"
                    ],
                ),
            ],
            "iam_user": [
                RemediationSuggestion(
                    priority=1,
                    title="Enforce MFA for All Users",
                    description="Require multi-factor authentication",
                    steps=[
                        "Create IAM policy requiring MFA",
                        "Attach policy to user group",
                        "Notify users to configure MFA",
                        "Monitor compliance",
                    ],
                    automation_available=False,
                    estimated_effort="1 hour",
                    impact="Significantly reduces unauthorized access risk",
                    references=[
                        "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"
                    ],
                ),
            ],
        }

        return practices.get(resource_type, [])

    def _generate_generic_suggestion(
        self,
        rule_id: UUID,
        occurrence_count: int,
    ) -> Optional[RemediationSuggestion]:
        """Generate a generic suggestion for a common issue."""
        return RemediationSuggestion(
            priority=1,
            title=f"Address Common Issue (occurs {occurrence_count}x)",
            description="This issue appears across multiple resources",
            steps=[
                "Review all affected resources",
                "Identify root cause (misconfiguration, policy gap, etc.)",
                "Implement systematic fix",
                "Verify resolution across all instances",
                "Update policies to prevent recurrence",
            ],
            automation_available=True,
            estimated_effort="Varies by issue",
            impact="Reduces risk across multiple resources",
            references=[],
        )

    def _matches_severity(
        self,
        suggestion: RemediationSuggestion,
        severity: str,
    ) -> bool:
        """Check if suggestion matches severity filter."""
        # Simple heuristic: priority 1 = critical/high, 2+ = medium/low
        if severity in ["critical", "high"]:
            return suggestion.priority == 1
        else:
            return suggestion.priority >= 2
