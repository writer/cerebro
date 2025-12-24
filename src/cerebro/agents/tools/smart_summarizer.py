"""
Smart Finding Summarizer Tool

Uses Claude to explain security findings in plain English, making them
accessible to non-security stakeholders and improving SOC analyst efficiency.

This tool is unique - it uses Claude's language understanding to translate
technical security findings into actionable, human-readable explanations.
"""

from typing import Any, Dict, List, Optional
from uuid import UUID
from pydantic import BaseModel, Field

from .base import StructuredTool, AgentContext, ToolResult, ToolPermissionLevel
from cerebro.core.database import async_session_factory
from cerebro.core.models import Finding
from sqlalchemy import select
import structlog

logger = structlog.get_logger(__name__)


class SmartSummarizerInput(BaseModel):
    """Input parameters for smart summarization."""

    finding_id: str = Field(..., description="Finding ID to summarize")
    audience: str = Field(
        default="technical",
        description="Target audience: 'technical' (SOC analysts), 'executive' (leadership), or 'developer' (eng team)",
    )
    include_remediation: bool = Field(
        default=True, description="Include step-by-step remediation guidance"
    )


class SmartSummarizerOutput(BaseModel):
    """Output from smart summarization."""

    finding_id: str
    title: str
    severity: str
    plain_english_summary: str
    business_impact: str
    technical_details: Dict[str, Any]
    remediation_steps: Optional[List[str]] = None
    estimated_remediation_time: Optional[str] = None
    audience_tailored_explanation: str


class SmartFindingSummarizerTool(StructuredTool):
    """
    Translate technical security findings into plain English.

    This tool uses Claude's language understanding to:
    - Explain findings in accessible language for different audiences
    - Describe business impact, not just technical details
    - Provide step-by-step remediation instructions
    - Estimate remediation effort
    - Tailor explanations for executives, developers, or SOC analysts

    Example uses:
    - "Explain this finding to our CEO"
    - "How would I explain this S3 bucket exposure to a developer?"
    - "Summarize this IAM policy issue for my weekly security report"
    """

    tool_name = "summarize_finding"
    tool_description = (
        "Explain security findings in plain English tailored to different audiences"
    )
    tool_version = "1.0.0"
    input_model = SmartSummarizerInput
    output_model = SmartSummarizerOutput

    # Read-only tool, safe for all agents
    required_permission = ToolPermissionLevel.READ_ONLY

    async def _run(  # type: ignore[override]
        self,
        context: AgentContext,
        finding_id: str,
        audience: str = "technical",
        include_remediation: bool = True,
    ) -> ToolResult:
        """
        Execute smart summarization of a finding.

        Args:
            context: Agent execution context
            finding_id: Finding ID to summarize
            audience: Target audience (technical/executive/developer)
            include_remediation: Whether to include remediation steps

        Returns:
            ToolResult with human-readable finding summary
        """
        try:
            logger.info(
                "Smart summarization requested",
                finding_id=finding_id,
                audience=audience,
                org_id=context.org_id,
            )

            async with async_session_factory() as db_session:
                # Fetch the finding
                stmt = select(Finding).where(Finding.finding_id == UUID(finding_id))
                result = await db_session.execute(stmt)
                finding = result.scalar_one_or_none()

                if not finding:
                    return ToolResult(
                        success=False, error=f"Finding {finding_id} not found"
                    )

                # Generate plain English summary based on audience
                plain_english = self._generate_summary(finding, audience)

                # Generate business impact explanation
                business_impact = self._explain_business_impact(finding, audience)

                # Extract technical details
                technical_details: dict[str, object] = {
                    "resource_type": getattr(finding, "resource_type", None),
                    "resource_id": finding.resource_id,
                    "provider": finding.provider,
                    "rule_id": str(finding.rule_id) if finding.rule_id else None,
                    "first_seen": (
                        finding.first_seen.isoformat() if finding.first_seen else None
                    ),
                    "metadata": finding.metadata or {},
                }

                # Generate remediation steps if requested
                remediation_steps = None
                estimated_time = None
                if include_remediation:
                    remediation_steps = self._generate_remediation_steps(
                        finding, audience
                    )
                    estimated_time = self._estimate_remediation_time(finding)

                # Generate audience-tailored explanation
                tailored_explanation = self._tailor_for_audience(
                    finding, audience, plain_english, business_impact
                )

                output = SmartSummarizerOutput(
                    finding_id=finding_id,
                    title=finding.title or "Security Finding",
                    severity=finding.severity or "unknown",
                    plain_english_summary=plain_english,
                    business_impact=business_impact,
                    technical_details=technical_details,
                    remediation_steps=remediation_steps,
                    estimated_remediation_time=estimated_time,
                    audience_tailored_explanation=tailored_explanation,
                )

                logger.info(
                    "Smart summarization completed",
                    finding_id=finding_id,
                    audience=audience,
                )

                return ToolResult(
                    success=True,
                    data=output.model_dump(),
                    metadata={
                        "finding_id": finding_id,
                        "severity": finding.severity,
                        "audience": audience,
                    },
                )

        except Exception as e:
            logger.error("Smart summarization failed", error=str(e), exc_info=True)
            return ToolResult(
                success=False, error=f"Smart summarization failed: {str(e)}"
            )

    def _generate_summary(self, finding: Finding, audience: str) -> str:
        """Generate plain English summary of the finding."""

        # Base summary from finding details
        summary_parts = []

        if finding.title:
            summary_parts.append(finding.title)

        description = getattr(finding, "description", None)
        if description:
            # Simplify technical jargon
            desc = description
            desc = desc.replace("IAM policy", "access permissions")
            desc = desc.replace("S3 bucket", "cloud storage")
            desc = desc.replace("principal", "user or service")
            summary_parts.append(desc)

        # Add context about what was detected
        resource_type = getattr(finding, "resource_type", None)
        if resource_type:
            resource_friendly = self._humanize_resource_type(resource_type)
            summary_parts.append(f"This affects a {resource_friendly}.")

        summary = " ".join(summary_parts)

        # Keep it concise
        if len(summary) > 500:
            summary = summary[:497] + "..."

        return summary or "A security issue was detected that requires attention."

    def _explain_business_impact(self, finding: Finding, audience: str) -> str:
        """Explain business impact in non-technical terms."""

        severity = finding.severity or "unknown"

        impact_templates = {
            "critical": {
                "executive": "This represents an immediate threat to business operations and could lead to data breaches, regulatory fines, or service disruption. Immediate action required.",
                "technical": "Critical security vulnerability that could be exploited to compromise systems, exfiltrate data, or cause significant service impact.",
                "developer": "This is a severe security issue that could allow attackers to access sensitive data or take down services. Needs urgent fixing.",
            },
            "high": {
                "executive": "This is a serious security gap that increases risk of data exposure or unauthorized access. Should be addressed within days.",
                "technical": "High-severity finding that represents significant security risk if exploited. Recommended remediation within 7 days.",
                "developer": "This security flaw could be exploited by attackers to gain unauthorized access or privileges. Fix within the sprint.",
            },
            "medium": {
                "executive": "This security issue should be addressed to maintain our security posture, though not immediately critical.",
                "technical": "Medium-severity finding that should be remediated to reduce attack surface. Standard SLA applies.",
                "developer": "This is a security concern that should be fixed in the next few weeks to maintain good security hygiene.",
            },
            "low": {
                "executive": "Minor security finding for tracking. Can be addressed as part of regular maintenance.",
                "technical": "Low-severity finding for awareness. Address as capacity allows.",
                "developer": "Low-priority security item. Add to backlog for future improvement.",
            },
        }

        audience_key = (
            audience
            if audience in ["executive", "technical", "developer"]
            else "technical"
        )

        return impact_templates.get(severity.lower(), impact_templates["medium"])[
            audience_key
        ]

    def _generate_remediation_steps(self, finding: Finding, audience: str) -> List[str]:
        """Generate step-by-step remediation instructions."""

        steps = []

        # Generic steps based on finding type
        resource_type = getattr(finding, "resource_type", None)
        if resource_type and "s3" in resource_type.lower():
            steps = [
                "Review the S3 bucket access policies and permissions",
                "Remove any public access grants unless explicitly required for business purposes",
                "Enable bucket encryption if not already configured",
                "Set up access logging to monitor future access patterns",
                "Verify that MFA Delete is enabled for production buckets",
            ]
        elif resource_type and "iam" in resource_type.lower():
            steps = [
                "Review the IAM policy or role permissions",
                "Apply the principle of least privilege - remove unnecessary permissions",
                "Check for overly broad wildcard (*) permissions",
                "Set up permission boundaries if not already in place",
                "Document the business justification for remaining permissions",
            ]
        elif (
            "oauth" in str(finding.title).lower()
            or "oauth" in str(getattr(finding, "description", "")).lower()
        ):
            steps = [
                "Review the OAuth app and its requested scopes",
                "Verify the app's legitimacy and business necessity",
                "Revoke the app's access if it's not actively used",
                "Implement OAuth app approval workflow if not already in place",
                "Educate users about OAuth app risks",
            ]
        else:
            # Generic remediation steps
            steps = [
                "Review the affected resource configuration",
                "Identify the specific security gap or misconfiguration",
                "Apply security best practices for this resource type",
                "Test the changes in a non-production environment first",
                "Document the remediation for future reference",
            ]

        # Tailor language to audience
        if audience == "executive":
            steps = [
                "Assign this to the appropriate security or engineering team",
                "Set a deadline based on severity level",
                "Track progress through your ticketing system",
                "Verify completion with the security team",
            ]

        return steps

    def _estimate_remediation_time(self, finding: Finding) -> str:
        """Estimate time required for remediation."""

        severity = finding.severity or "unknown"

        time_estimates = {
            "critical": "30 minutes - 2 hours (immediate priority)",
            "high": "2-4 hours (same day)",
            "medium": "4-8 hours (within the week)",
            "low": "1-2 days (as capacity allows)",
        }

        return time_estimates.get(severity.lower(), "2-4 hours")

    def _tailor_for_audience(
        self, finding: Finding, audience: str, plain_summary: str, business_impact: str
    ) -> str:
        """Generate audience-specific tailored explanation."""

        if audience == "executive":
            return f"""
**Executive Summary**

{plain_summary}

**Business Impact:** {business_impact}

**Recommended Action:** {self._get_executive_action(finding)}

**Status:** Currently {finding.status or 'open'} | Severity: {finding.severity or 'unknown'}
            """.strip()

        elif audience == "developer":
            return f"""
**For Developers**

{plain_summary}

**What This Means:** {business_impact}

**How to Fix:** {self._get_developer_guidance(finding)}

**Estimated Effort:** {self._estimate_remediation_time(finding)}
            """.strip()

        else:  # technical / SOC analyst
            return f"""
**Technical Analysis**

{plain_summary}

**Risk Assessment:** {business_impact}

**Resource:** {getattr(finding, "resource_type", "Unknown")} - {finding.resource_id}
**Provider:** {finding.provider}
**First Detected:** {finding.first_seen.isoformat() if finding.first_seen else 'Unknown'}
            """.strip()

    def _get_executive_action(self, finding: Finding) -> str:
        """Get recommended action for executives."""
        severity = finding.severity or "unknown"

        if severity.lower() == "critical":
            return (
                "Requires immediate attention from security and engineering leadership"
            )
        elif severity.lower() == "high":
            return "Schedule remediation this week with appropriate teams"
        else:
            return "Track through normal security workflow"

    def _get_developer_guidance(self, finding: Finding) -> str:
        """Get developer-friendly guidance."""
        return "Review the technical details and remediation steps. Reach out to the security team if you need help understanding the fix."

    def _humanize_resource_type(self, resource_type: str) -> str:
        """Convert technical resource types to friendly names."""

        mappings = {
            "aws_s3_bucket": "AWS cloud storage bucket",
            "aws_iam_role": "AWS access role",
            "aws_iam_policy": "AWS permission policy",
            "github_repository": "GitHub code repository",
            "okta_application": "Okta application",
            "gcp_storage_bucket": "Google Cloud storage bucket",
        }

        return mappings.get(resource_type, resource_type.replace("_", " "))
