"""
Security Analysis Tool

Provides comprehensive security analysis capabilities including:
- Attack surface analysis
- Risk scoring
- Compliance gap analysis
- Security posture assessment
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from .base import StructuredTool, AgentContext, ToolResult, ToolPermissionLevel
import structlog

logger = structlog.get_logger(__name__)


class SecurityAnalysisInput(BaseModel):
    """Input parameters for security analysis."""

    analysis_type: str = Field(
        ...,
        description="Type of analysis: attack_surface, risk_score, compliance_gaps, posture_assessment"
    )
    scope: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Scope parameters (providers, resource types, time range)"
    )
    filters: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Additional filters for analysis"
    )


class SecurityAnalysisOutput(BaseModel):
    """Output from security analysis."""

    analysis_type: str
    summary: str
    score: Optional[float] = None
    findings_count: int
    critical_items: List[Dict[str, Any]]
    recommendations: List[str]
    details: Dict[str, Any]


class SecurityAnalysisTool(StructuredTool):
    """
    Perform comprehensive security analysis across resources.

    Analyzes security posture, identifies attack surfaces, calculates risk scores,
    and provides actionable recommendations.
    """

    tool_name = "security_analysis"
    tool_description = "Perform comprehensive security analysis: attack surface, risk scoring, compliance gaps, or posture assessment"
    tool_version = "1.0.0"
    input_model = SecurityAnalysisInput
    output_model = SecurityAnalysisOutput
    required_permission = ToolPermissionLevel.READ_ONLY

    async def _run(
        self,
        context: AgentContext,
        analysis_type: str,
        scope: Optional[Dict[str, Any]] = None,
        filters: Optional[Dict[str, Any]] = None,
    ) -> ToolResult:
        """
        Execute security analysis.

        Args:
            context: Agent execution context
            analysis_type: Type of analysis to perform
            scope: Scope parameters
            filters: Additional filters

        Returns:
            ToolResult with analysis results
        """
        try:
            logger.info(
                "Performing security analysis",
                analysis_type=analysis_type,
                org_id=context.org_id,
                scope=scope,
            )

            scope = scope or {}
            filters = filters or {}

            # Route to appropriate analysis
            if analysis_type == "attack_surface":
                result = await self._analyze_attack_surface(context, scope, filters)
            elif analysis_type == "risk_score":
                result = await self._calculate_risk_score(context, scope, filters)
            elif analysis_type == "compliance_gaps":
                result = await self._analyze_compliance_gaps(context, scope, filters)
            elif analysis_type == "posture_assessment":
                result = await self._assess_security_posture(context, scope, filters)
            else:
                return ToolResult(
                    success=False,
                    error=f"Unknown analysis type: {analysis_type}",
                )

            return ToolResult(
                success=True,
                data=result.dict(),
                metadata={
                    "analysis_type": analysis_type,
                    "scope": scope,
                },
            )

        except Exception as e:
            logger.exception(
                "Security analysis failed",
                analysis_type=analysis_type,
                error=str(e),
            )
            return ToolResult(
                success=False,
                error=f"Security analysis failed: {str(e)}",
            )

    async def _analyze_attack_surface(
        self,
        context: AgentContext,
        scope: Dict[str, Any],
        filters: Dict[str, Any],
    ) -> SecurityAnalysisOutput:
        """Analyze attack surface."""
        from cerebro.core.database import async_session_factory
        from cerebro.core.models import Resource, Finding
        from sqlalchemy import select, func

        async with async_session_factory() as db:
            # Get exposed resources
            exposed_query = (
                select(Resource)
                .where(Resource.org_id == context.org_id)
                .where(Resource.metadata["is_public"].astext == "true")
            )

            if scope.get("providers"):
                exposed_query = exposed_query.where(
                    Resource.provider.in_(scope["providers"])
                )

            exposed_result = await db.execute(exposed_query)
            exposed_resources = exposed_result.scalars().all()

            # Get related findings
            findings_query = (
                select(Finding, func.count())
                .where(Finding.org_id == context.org_id)
                .where(Finding.status != "resolved")
                .group_by(Finding.severity)
            )

            findings_result = await db.execute(findings_query)
            severity_counts = {row[0].severity: row[1] for row in findings_result}

            critical_items = [
                {
                    "resource_id": str(r.resource_id),
                    "resource_type": r.resource_type,
                    "provider": r.provider,
                    "exposure": "public",
                    "risk_level": "high",
                }
                for r in exposed_resources[:10]
            ]

            total_findings = sum(severity_counts.values())

            return SecurityAnalysisOutput(
                analysis_type="attack_surface",
                summary=f"Found {len(exposed_resources)} publicly exposed resources with {total_findings} open findings",
                score=self._calculate_exposure_score(len(exposed_resources), total_findings),
                findings_count=total_findings,
                critical_items=critical_items,
                recommendations=[
                    "Review and restrict public access to sensitive resources",
                    "Enable MFA on all publicly accessible services",
                    "Implement network segmentation for critical assets",
                    "Enable comprehensive logging and monitoring",
                ],
                details={
                    "exposed_count": len(exposed_resources),
                    "severity_breakdown": severity_counts,
                    "providers_analyzed": scope.get("providers", ["all"]),
                },
            )

    async def _calculate_risk_score(
        self,
        context: AgentContext,
        scope: Dict[str, Any],
        filters: Dict[str, Any],
    ) -> SecurityAnalysisOutput:
        """Calculate overall risk score."""
        from cerebro.core.database import async_session_factory
        from cerebro.core.models import Finding
        from sqlalchemy import select, func

        async with async_session_factory() as db:
            # Get finding counts by severity
            query = (
                select(Finding.severity, func.count(Finding.finding_id))
                .where(Finding.org_id == context.org_id)
                .where(Finding.status != "resolved")
                .group_by(Finding.severity)
            )

            result = await db.execute(query)
            severity_counts = dict(result.all())

            # Calculate weighted risk score
            weights = {"critical": 10, "high": 5, "medium": 2, "low": 1}
            risk_score = sum(
                severity_counts.get(severity, 0) * weight
                for severity, weight in weights.items()
            )

            # Normalize to 0-100 scale
            max_possible = 1000  # Assume max of 100 critical findings
            normalized_score = min(100, (risk_score / max_possible) * 100)

            total_findings = sum(severity_counts.values())

            return SecurityAnalysisOutput(
                analysis_type="risk_score",
                summary=f"Organization risk score: {normalized_score:.1f}/100 based on {total_findings} open findings",
                score=normalized_score,
                findings_count=total_findings,
                critical_items=[
                    {
                        "severity": severity,
                        "count": count,
                        "weight": weights.get(severity, 0),
                    }
                    for severity, count in severity_counts.items()
                ],
                recommendations=[
                    "Prioritize remediation of critical findings",
                    "Implement automated remediation where possible",
                    "Establish SLAs for finding remediation",
                    "Regular security reviews and audits",
                ],
                details={
                    "severity_breakdown": severity_counts,
                    "raw_risk_score": risk_score,
                    "normalized_score": normalized_score,
                },
            )

    async def _analyze_compliance_gaps(
        self,
        context: AgentContext,
        scope: Dict[str, Any],
        filters: Dict[str, Any],
    ) -> SecurityAnalysisOutput:
        """Analyze compliance gaps."""
        from cerebro.core.database import async_session_factory
        from cerebro.core.models import Finding
        from sqlalchemy import select

        async with async_session_factory() as db:
            # Get findings mapped to compliance frameworks
            framework = scope.get("framework", "all")

            query = select(Finding).where(Finding.org_id == context.org_id)

            if framework and framework != "all":
                # This would join with rules and filter by framework
                # For now, simplified
                pass

            result = await db.execute(query)
            findings = result.scalars().all()

            # Group by compliance framework
            framework_gaps = {}
            for finding in findings:
                # This would map findings to frameworks
                # Simplified for demo
                if finding.severity in ["critical", "high"]:
                    framework_gaps.setdefault("CIS", []).append(finding)
                    framework_gaps.setdefault("SOC2", []).append(finding)

            critical_gaps = [
                {
                    "framework": fw,
                    "gap_count": len(gaps),
                    "critical_count": len([g for g in gaps if g.severity == "critical"]),
                }
                for fw, gaps in list(framework_gaps.items())[:5]
            ]

            return SecurityAnalysisOutput(
                analysis_type="compliance_gaps",
                summary=f"Identified gaps across {len(framework_gaps)} compliance frameworks",
                findings_count=len(findings),
                critical_items=critical_gaps,
                recommendations=[
                    "Implement automated compliance monitoring",
                    "Regular compliance audits and assessments",
                    "Document remediation efforts for audit trails",
                    "Establish compliance review cadence",
                ],
                details={
                    "frameworks_analyzed": list(framework_gaps.keys()),
                    "total_gaps": len(findings),
                },
            )

    async def _assess_security_posture(
        self,
        context: AgentContext,
        scope: Dict[str, Any],
        filters: Dict[str, Any],
    ) -> SecurityAnalysisOutput:
        """Assess overall security posture."""
        from cerebro.core.database import async_session_factory
        from cerebro.core.models import Finding, Resource, Account
        from sqlalchemy import select, func

        async with async_session_factory() as db:
            # Get metrics
            findings_count = await db.scalar(
                select(func.count(Finding.finding_id))
                .where(Finding.org_id == context.org_id)
                .where(Finding.status != "resolved")
            )

            resources_count = await db.scalar(
                select(func.count(Resource.resource_id))
                .where(Resource.org_id == context.org_id)
            )

            accounts_count = await db.scalar(
                select(func.count(Account.account_id))
                .where(Account.org_id == context.org_id)
            )

            # Calculate posture score (0-100, higher is better)
            findings_per_resource = findings_count / max(resources_count, 1)
            posture_score = max(0, 100 - (findings_per_resource * 10))

            return SecurityAnalysisOutput(
                analysis_type="posture_assessment",
                summary=f"Security posture score: {posture_score:.1f}/100 across {accounts_count} accounts and {resources_count} resources",
                score=posture_score,
                findings_count=findings_count,
                critical_items=[
                    {
                        "metric": "Total Resources",
                        "value": resources_count,
                    },
                    {
                        "metric": "Open Findings",
                        "value": findings_count,
                    },
                    {
                        "metric": "Connected Accounts",
                        "value": accounts_count,
                    },
                    {
                        "metric": "Findings per Resource",
                        "value": round(findings_per_resource, 2),
                    },
                ],
                recommendations=[
                    "Implement continuous security monitoring",
                    "Automate security controls where possible",
                    "Regular security training for teams",
                    "Establish security metrics and KPIs",
                ],
                details={
                    "resources": resources_count,
                    "findings": findings_count,
                    "accounts": accounts_count,
                    "posture_score": posture_score,
                },
            )

    def _calculate_exposure_score(self, exposed_count: int, findings_count: int) -> float:
        """Calculate exposure score (0-100, lower is better)."""
        # Weighted combination of exposed resources and findings
        exposure_weight = min(100, (exposed_count / 10) * 100)
        findings_weight = min(100, (findings_count / 50) * 100)
        return (exposure_weight * 0.6 + findings_weight * 0.4)