"""
Identity Anomaly Hunter Tool

Enables agents to detect unusual identity behavior patterns using ML-based
anomaly detection across OAuth apps, permissions, and lateral movement.

This tool leverages the IdentityAnomalyDetector to find suspicious patterns
that may indicate compromised accounts or insider threats.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from .base import StructuredTool, AgentContext, ToolResult, ToolPermissionLevel
from cerebro.analysis.identity_anomaly import (
    IdentityAnomalyDetector,
    RiskLevel,
)
import structlog

logger = structlog.get_logger(__name__)


class IdentityAnomalyHunterInput(BaseModel):
    """Input parameters for identity anomaly hunting."""

    principal_id: Optional[str] = Field(
        None,
        description="Specific principal/user to analyze (leave empty to analyze all)",
    )
    lookback_days: int = Field(
        default=30,
        description="Number of days of historical data to analyze",
        ge=1,
        le=90,
    )
    min_risk_level: str = Field(
        default="medium",
        description="Minimum risk level to report: 'low', 'medium', 'high', or 'critical'",
    )
    anomaly_types: Optional[List[str]] = Field(
        None,
        description="Specific anomaly types to detect (empty = all). Options: login_pattern, permission_escalation, access_time, resource_access, velocity, cross_provider",
    )


class IdentityAnomalyOutput(BaseModel):
    """Single anomaly detection result."""

    principal_id: str
    anomaly_type: str
    risk_level: str
    score: float
    confidence: float
    description: str
    details: Dict[str, Any]
    detected_at: str
    affected_resources: List[str]
    recommended_actions: List[str]


class IdentityAnomalyHunterOutput(BaseModel):
    """Output from identity anomaly hunting."""

    total_anomalies: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    principals_analyzed: int
    anomalies: List[IdentityAnomalyOutput]
    risk_summary: str
    immediate_actions: List[str]


class IdentityAnomalyHunterTool(StructuredTool):
    """
    Hunt for identity anomalies using ML-powered behavioral analysis.

    This tool uses machine learning to detect unusual patterns in identity
    behavior across your infrastructure, including:
    - Unusual login patterns (time, location, frequency)
    - Permission escalation attempts
    - Abnormal resource access patterns
    - OAuth app anomalies
    - Cross-provider lateral movement
    - Velocity attacks (rapid access across systems)

    Example uses:
    - "Find any unusual OAuth app authorizations in the last 24 hours"
    - "Detect anomalous behavior for user john@company.com"
    - "Hunt for potential compromised accounts across all users"
    - "Find permission escalation attempts in the last week"
    """

    tool_name = "hunt_identity_anomalies"
    tool_description = (
        "ML-powered anomaly detection for suspicious identity behavior patterns"
    )
    tool_version = "1.0.0"
    input_model = IdentityAnomalyHunterInput
    output_model = IdentityAnomalyHunterOutput

    # Read-only analysis, safe for all agents
    required_permission = ToolPermissionLevel.READ_ONLY

    async def _run(  # type: ignore[override]
        self,
        context: AgentContext,
        principal_id: Optional[str] = None,
        lookback_days: int = 30,
        min_risk_level: str = "medium",
        anomaly_types: Optional[List[str]] = None,
    ) -> ToolResult:
        """
        Execute identity anomaly hunting.

        Args:
            context: Agent execution context
            principal_id: Specific principal to analyze (optional)
            lookback_days: Days of historical data to analyze
            min_risk_level: Minimum risk level to report
            anomaly_types: Specific anomaly types to detect

        Returns:
            ToolResult with detected anomalies and risk assessment
        """
        try:
            logger.info(
                "Identity anomaly hunting requested",
                principal_id=principal_id,
                lookback_days=lookback_days,
                org_id=context.org_id,
            )

            # Initialize detector
            detector = IdentityAnomalyDetector(lookback_days=lookback_days)

            # Run anomaly detection
            anomalies = await detector.analyze_identity_anomalies(
                org_id=str(context.org_id), principal_id=principal_id
            )

            # Filter by minimum risk level
            risk_levels = {
                "low": [
                    RiskLevel.LOW,
                    RiskLevel.MEDIUM,
                    RiskLevel.HIGH,
                    RiskLevel.CRITICAL,
                ],
                "medium": [RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL],
                "high": [RiskLevel.HIGH, RiskLevel.CRITICAL],
                "critical": [RiskLevel.CRITICAL],
            }
            allowed_levels = risk_levels.get(
                min_risk_level.lower(), risk_levels["medium"]
            )

            filtered_anomalies = [
                a for a in anomalies if a.risk_level in allowed_levels
            ]

            # Filter by anomaly types if specified
            if anomaly_types:
                anomaly_type_set = set(at.lower() for at in anomaly_types)
                filtered_anomalies = [
                    a
                    for a in filtered_anomalies
                    if a.anomaly_type.value.lower() in anomaly_type_set
                ]

            # Count by risk level
            critical_count = sum(
                1 for a in filtered_anomalies if a.risk_level == RiskLevel.CRITICAL
            )
            high_count = sum(
                1 for a in filtered_anomalies if a.risk_level == RiskLevel.HIGH
            )
            medium_count = sum(
                1 for a in filtered_anomalies if a.risk_level == RiskLevel.MEDIUM
            )
            low_count = sum(
                1 for a in filtered_anomalies if a.risk_level == RiskLevel.LOW
            )

            # Get unique principals analyzed
            principals_analyzed = len(set(a.principal_id for a in anomalies))

            # Convert anomalies to output format (limit to top 20 by score)
            sorted_anomalies = sorted(
                filtered_anomalies,
                key=lambda a: (a.risk_level.value, a.score),
                reverse=True,
            )[:20]

            anomaly_outputs = [
                IdentityAnomalyOutput(
                    principal_id=a.principal_id,
                    anomaly_type=a.anomaly_type.value,
                    risk_level=a.risk_level.value,
                    score=round(a.score, 3),
                    confidence=round(a.confidence, 3),
                    description=a.description,
                    details=a.details,
                    detected_at=a.detected_at.isoformat(),
                    affected_resources=a.affected_resources[:5],  # Top 5 resources
                    recommended_actions=a.recommended_actions,
                )
                for a in sorted_anomalies
            ]

            # Generate risk summary
            risk_summary = self._generate_risk_summary(
                total=len(filtered_anomalies),
                critical=critical_count,
                high=high_count,
                medium=medium_count,
                low=low_count,
                principals=principals_analyzed,
            )

            # Generate immediate actions
            immediate_actions = self._generate_immediate_actions(
                sorted_anomalies[:5]  # Top 5 most critical
            )

            output = IdentityAnomalyHunterOutput(
                total_anomalies=len(filtered_anomalies),
                critical_count=critical_count,
                high_count=high_count,
                medium_count=medium_count,
                low_count=low_count,
                principals_analyzed=principals_analyzed,
                anomalies=anomaly_outputs,
                risk_summary=risk_summary,
                immediate_actions=immediate_actions,
            )

            logger.info(
                "Identity anomaly hunting completed",
                total_anomalies=len(filtered_anomalies),
                critical=critical_count,
                high=high_count,
            )

            return ToolResult(
                success=True,
                data=output.model_dump(),
                metadata={
                    "lookback_days": lookback_days,
                    "principals_analyzed": principals_analyzed,
                    "anomalies_detected": len(filtered_anomalies),
                    "min_risk_level": min_risk_level,
                },
            )

        except Exception as e:
            logger.error("Identity anomaly hunting failed", error=str(e), exc_info=True)
            return ToolResult(
                success=False, error=f"Identity anomaly hunting failed: {str(e)}"
            )

    def _generate_risk_summary(
        self,
        total: int,
        critical: int,
        high: int,
        medium: int,
        low: int,
        principals: int,
    ) -> str:
        """Generate human-readable risk summary."""

        if total == 0:
            return f"✅ No identity anomalies detected across {principals} principals. Baseline behavior observed."

        summary_parts = [
            f"⚠️ Detected {total} identity anomalies across {principals} principals:"
        ]

        if critical > 0:
            summary_parts.append(
                f"  🔴 {critical} CRITICAL - Immediate investigation required"
            )
        if high > 0:
            summary_parts.append(f"  🟠 {high} HIGH - Priority attention needed")
        if medium > 0:
            summary_parts.append(f"  🟡 {medium} MEDIUM - Review recommended")
        if low > 0:
            summary_parts.append(f"  🟢 {low} LOW - Monitor for patterns")

        if critical > 0 or high > 0:
            summary_parts.append(
                "\n🚨 Immediate security team notification recommended."
            )

        return "\n".join(summary_parts)

    def _generate_immediate_actions(self, top_anomalies: List[Any]) -> List[str]:
        """Generate actionable recommendations based on top anomalies."""

        if not top_anomalies:
            return ["Continue monitoring. No immediate action required."]

        actions = []
        seen_actions = set()

        for anomaly in top_anomalies:
            for action in anomaly.recommended_actions:
                if action not in seen_actions:
                    actions.append(action)
                    seen_actions.add(action)

        # Add general actions if few specific ones
        if len(actions) < 3:
            general_actions = [
                "Review audit logs for affected principals",
                "Verify MFA is enabled for all flagged accounts",
                "Check for unauthorized OAuth app authorizations",
                "Validate recent permission changes",
            ]
            for general_action in general_actions:
                if general_action not in seen_actions and len(actions) < 5:
                    actions.append(general_action)
                    seen_actions.add(general_action)

        return actions[:10]  # Top 10 actions
