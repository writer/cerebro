"""
Compliance Control Auto-Tester Tool

Enables agents to autonomously test compliance controls across frameworks
(SOC2, ISO27001) and collect cryptographically-verified evidence.

This tool automates manual compliance testing, reducing audit prep time
from weeks to hours while ensuring continuous compliance monitoring.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
from pydantic import BaseModel, Field

from .base import StructuredTool, AgentContext, ToolResult, ToolPermissionLevel
from cerebro.compliance.control_tests import ControlTestRunner, TestStatus
from cerebro.compliance.framework_registry import get_framework_registry
from cerebro.rules.engine import RuleEngine
from cerebro.query.bootstrap import get_query_engine
from cerebro.core.database import async_session_factory
import structlog

logger = structlog.get_logger(__name__)


class ComplianceTesterInput(BaseModel):
    """Input parameters for compliance testing."""

    framework_id: str = Field(
        ...,
        description="Compliance framework: 'soc2', 'iso27001'"
    )
    control_id: Optional[str] = Field(
        None,
        description="Specific control to test (e.g., 'CC6.1', 'A.9.2.1'). Leave empty to test all controls."
    )
    collect_evidence: bool = Field(
        default=True,
        description="Whether to collect and preserve audit evidence"
    )
    audit_period_days: int = Field(
        default=90,
        description="Number of days to look back for compliance testing",
        ge=1,
        le=365
    )


class ComplianceTesterOutput(BaseModel):
    """Output from compliance testing."""

    framework_id: str
    controls_tested: int
    controls_passed: int
    controls_failed: int
    controls_with_errors: int
    overall_compliance_score: float
    test_results: List[Dict[str, Any]]
    evidence_collected: int
    gaps_identified: List[str]
    recommendations: List[str]


class ComplianceControlTesterTool(StructuredTool):
    """
    Autonomously test compliance controls and collect evidence.

    This tool allows agents to:
    - Test all controls in a framework (SOC2, ISO27001)
    - Validate specific control requirements
    - Collect cryptographically-signed audit evidence
    - Identify compliance gaps before auditors do
    - Generate audit-ready reports

    Example uses:
    - "Test all SOC2 controls and show me what's failing"
    - "Validate ISO27001 control A.9.2.1 (user access provisioning)"
    - "Generate evidence bundle for our annual audit"
    """

    tool_name = "test_compliance_control"
    tool_description = "Autonomously test compliance controls and collect cryptographic evidence for audits"
    tool_version = "1.0.0"
    input_model = ComplianceTesterInput
    output_model = ComplianceTesterOutput
    required_permission = ToolPermissionLevel.READ_ONLY

    async def _run(
        self,
        context: AgentContext,
        framework_id: str,
        control_id: Optional[str] = None,
        collect_evidence: bool = True,
        audit_period_days: int = 90,
    ) -> ToolResult:
        """
        Execute compliance control testing.

        Args:
            context: Agent execution context
            framework_id: Framework to test (soc2, iso27001)
            control_id: Specific control ID (optional, tests all if not provided)
            collect_evidence: Whether to collect audit evidence
            audit_period_days: Audit period lookback

        Returns:
            ToolResult with test results and compliance score
        """
        try:
            logger.info(
                "Compliance testing requested",
                framework=framework_id,
                control=control_id,
                org_id=context.org_id,
            )

            async with async_session_factory() as db_session:
                # Initialize compliance framework registry
                framework_registry = get_framework_registry()

                # Validate framework
                framework = framework_registry.get_framework(framework_id)
                if not framework:
                    return ToolResult(
                        success=False,
                        error=f"Framework '{framework_id}' not found. Available: soc2, iso27001"
                    )

                # Initialize test runner
                rule_engine = RuleEngine(db_session)
                query_engine = get_query_engine()
                test_runner = ControlTestRunner(
                    rule_engine=rule_engine,
                    query_engine=query_engine,
                    db_session=db_session
                )

                # Determine which controls to test
                if control_id:
                    # Test specific control
                    control = framework.get_control(control_id)
                    if not control:
                        return ToolResult(
                            success=False,
                            error=f"Control '{control_id}' not found in {framework_id}"
                        )
                    controls_to_test = [control]
                else:
                    # Test all controls
                    controls_to_test = list(framework.controls)

                # Calculate audit period
                period_end = datetime.utcnow()
                period_start = period_end - timedelta(days=audit_period_days)

                # Run tests
                test_results = []
                evidence_collected = 0
                gaps = []

                for control in controls_to_test:
                    logger.info(f"Testing control {control.control_id}: {control.title}")

                    try:
                        # Execute control test
                        result = await test_runner.run_control_test(
                            org_id=context.org_id,
                            framework_id=framework_id,
                            control_id=control.control_id,
                            period_start=period_start,
                            period_end=period_end,
                            collect_evidence=collect_evidence
                        )

                        # Format result for output
                        test_result = {
                            "control_id": control.control_id,
                            "control_title": control.title,
                            "status": result.status.value,
                            "passed": result.passed,
                            "pass_rate": round(result.pass_rate * 100, 2),
                            "pass_count": result.pass_count,
                            "fail_count": result.fail_count,
                            "total_count": result.total_count,
                            "execution_time_seconds": round(result.duration_seconds, 2),
                            "evidence_items": len(result.evidence_items)
                        }

                        # Add to results
                        test_results.append(test_result)
                        evidence_collected += len(result.evidence_items)

                        # Track gaps
                        if result.status == TestStatus.FAIL:
                            gaps.append(
                                f"{control.control_id} - {control.title}: "
                                f"{result.fail_count}/{result.total_count} checks failed"
                            )
                        elif result.status == TestStatus.ERROR:
                            gaps.append(
                                f"{control.control_id} - {control.title}: "
                                f"Test execution error"
                            )

                    except Exception as e:
                        logger.error(
                            "Control test failed",
                            control_id=control.control_id,
                            error=str(e)
                        )
                        test_results.append({
                            "control_id": control.control_id,
                            "control_title": control.title,
                            "status": "error",
                            "passed": False,
                            "error_message": str(e)
                        })
                        gaps.append(f"{control.control_id}: Test execution failed")

                # Calculate overall metrics
                controls_tested = len(test_results)
                controls_passed = sum(1 for r in test_results if r.get("passed", False))
                controls_failed = sum(
                    1 for r in test_results
                    if r.get("status") == "fail"
                )
                controls_with_errors = sum(
                    1 for r in test_results
                    if r.get("status") == "error"
                )

                overall_score = (
                    (controls_passed / controls_tested * 100)
                    if controls_tested > 0 else 0.0
                )

                # Generate recommendations
                recommendations = self._generate_recommendations(
                    framework_id=framework_id,
                    test_results=test_results,
                    overall_score=overall_score,
                    gaps=gaps
                )

                output = ComplianceTesterOutput(
                    framework_id=framework_id,
                    controls_tested=controls_tested,
                    controls_passed=controls_passed,
                    controls_failed=controls_failed,
                    controls_with_errors=controls_with_errors,
                    overall_compliance_score=round(overall_score, 2),
                    test_results=test_results[:20],  # Limit to top 20 for tokens
                    evidence_collected=evidence_collected,
                    gaps_identified=gaps[:10],  # Top 10 gaps
                    recommendations=recommendations
                )

                logger.info(
                    "Compliance testing completed",
                    framework=framework_id,
                    score=overall_score,
                    controls_tested=controls_tested,
                )

                return ToolResult(
                    success=True,
                    data=output.model_dump(),
                    metadata={
                        "framework_id": framework_id,
                        "compliance_score": overall_score,
                        "audit_period_days": audit_period_days
                    }
                )

        except Exception as e:
            logger.error("Compliance testing failed", error=str(e), exc_info=True)
            return ToolResult(
                success=False,
                error=f"Compliance testing failed: {str(e)}"
            )

    def _generate_recommendations(
        self,
        framework_id: str,
        test_results: List[Dict],
        overall_score: float,
        gaps: List[str]
    ) -> List[str]:
        """Generate actionable recommendations based on test results."""

        recommendations = []

        # Score-based recommendations
        if overall_score < 50:
            recommendations.append(
                f"CRITICAL: {framework_id.upper()} compliance score is {overall_score:.1f}%. "
                "Immediate remediation required across multiple controls."
            )
        elif overall_score < 75:
            recommendations.append(
                f"WARNING: {framework_id.upper()} compliance score is {overall_score:.1f}%. "
                "Several gaps need attention before audit."
            )
        elif overall_score < 90:
            recommendations.append(
                f"GOOD: {framework_id.upper()} compliance score is {overall_score:.1f}%. "
                "Focus on remaining gaps for certification readiness."
            )
        else:
            recommendations.append(
                f"EXCELLENT: {framework_id.upper()} compliance score is {overall_score:.1f}%. "
                "Maintain continuous testing to ensure ongoing compliance."
            )

        # Gap-specific recommendations
        if gaps:
            high_priority_gaps = [g for g in gaps if "error" in g.lower() or "failed" in g.lower()]
            if high_priority_gaps:
                recommendations.append(
                    f"Address {len(high_priority_gaps)} high-priority control gaps first: "
                    f"{high_priority_gaps[0]}"
                )

        # Evidence collection
        evidence_count = sum(r.get("evidence_items", 0) for r in test_results)
        if evidence_count > 0:
            recommendations.append(
                f"Successfully collected {evidence_count} pieces of audit evidence. "
                "These are cryptographically signed and audit-ready."
            )
        else:
            recommendations.append(
                "No evidence collected. Enable evidence collection for audit readiness."
            )

        # Framework-specific recommendations
        if framework_id == "soc2":
            recommendations.append(
                "For SOC2: Focus on CC6 (Logical Access), CC7 (System Operations), "
                "and CC8 (Change Management) as these are commonly scrutinized."
            )
        elif framework_id == "iso27001":
            recommendations.append(
                "For ISO27001: Ensure A.9 (Access Control) and A.12 (Operations Security) "
                "are fully documented with evidence."
            )

        # Continuous monitoring
        recommendations.append(
            "Set up continuous compliance monitoring to catch gaps early. "
            "Run tests daily or weekly instead of just before audits."
        )

        return recommendations


class EvidenceBundleBuilderTool(StructuredTool):
    """
    Build cryptographically-signed evidence bundles for auditors.

    Creates tamper-proof WORM (Write-Once-Read-Many) evidence packages
    that auditors can verify independently.
    """

    tool_name = "build_evidence_bundle"
    tool_description = "Create cryptographically-signed audit evidence bundles (WORM storage)"
    tool_version = "1.0.0"
    required_permission = ToolPermissionLevel.READ_ONLY

    class Input(BaseModel):
        framework_id: str = Field(..., description="Framework to collect evidence for")
        control_ids: Optional[List[str]] = Field(None, description="Specific controls (all if not provided)")
        include_raw_data: bool = Field(default=False, description="Include raw evidence data")

    class Output(BaseModel):
        bundle_id: str
        framework_id: str
        controls_included: int
        evidence_items: int
        bundle_size_bytes: int
        cryptographic_hash: str
        created_at: str
        worm_storage_enabled: bool

    input_model = Input
    output_model = Output

    async def _run(
        self,
        context: AgentContext,
        framework_id: str,
        control_ids: Optional[List[str]] = None,
        include_raw_data: bool = False,
    ) -> ToolResult:
        """Build evidence bundle for audit."""
        try:
            logger.info(
                "Evidence bundle creation requested",
                framework=framework_id,
                org_id=context.org_id,
            )

            async with async_session_factory() as db_session:
                from cerebro.auditability.evidence_bundles import EvidenceBundleBuilder

                # Create bundle
                builder = EvidenceBundleBuilder(db_session)
                bundle = await builder.create_bundle(
                    org_id=context.org_id,
                    framework_id=framework_id,
                    control_ids=control_ids,
                    include_raw_data=include_raw_data
                )

                output = self.Output(
                    bundle_id=str(bundle.bundle_id),
                    framework_id=framework_id,
                    controls_included=bundle.controls_included,
                    evidence_items=bundle.evidence_items_count,
                    bundle_size_bytes=bundle.bundle_size_bytes,
                    cryptographic_hash=bundle.sha256_hash,
                    created_at=bundle.created_at.isoformat(),
                    worm_storage_enabled=bundle.worm_enabled
                )

                logger.info(
                    "Evidence bundle created",
                    bundle_id=bundle.bundle_id,
                    controls=bundle.controls_included,
                )

                return ToolResult(
                    success=True,
                    data=output.model_dump(),
                    metadata={"bundle_id": str(bundle.bundle_id)}
                )

        except Exception as e:
            logger.error("Evidence bundle creation failed", error=str(e), exc_info=True)
            return ToolResult(
                success=False,
                error=f"Evidence bundle creation failed: {str(e)}"
            )