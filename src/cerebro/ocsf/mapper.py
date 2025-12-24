"""
OCSF Mapper

Transforms Cerebro security data into OCSF v1.4.0 compliant events.
"""

from datetime import UTC, datetime
from typing import Any

import structlog

from cerebro.core.models import Account, Finding, Principal, Resource
from cerebro.ocsf.models import (
    OCSFAccount,
    OCSFActivityID,
    OCSFCloud,
    OCSFCompliance,
    OCSFComplianceFinding,
    OCSFFinding,
    OCSFFindingInfo,
    OCSFMappings,
    OCSFMetadata,
    OCSFObservables,
    OCSFProduct,
    OCSFRemediation,
    OCSFResource,
    OCSFSeverity,
    OCSFTypeUID,
)

logger = structlog.get_logger(__name__)


class OCSFMapper:
    """
    Maps Cerebro security data to OCSF schema.

    Supports:
    - Findings → OCSF Security Finding (2001)
    - Compliance results → OCSF Compliance Finding (2003)
    - IAM events → OCSF Identity Activity (3xxx)
    """

    def __init__(self):
        self.product = OCSFProduct(
            name="Cerebro",
            version="1.0.0",
            vendor_name="Cerebro Security",
        )

    async def finding_to_ocsf(
        self,
        finding: Finding,
        resources: list[Resource] | None = None,
        account: Account | None = None,
        principals: list[Principal] | None = None,
    ) -> OCSFFinding:
        """
        Convert Cerebro Finding to OCSF Security Finding.

        Args:
            finding: Cerebro Finding object
            resources: Related resources (optional)
            account: Cloud account context (optional)
            principals: Related principals/identities (optional)

        Returns:
            OCSFFinding compliant with OCSF v1.4.0
        """

        # Map severity
        severity_id = OCSFMappings.SEVERITY_MAP.get(
            finding.severity, OCSFSeverity.UNKNOWN
        )
        severity = OCSFSeverity(severity_id).name.title()

        # Determine activity based on finding lifecycle
        activity_id = OCSFActivityID.CREATE
        activity_name = "Create"
        if finding.status == "fixed":
            activity_id = OCSFActivityID.CLOSE
            activity_name = "Close"

        # Calculate type_uid
        type_uid = OCSFTypeUID.calculate(
            category_uid=2,  # Findings
            class_uid=2001,  # Security Finding
            activity_id=activity_id,
        )

        # Build finding info
        finding_info = OCSFFindingInfo(
            title=finding.title,
            desc=finding.summary or "",
            uid=str(finding.finding_id),
            types=self._extract_finding_types(finding),
            first_seen_time=self._to_epoch_ms(finding.first_seen),
            last_seen_time=self._to_epoch_ms(finding.last_seen),
            created_time=self._to_epoch_ms(finding.first_seen),
            modified_time=self._to_epoch_ms(finding.last_seen),
            src_url=f"cerebro://findings/{finding.finding_id}",
        )

        # Build metadata
        metadata = OCSFMetadata(
            version="1.4.0",
            product=self.product,
            profiles=self._determine_profiles(finding, account),
            event_code=str(finding.rule_id) if finding.rule_id else None,
            correlation_uid=str(finding.finding_id),
            logged_time=self._to_epoch_ms(finding.first_seen),
        )

        # Map resources
        ocsf_resources = []
        if resources:
            for resource in resources:
                ocsf_resources.append(
                    OCSFResource(
                        name=resource.name or "",
                        uid=str(resource.resource_id),
                        type=resource.resource_type,
                        labels=[],  # Resource model doesn't have tags
                        data=(
                            {"arn": str(resource.resource_id)}
                            if resource.provider == "aws"
                            else {}
                        ),
                    )
                )

        # Map cloud context
        cloud = None
        if account:
            evidence = finding.evidence or {}
            cloud = OCSFCloud(
                provider=account.provider.upper(),
                region=evidence.get("region") if evidence else None,
                account=OCSFAccount(
                    uid=str(account.account_id),
                    name=account.display_name or account.external_id,
                    type="cloud_account",
                ),
            )

        # Map compliance (if applicable)
        compliance = None
        evidence = finding.evidence or {}
        compliance_frameworks = evidence.get("compliance_frameworks", [])
        if compliance_frameworks:
            compliance = OCSFCompliance(
                requirements=compliance_frameworks,
                status="Fail",  # Findings represent violations
                status_detail=f"Non-compliant with {len(compliance_frameworks)} frameworks",
            )

        # Build remediation guidance
        remediation = None
        if evidence and evidence.get("remediation"):
            remediation = OCSFRemediation(
                desc=evidence["remediation"],
                references=[evidence.get("documentation", "")],
            )

        # Extract observables (IoCs, principals, resource IDs)
        observables = self._extract_observables(finding, resources, principals)

        # Determine risk score
        risk_score = self._calculate_risk_score(finding)

        return OCSFFinding(
            type_uid=type_uid,
            type_name=f"Security Finding: {activity_name}",
            time=self._to_epoch_ms(finding.first_seen),
            message=f"{finding.title}: {finding.summary or ''}",
            severity_id=severity_id,
            severity=severity,
            activity_id=activity_id,
            activity_name=activity_name,
            metadata=metadata,
            finding_info=finding_info,
            resources=ocsf_resources,
            remediation=remediation,
            compliance=compliance,
            risk_score=risk_score,
            risk_level=(
                "High" if risk_score >= 70 else "Medium" if risk_score >= 40 else "Low"
            ),
            cloud=cloud,
            observables=observables,
            unmapped=(
                {"cerebro_evidence": finding.evidence} if finding.evidence else None
            ),
        )

    async def compliance_result_to_ocsf(
        self,
        control_id: str,
        control_title: str,
        status: str,  # pass, fail
        framework: str,  # SOC2, ISO27001, etc.
        evidence: dict[str, Any] | None = None,
        account: Account | None = None,
    ) -> OCSFComplianceFinding:
        """
        Convert compliance control test result to OCSF Compliance Finding.

        Args:
            control_id: Control identifier (e.g., "SOC2-CC6.1")
            control_title: Human-readable control name
            status: pass or fail
            framework: Compliance framework name
            evidence: Supporting evidence data
            account: Cloud account context

        Returns:
            OCSFComplianceFinding
        """

        # Map status
        compliance_status = "Pass" if status.lower() == "pass" else "Fail"
        severity_id = (
            OCSFSeverity.INFORMATIONAL
            if status.lower() == "pass"
            else OCSFSeverity.HIGH
        )
        severity = OCSFSeverity(severity_id).name.title()

        # Activity: Create (new test result)
        activity_id = OCSFActivityID.CREATE
        activity_name = "Create"

        # Calculate type_uid
        type_uid = OCSFTypeUID.calculate(
            category_uid=2,  # Findings
            class_uid=2003,  # Compliance Finding
            activity_id=activity_id,
        )

        # Build finding info
        finding_info = OCSFFindingInfo(
            title=f"{framework} {control_id}: {control_title}",
            desc=f"Compliance control test result for {control_id}",
            uid=f"{framework}-{control_id}-{datetime.now(UTC).isoformat()}",
            types=["Compliance", "Control Test"],
            created_time=self._to_epoch_ms(datetime.now(UTC)),
        )

        # Build metadata
        metadata = OCSFMetadata(
            version="1.4.0",
            product=self.product,
            profiles=["cloud", "security_control"],
            event_code=control_id,
        )

        # Build compliance object
        compliance = OCSFCompliance(
            requirements=[f"{framework} {control_id}"],
            status=compliance_status,
            status_detail=control_title,
        )

        # Cloud context
        cloud = None
        if account:
            cloud = OCSFCloud(
                provider=account.provider.upper(),
                account=OCSFAccount(
                    uid=str(account.account_id),
                    name=account.display_name or account.external_id,
                ),
            )

        return OCSFComplianceFinding(
            type_uid=type_uid,
            type_name=f"Compliance Finding: {activity_name}",
            time=self._to_epoch_ms(datetime.now(UTC)),
            message=f"{framework} {control_id} test result: {compliance_status}",
            severity_id=severity_id,
            severity=severity,
            activity_id=activity_id,
            activity_name=activity_name,
            metadata=metadata,
            finding_info=finding_info,
            compliance=compliance,
            cloud=cloud,
            unmapped={"evidence": evidence} if evidence else None,
        )

    # ==================== Helper Methods ====================

    def _to_epoch_ms(self, dt: datetime | None) -> int | None:
        """Convert datetime to Unix epoch milliseconds."""
        if not dt:
            return None
        return int(dt.timestamp() * 1000)

    def _extract_finding_types(self, finding: Finding) -> list[str]:
        """Extract finding types from Cerebro finding."""
        types = []

        # Map from severity
        if finding.severity in ["critical", "high"]:
            types.append("Security Issue")

        # Map from metadata or rule
        if finding.metadata:
            if "misconfiguration" in finding.title.lower():
                types.append("Misconfiguration")
            if "compliance" in finding.title.lower():
                types.append("Compliance Violation")
            if "vulnerability" in finding.title.lower():
                types.append("Vulnerability")
            if "iam" in finding.title.lower() or "permission" in finding.title.lower():
                types.append("Excessive Permissions")

        return types if types else ["Security Issue"]

    def _determine_profiles(
        self, finding: Finding, account: Account | None
    ) -> list[str]:
        """Determine applicable OCSF profiles."""
        profiles = []

        if account:
            if account.provider in ["aws", "azure", "gcp"]:
                profiles.append("cloud")

        # Add more profile detection based on finding type
        if finding.metadata and "container" in str(finding.metadata).lower():
            profiles.append("container")

        if "host" in finding.title.lower() or "instance" in finding.title.lower():
            profiles.append("host")

        return profiles if profiles else ["cloud"]

    def _extract_observables(
        self,
        finding: Finding,
        resources: list[Resource] | None,
        principals: list[Principal] | None,
    ) -> list[OCSFObservables]:
        """Extract observables (IoCs) from finding."""
        observables = []

        # Add resource IDs as observables
        if resources:
            for resource in resources[:5]:  # Limit to 5
                observables.append(
                    OCSFObservables(
                        name=resource.name or "Resource",
                        type="resource_uid",
                        type_id=10,  # Resource UID type
                        value=resource.resource_id,
                    )
                )

        # Add principal IDs as observables
        if principals:
            for principal in principals[:5]:  # Limit to 5
                observables.append(
                    OCSFObservables(
                        name=principal.display_name or "Principal",
                        type="user",
                        type_id=4,  # User type
                        value=str(principal.principal_id),
                    )
                )

        return observables

    def _calculate_risk_score(self, finding: Finding) -> int:
        """Calculate risk score 0-100 based on finding characteristics."""
        base_scores = {
            "critical": 90,
            "high": 70,
            "medium": 50,
            "low": 30,
            "informational": 10,
        }

        score = base_scores.get(finding.severity, 50)

        # Adjust based on age (older findings = higher risk)
        if finding.first_seen:
            age_days = (datetime.now(UTC) - finding.first_seen).days
            if age_days > 90:
                score = min(100, score + 10)
            elif age_days > 30:
                score = min(100, score + 5)

        # Adjust based on compliance frameworks (more frameworks = higher risk)
        evidence = finding.evidence or {}
        compliance_frameworks = evidence.get("compliance_frameworks", [])
        if compliance_frameworks:
            score = min(100, score + len(compliance_frameworks) * 2)

        return score
