"""
OCSF Mapper

Transforms Cerebro security data into OCSF v1.4.0 compliant events.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

import structlog

from cerebro.core.models import Finding, Principal, Resource, Account
from cerebro.ocsf.models import (
    OCSFFinding,
    OCSFComplianceFinding,
    OCSFIdentityActivity,
    OCSFFindingInfo,
    OCSFMetadata,
    OCSFProduct,
    OCSFResource,
    OCSFUser,
    OCSFCloud,
    OCSFAccount,
    OCSFCompliance,
    OCSFRemediation,
    OCSFObservables,
    OCSFMappings,
    OCSFTypeUID,
    OCSFSeverity,
    OCSFActivityID,
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
        resources: Optional[List[Resource]] = None,
        account: Optional[Account] = None,
        principals: Optional[List[Principal]] = None,
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
        if finding.resolved_at:
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
            desc=finding.description,
            uid=str(finding.id),
            types=self._extract_finding_types(finding),
            first_seen_time=self._to_epoch_ms(finding.first_seen_at),
            last_seen_time=self._to_epoch_ms(finding.last_seen_at),
            created_time=self._to_epoch_ms(finding.created_at),
            modified_time=self._to_epoch_ms(finding.updated_at),
            src_url=f"cerebro://findings/{finding.id}",
        )

        # Build metadata
        metadata = OCSFMetadata(
            version="1.4.0",
            product=self.product,
            profiles=self._determine_profiles(finding, account),
            event_code=finding.rule_id if finding.rule_id else None,
            correlation_uid=str(finding.id),
            logged_time=self._to_epoch_ms(finding.created_at),
        )

        # Map resources
        ocsf_resources = []
        if resources:
            for resource in resources:
                ocsf_resources.append(
                    OCSFResource(
                        name=resource.name,
                        uid=resource.resource_id,
                        type=resource.resource_type,
                        labels=resource.tags.get("labels", []) if resource.tags else [],
                        data={"arn": resource.resource_id} if resource.provider == "aws" else {},
                    )
                )

        # Map cloud context
        cloud = None
        if account:
            cloud = OCSFCloud(
                provider=account.provider.upper(),
                region=finding.metadata.get("region") if finding.metadata else None,
                account=OCSFAccount(
                    uid=account.account_id,
                    name=account.name,
                    type="cloud_account",
                ),
            )

        # Map compliance (if applicable)
        compliance = None
        if finding.compliance_frameworks:
            compliance = OCSFCompliance(
                requirements=finding.compliance_frameworks,
                status="Fail",  # Findings represent violations
                status_detail=f"Non-compliant with {len(finding.compliance_frameworks)} frameworks",
            )

        # Build remediation guidance
        remediation = None
        if finding.metadata and finding.metadata.get("remediation"):
            remediation = OCSFRemediation(
                desc=finding.metadata["remediation"],
                references=[
                    finding.metadata.get("documentation", "")
                ],
            )

        # Extract observables (IoCs, principals, resource IDs)
        observables = self._extract_observables(finding, resources, principals)

        # Determine risk score
        risk_score = self._calculate_risk_score(finding)

        return OCSFFinding(
            type_uid=type_uid,
            type_name=f"Security Finding: {activity_name}",
            time=self._to_epoch_ms(finding.created_at),
            message=f"{finding.title}: {finding.description}",
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
            risk_level="High" if risk_score >= 70 else "Medium" if risk_score >= 40 else "Low",
            cloud=cloud,
            observables=observables,
            unmapped={"cerebro_metadata": finding.metadata} if finding.metadata else None,
        )

    async def compliance_result_to_ocsf(
        self,
        control_id: str,
        control_title: str,
        status: str,  # pass, fail
        framework: str,  # SOC2, ISO27001, etc.
        evidence: Optional[Dict[str, Any]] = None,
        account: Optional[Account] = None,
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
        severity_id = OCSFSeverity.INFORMATIONAL if status.lower() == "pass" else OCSFSeverity.HIGH
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
            uid=f"{framework}-{control_id}-{datetime.now(timezone.utc).isoformat()}",
            types=["Compliance", "Control Test"],
            created_time=self._to_epoch_ms(datetime.now(timezone.utc)),
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
                    uid=account.account_id,
                    name=account.name,
                ),
            )

        return OCSFComplianceFinding(
            type_uid=type_uid,
            type_name=f"Compliance Finding: {activity_name}",
            time=self._to_epoch_ms(datetime.now(timezone.utc)),
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

    def _to_epoch_ms(self, dt: Optional[datetime]) -> Optional[int]:
        """Convert datetime to Unix epoch milliseconds."""
        if not dt:
            return None
        return int(dt.timestamp() * 1000)

    def _extract_finding_types(self, finding: Finding) -> List[str]:
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

    def _determine_profiles(self, finding: Finding, account: Optional[Account]) -> List[str]:
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
        resources: Optional[List[Resource]],
        principals: Optional[List[Principal]],
    ) -> List[OCSFObservables]:
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
                        name=principal.name or "Principal",
                        type="user",
                        type_id=4,  # User type
                        value=principal.principal_id,
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
        if finding.first_seen_at:
            age_days = (datetime.now(timezone.utc) - finding.first_seen_at).days
            if age_days > 90:
                score = min(100, score + 10)
            elif age_days > 30:
                score = min(100, score + 5)

        # Adjust based on compliance frameworks (more frameworks = higher risk)
        if finding.compliance_frameworks:
            score = min(100, score + len(finding.compliance_frameworks) * 2)

        return score