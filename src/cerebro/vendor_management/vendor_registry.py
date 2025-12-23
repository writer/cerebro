"""
Vendor registry for tracking third-party vendors and their security profiles.

Manages vendor onboarding, risk assessment, and ongoing monitoring.
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

from ..compliance.models import create_vendor_evidence, metadata_to_dict

logger = logging.getLogger(__name__)


class VendorRiskLevel(Enum):
    """Risk levels for vendor assessment."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VendorCategory(Enum):
    """Categories of vendors."""

    CLOUD_PROVIDER = "cloud_provider"
    SAAS_APPLICATION = "saas_application"
    SECURITY_VENDOR = "security_vendor"
    DATA_PROCESSOR = "data_processor"
    CONSULTING_SERVICES = "consulting_services"
    INFRASTRUCTURE = "infrastructure"
    DEVELOPMENT_TOOLS = "development_tools"
    BUSINESS_APPLICATIONS = "business_applications"


@dataclass
class Vendor:
    """Vendor entity with security assessment data."""

    vendor_id: str
    org_id: Optional[str]
    name: str
    website_url: str
    primary_contact: str

    # Classification
    category: VendorCategory
    industry: str
    country: str
    data_processing_locations: List[str]

    # Risk assessment
    risk_level: VendorRiskLevel
    inherent_risk_score: float
    residual_risk_score: float
    last_assessment_date: datetime
    next_review_due: datetime

    # Compliance
    certifications: List[str]  # SOC2, ISO27001, etc.
    compliance_frameworks: List[str]
    data_processing_agreements: List[str]

    # Security profile
    security_questionnaire_completed: bool
    penetration_test_results: Optional[Dict[str, Any]]
    vulnerability_disclosure_policy: Optional[str]
    incident_response_plan: bool

    # Business relationship
    contract_start_date: datetime
    contract_end_date: Optional[datetime]
    annual_spend: Optional[float]
    business_criticality: str  # "low", "medium", "high", "critical"

    # Data handling
    data_types_processed: List[str]  # "PII", "PHI", "Financial", etc.
    data_retention_period: Optional[str]
    data_deletion_policy: Optional[str]

    # Integration details
    integration_type: str  # "API", "File Transfer", "Database", etc.
    network_access: List[str]  # IP ranges, VPN access, etc.
    authentication_methods: List[str]

    # Monitoring
    access_monitoring_enabled: bool
    security_alerts_configured: bool
    incident_count_last_year: int

    # Metadata
    created_at: datetime
    updated_at: datetime
    created_by: str
    tags: List[str]
    metadata: Dict[str, Any]


class VendorRegistry:
    """
    Registry for managing vendor relationships and security assessments.

    Tracks vendor security profiles, risk assessments, and compliance status.
    """

    def __init__(self):
        self.vendors: Dict[str, Vendor] = {}

    async def register_vendor(
        self,
        name: str,
        website_url: str,
        category: VendorCategory,
        created_by: str,
        org_id: Optional[str] = None,
        **vendor_data,
    ) -> Vendor:
        """Register a new vendor in the system."""
        vendor_id = (
            f"vendor_{name.lower().replace(' ', '_')}_{int(datetime.now().timestamp())}"
        )

        vendor = Vendor(
            vendor_id=vendor_id,
            org_id=org_id,
            name=name,
            website_url=website_url,
            primary_contact=vendor_data.get("primary_contact", ""),
            category=category,
            industry=vendor_data.get("industry", ""),
            country=vendor_data.get("country", ""),
            data_processing_locations=vendor_data.get("data_processing_locations", []),
            risk_level=VendorRiskLevel.MEDIUM,  # Default
            inherent_risk_score=0.5,
            residual_risk_score=0.5,
            last_assessment_date=datetime.now(),
            next_review_due=datetime.now() + timedelta(days=365),
            certifications=vendor_data.get("certifications", []),
            compliance_frameworks=vendor_data.get("compliance_frameworks", []),
            data_processing_agreements=vendor_data.get(
                "data_processing_agreements", []
            ),
            security_questionnaire_completed=False,
            penetration_test_results=None,
            vulnerability_disclosure_policy=vendor_data.get(
                "vulnerability_disclosure_policy"
            ),
            incident_response_plan=vendor_data.get("incident_response_plan", False),
            contract_start_date=vendor_data.get("contract_start_date", datetime.now()),
            contract_end_date=vendor_data.get("contract_end_date"),
            annual_spend=vendor_data.get("annual_spend"),
            business_criticality=vendor_data.get("business_criticality", "medium"),
            data_types_processed=vendor_data.get("data_types_processed", []),
            data_retention_period=vendor_data.get("data_retention_period"),
            data_deletion_policy=vendor_data.get("data_deletion_policy"),
            integration_type=vendor_data.get("integration_type", "API"),
            network_access=vendor_data.get("network_access", []),
            authentication_methods=vendor_data.get("authentication_methods", []),
            access_monitoring_enabled=False,
            security_alerts_configured=False,
            incident_count_last_year=0,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            created_by=created_by,
            tags=vendor_data.get("tags", []),
            metadata=vendor_data.get("metadata", {}),
        )

        # Perform initial risk assessment
        await self._assess_vendor_risk(vendor)
        self._update_vendor_metadata(vendor)

        self.vendors[vendor_id] = vendor

        logger.info(f"Registered vendor: {name} ({vendor_id})")

        return vendor

    async def _assess_vendor_risk(self, vendor: Vendor):
        """Perform initial vendor risk assessment."""
        risk_score = 0.5  # Base risk

        # Category-based risk
        category_risks = {
            VendorCategory.CLOUD_PROVIDER: 0.7,
            VendorCategory.SECURITY_VENDOR: 0.6,
            VendorCategory.DATA_PROCESSOR: 0.8,
            VendorCategory.SAAS_APPLICATION: 0.6,
            VendorCategory.CONSULTING_SERVICES: 0.4,
            VendorCategory.INFRASTRUCTURE: 0.7,
            VendorCategory.DEVELOPMENT_TOOLS: 0.5,
            VendorCategory.BUSINESS_APPLICATIONS: 0.5,
        }

        risk_score = category_risks.get(vendor.category, 0.5)

        # Data type risk adjustment
        sensitive_data_types = ["PII", "PHI", "Financial", "Confidential"]
        if any(
            data_type in vendor.data_types_processed
            for data_type in sensitive_data_types
        ):
            risk_score += 0.2

        # Certification bonus
        if "SOC2" in vendor.certifications or "ISO27001" in vendor.certifications:
            risk_score -= 0.1

        # Geographic risk
        high_risk_countries = ["Unknown", "Non-Compliant"]
        if vendor.country in high_risk_countries:
            risk_score += 0.2

        # Business criticality multiplier
        criticality_multipliers = {
            "critical": 1.3,
            "high": 1.1,
            "medium": 1.0,
            "low": 0.8,
        }

        risk_score *= criticality_multipliers.get(vendor.business_criticality, 1.0)

        # Normalize to 0-1 range
        vendor.inherent_risk_score = min(max(risk_score, 0.0), 1.0)
        vendor.residual_risk_score = vendor.inherent_risk_score  # Initially same

        # Set risk level enum
        if vendor.inherent_risk_score >= 0.8:
            vendor.risk_level = VendorRiskLevel.CRITICAL
        elif vendor.inherent_risk_score >= 0.6:
            vendor.risk_level = VendorRiskLevel.HIGH
        elif vendor.inherent_risk_score >= 0.4:
            vendor.risk_level = VendorRiskLevel.MEDIUM
        else:
            vendor.risk_level = VendorRiskLevel.LOW

    def _update_vendor_metadata(self, vendor: Vendor):
        """Generate rich metadata envelope for vendor consumers."""

        lifecycle_stage = self._determine_lifecycle_stage(vendor)

        evidence = create_vendor_evidence(
            vendor_id=vendor.vendor_id,
            vendor_name=vendor.name,
            created_by=vendor.created_by,
            risk_level=vendor.risk_level.value,
            inherent_risk_score=vendor.inherent_risk_score,
            residual_risk_score=vendor.residual_risk_score,
            business_criticality=vendor.business_criticality,
            vendor_category=vendor.category.value,
            data_types_processed=vendor.data_types_processed,
            certifications=vendor.certifications,
            compliance_frameworks=vendor.compliance_frameworks,
            last_assessment_date=vendor.last_assessment_date,
            next_review_due=vendor.next_review_due,
            contract_end_date=vendor.contract_end_date,
            lifecycle_stage=lifecycle_stage,
            relationship_owner=vendor.created_by,
            service_regions=vendor.data_processing_locations,
            primary_contacts=[vendor.primary_contact] if vendor.primary_contact else [],
            access_monitoring_enabled=vendor.access_monitoring_enabled,
            security_alerts_configured=vendor.security_alerts_configured,
            incident_count_last_year=vendor.incident_count_last_year,
            tags={"org_id": vendor.org_id} if vendor.org_id else None,
        )

        vendor.metadata = {
            "evidence": metadata_to_dict(evidence),
            "risk_summary": {
                "level": vendor.risk_level.value,
                "inherent_score": round(vendor.inherent_risk_score, 3),
                "residual_score": round(vendor.residual_risk_score, 3),
                "incident_count_last_year": vendor.incident_count_last_year,
                "monitoring": {
                    "access_monitoring_enabled": vendor.access_monitoring_enabled,
                    "security_alerts_configured": vendor.security_alerts_configured,
                },
            },
            "compliance_summary": {
                "certifications": vendor.certifications,
                "frameworks": vendor.compliance_frameworks,
                "data_processing_agreements": vendor.data_processing_agreements,
                "security_questionnaire_completed": vendor.security_questionnaire_completed,
                "vulnerability_disclosure_policy": bool(
                    vendor.vulnerability_disclosure_policy
                ),
                "penetration_test_results_present": bool(
                    vendor.penetration_test_results
                ),
            },
            "relationship": {
                "business_criticality": vendor.business_criticality,
                "annual_spend": vendor.annual_spend,
                "contract": {
                    "start_date": vendor.contract_start_date.isoformat(),
                    "end_date": (
                        vendor.contract_end_date.isoformat()
                        if vendor.contract_end_date
                        else None
                    ),
                    "next_review_due": vendor.next_review_due.isoformat(),
                },
            },
            "integration": {
                "integration_type": vendor.integration_type,
                "network_access": vendor.network_access,
                "authentication_methods": vendor.authentication_methods,
            },
            "lifecycle_stage": lifecycle_stage,
            "org_id": vendor.org_id,
        }

        tag_updates = {
            f"risk:{vendor.risk_level.value}",
            f"criticality:{vendor.business_criticality}",
            f"category:{vendor.category.value}",
            f"stage:{lifecycle_stage}",
        }
        if vendor.org_id:
            tag_updates.add(f"org:{vendor.org_id}")
        vendor.tags = sorted({*vendor.tags, *tag_updates})

    def _determine_lifecycle_stage(self, vendor: Vendor) -> str:
        """Derive vendor lifecycle stage from contract and review timelines."""

        now = datetime.now()
        if vendor.contract_end_date and vendor.contract_end_date < now:
            return "offboarding"
        days_until_review = (vendor.next_review_due - now).days
        if days_until_review < 0:
            return "review_overdue"
        if vendor.contract_end_date and (vendor.contract_end_date - now).days <= 90:
            return "renewal"
        if days_until_review <= 30:
            return "review_due_soon"
        return "active"

    async def refresh_vendor_profile(self, vendor_id: str) -> Optional[Vendor]:
        """Recalculate risk and metadata for a vendor."""

        vendor = self.vendors.get(vendor_id)
        if not vendor:
            return None

        await self._assess_vendor_risk(vendor)
        self._update_vendor_metadata(vendor)
        vendor.updated_at = datetime.now()
        return vendor

    async def get_vendors_by_risk_level(
        self, risk_level: VendorRiskLevel
    ) -> List[Vendor]:
        """Get vendors filtered by risk level."""
        return [
            vendor
            for vendor in self.vendors.values()
            if vendor.risk_level == risk_level
        ]

    async def get_overdue_reviews(self) -> List[Vendor]:
        """Get vendors with overdue security reviews."""
        current_date = datetime.now()
        return [
            vendor
            for vendor in self.vendors.values()
            if vendor.next_review_due < current_date
        ]

    async def get_vendors_by_category(self, category: VendorCategory) -> List[Vendor]:
        """Get vendors by category."""
        return [
            vendor for vendor in self.vendors.values() if vendor.category == category
        ]

    async def get_vendors_processing_sensitive_data(self) -> List[Vendor]:
        """Get vendors that process sensitive data types."""
        sensitive_types = ["PII", "PHI", "Financial", "Confidential"]

        return [
            vendor
            for vendor in self.vendors.values()
            if any(
                data_type in vendor.data_types_processed
                for data_type in sensitive_types
            )
        ]

    async def generate_vendor_risk_report(self, org_id: str) -> Dict[str, Any]:
        """Generate comprehensive vendor risk report."""
        vendors = list(self.vendors.values())

        # Risk distribution
        risk_distribution = {
            "critical": len(
                [v for v in vendors if v.risk_level == VendorRiskLevel.CRITICAL]
            ),
            "high": len([v for v in vendors if v.risk_level == VendorRiskLevel.HIGH]),
            "medium": len(
                [v for v in vendors if v.risk_level == VendorRiskLevel.MEDIUM]
            ),
            "low": len([v for v in vendors if v.risk_level == VendorRiskLevel.LOW]),
        }

        # Category distribution
        category_distribution: Dict[str, int] = {}
        for vendor in vendors:
            category = vendor.category.value
            category_distribution[category] = category_distribution.get(category, 0) + 1

        # Compliance status
        certified_vendors = len([v for v in vendors if v.certifications])
        questionnaire_complete = len(
            [v for v in vendors if v.security_questionnaire_completed]
        )

        # Overdue reviews
        overdue_vendors = await self.get_overdue_reviews()

        return {
            "organization_id": org_id,
            "report_date": datetime.now().isoformat(),
            "summary": {
                "total_vendors": len(vendors),
                "high_risk_vendors": risk_distribution["critical"]
                + risk_distribution["high"],
                "overdue_reviews": len(overdue_vendors),
                "compliance_rate": round(
                    (certified_vendors / max(len(vendors), 1)) * 100, 1
                ),
            },
            "risk_distribution": risk_distribution,
            "category_distribution": category_distribution,
            "compliance_metrics": {
                "vendors_with_certifications": certified_vendors,
                "security_questionnaires_complete": questionnaire_complete,
                "vendors_with_incident_response": len(
                    [v for v in vendors if v.incident_response_plan]
                ),
            },
            "overdue_reviews": [
                {
                    "vendor_id": vendor.vendor_id,
                    "name": vendor.name,
                    "risk_level": vendor.risk_level.value,
                    "days_overdue": (datetime.now() - vendor.next_review_due).days,
                    "last_assessment": vendor.last_assessment_date.isoformat(),
                }
                for vendor in overdue_vendors
            ][:10],
            "high_risk_vendors": [
                {
                    "vendor_id": vendor.vendor_id,
                    "name": vendor.name,
                    "risk_level": vendor.risk_level.value,
                    "risk_score": vendor.inherent_risk_score,
                    "category": vendor.category.value,
                    "data_types": vendor.data_types_processed,
                }
                for vendor in vendors
                if vendor.risk_level in [VendorRiskLevel.HIGH, VendorRiskLevel.CRITICAL]
            ][:10],
        }


# Global vendor registry
_vendor_registry = VendorRegistry()


def get_vendor_registry() -> VendorRegistry:
    """Get global vendor registry."""
    return _vendor_registry
