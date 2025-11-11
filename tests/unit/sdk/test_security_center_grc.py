from __future__ import annotations

from datetime import datetime

from cerebro_sdk.security_center import (
    ControlCatalog,
    ControlDefinition,
    ControlMappingOptions,
    ControlTolerance,
    SecurityCenterCustomerInsight,
    SecurityCenterVendorInsight,
    map_to_control_framework,
)


def _vendor() -> SecurityCenterVendorInsight:
    metadata = {
        "integration": {
            "integrationType": "github",
            "authenticationMethods": ["oauth"],
        },
        "complianceSummary": {
            "certifications": ["soc2"],
            "frameworks": ["iso27001"],
            "securityQuestionnaireCompleted": True,
            "penetrationTestResultsPresent": False,
        },
        "evidence": {"id": "evidence-1", "securityQuestionnaireCompleted": True},
        "riskSummary": {"monitoring": {"accessMonitoringEnabled": True}},
    }
    return SecurityCenterVendorInsight(
        vendor_id="vendor-1",
        name="Acme Cloud",
        category="security",
        risk_level="medium",
        inherent_risk_score=0.6,
        residual_risk_score=0.65,
        lifecycle_stage="active",
        next_review_due=datetime(2024, 11, 1),
        business_criticality="high",
        metadata=metadata,
    )


def _customer() -> SecurityCenterCustomerInsight:
    metadata = {
        "successPrograms": ["design_partner"],
        "evidence": {"id": "cust-ev-1", "support_tickets_open": 2},
        "engagement": {"openSupportTickets": 2},
        "adoption": {"metrics": {"github": 0.92}},
    }
    return SecurityCenterCustomerInsight(
        customer_id="customer-1",
        name="Beta Corp",
        segment="enterprise",
        health_band="at_risk",
        health_score=0.55,
        churn_risk_score=0.45,
        lifecycle_stage="active",
        account_manager="csm-amy",
        next_qbr_at=datetime(2024, 12, 1),
        metadata=metadata,
    )


def test_map_to_control_framework_generates_evidence_bundle() -> None:
    vendor = _vendor()
    customer = _customer()

    catalog = ControlCatalog(
        frameworks={
            "soc2": {
                "cc-2.1": ControlDefinition(
                    name="Vendor monitoring",
                    policies=["TPRM"],
                    owner="trust-and-safety",
                    vendor_tags=["github"],
                    customer_tags=["design_partner"],
                    tolerance=ControlTolerance(
                        residual_risk_max=0.5,
                        churn_risk_max=0.4,
                    ),
                )
            }
        }
    )

    mappings = map_to_control_framework(
        [vendor],
        [customer],
        ControlMappingOptions(catalog=catalog),
    )

    assert len(mappings) == 1
    mapping = mappings[0]
    assert mapping.control_id == "cc-2.1"
    assert mapping.framework == "soc2"
    assert mapping.related_vendors == ["vendor-1"]
    assert mapping.related_customers == ["customer-1"]
    # residual risk exceeds tolerance -> at_risk
    assert mapping.status == "at_risk"
    assert "vendor(s) exceeding tolerance" in mapping.rationale

    vendor_evidence = mapping.evidence_report.vendor_evidence
    assert {artifact.artifact_id for artifact in vendor_evidence} == {"evidence-1"}
    assert mapping.evidence_report.vendor_summary.status == "fresh"

    customer_evidence = mapping.evidence_report.customer_evidence
    assert {artifact.artifact_id for artifact in customer_evidence} == {"cust-ev-1"}
    assert mapping.evidence_report.customer_summary.status == "fresh"
