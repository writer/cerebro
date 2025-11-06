from __future__ import annotations

from datetime import datetime, timedelta

from cerebro_sdk.security_center import (
    GenerateRemediationOptions,
    RemediationPolicy,
    RemediationQueue,
    SecurityCenterCustomerInsight,
    SecurityCenterVendorInsight,
    generate_remediation_actions,
)


def _vendor(high_risk: bool = True) -> SecurityCenterVendorInsight:
    metadata = {
        "complianceSummary": {
            "certifications": [],
            "penetrationTestResultsPresent": False,
        },
        "riskSummary": {"monitoring": {"accessMonitoringEnabled": True}},
        "evidence": {"id": "vendor-ev-1", "securityQuestionnaireCompleted": True},
    }
    return SecurityCenterVendorInsight(
        vendor_id="vendor-123",
        name="Acme Cloud",
        category="security",
        risk_level="high" if high_risk else "medium",
        inherent_risk_score=0.6,
        residual_risk_score=0.82 if high_risk else 0.35,
        next_review_due=datetime.utcnow() - timedelta(days=5),
        metadata=metadata,
    )


def _customer(at_risk: bool = True) -> SecurityCenterCustomerInsight:
    metadata = {
        "evidence": {"id": "cust-ev-1", "support_tickets_open": 3},
        "engagement": {"openSupportTickets": 3},
        "adoption": {"metrics": {"pagerduty": 0.5}},
    }
    return SecurityCenterCustomerInsight(
        customer_id="customer-42",
        name="Beta Corp",
        segment="enterprise",
        health_band="at_risk" if at_risk else "healthy",
        health_score=0.5,
        churn_risk_score=0.7 if at_risk else 0.2,
        account_manager="csm-amy",
        metadata=metadata,
    )


def test_generate_remediation_actions_creates_vendor_and_customer_queue() -> None:
    vendor = _vendor(high_risk=True)
    customer = _customer(at_risk=True)

    queue = generate_remediation_actions(
        [vendor],
        [customer],
        GenerateRemediationOptions(
            vendor_policy=RemediationPolicy(
                risk_threshold=0.6,
                overdue_review_days=2,
                attestation_window_days=7,
                owner_resolver=lambda entity: "vendor-owner",
            ),
            customer_policy=RemediationPolicy(
                risk_threshold=0.5,
                attestation_window_days=5,
                owner_resolver=lambda entity: "customer-success",
            ),
        ),
    )

    assert isinstance(queue, RemediationQueue)
    assert len(queue.actions) == 2
    vendor_action = next(action for action in queue.actions if action.entity_type == "vendor")
    assert vendor_action.owner == "vendor-owner"
    assert vendor_action.severity == "critical"
    assert "Residual risk score" in vendor_action.description
    assert "Missing penetration test results" in vendor_action.description
    assert "vendor-ev-1" in vendor_action.evidence_ids

    customer_action = next(action for action in queue.actions if action.entity_type == "customer")
    assert customer_action.owner == "customer-success"
    assert customer_action.severity == "high"
    assert "support-tickets-3" in customer_action.evidence_ids
