from __future__ import annotations

from datetime import datetime, timedelta

from cerebro_sdk.security_center import (
    GovernanceAlert,
    MonitoringContext,
    MonitoringEvent,
    SecurityCenterCustomerInsight,
    SecurityCenterVendorInsight,
    evaluate_monitoring_events,
)


def _vendor() -> SecurityCenterVendorInsight:
    return SecurityCenterVendorInsight(
        vendor_id="vendor-1",
        name="Acme Cloud",
        category="security",
        risk_level="medium",
    )


def _customer() -> SecurityCenterCustomerInsight:
    return SecurityCenterCustomerInsight(
        customer_id="customer-1",
        name="Beta Corp",
        segment="enterprise",
        health_band="healthy",
    )


def test_evaluate_monitoring_events_builds_alerts_with_escalations() -> None:
    vendor = _vendor()
    customer = _customer()

    events = [
        MonitoringEvent(
            id="event-incident",
            entity_type="vendor",
            entity_id="vendor-1",
            event_type="incident",
            status="open",
            occurred_at=datetime.utcnow(),
            description="Vendor breach declared",
            severity="critical",
        ),
        MonitoringEvent(
            id="event-review",
            entity_type="customer",
            entity_id="customer-1",
            event_type="review",
            status="open",
            occurred_at=datetime.utcnow() - timedelta(days=30),
            description="Customer QBR overdue",
            severity="warning",
        ),
    ]

    context = MonitoringContext(
        vendor_resolver=lambda vendor_id: vendor if vendor_id == "vendor-1" else None,
        customer_resolver=lambda customer_id: customer if customer_id == "customer-1" else None,
        escalation_resolver=lambda entity, event: "governance" if event.event_type == "incident" else None,
    )

    alerts = evaluate_monitoring_events(events, context)
    assert len(alerts) == 2

    incident = next(alert for alert in alerts if alert.entity_type == "vendor")
    assert incident.severity == "critical"
    assert incident.escalation_target == "governance"
    assert incident.requires_review is True

    review_alert = next(alert for alert in alerts if alert.entity_type == "customer")
    assert review_alert.severity == "warning"
    assert review_alert.requires_review is True
    assert review_alert.escalation_target == "policy-owner"
