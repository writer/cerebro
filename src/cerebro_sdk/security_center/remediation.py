"""Remediation and corrective action planning for Security Center entities."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Iterable, List, Sequence

from .models import SecurityCenterCustomerInsight, SecurityCenterVendorInsight


RemediationSeverity = str


@dataclass
class RemediationAction:
    id: str
    entity_type: str
    entity_id: str
    title: str
    description: str
    owner: str
    due_date: datetime | None
    severity: RemediationSeverity
    attestation_required: bool
    evidence_ids: Sequence[str]


@dataclass
class RemediationQueue:
    actions: Sequence[RemediationAction]
    generated_at: datetime


@dataclass
class RemediationPolicy:
    risk_threshold: float
    overdue_review_days: int | None = None
    attestation_window_days: int | None = None
    owner_resolver: (
        Callable[[SecurityCenterVendorInsight | SecurityCenterCustomerInsight], str]
        | None
    ) = None


@dataclass
class GenerateRemediationOptions:
    vendor_policy: RemediationPolicy
    customer_policy: RemediationPolicy


def generate_remediation_actions(
    vendors: Iterable[SecurityCenterVendorInsight],
    customers: Iterable[SecurityCenterCustomerInsight],
    options: GenerateRemediationOptions,
) -> RemediationQueue:
    now = datetime.utcnow()
    actions: List[RemediationAction] = []

    for vendor in vendors:
        risk_score = vendor.residual_risk_score or vendor.inherent_risk_score or 0.0
        overdue_days = _compute_overdue_days(vendor.next_review_due, now)
        overdue_limit = options.vendor_policy.overdue_review_days or 0
        if (
            risk_score < options.vendor_policy.risk_threshold
            and overdue_days <= overdue_limit
        ):
            continue

        actions.append(
            RemediationAction(
                id=f"remediate-vendor-{vendor.vendor_id}",
                entity_type="vendor",
                entity_id=vendor.vendor_id,
                title=f"Mitigate vendor risk: {vendor.name}",
                description=_build_vendor_description(vendor, risk_score, overdue_days),
                owner=_resolve_owner(
                    vendor, options.vendor_policy.owner_resolver, "sec-ops"
                ),
                due_date=_compute_due_date(
                    now, options.vendor_policy.attestation_window_days or 14
                ),
                severity=_classify_severity(risk_score),
                attestation_required=True,
                evidence_ids=_collect_vendor_evidence(vendor),
            )
        )

    for customer in customers:
        risk_score = customer.churn_risk_score or customer.health_score or 0.0
        if risk_score < options.customer_policy.risk_threshold:
            continue

        actions.append(
            RemediationAction(
                id=f"remediate-customer-{customer.customer_id}",
                entity_type="customer",
                entity_id=customer.customer_id,
                title=f"Engage customer at risk: {customer.name}",
                description=_build_customer_description(customer, risk_score),
                owner=_resolve_owner(
                    customer,
                    options.customer_policy.owner_resolver,
                    customer.account_manager or "customer-success",
                ),
                due_date=_compute_due_date(
                    now, options.customer_policy.attestation_window_days or 10
                ),
                severity=_classify_severity(risk_score),
                attestation_required=False,
                evidence_ids=_collect_customer_evidence(customer),
            )
        )

    return RemediationQueue(actions=actions, generated_at=now)


def _compute_overdue_days(next_review_due: datetime | None, now: datetime) -> int:
    if not next_review_due:
        return 0
    diff = now - next_review_due
    if diff <= timedelta(0):
        return 0
    return int(diff.days)


def _compute_due_date(now: datetime, window_days: int) -> datetime:
    return now + timedelta(days=window_days)


def _classify_severity(score: float) -> RemediationSeverity:
    if score >= 0.8:
        return "critical"
    if score >= 0.6:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


def _resolve_owner(
    entity: SecurityCenterVendorInsight | SecurityCenterCustomerInsight,
    resolver: (
        Callable[[SecurityCenterVendorInsight | SecurityCenterCustomerInsight], str]
        | None
    ),
    fallback: str,
) -> str:
    if resolver:
        owner = resolver(entity)
        if owner:
            return owner
    return fallback


def _build_vendor_description(
    vendor: SecurityCenterVendorInsight,
    risk_score: float,
    overdue_days: int,
) -> str:
    parts = [f"Residual risk score: {risk_score:.2f}"]
    if overdue_days > 0:
        parts.append(f"Review overdue by {overdue_days} day(s)")
    compliance = (
        vendor.metadata.get("complianceSummary")
        if isinstance(vendor.metadata, dict)
        else None
    )
    if isinstance(compliance, dict) and not compliance.get("certifications"):
        parts.append("No certifications on file")
    if (
        isinstance(compliance, dict)
        and compliance.get("penetrationTestResultsPresent") is False
    ):
        parts.append("Missing penetration test results")
    return "; ".join(parts)


def _build_customer_description(
    customer: SecurityCenterCustomerInsight, risk_score: float
) -> str:
    parts = [f"Churn risk score: {risk_score:.2f}"]
    engagement = (
        customer.metadata.get("engagement")
        if isinstance(customer.metadata, dict)
        else None
    )
    if isinstance(engagement, dict):
        tickets = engagement.get("openSupportTickets") or engagement.get(
            "open_support_tickets"
        )
        if isinstance(tickets, int) and tickets > 0:
            parts.append(f"{tickets} open support ticket(s)")
    adoption = (
        customer.metadata.get("adoption")
        if isinstance(customer.metadata, dict)
        else None
    )
    metrics = adoption.get("metrics") if isinstance(adoption, dict) else None
    if isinstance(metrics, dict) and metrics:
        metric_str = ", ".join(f"{key}={value}" for key, value in metrics.items())
        parts.append(f"Adoption metrics: {metric_str}")
    return "; ".join(parts)


def _collect_vendor_evidence(vendor: SecurityCenterVendorInsight) -> List[str]:
    evidence_ids: List[str] = []
    evidence = (
        vendor.metadata.get("evidence") if isinstance(vendor.metadata, dict) else None
    )
    if isinstance(evidence, dict):
        evidence_id = evidence.get("id")
        if isinstance(evidence_id, str):
            evidence_ids.append(evidence_id)
        if (
            evidence.get("securityQuestionnaireCompleted") is False
            or evidence.get("security_questionnaire_completed") is False
        ):
            evidence_ids.append("missing-security-questionnaire")
    risk_summary = (
        vendor.metadata.get("riskSummary")
        if isinstance(vendor.metadata, dict)
        else None
    )
    if isinstance(risk_summary, dict):
        monitoring = risk_summary.get("monitoring")
        if (
            isinstance(monitoring, dict)
            and monitoring.get("accessMonitoringEnabled") is False
        ):
            evidence_ids.append("access-monitoring-gap")
    return evidence_ids


def _collect_customer_evidence(customer: SecurityCenterCustomerInsight) -> List[str]:
    evidence_ids: List[str] = []
    evidence = (
        customer.metadata.get("evidence")
        if isinstance(customer.metadata, dict)
        else None
    )
    if isinstance(evidence, dict):
        evidence_id = evidence.get("id")
        if isinstance(evidence_id, str):
            evidence_ids.append(evidence_id)
        tickets = evidence.get("support_tickets_open") or evidence.get(
            "supportTicketsOpen"
        )
        if isinstance(tickets, int) and tickets > 0:
            evidence_ids.append(f"support-tickets-{tickets}")
    engagement = (
        customer.metadata.get("engagement")
        if isinstance(customer.metadata, dict)
        else None
    )
    if isinstance(engagement, dict):
        tickets = engagement.get("openSupportTickets") or engagement.get(
            "open_support_tickets"
        )
        if (
            isinstance(tickets, int)
            and tickets > 0
            and f"support-tickets-{tickets}" not in evidence_ids
        ):
            evidence_ids.append(f"support-tickets-{tickets}")
    return evidence_ids
