"""Governance, risk, and compliance utilities for Security Center."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, Iterable, List, Mapping, Sequence

from .models import SecurityCenterCustomerInsight, SecurityCenterVendorInsight
from .primitives import (
    EvidenceArtifact,
    EvidenceSetSummary,
    LifecyclePolicy,
    extract_evidence_artifacts,
    summarize_evidence_set,
)

ControlStatus = str


@dataclass
class EvidenceBundle:
    exported_at: datetime
    control_id: str
    framework: str
    vendor_evidence: Sequence[EvidenceArtifact]
    customer_evidence: Sequence[EvidenceArtifact]
    vendor_summary: EvidenceSetSummary
    customer_summary: EvidenceSetSummary


@dataclass
class ControlDefinition:
    name: str
    policies: Sequence[str]
    owner: str
    vendor_tags: Sequence[str] | None = None
    customer_tags: Sequence[str] | None = None
    tolerance: "ControlTolerance" | None = None


@dataclass
class ControlTolerance:
    residual_risk_max: float | None = None
    churn_risk_max: float | None = None
    overdue_review_max: int | None = None


@dataclass
class ControlCatalog:
    frameworks: Mapping[str, Mapping[str, ControlDefinition]]


@dataclass
class ControlMapping:
    control_id: str
    control_name: str
    framework: str
    policy_owner: str
    status: ControlStatus
    rationale: str
    related_vendors: Sequence[str]
    related_customers: Sequence[str]
    evidence_report: EvidenceBundle


@dataclass
class ControlMappingOptions:
    catalog: ControlCatalog
    vendor_tags: Callable[[SecurityCenterVendorInsight], Sequence[str]] | None = None
    customer_tags: Callable[[SecurityCenterCustomerInsight], Sequence[str]] | None = (
        None
    )
    evidence_policy: LifecyclePolicy | None = None


def map_to_control_framework(
    vendors: Iterable[SecurityCenterVendorInsight],
    customers: Iterable[SecurityCenterCustomerInsight],
    options: ControlMappingOptions,
) -> List[ControlMapping]:
    """Project vendors/customers into control mappings based on the provided catalog."""

    vendor_index: Dict[str, List[SecurityCenterVendorInsight]] = {}
    customer_index: Dict[str, List[SecurityCenterCustomerInsight]] = {}

    for vendor in vendors:
        tags = {
            *(options.vendor_tags(vendor) if options.vendor_tags else []),
            *extract_vendor_tags(vendor.metadata),
            *extract_vendor_tags(vendor.raw_metadata),
        }
        for tag in tags:
            vendor_index.setdefault(tag.lower(), []).append(vendor)

    for customer in customers:
        tags = {
            *(options.customer_tags(customer) if options.customer_tags else []),
            *extract_customer_tags(customer.metadata),
            *extract_customer_tags(customer.raw_metadata),
        }
        for tag in tags:
            customer_index.setdefault(tag.lower(), []).append(customer)

    exported_at = datetime.utcnow()
    mappings: List[ControlMapping] = []

    for framework, controls in options.catalog.frameworks.items():
        for control_id, control in controls.items():
            related_vendors = _collect_entities(control.vendor_tags, vendor_index)
            related_customers = _collect_entities(control.customer_tags, customer_index)

            status, rationale = _evaluate_control(
                control, related_vendors, related_customers
            )
            evidence_report = _build_evidence_bundle(
                exported_at,
                control_id,
                framework,
                related_vendors,
                related_customers,
                options.evidence_policy,
            )

            mappings.append(
                ControlMapping(
                    control_id=control_id,
                    control_name=control.name,
                    framework=framework,
                    policy_owner=control.owner,
                    status=status,
                    rationale=rationale,
                    related_vendors=[vendor.vendor_id for vendor in related_vendors],
                    related_customers=[
                        customer.customer_id for customer in related_customers
                    ],
                    evidence_report=evidence_report,
                )
            )

    return mappings


def _collect_entities(
    tags: Sequence[str] | None,
    index: Mapping[str, List[Any]],
) -> List[Any]:
    if not tags:
        return []
    results: List[Any] = []
    seen_ids: set[int] = set()
    for tag in tags:
        matches = index.get(tag.lower())
        if not matches:
            continue
        for match in matches:
            marker = id(match)
            if marker in seen_ids:
                continue
            seen_ids.add(marker)
            results.append(match)
    return results


def _evaluate_control(
    control: ControlDefinition,
    vendors: Sequence[SecurityCenterVendorInsight],
    customers: Sequence[SecurityCenterCustomerInsight],
) -> tuple[ControlStatus, str]:
    tolerance = control.tolerance or ControlTolerance()
    residual_max = tolerance.residual_risk_max
    churn_max = tolerance.churn_risk_max

    vendor_breaches = [
        vendor
        for vendor in vendors
        if residual_max is not None
        and (vendor.residual_risk_score or 0.0) > residual_max
    ]
    customer_breaches = [
        customer
        for customer in customers
        if churn_max is not None and (customer.churn_risk_score or 0.0) > churn_max
    ]

    if not vendor_breaches and not customer_breaches:
        if not vendors and not customers:
            return "pass", "Control not applicable: no related vendors or customers"
        return "pass", "All related vendors/customers within tolerance"

    parts: List[str] = []
    if vendor_breaches:
        names = ", ".join(vendor.name for vendor in vendor_breaches)
        parts.append(f"{len(vendor_breaches)} vendor(s) exceeding tolerance: {names}")
    if customer_breaches:
        names = ", ".join(customer.name for customer in customer_breaches)
        parts.append(
            f"{len(customer_breaches)} customer(s) exceeding tolerance: {names}"
        )

    severity = "gap" if len(vendor_breaches) + len(customer_breaches) > 2 else "at_risk"
    return severity, "; ".join(parts)


def _build_evidence_bundle(
    exported_at: datetime,
    control_id: str,
    framework: str,
    vendors: Sequence[SecurityCenterVendorInsight],
    customers: Sequence[SecurityCenterCustomerInsight],
    evidence_policy: LifecyclePolicy | None,
) -> EvidenceBundle:
    policy = evidence_policy or LifecyclePolicy(
        max_age_days=90, refresh_window_days=14, hard_expiry_days=365
    )

    vendor_evidence: List[EvidenceArtifact] = []
    for vendor in vendors:
        vendor_evidence.extend(
            extract_evidence_artifacts(
                kind="vendor",
                entity_id=vendor.vendor_id,
                metadata=vendor.metadata,
                default_source="metadata",
            )
        )
        vendor_evidence.extend(
            extract_evidence_artifacts(
                kind="vendor",
                entity_id=vendor.vendor_id,
                metadata=vendor.raw_metadata,
                default_source="raw",
            )
        )

    customer_evidence: List[EvidenceArtifact] = []
    for customer in customers:
        customer_evidence.extend(
            extract_evidence_artifacts(
                kind="customer",
                entity_id=customer.customer_id,
                metadata=customer.metadata,
                default_source="metadata",
            )
        )
        customer_evidence.extend(
            extract_evidence_artifacts(
                kind="customer",
                entity_id=customer.customer_id,
                metadata=customer.raw_metadata,
                default_source="raw",
            )
        )

    vendor_summary = summarize_evidence_set(vendor_evidence, policy, now=exported_at)
    customer_summary = summarize_evidence_set(
        customer_evidence, policy, now=exported_at
    )

    return EvidenceBundle(
        exported_at=exported_at,
        control_id=control_id,
        framework=framework,
        vendor_evidence=vendor_evidence,
        customer_evidence=customer_evidence,
        vendor_summary=vendor_summary,
        customer_summary=customer_summary,
    )


def extract_vendor_tags(metadata: Mapping[str, Any] | None) -> Sequence[str]:
    if not metadata:
        return []
    tags: List[str] = []
    integration = metadata.get("integration")
    if isinstance(integration, Mapping):
        integration_type = integration.get("integrationType") or integration.get(
            "integration_type"
        )
        if isinstance(integration_type, str):
            tags.append(integration_type)
        auth_methods = integration.get("authenticationMethods") or integration.get(
            "authentication_methods"
        )
        if isinstance(auth_methods, Sequence):
            tags.extend(str(method) for method in auth_methods)
    compliance = metadata.get("complianceSummary") or metadata.get("compliance_summary")
    if isinstance(compliance, Mapping):
        certifications = compliance.get("certifications")
        if isinstance(certifications, Sequence):
            tags.extend(str(cert) for cert in certifications)
        frameworks = compliance.get("frameworks")
        if isinstance(frameworks, Sequence):
            tags.extend(str(item) for item in frameworks)
    tags_section = metadata.get("tags")
    if isinstance(tags_section, Mapping):
        tags.extend(str(value) for value in tags_section.values())
    return tags


def extract_customer_tags(metadata: Mapping[str, Any] | None) -> Sequence[str]:
    if not metadata:
        return []
    tags: List[str] = []
    programs = metadata.get("successPrograms") or metadata.get("success_programs")
    if isinstance(programs, Sequence):
        tags.extend(str(program) for program in programs)
    tags_section = metadata.get("tags")
    if isinstance(tags_section, Mapping):
        tags.extend(str(value) for value in tags_section.values())
    return tags
