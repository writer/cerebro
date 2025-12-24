"""Entity relations and exposure dashboards for the Security Center SDK."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional, Union
from uuid import UUID

from cerebro_sdk.agents.streaming import (
    AgentMessage,
    AgentStreamConsumers,
    AgentStreamEvent,
    CompletionUpdate,
    ToolCallDelta,
)
from cerebro_sdk.analytics import (
    IntegrationAccountSummary,
    IntegrationCoverageRecord,
    IntegrationScopeBreakdown,
)
from cerebro_sdk.findings import FindingRecord

from .analytics import (
    CustomerRiskDashboard,
    TrendAlert,
    VendorRiskDashboard,
    build_customer_risk_dashboard,
    build_vendor_risk_dashboard,
)
from .models import SecurityCenterCustomerInsight, SecurityCenterVendorInsight


def _normalize(value: str | None) -> str:
    return (value or "").strip().lower()


def _as_list(value: Iterable[object] | None) -> list[object]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable):
        return list(value)
    return [value]


async def _resolve(
    source: Callable[..., Iterable[object] | Awaitable[Iterable[object]]], *args
) -> list[object]:
    result = source(*args)
    if isinstance(result, Awaitable):
        resolved = await result
        return list(resolved)
    if isinstance(result, Iterable):
        return list(result)
    raise TypeError("Unsupported source callable return type")


@dataclass
class IntegrationCoverageHealth:
    integration: str
    providers: list[str]
    status: str
    scopes: IntegrationScopeBreakdown
    accounts: IntegrationAccountSummary
    coverage_ratio: float | None
    last_success: datetime | None
    evaluated_at: datetime
    healthy_percentage: float
    warning_percentage: float
    critical_percentage: float
    overall_score: float


def _to_ratio(value: int | float | None, total: int | float | None) -> float:
    if total is None or not isinstance(total, (int, float)) or total <= 0:
        return 0.0
    numerator = float(value or 0)
    return numerator / float(total)


def compute_coverage_health(
    record: IntegrationCoverageRecord,
) -> IntegrationCoverageHealth:
    total_scopes = record.scopes.total or 0
    healthy_percentage = _to_ratio(record.scopes.healthy, total_scopes)
    warning_percentage = _to_ratio(record.scopes.warning, total_scopes)
    critical_percentage = _to_ratio(record.scopes.critical, total_scopes)
    overall_score = healthy_percentage - warning_percentage * 0.5 - critical_percentage

    return IntegrationCoverageHealth(
        integration=record.integration,
        providers=list(record.providers),
        status=record.status,
        scopes=record.scopes,
        accounts=record.accounts,
        coverage_ratio=record.coverage_ratio,
        last_success=record.last_success,
        evaluated_at=record.evaluated_at,
        healthy_percentage=healthy_percentage,
        warning_percentage=warning_percentage,
        critical_percentage=critical_percentage,
        overall_score=overall_score,
    )


ConsumerFn = Callable[..., Union[Awaitable[None], None]]


@dataclass
class RelationsContext:
    fetch_vendors: Callable[
        [str],
        Iterable[SecurityCenterVendorInsight]
        | Awaitable[Iterable[SecurityCenterVendorInsight]],
    ]
    fetch_customers: Callable[
        [str],
        Iterable[SecurityCenterCustomerInsight]
        | Awaitable[Iterable[SecurityCenterCustomerInsight]],
    ]
    fetch_coverage: Callable[
        [],
        Iterable[IntegrationCoverageRecord]
        | Awaitable[Iterable[IntegrationCoverageRecord]],
    ]
    fetch_findings: Callable[
        [str], Iterable[FindingRecord] | Awaitable[Iterable[FindingRecord]]
    ]
    provider_aliases: Mapping[str, Sequence[str]] | None = None


@dataclass
class RelationsIndex:
    org_id: str
    vendors: list[SecurityCenterVendorInsight]
    customers: list[SecurityCenterCustomerInsight]
    coverage: list[IntegrationCoverageRecord]
    findings: list[FindingRecord]
    provider_aliases: dict[str, list[str]]
    vendor_by_id: dict[str, SecurityCenterVendorInsight]
    customer_by_id: dict[str, SecurityCenterCustomerInsight]
    vendor_provider_keys: dict[str, set[str]]
    customer_provider_keys: dict[str, set[str]]
    findings_by_provider: dict[str, list[FindingRecord]]
    providers_to_vendor_ids: dict[str, set[str]]
    providers_to_customer_ids: dict[str, set[str]]


@dataclass
class VendorExposure:
    vendor: SecurityCenterVendorInsight
    related_integrations: list[IntegrationCoverageRecord]
    coverage_health: list[IntegrationCoverageHealth]
    related_findings: list[FindingRecord]
    dashboard: VendorRiskDashboard


@dataclass
class CustomerEngagement:
    customer: SecurityCenterCustomerInsight
    related_integrations: list[IntegrationCoverageRecord]
    related_findings: list[FindingRecord]
    dashboard: CustomerRiskDashboard


@dataclass
class IntegrationSummary:
    total: int
    degraded: int
    average_coverage_ratio: float | None
    coverage_health: list[IntegrationCoverageHealth]


@dataclass
class FindingsSummary:
    total: int
    by_severity: dict[str, int]
    linked_to_vendors: int
    linked_to_customers: int


@dataclass
class ExposureCollections:
    top_vendors: list[VendorExposure]
    top_customers: list[CustomerEngagement]


@dataclass
class OrgExposureDashboard:
    org_id: str
    vendor_dashboard: VendorRiskDashboard
    customer_dashboard: CustomerRiskDashboard
    integration: IntegrationSummary
    findings: FindingsSummary
    exposures: ExposureCollections
    alerts: list[TrendAlert]


async def build_relations_index(
    org_id: str, context: RelationsContext
) -> RelationsIndex:
    vendors = [
        entry
        for entry in await _resolve(context.fetch_vendors, org_id)
        if isinstance(entry, SecurityCenterVendorInsight)
    ]
    customers = [
        entry
        for entry in await _resolve(context.fetch_customers, org_id)
        if isinstance(entry, SecurityCenterCustomerInsight)
    ]
    coverage = [
        entry
        for entry in await _resolve(context.fetch_coverage)
        if isinstance(entry, IntegrationCoverageRecord)
    ]
    findings = [
        entry
        for entry in await _resolve(context.fetch_findings, org_id)
        if isinstance(entry, FindingRecord)
    ]

    provider_aliases = {
        _normalize(key): [normalized for normalized in map(_normalize, values)]
        for key, values in (context.provider_aliases or {}).items()
    }

    vendor_by_id: dict[str, SecurityCenterVendorInsight] = {}
    customer_by_id: dict[str, SecurityCenterCustomerInsight] = {}
    vendor_provider_keys: dict[str, set[str]] = {}
    customer_provider_keys: dict[str, set[str]] = {}
    findings_by_provider: dict[str, list[FindingRecord]] = {}
    providers_to_vendor_ids: dict[str, set[str]] = {}
    providers_to_customer_ids: dict[str, set[str]] = {}

    for vendor in vendors:
        vendor_by_id[vendor.vendor_id] = vendor
        keys = _derive_vendor_provider_keys(vendor)
        vendor_provider_keys[vendor.vendor_id] = keys
        for key in keys:
            providers_to_vendor_ids.setdefault(key, set()).add(vendor.vendor_id)

    for customer in customers:
        customer_by_id[customer.customer_id] = customer
        keys = _derive_customer_provider_keys(customer)
        customer_provider_keys[customer.customer_id] = keys
        for key in keys:
            providers_to_customer_ids.setdefault(key, set()).add(customer.customer_id)

    for finding in findings:
        key = _normalize(finding.provider)
        findings_by_provider.setdefault(key, []).append(finding)

    return RelationsIndex(
        org_id=org_id,
        vendors=vendors,
        customers=customers,
        coverage=coverage,
        findings=findings,
        provider_aliases=provider_aliases,
        vendor_by_id=vendor_by_id,
        customer_by_id=customer_by_id,
        vendor_provider_keys=vendor_provider_keys,
        customer_provider_keys=customer_provider_keys,
        findings_by_provider=findings_by_provider,
        providers_to_vendor_ids=providers_to_vendor_ids,
        providers_to_customer_ids=providers_to_customer_ids,
    )


async def get_vendor_exposure(
    org_id: str,
    vendor_id: str,
    context: RelationsContext,
    index: RelationsIndex | None = None,
) -> VendorExposure:
    relations = index or await build_relations_index(org_id, context)
    vendor = relations.vendor_by_id.get(vendor_id)
    if vendor is None:
        raise KeyError(f"Vendor {vendor_id} not found in org {org_id}")

    provider_keys = relations.vendor_provider_keys.get(vendor_id, set())
    related_integrations = [
        record
        for record in relations.coverage
        if _has_provider_match(record, provider_keys, relations.provider_aliases)
    ]
    coverage_health = [
        compute_coverage_health(record) for record in related_integrations
    ]
    related_findings = _collect_findings_for_providers(
        provider_keys, relations.findings_by_provider
    )

    dashboard = build_vendor_risk_dashboard([vendor])

    return VendorExposure(
        vendor=vendor,
        related_integrations=related_integrations,
        coverage_health=coverage_health,
        related_findings=related_findings,
        dashboard=dashboard,
    )


async def get_customer_engagement(
    org_id: str,
    customer_id: str,
    context: RelationsContext,
    index: RelationsIndex | None = None,
) -> CustomerEngagement:
    relations = index or await build_relations_index(org_id, context)
    customer = relations.customer_by_id.get(customer_id)
    if customer is None:
        raise KeyError(f"Customer {customer_id} not found in org {org_id}")

    provider_keys = relations.customer_provider_keys.get(customer_id, set())
    related_integrations = [
        record
        for record in relations.coverage
        if _has_provider_match(record, provider_keys, relations.provider_aliases)
    ]
    related_findings = _collect_findings_for_providers(
        provider_keys, relations.findings_by_provider
    )
    dashboard = build_customer_risk_dashboard([customer])

    return CustomerEngagement(
        customer=customer,
        related_integrations=related_integrations,
        related_findings=related_findings,
        dashboard=dashboard,
    )


async def build_org_exposure_dashboard(
    org_id: str,
    context: RelationsContext,
    index: RelationsIndex | None = None,
) -> OrgExposureDashboard:
    relations = index or await build_relations_index(org_id, context)

    vendor_dashboard = build_vendor_risk_dashboard(relations.vendors)
    customer_dashboard = build_customer_risk_dashboard(relations.customers)

    coverage_health = [compute_coverage_health(record) for record in relations.coverage]
    degraded = sum(1 for entry in coverage_health if _normalize(entry.status) != "ok")
    average_coverage_ratio = (
        sum(entry.coverage_ratio or 0.0 for entry in relations.coverage)
        / len(relations.coverage)
        if relations.coverage
        else None
    )

    integration_summary = IntegrationSummary(
        total=len(relations.coverage),
        degraded=degraded,
        average_coverage_ratio=average_coverage_ratio,
        coverage_health=coverage_health,
    )

    by_severity: dict[str, int] = {}
    linked_to_vendors = 0
    linked_to_customers = 0
    for finding in relations.findings:
        severity = _normalize(finding.severity) or "unknown"
        by_severity[severity] = by_severity.get(severity, 0) + 1
        provider_key = _normalize(finding.provider)
        if relations.providers_to_vendor_ids.get(provider_key):
            linked_to_vendors += 1
        if relations.providers_to_customer_ids.get(provider_key):
            linked_to_customers += 1

    findings_summary = FindingsSummary(
        total=len(relations.findings),
        by_severity=by_severity,
        linked_to_vendors=linked_to_vendors,
        linked_to_customers=linked_to_customers,
    )

    top_vendors = sorted(
        relations.vendors,
        key=lambda vendor: vendor.residual_risk_score or 0.0,
        reverse=True,
    )[:3]
    top_customers = sorted(
        relations.customers,
        key=lambda customer: customer.churn_risk_score or 0.0,
        reverse=True,
    )[:3]

    vendor_exposures = [
        await get_vendor_exposure(org_id, vendor.vendor_id, context, relations)
        for vendor in top_vendors
    ]
    customer_engagements = [
        await get_customer_engagement(org_id, customer.customer_id, context, relations)
        for customer in top_customers
    ]

    exposures = ExposureCollections(
        top_vendors=vendor_exposures, top_customers=customer_engagements
    )

    alerts: list[TrendAlert] = []
    for warning in vendor_dashboard.warnings:
        alerts.append(TrendAlert(severity="warning", metric="vendor", message=warning))
    for warning in customer_dashboard.warnings:
        alerts.append(
            TrendAlert(severity="warning", metric="customer", message=warning)
        )
    if degraded:
        severity_level = "critical" if degraded >= 3 else "warning"
        alerts.append(
            TrendAlert(
                severity=severity_level,  # type: ignore[arg-type]
                metric="integration",
                message=f"{degraded} integration(s) reporting degraded coverage",
            )
        )

    return OrgExposureDashboard(
        org_id=org_id,
        vendor_dashboard=vendor_dashboard,
        customer_dashboard=customer_dashboard,
        integration=integration_summary,
        findings=findings_summary,
        exposures=exposures,
        alerts=alerts,
    )


@dataclass
class EntityAnnotationSummary:
    vendors: list[dict[str, Any]]
    customers: list[dict[str, Any]]


@dataclass
class EntityAnnotation:
    event: AgentStreamEvent
    vendors: list[SecurityCenterVendorInsight]
    customers: list[SecurityCenterCustomerInsight]
    summary: EntityAnnotationSummary


def annotate_agent_event(
    event: AgentStreamEvent,
    vendors: Sequence[SecurityCenterVendorInsight],
    customers: Sequence[SecurityCenterCustomerInsight],
) -> EntityAnnotation:
    vendor_by_id = {vendor.vendor_id: vendor for vendor in vendors}
    customer_by_id = {customer.customer_id: customer for customer in customers}

    vendor_matches: list[SecurityCenterVendorInsight] = []
    customer_matches: list[SecurityCenterCustomerInsight] = []

    payload = event.payload or {}

    if event.type == "message":
        metadata = payload.get("metadata")
        if isinstance(metadata, Mapping):
            _collect_matching_entities(
                metadata, vendor_by_id, customer_by_id, vendor_matches, customer_matches
            )
    elif event.type == "tool":
        input_data = payload.get("input_data") or payload.get("inputData")
        if isinstance(input_data, Mapping):
            _collect_matching_entities(
                input_data,
                vendor_by_id,
                customer_by_id,
                vendor_matches,
                customer_matches,
            )

    if isinstance(payload, Mapping):
        _collect_matching_entities(
            payload, vendor_by_id, customer_by_id, vendor_matches, customer_matches
        )

    summary = EntityAnnotationSummary(
        vendors=[
            {
                "vendor_id": vendor.vendor_id,
                "name": vendor.name,
                "risk_level": vendor.risk_level,
                "residual_risk_score": vendor.residual_risk_score,
            }
            for vendor in vendor_matches
        ],
        customers=[
            {
                "customer_id": customer.customer_id,
                "name": customer.name,
                "health_band": customer.health_band,
                "churn_risk_score": customer.churn_risk_score,
            }
            for customer in customer_matches
        ],
    )

    return EntityAnnotation(
        event=event, vendors=vendor_matches, customers=customer_matches, summary=summary
    )


def annotate_agent_events(
    events: Sequence[AgentStreamEvent],
    vendors: Sequence[SecurityCenterVendorInsight],
    customers: Sequence[SecurityCenterCustomerInsight],
) -> list[EntityAnnotation]:
    return [annotate_agent_event(event, vendors, customers) for event in events]


async def _maybe_call(fn: Optional[ConsumerFn], *args: Any, **kwargs: Any) -> None:
    if fn is None:
        return
    result = fn(*args, **kwargs)
    if inspect.isawaitable(result):
        await result


def create_entity_aware_consumers(
    vendors: Sequence[SecurityCenterVendorInsight],
    customers: Sequence[SecurityCenterCustomerInsight],
    consumers: AgentStreamConsumers | None = None,
    on_entity: Optional[Callable[[EntityAnnotation], Awaitable[None] | None]] = None,
) -> AgentStreamConsumers:
    base = consumers or AgentStreamConsumers()

    async def dispatch(event: AgentStreamEvent) -> None:
        if on_entity is None:
            return
        annotation = annotate_agent_event(event, vendors, customers)
        await _maybe_call(on_entity, annotation)

    async def wrapped_message(message: AgentMessage, event: AgentStreamEvent) -> None:
        await _maybe_call(base.on_message, message, event)
        await dispatch(event)

    async def wrapped_tool(delta: ToolCallDelta, event: AgentStreamEvent) -> None:
        await _maybe_call(base.on_tool, delta, event)
        await dispatch(event)

    async def wrapped_status(update: CompletionUpdate, event: AgentStreamEvent) -> None:
        await _maybe_call(base.on_status, update, event)
        await dispatch(event)

    async def wrapped_heartbeat(event: AgentStreamEvent) -> None:
        await _maybe_call(base.on_heartbeat, event)
        await dispatch(event)

    async def wrapped_unknown(event: AgentStreamEvent) -> None:
        await _maybe_call(base.on_unknown, event)
        await dispatch(event)

    return AgentStreamConsumers(
        on_message=wrapped_message,
        on_tool=wrapped_tool,
        on_status=wrapped_status,
        on_heartbeat=wrapped_heartbeat,
        on_unknown=wrapped_unknown,
    )


def _collect_matching_entities(
    payload: Mapping[str, Any],
    vendor_by_id: Mapping[str, SecurityCenterVendorInsight],
    customer_by_id: Mapping[str, SecurityCenterCustomerInsight],
    vendor_matches: list[SecurityCenterVendorInsight],
    customer_matches: list[SecurityCenterCustomerInsight],
) -> None:
    vendor_id = payload.get("vendorId") or payload.get("vendor_id")
    if isinstance(vendor_id, str):
        match = vendor_by_id.get(vendor_id)
        if match and match not in vendor_matches:
            vendor_matches.append(match)

    customer_id = payload.get("customerId") or payload.get("customer_id")
    if isinstance(customer_id, str):
        customer_match = customer_by_id.get(customer_id)
        if customer_match and customer_match not in customer_matches:
            customer_matches.append(customer_match)

    for value in payload.values():
        if isinstance(value, Mapping):
            _collect_matching_entities(
                value, vendor_by_id, customer_by_id, vendor_matches, customer_matches
            )
        elif isinstance(value, Sequence) and not isinstance(
            value, (str, bytes, bytearray)
        ):
            for item in value:
                if isinstance(item, Mapping):
                    _collect_matching_entities(
                        item,
                        vendor_by_id,
                        customer_by_id,
                        vendor_matches,
                        customer_matches,
                    )


def _collect_findings_for_providers(
    provider_keys: set[str],
    findings_by_provider: Mapping[str, Sequence[FindingRecord]],
) -> list[FindingRecord]:
    results: list[FindingRecord] = []
    seen: set[UUID] = set()
    for key in provider_keys:
        findings = findings_by_provider.get(key)
        if not findings:
            continue
        for finding in findings:
            if finding.finding_id in seen:
                continue
            seen.add(finding.finding_id)
            results.append(finding)
    return results


def _derive_vendor_provider_keys(vendor: SecurityCenterVendorInsight) -> set[str]:
    keys: set[str] = {_normalize(vendor.category)}
    metadata = vendor.metadata or {}
    integration = (
        metadata.get("integration") or metadata.get("integration_summary") or {}
    )

    integration_type = integration.get("integration_type") or integration.get(
        "integrationType"
    )
    if isinstance(integration_type, str):
        keys.add(_normalize(integration_type))

    for method in _as_list(
        integration.get("authentication_methods")
        or integration.get("authenticationMethods")
    ):
        if isinstance(method, str):
            keys.add(_normalize(method))

    for access in _as_list(
        integration.get("network_access") or integration.get("networkAccess")
    ):
        if isinstance(access, str):
            keys.add(_normalize(access))

    raw_metadata = vendor.raw_metadata or {}
    tags = raw_metadata.get("tags")
    if isinstance(tags, Mapping):
        for value in tags.values():
            if isinstance(value, str):
                keys.add(_normalize(value))

    return {key for key in keys if key}


def _derive_customer_provider_keys(customer: SecurityCenterCustomerInsight) -> set[str]:
    keys: set[str] = {_normalize(customer.segment)}
    metadata = customer.metadata or {}

    programs = metadata.get("success_programs") or metadata.get("successPrograms")
    for program in _as_list(programs):
        if isinstance(program, str):
            keys.add(_normalize(program))

    adoption = metadata.get("adoption") or {}
    metrics = adoption.get("metrics") or {}
    if isinstance(metrics, Mapping):
        for metric in metrics.keys():
            keys.add(_normalize(str(metric)))

    engagement = metadata.get("engagement") or {}
    tickets = engagement.get("open_support_tickets") or engagement.get(
        "openSupportTickets"
    )
    if isinstance(tickets, int) and tickets > 0:
        keys.add("support")

    raw_metadata = customer.raw_metadata or {}
    tags = raw_metadata.get("tags")
    if isinstance(tags, Mapping):
        for value in tags.values():
            if isinstance(value, str):
                keys.add(_normalize(value))

    return {key for key in keys if key}


def _has_provider_match(
    record: IntegrationCoverageRecord,
    provider_keys: set[str],
    provider_aliases: Mapping[str, Sequence[str]],
) -> bool:
    if not provider_keys:
        return False

    normalized: set[str] = {_normalize(record.integration)}
    for provider in record.providers:
        normalized.add(_normalize(provider))
    for alias in provider_aliases.get(_normalize(record.integration), []):
        normalized.add(_normalize(alias))

    return any(key in normalized for key in provider_keys)


__all__ = [
    "RelationsContext",
    "RelationsIndex",
    "IntegrationCoverageHealth",
    "VendorExposure",
    "CustomerEngagement",
    "IntegrationSummary",
    "FindingsSummary",
    "ExposureCollections",
    "OrgExposureDashboard",
    "build_relations_index",
    "compute_coverage_health",
    "get_vendor_exposure",
    "get_customer_engagement",
    "build_org_exposure_dashboard",
    "EntityAnnotationSummary",
    "EntityAnnotation",
    "annotate_agent_event",
    "annotate_agent_events",
    "create_entity_aware_consumers",
]
