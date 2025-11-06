"""Monitoring alerts and governance escalation helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Iterable, List, Optional

from .models import SecurityCenterCustomerInsight, SecurityCenterVendorInsight


@dataclass(slots=True)
class MonitoringEvent:
    id: str
    entity_type: str
    entity_id: str
    event_type: str
    status: str
    occurred_at: datetime
    description: str
    severity: str


@dataclass(slots=True)
class GovernanceAlert:
    id: str
    entity_type: str
    entity_id: str
    title: str
    detail: str
    severity: str
    requires_review: bool
    escalation_target: str


@dataclass(slots=True)
class MonitoringContext:
    vendor_resolver: Callable[[str], Optional[SecurityCenterVendorInsight]] | None = None
    customer_resolver: Callable[[str], Optional[SecurityCenterCustomerInsight]] | None = None
    escalation_resolver: Callable[
        [SecurityCenterVendorInsight | SecurityCenterCustomerInsight, MonitoringEvent],
        Optional[str],
    ] | None = None


def evaluate_monitoring_events(
    events: Iterable[MonitoringEvent],
    context: MonitoringContext,
) -> List[GovernanceAlert]:
    alerts: List[GovernanceAlert] = []
    for event in events:
        entity = _resolve_entity(event, context)
        if entity is None:
            continue

        if event.event_type == "incident":
            alerts.append(
                _build_alert(
                    event,
                    entity,
                    "Incident reported",
                    "critical",
                    requires_review=True,
                    fallback="grc-committee",
                    context=context,
                )
            )
        elif event.event_type == "audit" and event.status != "resolved":
            severity = "critical" if event.severity == "critical" else "warning"
            alerts.append(
                _build_alert(
                    event,
                    entity,
                    "Audit finding outstanding",
                    severity,
                    requires_review=True,
                    fallback="audit-team",
                    context=context,
                )
            )
        elif event.event_type == "questionnaire" and event.status == "open":
            alerts.append(
                _build_alert(
                    event,
                    entity,
                    "Questionnaire pending",
                    "warning",
                    requires_review=False,
                    fallback="compliance-team",
                    context=context,
                )
            )
        elif event.event_type == "review" and _is_review_overdue(event):
            alerts.append(
                _build_alert(
                    event,
                    entity,
                    "Periodic review overdue",
                    "warning",
                    requires_review=True,
                    fallback="policy-owner",
                    context=context,
                )
            )
        else:
            alerts.append(
                _build_alert(
                    event,
                    entity,
                    "Monitoring event",
                    event.severity,
                    requires_review=event.severity != "info",
                    fallback="governance",
                    context=context,
                )
            )

    return alerts


def _resolve_entity(
    event: MonitoringEvent,
    context: MonitoringContext,
) -> SecurityCenterVendorInsight | SecurityCenterCustomerInsight | None:
    if event.entity_type == "vendor":
        resolver = context.vendor_resolver
        return resolver(event.entity_id) if resolver else None
    resolver = context.customer_resolver
    return resolver(event.entity_id) if resolver else None


def _build_alert(
    event: MonitoringEvent,
    entity: SecurityCenterVendorInsight | SecurityCenterCustomerInsight,
    prefix: str,
    severity: str,
    *,
    requires_review: bool,
    fallback: str,
    context: MonitoringContext,
) -> GovernanceAlert:
    title = f"{prefix} for {entity.name}"
    escalation_target = _resolve_escalation(context, entity, event, fallback)
    return GovernanceAlert(
        id=f"alert-{event.id}",
        entity_type=event.entity_type,
        entity_id=event.entity_id,
        title=title,
        detail=event.description,
        severity=severity,
        requires_review=requires_review,
        escalation_target=escalation_target,
    )


def _resolve_escalation(
    context: MonitoringContext,
    entity: SecurityCenterVendorInsight | SecurityCenterCustomerInsight,
    event: MonitoringEvent,
    fallback: str,
) -> str:
    if context.escalation_resolver:
        target = context.escalation_resolver(entity, event)
        if target:
            return target
    return fallback


def _is_review_overdue(event: MonitoringEvent) -> bool:
    return datetime.utcnow() - event.occurred_at > timedelta(days=14)
