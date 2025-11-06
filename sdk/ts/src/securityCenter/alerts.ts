import type {
  SecurityCenterCustomerInsight,
  SecurityCenterVendorInsight,
} from "../clients/securityCenter.js";

export interface MonitoringEvent {
  id: string;
  entityType: "vendor" | "customer";
  entityId: string;
  eventType: "questionnaire" | "audit" | "incident" | "review";
  status: "open" | "resolved" | "acknowledged";
  occurredAt: Date;
  description: string;
  severity: "info" | "warning" | "critical";
}

export interface GovernanceAlert {
  id: string;
  entityType: "vendor" | "customer";
  entityId: string;
  title: string;
  detail: string;
  severity: "info" | "warning" | "critical";
  requiresReview: boolean;
  escalationTarget: string;
}

export interface MonitoringContext {
  vendorResolver?: (id: string) => SecurityCenterVendorInsight | undefined;
  customerResolver?: (id: string) => SecurityCenterCustomerInsight | undefined;
  escalationResolver?: (
    entity: SecurityCenterVendorInsight | SecurityCenterCustomerInsight,
    event: MonitoringEvent,
  ) => string;
}

export function evaluateMonitoringEvents(
  events: MonitoringEvent[],
  context: MonitoringContext,
): GovernanceAlert[] {
  const alerts: GovernanceAlert[] = [];

  for (const event of events) {
    const entity = resolveEntity(event, context);
    if (!entity) continue;

    switch (event.eventType) {
      case "incident":
        alerts.push(buildIncidentAlert(event, entity, context));
        break;
      case "audit":
        if (event.status !== "resolved") alerts.push(buildAuditAlert(event, entity, context));
        break;
      case "questionnaire":
        if (event.status === "open") alerts.push(buildQuestionnaireAlert(event, entity, context));
        break;
      case "review":
        if (isReviewOverdue(event)) alerts.push(buildReviewAlert(event, entity, context));
        break;
      default:
        alerts.push(buildGenericAlert(event, entity, context));
    }
  }

  return alerts;
}

function resolveEntity(
  event: MonitoringEvent,
  context: MonitoringContext,
): SecurityCenterVendorInsight | SecurityCenterCustomerInsight | undefined {
  if (event.entityType === "vendor") return context.vendorResolver?.(event.entityId);
  return context.customerResolver?.(event.entityId);
}

function buildIncidentAlert(
  event: MonitoringEvent,
  entity: SecurityCenterVendorInsight | SecurityCenterCustomerInsight,
  context: MonitoringContext,
): GovernanceAlert {
  return {
    id: `alert-${event.id}`,
    entityType: event.entityType,
    entityId: event.entityId,
    title: `Incident reported for ${entity.name}`,
    detail: event.description,
    severity: "critical",
    requiresReview: true,
    escalationTarget: resolveEscalation(entity, event, context, "grc-committee"),
  } satisfies GovernanceAlert;
}

function buildAuditAlert(
  event: MonitoringEvent,
  entity: SecurityCenterVendorInsight | SecurityCenterCustomerInsight,
  context: MonitoringContext,
): GovernanceAlert {
  return {
    id: `alert-${event.id}`,
    entityType: event.entityType,
    entityId: event.entityId,
    title: `Audit finding outstanding for ${entity.name}`,
    detail: event.description,
    severity: event.severity === "critical" ? "critical" : "warning",
    requiresReview: true,
    escalationTarget: resolveEscalation(entity, event, context, "audit-team"),
  } satisfies GovernanceAlert;
}

function buildQuestionnaireAlert(
  event: MonitoringEvent,
  entity: SecurityCenterVendorInsight | SecurityCenterCustomerInsight,
  context: MonitoringContext,
): GovernanceAlert {
  return {
    id: `alert-${event.id}`,
    entityType: event.entityType,
    entityId: event.entityId,
    title: `Questionnaire pending for ${entity.name}`,
    detail: event.description,
    severity: "warning",
    requiresReview: false,
    escalationTarget: resolveEscalation(entity, event, context, "compliance-team"),
  } satisfies GovernanceAlert;
}

function buildReviewAlert(
  event: MonitoringEvent,
  entity: SecurityCenterVendorInsight | SecurityCenterCustomerInsight,
  context: MonitoringContext,
): GovernanceAlert {
  return {
    id: `alert-${event.id}`,
    entityType: event.entityType,
    entityId: event.entityId,
    title: `Periodic review overdue for ${entity.name}`,
    detail: event.description,
    severity: "warning",
    requiresReview: true,
    escalationTarget: resolveEscalation(entity, event, context, "policy-owner"),
  } satisfies GovernanceAlert;
}

function buildGenericAlert(
  event: MonitoringEvent,
  entity: SecurityCenterVendorInsight | SecurityCenterCustomerInsight,
  context: MonitoringContext,
): GovernanceAlert {
  return {
    id: `alert-${event.id}`,
    entityType: event.entityType,
    entityId: event.entityId,
    title: `Monitoring event for ${entity.name}`,
    detail: event.description,
    severity: event.severity,
    requiresReview: event.severity !== "info",
    escalationTarget: resolveEscalation(entity, event, context, "governance"),
  } satisfies GovernanceAlert;
}

function resolveEscalation(
  entity: SecurityCenterVendorInsight | SecurityCenterCustomerInsight,
  event: MonitoringEvent,
  context: MonitoringContext,
  fallback: string,
): string {
  const target = context.escalationResolver?.(entity, event);
  return target ?? fallback;
}

function isReviewOverdue(event: MonitoringEvent): boolean {
  const now = Date.now();
  return now - event.occurredAt.getTime() > 14 * 24 * 60 * 60 * 1000;
}
