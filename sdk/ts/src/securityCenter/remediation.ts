import type { SecurityCenterCustomerInsight, SecurityCenterVendorInsight } from "../clients/securityCenter.js";

export type RemediationSeverity = "low" | "medium" | "high" | "critical";

export interface RemediationAction {
  id: string;
  entityType: "vendor" | "customer";
  entityId: string;
  title: string;
  description: string;
  owner: string;
  dueDate: Date | null;
  severity: RemediationSeverity;
  attestationRequired: boolean;
  evidenceIds: string[];
}

export interface RemediationQueue {
  actions: RemediationAction[];
  generatedAt: Date;
}

export interface RemediationPolicy {
  riskThreshold: number;
  overdueReviewDays?: number;
  attestationWindowDays?: number;
  ownerResolver?: (entity: SecurityCenterVendorInsight | SecurityCenterCustomerInsight) => string;
}

export interface GenerateRemediationOptions {
  vendorPolicy: RemediationPolicy;
  customerPolicy: RemediationPolicy;
}

export function generateRemediationActions(
  vendors: SecurityCenterVendorInsight[],
  customers: SecurityCenterCustomerInsight[],
  options: GenerateRemediationOptions,
): RemediationQueue {
  const actions: RemediationAction[] = [];
  const now = new Date();

  for (const vendor of vendors) {
    const riskScore = vendor.residualRiskScore ?? vendor.inherentRiskScore ?? 0;
    const overdueDays = computeOverdueDays(vendor.nextReviewDue, now);
    if (riskScore < options.vendorPolicy.riskThreshold && overdueDays <= (options.vendorPolicy.overdueReviewDays ?? 0)) continue;

    actions.push({
      id: `remediate-vendor-${vendor.vendorId}`,
      entityType: "vendor",
      entityId: vendor.vendorId,
      title: `Mitigate vendor risk: ${vendor.name}`,
      description: buildVendorDescription(vendor, riskScore, overdueDays),
      owner: resolveOwner(vendor, options.vendorPolicy.ownerResolver, "sec-ops"),
      dueDate: computeDueDate(now, options.vendorPolicy.attestationWindowDays ?? 14),
      severity: classifySeverity(riskScore),
      attestationRequired: true,
      evidenceIds: collectVendorEvidence(vendor),
    });
  }

  for (const customer of customers) {
    const riskScore = customer.churnRiskScore ?? customer.healthScore ?? 0;
    if (riskScore < options.customerPolicy.riskThreshold) continue;

    actions.push({
      id: `remediate-customer-${customer.customerId}`,
      entityType: "customer",
      entityId: customer.customerId,
      title: `Engage customer at risk: ${customer.name}`,
      description: buildCustomerDescription(customer, riskScore),
      owner: resolveOwner(customer, options.customerPolicy.ownerResolver, customer.accountManager ?? "customer-success"),
      dueDate: computeDueDate(now, options.customerPolicy.attestationWindowDays ?? 10),
      severity: classifySeverity(riskScore),
      attestationRequired: false,
      evidenceIds: collectCustomerEvidence(customer),
    });
  }

  return { actions, generatedAt: now } satisfies RemediationQueue;
}

function computeOverdueDays(nextReviewDue: Date | null | undefined, now: Date): number {
  if (!nextReviewDue) return 0;
  const diff = now.getTime() - nextReviewDue.getTime();
  if (diff <= 0) return 0;
  return Math.round(diff / (1000 * 60 * 60 * 24));
}

function computeDueDate(now: Date, windowDays: number): Date {
  const due = new Date(now);
  due.setDate(due.getDate() + windowDays);
  return due;
}

function classifySeverity(score: number): RemediationSeverity {
  if (score >= 0.8) return "critical";
  if (score >= 0.6) return "high";
  if (score >= 0.4) return "medium";
  return "low";
}

function resolveOwner(
  entity: SecurityCenterVendorInsight | SecurityCenterCustomerInsight,
  resolver: RemediationPolicy["ownerResolver"],
  fallback: string,
): string {
  const owner = resolver?.(entity);
  return owner ?? fallback;
}

function buildVendorDescription(
  vendor: SecurityCenterVendorInsight,
  riskScore: number,
  overdueDays: number,
): string {
  const parts = [`Residual risk score: ${riskScore.toFixed(2)}`];
  if (overdueDays > 0) parts.push(`Review overdue by ${overdueDays} day(s)`);
  if (vendor.metadata?.complianceSummary?.certifications?.length === 0)
    parts.push("No certifications on file");
  if (vendor.metadata?.complianceSummary?.penetrationTestResultsPresent === false)
    parts.push("Missing penetration test results");
  return parts.join("; ");
}

function buildCustomerDescription(customer: SecurityCenterCustomerInsight, riskScore: number): string {
  const parts = [`Churn risk score: ${riskScore.toFixed(2)}`];
  const engagement = customer.metadata?.engagement;
  if ((engagement?.openSupportTickets ?? 0) > 0)
    parts.push(`${engagement!.openSupportTickets} open support ticket(s)`);
  const adoptionMetrics = customer.metadata?.adoption?.metrics;
  if (adoptionMetrics)
    parts.push(
      `Adoption metrics: ${Object.entries(adoptionMetrics)
        .map(([key, value]) => `${key}=${value}`)
        .join(", ")}`,
    );
  return parts.join("; ");
}

function collectVendorEvidence(vendor: SecurityCenterVendorInsight): string[] {
  const evidenceIds: string[] = [];
  if (vendor.metadata?.evidence?.id) evidenceIds.push(vendor.metadata.evidence.id);
  if (vendor.metadata?.riskSummary?.monitoring?.accessMonitoringEnabled === false) evidenceIds.push("access-monitoring-gap");
  if (vendor.metadata?.complianceSummary?.securityQuestionnaireCompleted === false)
    evidenceIds.push("missing-security-questionnaire");
  return evidenceIds;
}

function collectCustomerEvidence(customer: SecurityCenterCustomerInsight): string[] {
  const evidenceIds: string[] = [];
  if (customer.metadata?.evidence?.id) evidenceIds.push(customer.metadata.evidence.id);
  const engagement = customer.metadata?.engagement;
  if (engagement?.openSupportTickets)
    evidenceIds.push(`support-tickets-${engagement.openSupportTickets}`);
  return evidenceIds;
}
