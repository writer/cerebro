import {
  buildCustomerRiskDashboard,
  buildVendorRiskDashboard,
  type CustomerRiskDashboard,
  type TrendAlert,
  type VendorRiskDashboard,
} from "./analytics.js";
import type {
  SecurityCenterClient,
  SecurityCenterCustomerInsight,
  SecurityCenterVendorInsight,
} from "../clients/securityCenter.js";
import type { IntegrationsClient } from "../clients/integrations.js";
import type { FindingsClient } from "../clients/findings.js";
import type {
  IntegrationCoverageHealth,
  IntegrationCoverageRecord,
  FindingRecord,
} from "../types.js";
import { computeCoverageHealth } from "../integrations/metrics.js";
import type {
  AgentMessage,
  AgentStreamConsumers,
  AgentStreamEvent,
  CompletionUpdate,
  ToolCallDelta,
} from "../agents/streaming.js";

export interface ExposureContext {
  securityCenter: SecurityCenterClient;
  integrations: IntegrationsClient;
  findings: FindingsClient;
  providerAliases?: Record<string, string[]>;
}

export interface RelationsIndex {
  orgId: string;
  vendors: SecurityCenterVendorInsight[];
  customers: SecurityCenterCustomerInsight[];
  coverage: IntegrationCoverageRecord[];
  findings: FindingRecord[];
  providerAliases: Record<string, string[]>;
  vendorById: Map<string, SecurityCenterVendorInsight>;
  customerById: Map<string, SecurityCenterCustomerInsight>;
  vendorProviderKeys: Map<string, Set<string>>;
  customerProviderKeys: Map<string, Set<string>>;
  findingsByProvider: Map<string, FindingRecord[]>;
  providersToVendorIds: Map<string, Set<string>>;
  providersToCustomerIds: Map<string, Set<string>>;
}

export interface VendorExposure {
  vendor: SecurityCenterVendorInsight;
  relatedIntegrations: IntegrationCoverageRecord[];
  coverageHealth: IntegrationCoverageHealth[];
  relatedFindings: FindingRecord[];
  dashboard: VendorRiskDashboard;
}

export interface CustomerEngagement {
  customer: SecurityCenterCustomerInsight;
  relatedIntegrations: IntegrationCoverageRecord[];
  relatedFindings: FindingRecord[];
  dashboard: CustomerRiskDashboard;
}

export interface OrgExposureDashboard {
  orgId: string;
  vendorDashboard: VendorRiskDashboard;
  customerDashboard: CustomerRiskDashboard;
  integration: {
    total: number;
    degraded: number;
    averageCoverageRatio: number | null;
    coverageHealth: IntegrationCoverageHealth[];
  };
  findings: {
    total: number;
    bySeverity: Record<string, number>;
    linkedToVendors: number;
    linkedToCustomers: number;
  };
  exposures: {
    topVendors: VendorExposure[];
    topCustomers: CustomerEngagement[];
  };
  alerts: TrendAlert[];
}

export interface EntityAnnotationSummary {
  vendors: Array<{
    vendorId: string;
    name: string;
    riskLevel: string;
    residualRiskScore: number | null;
  }>;
  customers: Array<{
    customerId: string;
    name: string;
    healthBand: string;
    churnRiskScore: number | null;
  }>;
}

export interface EntityAnnotation {
  event: AgentStreamEvent;
  vendors: SecurityCenterVendorInsight[];
  customers: SecurityCenterCustomerInsight[];
  summary: EntityAnnotationSummary;
}

export async function buildRelationsIndex(orgId: string, context: ExposureContext): Promise<RelationsIndex> {
  const [vendors, customers, coverage, findings] = await Promise.all([
    context.securityCenter.iterateVendors(orgId),
    context.securityCenter.iterateCustomers(orgId),
    context.integrations.getCoverage(),
    context.findings.list({ orgId }),
  ]);

  const providerAliases = context.providerAliases ?? {};
  const vendorById = new Map<string, SecurityCenterVendorInsight>();
  const customerById = new Map<string, SecurityCenterCustomerInsight>();
  const vendorProviderKeys = new Map<string, Set<string>>();
  const customerProviderKeys = new Map<string, Set<string>>();
  const findingsByProvider = new Map<string, FindingRecord[]>();
  const providersToVendorIds = new Map<string, Set<string>>();
  const providersToCustomerIds = new Map<string, Set<string>>();

  for (const vendor of vendors) {
    vendorById.set(vendor.vendorId, vendor);
    const keys = deriveVendorProviderKeys(vendor);
    vendorProviderKeys.set(vendor.vendorId, keys);
    for (const key of keys) {
      if (!providersToVendorIds.has(key)) providersToVendorIds.set(key, new Set());
      providersToVendorIds.get(key)!.add(vendor.vendorId);
    }
  }

  for (const customer of customers) {
    customerById.set(customer.customerId, customer);
    const keys = deriveCustomerProviderKeys(customer);
    customerProviderKeys.set(customer.customerId, keys);
    for (const key of keys) {
      if (!providersToCustomerIds.has(key)) providersToCustomerIds.set(key, new Set());
      providersToCustomerIds.get(key)!.add(customer.customerId);
    }
  }

  for (const finding of findings) {
    const key = normalize(finding.provider);
    if (!findingsByProvider.has(key)) findingsByProvider.set(key, []);
    findingsByProvider.get(key)!.push(finding);
  }

  return {
    orgId,
    vendors,
    customers,
    coverage,
    findings,
    providerAliases,
    vendorById,
    customerById,
    vendorProviderKeys,
    customerProviderKeys,
    findingsByProvider,
    providersToVendorIds,
    providersToCustomerIds,
  } satisfies RelationsIndex;
}

export async function getVendorExposure(
  orgId: string,
  vendorId: string,
  context: ExposureContext,
  index?: RelationsIndex,
): Promise<VendorExposure> {
  const relations = index ?? (await buildRelationsIndex(orgId, context));
  const vendor = relations.vendorById.get(vendorId);
  if (!vendor) {
    throw new Error(`Vendor ${vendorId} not found in org ${orgId}`);
  }

  const providerKeys = relations.vendorProviderKeys.get(vendorId) ?? new Set<string>();
  const relatedIntegrations = relations.coverage.filter((record) =>
    hasProviderMatch(record, providerKeys, relations.providerAliases),
  );
  const coverageHealth = relatedIntegrations.map(computeCoverageHealth);
  const relatedFindings = collectFindingsForProviders(providerKeys, relations.findingsByProvider);

  return {
    vendor,
    relatedIntegrations,
    coverageHealth,
    relatedFindings,
    dashboard: buildVendorRiskDashboard([vendor]),
  } satisfies VendorExposure;
}

export async function getCustomerEngagement(
  orgId: string,
  customerId: string,
  context: ExposureContext,
  index?: RelationsIndex,
): Promise<CustomerEngagement> {
  const relations = index ?? (await buildRelationsIndex(orgId, context));
  const customer = relations.customerById.get(customerId);
  if (!customer) {
    throw new Error(`Customer ${customerId} not found in org ${orgId}`);
  }

  const providerKeys = relations.customerProviderKeys.get(customerId) ?? new Set<string>();
  const relatedIntegrations = relations.coverage.filter((record) =>
    hasProviderMatch(record, providerKeys, relations.providerAliases),
  );
  const relatedFindings = collectFindingsForProviders(providerKeys, relations.findingsByProvider);

  return {
    customer,
    relatedIntegrations,
    relatedFindings,
    dashboard: buildCustomerRiskDashboard([customer]),
  } satisfies CustomerEngagement;
}

export async function buildOrgExposureDashboard(
  orgId: string,
  context: ExposureContext,
  index?: RelationsIndex,
): Promise<OrgExposureDashboard> {
  const relations = index ?? (await buildRelationsIndex(orgId, context));
  const vendorDashboard = buildVendorRiskDashboard(relations.vendors);
  const customerDashboard = buildCustomerRiskDashboard(relations.customers);

  const coverageHealth = relations.coverage.map(computeCoverageHealth);
  const degraded = coverageHealth.filter((entry) => entry.status !== "ok").length;
  const averageCoverageRatio = relations.coverage.length
    ? relations.coverage.reduce((total, record) => total + (record.coverageRatio ?? 0), 0) /
      relations.coverage.length
    : null;

  const bySeverity: Record<string, number> = {};
  let linkedToVendors = 0;
  let linkedToCustomers = 0;
  for (const finding of relations.findings) {
    const severity = (finding.severity ?? "unknown").toLowerCase();
    bySeverity[severity] = (bySeverity[severity] ?? 0) + 1;
    const key = normalize(finding.provider);
    if ((relations.providersToVendorIds.get(key)?.size ?? 0) > 0) linkedToVendors += 1;
    if ((relations.providersToCustomerIds.get(key)?.size ?? 0) > 0) linkedToCustomers += 1;
  }

  const topVendors = [...relations.vendors]
    .sort((a, b) => (b.residualRiskScore ?? 0) - (a.residualRiskScore ?? 0))
    .slice(0, 3);
  const topCustomers = [...relations.customers]
    .sort((a, b) => (b.churnRiskScore ?? 0) - (a.churnRiskScore ?? 0))
    .slice(0, 3);

  const vendorExposures = await Promise.all(
    topVendors.map((vendor) => getVendorExposure(orgId, vendor.vendorId, context, relations)),
  );
  const customerEngagements = await Promise.all(
    topCustomers.map((customer) => getCustomerEngagement(orgId, customer.customerId, context, relations)),
  );

  const alerts: TrendAlert[] = [];
  for (const warning of vendorDashboard.warnings ?? []) {
    alerts.push({ severity: "warning", metric: "vendor", message: warning });
  }
  for (const warning of customerDashboard.warnings ?? []) {
    alerts.push({ severity: "warning", metric: "customer", message: warning });
  }
  if (degraded > 0) {
    alerts.push({
      severity: degraded >= 3 ? "critical" : "warning",
      metric: "integration",
      message: `${degraded} integration(s) reporting degraded coverage`,
    });
  }

  return {
    orgId,
    vendorDashboard,
    customerDashboard,
    integration: {
      total: relations.coverage.length,
      degraded,
      averageCoverageRatio,
      coverageHealth,
    },
    findings: {
      total: relations.findings.length,
      bySeverity,
      linkedToVendors,
      linkedToCustomers,
    },
    exposures: {
      topVendors: vendorExposures,
      topCustomers: customerEngagements,
    },
    alerts,
  } satisfies OrgExposureDashboard;
}

export function annotateAgentEvent(
  event: AgentStreamEvent,
  vendors: SecurityCenterVendorInsight[],
  customers: SecurityCenterCustomerInsight[],
): EntityAnnotation {
  const vendorMatches: SecurityCenterVendorInsight[] = [];
  const customerMatches: SecurityCenterCustomerInsight[] = [];

  if (event.type === "message" && event.payload.metadata) {
    const metadata = event.payload.metadata as Record<string, unknown>;
    const vendorId = metadata.vendorId ?? metadata.vendor_id;
    if (typeof vendorId === "string") {
      const match = vendors.find((entry) => entry.vendorId === vendorId);
      if (match) vendorMatches.push(match);
    }
    const customerId = metadata.customerId ?? metadata.customer_id;
    if (typeof customerId === "string") {
      const match = customers.find((entry) => entry.customerId === customerId);
      if (match) customerMatches.push(match);
    }
  }

  if (event.type === "tool" && event.payload.inputData) {
    const input = event.payload.inputData as Record<string, unknown>;
    collectMatchingEntities(input, vendors, customers, vendorMatches, customerMatches);
  }

  const summary: EntityAnnotationSummary = {
    vendors: vendorMatches.map((vendor) => ({
      vendorId: vendor.vendorId,
      name: vendor.name,
      riskLevel: vendor.riskLevel,
      residualRiskScore: vendor.residualRiskScore ?? null,
    })),
    customers: customerMatches.map((customer) => ({
      customerId: customer.customerId,
      name: customer.name,
      healthBand: customer.healthBand,
      churnRiskScore: customer.churnRiskScore ?? null,
    })),
  };

  return { event, vendors: vendorMatches, customers: customerMatches, summary } satisfies EntityAnnotation;
}

export function annotateAgentEvents(
  events: AgentStreamEvent[],
  vendors: SecurityCenterVendorInsight[],
  customers: SecurityCenterCustomerInsight[],
): EntityAnnotation[] {
  return events.map((event) => annotateAgentEvent(event, vendors, customers));
}

export function createEntityAwareConsumers(
  vendors: SecurityCenterVendorInsight[],
  customers: SecurityCenterCustomerInsight[],
  consumers: AgentStreamConsumers = {},
  onEntity?: (annotation: EntityAnnotation) => Promise<void> | void,
): AgentStreamConsumers {
  const dispatch = async (event: AgentStreamEvent) => {
    const annotation = annotateAgentEvent(event, vendors, customers);
    await onEntity?.(annotation);
  };

  return {
    ...consumers,
    async onMessage(message: AgentMessage, event) {
      await consumers.onMessage?.(message, event);
      await dispatch(event);
    },
    async onTool(delta: ToolCallDelta, event) {
      await consumers.onTool?.(delta, event);
      await dispatch(event);
    },
    async onStatus(update: CompletionUpdate, event) {
      await consumers.onStatus?.(update, event);
      await dispatch(event);
    },
    async onHeartbeat(event) {
      await consumers.onHeartbeat?.(event);
      await dispatch(event);
    },
    async onUnknown(event) {
      await consumers.onUnknown?.(event);
      await dispatch(event);
    },
  } satisfies AgentStreamConsumers;
}

function collectMatchingEntities(
  payload: Record<string, unknown>,
  vendors: SecurityCenterVendorInsight[],
  customers: SecurityCenterCustomerInsight[],
  vendorMatches: SecurityCenterVendorInsight[],
  customerMatches: SecurityCenterCustomerInsight[],
) {
  const vendorId = payload.vendorId ?? payload.vendor_id;
  if (typeof vendorId === "string") {
    const match = vendors.find((entry) => entry.vendorId === vendorId);
    if (match && !vendorMatches.includes(match)) vendorMatches.push(match);
  }

  const customerId = payload.customerId ?? payload.customer_id;
  if (typeof customerId === "string") {
    const match = customers.find((entry) => entry.customerId === customerId);
    if (match && !customerMatches.includes(match)) customerMatches.push(match);
  }

  const nested = Object.values(payload).filter((value): value is Record<string, unknown> => typeof value === "object" && value !== null);
  for (const record of nested) {
    collectMatchingEntities(record, vendors, customers, vendorMatches, customerMatches);
  }
}

function collectFindingsForProviders(
  providerKeys: Set<string>,
  findingsByProvider: Map<string, FindingRecord[]>,
): FindingRecord[] {
  const results: FindingRecord[] = [];
  const seen = new Set<string>();
  for (const key of providerKeys) {
    const matches = findingsByProvider.get(key);
    if (!matches) continue;
    for (const finding of matches) {
      if (seen.has(finding.findingId)) continue;
      seen.add(finding.findingId);
      results.push(finding);
    }
  }
  return results;
}

function deriveVendorProviderKeys(vendor: SecurityCenterVendorInsight): Set<string> {
  const keys = new Set<string>();
  keys.add(normalize(vendor.category));
  if (vendor.metadata?.integration.integrationType) {
    keys.add(normalize(vendor.metadata.integration.integrationType));
  }
  for (const method of vendor.metadata?.integration.authenticationMethods ?? []) {
    keys.add(normalize(method));
  }
  for (const access of vendor.metadata?.integration.networkAccess ?? []) {
    keys.add(normalize(access));
  }
  if (vendor.rawMetadata?.tags && typeof vendor.rawMetadata.tags === "object") {
    for (const value of Object.values(vendor.rawMetadata.tags as Record<string, unknown>)) {
      if (typeof value === "string") keys.add(normalize(value));
    }
  }
  return keys;
}

function deriveCustomerProviderKeys(customer: SecurityCenterCustomerInsight): Set<string> {
  const keys = new Set<string>();
  keys.add(normalize(customer.segment));
  for (const program of customer.metadata?.successPrograms ?? []) {
    keys.add(normalize(program));
  }
  if (customer.metadata?.adoption.metrics) {
    for (const key of Object.keys(customer.metadata.adoption.metrics)) {
      keys.add(normalize(key));
    }
  }
  if ((customer.metadata?.engagement.openSupportTickets ?? 0) > 0) {
    keys.add("support");
  }
  return keys;
}

function hasProviderMatch(
  record: IntegrationCoverageRecord,
  providerKeys: Set<string>,
  providerAliases: Record<string, string[]>,
): boolean {
  const normalized = new Set<string>();
  normalized.add(normalize(record.integration));
  for (const provider of record.providers) normalized.add(normalize(provider));
  for (const alias of providerAliases[record.integration] ?? []) normalized.add(normalize(alias));
  for (const key of providerKeys) {
    if (normalized.has(key)) return true;
  }
  return false;
}

function normalize(value: string | null | undefined): string {
  return (value ?? "").toString().trim().toLowerCase();
}

