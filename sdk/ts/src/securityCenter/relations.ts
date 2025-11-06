import { buildCustomerRiskDashboard, buildVendorRiskDashboard } from "./analytics.js";
import type { SecurityCenterClient, SecurityCenterCustomerInsight, SecurityCenterVendorInsight } from "../clients/securityCenter.js";
import type { IntegrationsClient } from "../clients/integrations.js";
import type { FindingsClient } from "../clients/findings.js";
import type {
  IntegrationCoverageHealth,
  IntegrationCoverageRecord,
  FindingRecord,
} from "../types.js";
import { computeCoverageHealth } from "../integrations/metrics.js";
import type { AgentStreamEvent } from "../agents/streaming.js";

export interface VendorExposure {
  vendor: SecurityCenterVendorInsight;
  relatedIntegrations: IntegrationCoverageRecord[];
  coverageHealth: IntegrationCoverageHealth[];
  relatedFindings: FindingRecord[];
  dashboard: ReturnType<typeof buildVendorRiskDashboard>;
}

export interface CustomerEngagement {
  customer: SecurityCenterCustomerInsight;
  relatedIntegrations: IntegrationCoverageRecord[];
  relatedFindings: FindingRecord[];
  dashboard: ReturnType<typeof buildCustomerRiskDashboard>;
}

export interface ExposureContext {
  securityCenter: SecurityCenterClient;
  integrations: IntegrationsClient;
  findings: FindingsClient;
  providerAliases?: Record<string, string[]>;
}

export interface EntityAnnotation {
  event: AgentStreamEvent;
  vendors: SecurityCenterVendorInsight[];
  customers: SecurityCenterCustomerInsight[];
}

export async function getVendorExposure(
  orgId: string,
  vendorId: string,
  context: ExposureContext,
): Promise<VendorExposure> {
  const vendors = await context.securityCenter.iterateVendors(orgId);
  const vendor = vendors.find((entry) => entry.vendorId === vendorId);
  if (!vendor) {
    throw new Error(`Vendor ${vendorId} not found in org ${orgId}`);
  }

  const providerKeys = deriveVendorProviderKeys(vendor);
  const coverage = await context.integrations.getCoverage();
  const relatedIntegrations = coverage.filter((record) => hasProviderMatch(record, providerKeys, context.providerAliases));
  const coverageHealth = relatedIntegrations.map(computeCoverageHealth);

  const findings = await context.findings.list({ orgId });
  const relatedFindings = findings.filter((finding) => providerKeys.has(normalize(finding.provider)));

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
): Promise<CustomerEngagement> {
  const customers = await context.securityCenter.iterateCustomers(orgId);
  const customer = customers.find((entry) => entry.customerId === customerId);
  if (!customer) {
    throw new Error(`Customer ${customerId} not found in org ${orgId}`);
  }

  const providerKeys = deriveCustomerProviderKeys(customer);
  const coverage = await context.integrations.getCoverage();
  const relatedIntegrations = coverage.filter((record) => hasProviderMatch(record, providerKeys, context.providerAliases));

  const findings = await context.findings.list({ orgId });
  const relatedFindings = findings.filter((finding) => providerKeys.has(normalize(finding.provider)));

  return {
    customer,
    relatedIntegrations,
    relatedFindings,
    dashboard: buildCustomerRiskDashboard([customer]),
  } satisfies CustomerEngagement;
}

export function annotateAgentEvents(
  events: AgentStreamEvent[],
  vendors: SecurityCenterVendorInsight[],
  customers: SecurityCenterCustomerInsight[],
): EntityAnnotation[] {
  return events.map((event) => {
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

    return { event, vendors: vendorMatches, customers: customerMatches } satisfies EntityAnnotation;
  });
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
  if (customer.metadata?.engagement.openSupportTickets ?? 0 > 0) {
    keys.add("support");
  }
  return keys;
}

function hasProviderMatch(
  record: IntegrationCoverageRecord,
  providerKeys: Set<string>,
  providerAliases: Record<string, string[]> | undefined,
): boolean {
  const normalized = new Set<string>();
  normalized.add(normalize(record.integration));
  for (const provider of record.providers) normalized.add(normalize(provider));
  for (const alias of providerAliases?.[record.integration] ?? []) normalized.add(normalize(alias));
  for (const key of providerKeys) {
    if (normalized.has(key)) return true;
  }
  return false;
}

function normalize(value: string | null | undefined): string {
  return (value ?? "").toString().trim().toLowerCase();
}
