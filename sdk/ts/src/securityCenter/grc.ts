import type {
  SecurityCenterCustomerInsight,
  SecurityCenterVendorInsight,
} from "../clients/securityCenter.js";
import {
  extractEvidenceArtifacts,
  summarizeEvidenceSet,
  type EvidenceArtifact,
  type EvidenceSetSummary,
  type LifecyclePolicy,
} from "./primitives.js";

export interface ControlMapping {
  controlId: string;
  controlName: string;
  framework: string;
  policyOwner: string;
  status: "pass" | "gap" | "at_risk";
  rationale: string;
  relatedVendors: string[];
  relatedCustomers: string[];
  evidenceReport: EvidenceBundle;
}
export interface EvidenceBundle {
  exportedAt: Date;
  controlId: string;
  framework: string;
  vendorEvidence: EvidenceArtifact[];
  customerEvidence: EvidenceArtifact[];
  vendorSummary: EvidenceSetSummary;
  customerSummary: EvidenceSetSummary;
}


export interface ControlCatalog {
  frameworks: Record<string, Record<string, ControlDefinition>>;
}

export interface ControlDefinition {
  name: string;
  policies: string[];
  owner: string;
  vendorTags?: string[];
  customerTags?: string[];
  tolerance?: {
    residualRiskMax?: number;
    churnRiskMax?: number;
    overdueReviewMax?: number;
  };
}

export interface ControlMappingOptions {
  catalog: ControlCatalog;
  vendorTags?: (vendor: SecurityCenterVendorInsight) => string[];
  customerTags?: (customer: SecurityCenterCustomerInsight) => string[];
  evidencePolicy?: LifecyclePolicy;
}

export function mapToControlFramework(
  vendors: SecurityCenterVendorInsight[],
  customers: SecurityCenterCustomerInsight[],
  options: ControlMappingOptions,
): ControlMapping[] {
  const mappings: ControlMapping[] = [];

  const vendorTagIndex = new Map<string, SecurityCenterVendorInsight[]>();
  const customerTagIndex = new Map<string, SecurityCenterCustomerInsight[]>();

  for (const vendor of vendors) {
    const tags = new Set<string>(options.vendorTags?.(vendor) ?? []);
    if (vendor.metadata?.complianceSummary?.certifications)
      for (const certification of vendor.metadata.complianceSummary.certifications) tags.add(certification.toLowerCase());
    if (vendor.rawMetadata?.tags && typeof vendor.rawMetadata.tags === "object")
      for (const value of Object.values(vendor.rawMetadata.tags as Record<string, unknown>))
        if (typeof value === "string") tags.add(value.toLowerCase());

    for (const tag of tags) {
      if (!vendorTagIndex.has(tag)) vendorTagIndex.set(tag, []);
      vendorTagIndex.get(tag)!.push(vendor);
    }
  }

  for (const customer of customers) {
    const tags = new Set<string>(options.customerTags?.(customer) ?? []);
    if (customer.metadata?.successPrograms)
      for (const program of customer.metadata.successPrograms) tags.add(program.toLowerCase());
    if (customer.rawMetadata?.tags && typeof customer.rawMetadata.tags === "object")
      for (const value of Object.values(customer.rawMetadata.tags as Record<string, unknown>))
        if (typeof value === "string") tags.add(value.toLowerCase());

    for (const tag of tags) {
      if (!customerTagIndex.has(tag)) customerTagIndex.set(tag, []);
      customerTagIndex.get(tag)!.push(customer);
    }
  }

  const exportedAt = new Date();

  for (const [framework, controls] of Object.entries(options.catalog.frameworks)) {
    for (const [controlId, control] of Object.entries(controls)) {
      const relatedVendors = collectEntities(control.vendorTags, vendorTagIndex);
      const relatedCustomers = collectEntities(control.customerTags, customerTagIndex);

      const { status, rationale } = evaluateControl(control, relatedVendors, relatedCustomers);
      const evidenceReport = buildEvidenceBundle({
        exportedAt,
        controlId,
        framework,
        vendors: relatedVendors,
        customers: relatedCustomers,
        policy: options.evidencePolicy,
      });

      mappings.push({
        controlId,
        controlName: control.name,
        framework,
        policyOwner: control.owner,
        status,
        rationale,
        relatedVendors: relatedVendors.map((vendor) => vendor.vendorId),
        relatedCustomers: relatedCustomers.map((customer) => customer.customerId),
        evidenceReport,
      });
    }
  }

  return mappings;
}

function collectEntities<T>(tags: string[] | undefined, index: Map<string, T[]>): T[] {
  if (!tags || tags.length === 0) return [];
  const results: T[] = [];
  const seen = new Set<T>();
  for (const tag of tags) {
    const matches = index.get(tag.toLowerCase());
    if (!matches) continue;
    for (const match of matches) {
      if (seen.has(match)) continue;
      seen.add(match);
      results.push(match);
    }
  }
  return results;
}

function evaluateControl(
  control: ControlDefinition,
  vendors: SecurityCenterVendorInsight[],
  customers: SecurityCenterCustomerInsight[],
): { status: ControlMapping["status"]; rationale: string } {
  const tolerance = control.tolerance ?? {};
  const vendorBreaches = vendors.filter((vendor) => {
    if (tolerance.residualRiskMax !== undefined && (vendor.residualRiskScore ?? 0) > tolerance.residualRiskMax)
      return true;
    return false;
  });

  const customerBreaches = customers.filter((customer) => {
    if (tolerance.churnRiskMax !== undefined && (customer.churnRiskScore ?? 0) > tolerance.churnRiskMax)
      return true;
    return false;
  });

  if (vendorBreaches.length === 0 && customerBreaches.length === 0) {
    if (vendors.length === 0 && customers.length === 0) {
      return {
        status: "pass",
        rationale: "Control not applicable: no related vendors or customers",
      };
    }
    return {
      status: "pass",
      rationale: "All related vendors/customers within tolerance",
    };
  }

  const rationale: string[] = [];
  if (vendorBreaches.length > 0)
    rationale.push(
      `${vendorBreaches.length} vendor(s) exceeding tolerance: ${vendorBreaches
        .map((vendor) => vendor.name)
        .join(", ")}`,
    );
  if (customerBreaches.length > 0)
    rationale.push(
      `${customerBreaches.length} customer(s) exceeding tolerance: ${customerBreaches
        .map((customer) => customer.name)
        .join(", ")}`,
    );

  return {
    status: vendorBreaches.length + customerBreaches.length > 2 ? "gap" : "at_risk",
    rationale: rationale.join("; "),
  };
}

function dedupeArtifacts(artifacts: EvidenceArtifact[]): EvidenceArtifact[] {
  const seen = new Map<string, EvidenceArtifact>();
  for (const artifact of artifacts) {
    if (!seen.has(artifact.id)) {
      seen.set(artifact.id, artifact);
    }
  }
  return Array.from(seen.values());
}

interface EvidenceParams {
  exportedAt: Date;
  controlId: string;
  framework: string;
  vendors: SecurityCenterVendorInsight[];
  customers: SecurityCenterCustomerInsight[];
  policy: LifecyclePolicy | undefined;
}

function buildEvidenceBundle(params: EvidenceParams): EvidenceBundle {
  const vendorEvidence = dedupeArtifacts(
    params.vendors.flatMap((vendor) => [
      ...extractEvidenceArtifacts({
        kind: "vendor",
        entityId: vendor.vendorId,
        metadata: asRecord(vendor.metadata),
        defaultSource: "metadata",
      }),
      ...extractEvidenceArtifacts({
        kind: "vendor",
        entityId: vendor.vendorId,
        metadata: asRecord(vendor.rawMetadata),
        defaultSource: "raw",
      }),
    ]),
  );

  const customerEvidence = dedupeArtifacts(
    params.customers.flatMap((customer) => [
      ...extractEvidenceArtifacts({
        kind: "customer",
        entityId: customer.customerId,
        metadata: asRecord(customer.metadata),
        defaultSource: "metadata",
      }),
      ...extractEvidenceArtifacts({
        kind: "customer",
        entityId: customer.customerId,
        metadata: asRecord(customer.rawMetadata),
        defaultSource: "raw",
      }),
    ]),
  );

  const policy = params.policy ?? { maxAgeDays: 90, refreshWindowDays: 14, hardExpiryDays: 365 } satisfies LifecyclePolicy;

  const vendorSummary = summarizeEvidenceSet(vendorEvidence, policy, params.exportedAt);
  const customerSummary = summarizeEvidenceSet(customerEvidence, policy, params.exportedAt);

  return {
    exportedAt: params.exportedAt,
    controlId: params.controlId,
    framework: params.framework,
    vendorEvidence,
    customerEvidence,
    vendorSummary,
    customerSummary,
  } satisfies EvidenceBundle;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : undefined;
}
