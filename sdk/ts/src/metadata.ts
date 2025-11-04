import {
  CustomerMetadataEnvelope,
  CustomerMetadataRecord,
  EvidenceMetadataRecord,
  VendorComplianceSummary,
  VendorIntegrationSummary,
  VendorMetadataEnvelope,
  VendorMetadataRecord,
  VendorRelationshipSummary,
  VendorRiskSummary,
} from "./types";

const toDate = (value: unknown): Date | null => {
  if (!value) {
    return null;
  }
  const date = new Date(String(value));
  return Number.isNaN(date.getTime()) ? null : date;
};

const ensureStringArray = (value: unknown): string[] => {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => String(item));
};

const ensureStringRecord = (value: unknown): Record<string, string> => {
  if (!value || typeof value !== "object") {
    return {};
  }

  return Object.entries(value as Record<string, unknown>).reduce<Record<string, string>>(
    (acc, [key, val]) => {
      acc[key] = val == null ? "" : String(val);
      return acc;
    },
    {},
  );
};

const ensureNumberRecord = (value: unknown): Record<string, number> => {
  if (!value || typeof value !== "object") {
    return {};
  }

  return Object.entries(value as Record<string, unknown>).reduce<Record<string, number>>(
    (acc, [key, val]) => {
      const num = Number(val);
      if (!Number.isNaN(num)) {
        acc[key] = num;
      }
      return acc;
    },
    {},
  );
};

const parseBoolean = (value: unknown): boolean => Boolean(value);

const toOptionalNumber = (value: unknown): number | null => {
  if (value == null) {
    return null;
  }
  const num = Number(value);
  return Number.isNaN(num) ? null : num;
};

const toEvidenceMetadataRecord = (raw: Record<string, unknown>): EvidenceMetadataRecord => ({
  id: String(raw.id ?? ""),
  category: String(raw.category ?? ""),
  contentType: String(raw.content_type ?? ""),
  collectorId: String(raw.collector_id ?? ""),
  collectorType: String(raw.collector_type ?? ""),
  collectionMethod: String(raw.collection_method ?? ""),
  sourceSystem: (raw.source_system as string | null | undefined) ?? null,
  contentSize: Number(raw.content_size ?? 0),
  contentHash: (raw.content_hash as string | null | undefined) ?? null,
  createdAt: toDate(raw.created_at) ?? new Date(0),
  collectedAt: toDate(raw.collected_at),
  verifiedAt: toDate(raw.verified_at),
  sealedAt: toDate(raw.sealed_at),
  status: String(raw.status ?? ""),
  retentionClass: String(raw.retention_class ?? ""),
  expiresAt: toDate(raw.expires_at),
  cryptoProof: (raw.crypto_proof as Record<string, unknown> | null | undefined) ?? null,
  chainOfCustody: Array.isArray(raw.chain_of_custody)
    ? (raw.chain_of_custody as Array<Record<string, unknown>>)
    : [],
  piiDetected: parseBoolean(raw.pii_detected),
  sensitivityLevel: String(raw.sensitivity_level ?? ""),
  encryptionRequired: parseBoolean(raw.encryption_required),
  tags: ensureStringRecord(raw.tags),
  relatedEvidenceIds: ensureStringArray(raw.related_evidence_ids),
  parentBundleId: (raw.parent_bundle_id as string | null | undefined) ?? null,
});

export const toVendorMetadataRecord = (raw: Record<string, unknown>): VendorMetadataRecord => ({
  ...toEvidenceMetadataRecord(raw),
  vendorId: String(raw.vendor_id ?? ""),
  vendorName: String(raw.vendor_name ?? ""),
  riskLevel: String(raw.risk_level ?? ""),
  inherentRiskScore: Number(raw.inherent_risk_score ?? 0),
  residualRiskScore: Number(raw.residual_risk_score ?? 0),
  businessCriticality: String(raw.business_criticality ?? ""),
  vendorCategory: (raw.vendor_category as string | null | undefined) ?? null,
  dataTypesProcessed: ensureStringArray(raw.data_types_processed),
  certifications: ensureStringArray(raw.certifications),
  complianceFrameworks: ensureStringArray(raw.compliance_frameworks),
  lastAssessmentDate: toDate(raw.last_assessment_date),
  nextReviewDue: toDate(raw.next_review_due),
  contractEndDate: toDate(raw.contract_end_date),
  lifecycleStage: String(raw.lifecycle_stage ?? ""),
  relationshipOwner: (raw.relationship_owner as string | null | undefined) ?? null,
  serviceRegions: ensureStringArray(raw.service_regions),
  primaryContacts: ensureStringArray(raw.primary_contacts),
  accessMonitoringEnabled: parseBoolean(raw.access_monitoring_enabled),
  securityAlertsConfigured: parseBoolean(raw.security_alerts_configured),
  incidentCountLastYear: Number(raw.incident_count_last_year ?? 0),
});

export const toCustomerMetadataRecord = (raw: Record<string, unknown>): CustomerMetadataRecord => ({
  ...toEvidenceMetadataRecord(raw),
  customerId: String(raw.customer_id ?? ""),
  customerName: String(raw.customer_name ?? ""),
  segment: String(raw.segment ?? ""),
  industry: (raw.industry as string | null | undefined) ?? null,
  region: (raw.region as string | null | undefined) ?? null,
  lifecycleStage: String(raw.lifecycle_stage ?? ""),
  healthScore: Number(raw.health_score ?? 0),
  churnRiskScore: Number(raw.churn_risk_score ?? 0),
  accountManager: (raw.account_manager as string | null | undefined) ?? null,
  annualRecurringRevenue: toOptionalNumber(raw.annual_recurring_revenue),
  seatsCommitted: toOptionalNumber(raw.seats_committed),
  adoptionMetrics: ensureNumberRecord(raw.adoption_metrics),
  lastEngagementAt: toDate(raw.last_engagement_at),
  nextQbrAt: toDate(raw.next_qbr_at),
  supportTicketsOpen: Number(raw.support_tickets_open ?? 0),
  advocacyLevel: String(raw.advocacy_level ?? ""),
  successPrograms: ensureStringArray(raw.success_programs),
});

const toVendorRiskSummary = (raw: Record<string, unknown>): VendorRiskSummary => ({
  level: String(raw.level ?? ""),
  inherentScore: Number(raw.inherent_score ?? 0),
  residualScore: Number(raw.residual_score ?? 0),
  incidentCountLastYear: Number(raw.incident_count_last_year ?? 0),
  monitoring: {
    accessMonitoringEnabled: parseBoolean(
      raw.monitoring && typeof raw.monitoring === "object"
        ? (raw.monitoring as Record<string, unknown>).access_monitoring_enabled
        : undefined,
    ),
    securityAlertsConfigured: parseBoolean(
      raw.monitoring && typeof raw.monitoring === "object"
        ? (raw.monitoring as Record<string, unknown>).security_alerts_configured
        : undefined,
    ),
  },
});

const toVendorComplianceSummary = (raw: Record<string, unknown>): VendorComplianceSummary => ({
  certifications: ensureStringArray(raw.certifications),
  frameworks: ensureStringArray(raw.frameworks),
  dataProcessingAgreements: ensureStringArray(raw.data_processing_agreements),
  securityQuestionnaireCompleted: parseBoolean(raw.security_questionnaire_completed),
  vulnerabilityDisclosurePolicy: parseBoolean(raw.vulnerability_disclosure_policy),
  penetrationTestResultsPresent: parseBoolean(raw.penetration_test_results_present),
});

const toVendorRelationshipSummary = (raw: Record<string, unknown>): VendorRelationshipSummary => {
  const contract = (raw.contract as Record<string, unknown> | undefined) ?? {};
  return {
    businessCriticality: String(raw.business_criticality ?? ""),
    annualSpend: toOptionalNumber(raw.annual_spend),
    contract: {
      startDate: toDate(contract.start_date) ?? new Date(0),
      endDate: toDate(contract.end_date),
      nextReviewDue: toDate(contract.next_review_due) ?? new Date(0),
    },
  };
};

const toVendorIntegrationSummary = (raw: Record<string, unknown>): VendorIntegrationSummary => ({
  integrationType: String(raw.integration_type ?? ""),
  networkAccess: ensureStringArray(raw.network_access),
  authenticationMethods: ensureStringArray(raw.authentication_methods),
});

export const toVendorMetadataEnvelope = (raw: Record<string, unknown>): VendorMetadataEnvelope => ({
  evidence: toVendorMetadataRecord((raw.evidence as Record<string, unknown>) ?? {}),
  riskSummary: toVendorRiskSummary((raw.risk_summary as Record<string, unknown>) ?? {}),
  complianceSummary: toVendorComplianceSummary((raw.compliance_summary as Record<string, unknown>) ?? {}),
  relationship: toVendorRelationshipSummary((raw.relationship as Record<string, unknown>) ?? {}),
  integration: toVendorIntegrationSummary((raw.integration as Record<string, unknown>) ?? {}),
  lifecycleStage: String(raw.lifecycle_stage ?? ""),
});

export const toCustomerMetadataEnvelope = (raw: Record<string, unknown>): CustomerMetadataEnvelope => ({
  evidence: toCustomerMetadataRecord((raw.evidence as Record<string, unknown>) ?? {}),
  health: {
    score: Number(
      raw.health && typeof raw.health === "object"
        ? (raw.health as Record<string, unknown>).score
        : 0,
    ),
    band: String(
      raw.health && typeof raw.health === "object"
        ? (raw.health as Record<string, unknown>).band
        : "",
    ),
    churnRisk: Number(
      raw.health && typeof raw.health === "object"
        ? (raw.health as Record<string, unknown>).churn_risk
        : 0,
    ),
    lifecycleStage: String(
      raw.health && typeof raw.health === "object"
        ? (raw.health as Record<string, unknown>).lifecycle_stage
        : "",
    ),
  },
  adoption: {
    productUsageScore: Number(
      raw.adoption && typeof raw.adoption === "object"
        ? (raw.adoption as Record<string, unknown>).product_usage_score
        : 0,
    ),
    metrics:
      raw.adoption && typeof raw.adoption === "object"
        ? ensureNumberRecord((raw.adoption as Record<string, unknown>).metrics)
        : {},
    seatsCommitted:
      raw.adoption && typeof raw.adoption === "object"
        ? toOptionalNumber((raw.adoption as Record<string, unknown>).seats_committed) ?? 0
        : 0,
  },
  engagement: {
    lastEngagementAt: toDate(
      raw.engagement && typeof raw.engagement === "object"
        ? (raw.engagement as Record<string, unknown>).last_engagement_at
        : undefined,
    ) ?? new Date(0),
    nextQbrAt: toDate(
      raw.engagement && typeof raw.engagement === "object"
        ? (raw.engagement as Record<string, unknown>).next_qbr_at
        : undefined,
    ),
    openSupportTickets: Number(
      raw.engagement && typeof raw.engagement === "object"
        ? (raw.engagement as Record<string, unknown>).open_support_tickets
        : 0,
    ),
  },
  successPrograms: ensureStringArray(raw.success_programs),
});
