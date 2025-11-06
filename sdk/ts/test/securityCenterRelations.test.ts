import { beforeEach, describe, expect, it, vi } from "vitest";

import HttpClient from "../src/httpClient";
import { SecurityCenterClient } from "../src/clients/securityCenter";
import { IntegrationsClient } from "../src/clients/integrations";
import { FindingsClient } from "../src/clients/findings";
import {
  annotateAgentEvents,
  getCustomerEngagement,
  getVendorExposure,
} from "../src/securityCenter/relations";
import type { AgentStreamEvent } from "../src/agents/streaming";

const fetchMock = vi.fn();

function createResponse(json: unknown) {
  return {
    ok: true,
    status: 200,
    headers: new Headers({ "content-type": "application/json" }),
    json: async () => json,
  } satisfies Response;
}

beforeEach(() => {
  fetchMock.mockReset();
  // @ts-expect-error assign test double
  globalThis.fetch = fetchMock;
});

describe("security center relations", () => {
  it("builds vendor exposure from cross-client data", async () => {
    const vendorsPayload = {
      count: 1,
      vendors: [vendorFixture],
      nextCursor: null,
    };

    const coveragePayload = [coverageFixtureGithub, coverageFixturePagerDuty];

    const findingsPayload = [findingGithub, findingPagerDuty];

    fetchMock
      .mockResolvedValueOnce(createResponse(vendorsPayload))
      .mockResolvedValueOnce(createResponse(coveragePayload))
      .mockResolvedValueOnce(createResponse(findingsPayload));

    const http = new HttpClient({ baseUrl: "https://api.test" });
    const securityCenter = new SecurityCenterClient(http);
    const integrations = new IntegrationsClient(http);
    const findings = new FindingsClient(http);

    const exposure = await getVendorExposure("org-1", "vendor-acme", {
      securityCenter,
      integrations,
      findings,
    });

    expect(exposure.vendor.vendorId).toBe("vendor-acme");
    expect(exposure.relatedIntegrations.map((entry) => entry.integration)).toContain("github");
    expect(exposure.relatedFindings).toHaveLength(1);
    expect(exposure.dashboard.kpis.totalVendors).toBe(1);
  });

  it("builds customer engagement snapshots", async () => {
    const customersPayload = {
      count: 1,
      customers: [customerFixture],
      nextCursor: null,
    };

    const coveragePayload = [coverageFixtureGithub];
    const findingsPayload = [findingGithub];

    fetchMock
      .mockResolvedValueOnce(createResponse(customersPayload))
      .mockResolvedValueOnce(createResponse(coveragePayload))
      .mockResolvedValueOnce(createResponse(findingsPayload));

    const http = new HttpClient({ baseUrl: "https://api.test" });
    const securityCenter = new SecurityCenterClient(http);
    const integrations = new IntegrationsClient(http);
    const findings = new FindingsClient(http);

    const engagement = await getCustomerEngagement("org-1", "customer-alpha", {
      securityCenter,
      integrations,
      findings,
    });

    expect(engagement.customer.customerId).toBe("customer-alpha");
    expect(engagement.relatedIntegrations[0]?.integration).toBe("github");
    expect(engagement.dashboard.kpis.totalCustomers).toBe(1);
  });

  it("annotates agent events with vendor and customer references", () => {
    const events: AgentStreamEvent[] = [
      {
        type: "message",
        payload: {
          messageId: "msg-1",
          role: "assistant",
          content: "Vendor update",
          metadata: { vendorId: "vendor-acme" },
        },
        raw: { data: "", event: "message", id: "1" },
      },
      {
        type: "tool",
        payload: {
          invocationId: "tool-1",
          status: "completed",
          inputData: { customer_id: "customer-alpha" },
        },
        raw: { data: "", event: "tool", id: "2" },
      },
    ];

    const annotations = annotateAgentEvents(events, [vendorMapped], [customerMapped]);
    expect(annotations[0]?.vendors[0]?.vendorId).toBe("vendor-acme");
    expect(annotations[1]?.customers[0]?.customerId).toBe("customer-alpha");
  });
});

const vendorFixture = {
  vendorId: "vendor-acme",
  name: "Acme Cloud",
  category: "security",
  riskLevel: "medium",
  inherentRiskScore: 0.6,
  residualRiskScore: 0.4,
  lifecycleStage: "active",
  nextReviewDue: "2024-11-10T00:00:00Z",
  businessCriticality: "high",
  metadata: {
    evidence: {
      id: "evidence",
      collector_id: "vendor_registry",
      collector_type: "automated",
      content_type: "application/json",
      content_size: 1,
      created_at: "2024-01-01T00:00:00Z",
      status: "collected",
      retention_class: "standard",
      pii_detected: false,
      sensitivity_level: "internal",
      encryption_required: true,
      tags: { integration: "github" },
      related_evidence_ids: [],
      vendor_id: "vendor-acme",
      vendor_name: "Acme",
      risk_level: "medium",
      inherent_risk_score: 0.6,
      residual_risk_score: 0.4,
      business_criticality: "high",
      data_types_processed: [],
      certifications: [],
      compliance_frameworks: [],
      lifecycle_stage: "active",
      relationship_owner: "sec-ops",
      service_regions: [],
      primary_contacts: [],
      access_monitoring_enabled: true,
      security_alerts_configured: true,
      incident_count_last_year: 0,
    },
    risk_summary: {
      level: "medium",
      inherent_score: 0.6,
      residual_score: 0.4,
      incident_count_last_year: 0,
      monitoring: {
        access_monitoring_enabled: true,
        security_alerts_configured: true,
      },
    },
    compliance_summary: {
      certifications: [],
      frameworks: [],
      data_processing_agreements: [],
      security_questionnaire_completed: true,
      vulnerability_disclosure_policy: true,
      penetration_test_results_present: true,
    },
    relationship: {
      business_criticality: "high",
      annual_spend: 100000,
      contract: {
        start_date: "2024-01-01T00:00:00Z",
        end_date: null,
        next_review_due: "2024-11-10T00:00:00Z",
      },
    },
    integration: {
      integration_type: "github",
      network_access: ["api"],
      authentication_methods: ["oauth"],
    },
    lifecycle_stage: "active",
  },
  rawMetadata: {
    tags: { integration: "github" },
  },
};

const vendorMapped = {
  ...vendorFixture,
  metadata: {
    ...vendorFixture.metadata,
    evidence: vendorFixture.metadata?.evidence && {
      ...vendorFixture.metadata.evidence,
      createdAt: new Date("2024-01-01T00:00:00Z"),
      tags: { integration: "github" },
      relatedEvidenceIds: [],
      dataTypesProcessed: [],
      certifications: [],
      complianceFrameworks: [],
      serviceRegions: [],
      primaryContacts: [],
    },
    riskSummary: vendorFixture.metadata?.risk_summary && {
      level: "medium",
      inherentScore: 0.6,
      residualScore: 0.4,
      incidentCountLastYear: 0,
      monitoring: {
        accessMonitoringEnabled: true,
        securityAlertsConfigured: true,
      },
    },
    complianceSummary: vendorFixture.metadata?.compliance_summary && {
      certifications: [],
      frameworks: [],
      dataProcessingAgreements: [],
      securityQuestionnaireCompleted: true,
      vulnerabilityDisclosurePolicy: true,
      penetrationTestResultsPresent: true,
    },
    relationship: vendorFixture.metadata?.relationship && {
      businessCriticality: "high",
      annualSpend: 100000,
      contract: {
        startDate: new Date("2024-01-01T00:00:00Z"),
        endDate: null,
        nextReviewDue: new Date("2024-11-10T00:00:00Z"),
      },
    },
    integration: vendorFixture.metadata?.integration && {
      integrationType: "github",
      networkAccess: ["api"],
      authenticationMethods: ["oauth"],
    },
    lifecycleStage: "active",
  },
} as SecurityCenterVendorInsight;

const customerFixture = {
  customerId: "customer-alpha",
  name: "Alpha Corp",
  segment: "enterprise",
  healthBand: "healthy",
  healthScore: 0.88,
  churnRiskScore: 0.15,
  lifecycleStage: "active",
  accountManager: "csm-amy",
  nextQbrAt: "2024-12-01T00:00:00Z",
  lastEngagementAt: "2024-10-10T00:00:00Z",
  metadata: {
    evidence: {
      id: "customer-meta",
      collector_id: "customer_registry",
      collector_type: "automated",
      content_type: "application/json",
      content_size: 1,
      created_at: "2024-01-01T00:00:00Z",
      status: "collected",
      retention_class: "standard",
      pii_detected: false,
      sensitivity_level: "internal",
      encryption_required: true,
      tags: { success_program: "design_partner" },
      related_evidence_ids: [],
      customer_id: "customer-alpha",
      customer_name: "Alpha",
      segment: "enterprise",
      lifecycle_stage: "active",
      health_score: 0.88,
      churn_risk_score: 0.15,
      account_manager: "csm-amy",
      adoption_metrics: { github: 0.92 },
      last_engagement_at: "2024-10-10T00:00:00Z",
      next_qbr_at: "2024-12-01T00:00:00Z",
      support_tickets_open: 1,
      advocacy_level: "champion",
      success_programs: ["design_partner"],
    },
    health: {
      score: 0.88,
      band: "healthy",
      churn_risk: 0.15,
      lifecycle_stage: "active",
    },
    adoption: {
      product_usage_score: 0.9,
      metrics: { github: 0.92 },
      seats_committed: 500,
    },
    engagement: {
      last_engagement_at: "2024-10-10T00:00:00Z",
      next_qbr_at: "2024-12-01T00:00:00Z",
      open_support_tickets: 1,
    },
    success_programs: ["design_partner"],
  },
  rawMetadata: {
    tags: { success_program: "design_partner" },
  },
};

const customerMapped = {
  ...customerFixture,
  metadata: {
    ...customerFixture.metadata,
    evidence: customerFixture.metadata?.evidence && {
      ...customerFixture.metadata.evidence,
      createdAt: new Date("2024-01-01T00:00:00Z"),
      tags: { successProgram: "design_partner" },
      relatedEvidenceIds: [],
    },
    health: customerFixture.metadata?.health && {
      score: 0.88,
      band: "healthy",
      churnRisk: 0.15,
      lifecycleStage: "active",
    },
    adoption: customerFixture.metadata?.adoption && {
      productUsageScore: 0.9,
      metrics: { github: 0.92 },
      seatsCommitted: 500,
    },
    engagement: customerFixture.metadata?.engagement && {
      lastEngagementAt: new Date("2024-10-10T00:00:00Z"),
      nextQbrAt: new Date("2024-12-01T00:00:00Z"),
      openSupportTickets: 1,
    },
  },
} as SecurityCenterCustomerInsight;

const coverageFixtureGithub = {
  integration: "github",
  providers: ["github"],
  status: "degraded",
  scopes: {
    total: 200,
    healthy: 150,
    warning: 30,
    critical: 20,
  },
  accounts: {
    total: 140,
  },
  coverage_ratio: 0.75,
  last_success: "2024-10-24T08:30:00Z",
  evaluated_at: "2024-10-24T09:00:00Z",
};

const coverageFixturePagerDuty = {
  integration: "pagerduty",
  providers: ["pagerduty"],
  status: "ok",
  scopes: {
    total: 80,
    healthy: 70,
    warning: 6,
    critical: 4,
  },
  accounts: {
    total: 60,
  },
  coverage_ratio: 0.88,
  last_success: "2024-10-24T08:00:00Z",
  evaluated_at: "2024-10-24T08:30:00Z",
};

const findingGithub = {
  finding_id: "finding-1",
  org_id: "org-1",
  account_id: "acct-1",
  provider: "github",
  rule_id: "RULE_001",
  rule_version: 3,
  resource_id: "res-123",
  principal_id: "user-42",
  first_seen: "2024-10-01T08:30:00Z",
  last_seen: "2024-10-26T09:45:00Z",
  status: "open",
  severity: "high",
  fingerprint: "abc123",
  title: "S3 bucket public",
  summary: "Bucket allows public read access",
  evidence: {
    bucket: "logs",
  },
};

const findingPagerDuty = {
  ...findingGithub,
  finding_id: "finding-2",
  provider: "pagerduty",
};
