import { beforeEach, describe, expect, it, vi } from "vitest";

import HttpClient from "../src/httpClient";
import { SecurityCenterClient } from "../src/clients/securityCenter";
import { IntegrationsClient } from "../src/clients/integrations";
import { FindingsClient } from "../src/clients/findings";
import {
  buildOrgExposureDashboard,
  buildRelationsIndex,
  getVendorExposure,
} from "../src/securityCenter/relations";

const fetchMock = vi.fn();

function response(payload: unknown) {
  return {
    ok: true,
    status: 200,
    headers: new Headers({ "content-type": "application/json" }),
    json: async () => payload,
  } satisfies Response;
}

beforeEach(() => {
  fetchMock.mockReset();
  // @ts-expect-error assign test double
  globalThis.fetch = fetchMock;
});

describe("security center org exposure scenarios", () => {
  it("builds dashboards for multiple orgs without extra calls when index reused", async () => {
    queueOrgResponses(org1Vendors, org1Customers, org1Coverage, org1Findings);

    const http = new HttpClient({ baseUrl: "https://api.test" });
    const context = {
      securityCenter: new SecurityCenterClient(http),
      integrations: new IntegrationsClient(http),
      findings: new FindingsClient(http),
    };

    const index = await buildRelationsIndex("org-1", context);
    const exposure = await getVendorExposure("org-1", "vendor-one", context, index);
    expect(exposure.vendor.name).toBe("Vendor One");

    const callsAfterIndex = fetchMock.mock.calls.length;
    await getVendorExposure("org-1", "vendor-one", context, index);
    expect(fetchMock.mock.calls.length).toBe(callsAfterIndex);

    const dashboard = await buildOrgExposureDashboard("org-1", context, index);
    expect(dashboard.vendorDashboard.kpis.totalVendors).toBe(2);
    expect(dashboard.findings.total).toBe(2);

    queueOrgResponses(org2Vendors, org2Customers, org2Coverage, org2Findings);
    const dashboardOrg2 = await buildOrgExposureDashboard("org-2", context);
    expect(dashboardOrg2.vendorDashboard.kpis.totalVendors).toBe(1);
    expect(dashboardOrg2.findings.bySeverity.high).toBe(1);
  });
});

function queueOrgResponses(vendors: unknown, customers: unknown, coverage: unknown, findings: unknown) {
  fetchMock
    .mockResolvedValueOnce(response(vendors))
    .mockResolvedValueOnce(response(customers))
    .mockResolvedValueOnce(response(coverage))
    .mockResolvedValueOnce(response(findings));
}

const org1Vendors = {
  count: 2,
  vendors: [
    {
      vendorId: "vendor-one",
      name: "Vendor One",
      category: "github",
      riskLevel: "medium",
      inherentRiskScore: 0.5,
      residualRiskScore: 0.4,
      lifecycleStage: "active",
      nextReviewDue: "2024-12-01T00:00:00Z",
      businessCriticality: "high",
      metadata: {
        evidence: { tags: { integration: "github" } },
        integration: { integration_type: "github", network_access: [], authentication_methods: [] },
        risk_summary: {
          level: "medium",
          inherent_score: 0.5,
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
            next_review_due: "2024-12-01T00:00:00Z",
          },
        },
        lifecycle_stage: "active",
      },
    },
    {
      vendorId: "vendor-two",
      name: "Vendor Two",
      category: "pagerduty",
      riskLevel: "high",
      inherentRiskScore: 0.7,
      residualRiskScore: 0.8,
      lifecycleStage: "onboarding",
      nextReviewDue: "2024-09-01T00:00:00Z",
      businessCriticality: "medium",
      metadata: {
        evidence: { tags: { integration: "pagerduty" } },
        integration: { integration_type: "pagerduty", network_access: [], authentication_methods: [] },
        risk_summary: {
          level: "high",
          inherent_score: 0.7,
          residual_score: 0.8,
          incident_count_last_year: 1,
          monitoring: {
            access_monitoring_enabled: true,
            security_alerts_configured: false,
          },
        },
        compliance_summary: {
          certifications: [],
          frameworks: [],
          data_processing_agreements: [],
          security_questionnaire_completed: false,
          vulnerability_disclosure_policy: false,
          penetration_test_results_present: false,
        },
        relationship: {
          business_criticality: "medium",
          annual_spend: 90000,
          contract: {
            start_date: "2024-03-01T00:00:00Z",
            end_date: null,
            next_review_due: "2024-09-01T00:00:00Z",
          },
        },
        lifecycle_stage: "onboarding",
      },
    },
  ],
  nextCursor: null,
};

const org1Customers = {
  count: 2,
  customers: [
    {
      customerId: "customer-alpha",
      name: "Alpha Corp",
      segment: "enterprise",
      healthBand: "healthy",
      healthScore: 0.9,
      churnRiskScore: 0.1,
      lifecycleStage: "active",
      accountManager: "csm-amy",
      nextQbrAt: "2024-12-01T00:00:00Z",
      lastEngagementAt: "2024-10-10T00:00:00Z",
      metadata: {
        success_programs: ["design_partner"],
        adoption: { metrics: { github: 0.9 }, product_usage_score: 0.9, seats_committed: 500 },
        engagement: {
          last_engagement_at: "2024-10-10T00:00:00Z",
          next_qbr_at: "2024-12-01T00:00:00Z",
          open_support_tickets: 1,
        },
      },
    },
    {
      customerId: "customer-beta",
      name: "Beta Ltd",
      segment: "midmarket",
      healthBand: "at_risk",
      healthScore: 0.6,
      churnRiskScore: 0.55,
      lifecycleStage: "renewal",
      accountManager: "csm-bob",
      nextQbrAt: "2024-11-15T00:00:00Z",
      lastEngagementAt: "2024-08-01T00:00:00Z",
      metadata: {
        success_programs: [],
        adoption: { metrics: { pagerduty: 0.2 }, product_usage_score: 0.45, seats_committed: 120 },
        engagement: {
          last_engagement_at: "2024-08-01T00:00:00Z",
          next_qbr_at: "2024-11-15T00:00:00Z",
          open_support_tickets: 4,
        },
      },
    },
  ],
  nextCursor: null,
};

const org1Coverage = [
  {
    integration: "github",
    providers: ["github"],
    status: "degraded",
    scopes: { total: 200, healthy: 150, warning: 30, critical: 20 },
    accounts: { total: 140 },
    coverage_ratio: 0.75,
    last_success: "2024-10-24T08:30:00Z",
    evaluated_at: "2024-10-24T09:00:00Z",
  },
  {
    integration: "pagerduty",
    providers: ["pagerduty"],
    status: "ok",
    scopes: { total: 80, healthy: 70, warning: 6, critical: 4 },
    accounts: { total: 60 },
    coverage_ratio: 0.88,
    last_success: "2024-10-24T08:00:00Z",
    evaluated_at: "2024-10-24T08:30:00Z",
  },
];

const org1Findings = [
  {
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
    evidence: {},
  },
  {
    finding_id: "finding-2",
    org_id: "org-1",
    account_id: "acct-2",
    provider: "pagerduty",
    rule_id: "RULE_200",
    rule_version: 1,
    resource_id: "incident-123",
    principal_id: null,
    first_seen: "2024-10-20T14:00:00Z",
    last_seen: "2024-10-24T09:00:00Z",
    status: "open",
    severity: "medium",
    fingerprint: "pagerduty-incident",
    title: "Service missing runbook",
    summary: "No runbook attached",
    evidence: {},
  },
];

const org2Vendors = {
  count: 1,
  vendors: [
    {
      vendorId: "vendor-three",
      name: "Vendor Three",
      category: "slack",
      riskLevel: "low",
      inherentRiskScore: 0.2,
      residualRiskScore: 0.1,
      lifecycleStage: "active",
      nextReviewDue: "2025-01-01T00:00:00Z",
      businessCriticality: "medium",
      metadata: {
        evidence: { tags: { integration: "slack" } },
        integration: { integration_type: "slack", network_access: [], authentication_methods: [] },
        risk_summary: {
          level: "low",
          inherent_score: 0.2,
          residual_score: 0.1,
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
          business_criticality: "medium",
          annual_spend: 40000,
          contract: {
            start_date: "2024-04-01T00:00:00Z",
            end_date: null,
            next_review_due: "2025-01-01T00:00:00Z",
          },
        },
        lifecycle_stage: "active",
      },
    },
  ],
  nextCursor: null,
};

const org2Customers = {
  count: 1,
  customers: [
    {
      customerId: "customer-gamma",
      name: "Gamma Inc",
      segment: "enterprise",
      healthBand: "healthy",
      healthScore: 0.95,
      churnRiskScore: 0.05,
      lifecycleStage: "active",
      accountManager: "csm-liz",
      nextQbrAt: "2025-01-15T00:00:00Z",
      lastEngagementAt: "2024-10-20T00:00:00Z",
      metadata: {
        success_programs: ["strategic"],
        adoption: { metrics: { slack: 0.95 }, product_usage_score: 0.95, seats_committed: 800 },
        engagement: {
          last_engagement_at: "2024-10-20T00:00:00Z",
          next_qbr_at: "2025-01-15T00:00:00Z",
          open_support_tickets: 0,
        },
      },
    },
  ],
  nextCursor: null,
};

const org2Coverage = [
  {
    integration: "slack",
    providers: ["slack"],
    status: "ok",
    scopes: { total: 50, healthy: 48, warning: 1, critical: 1 },
    accounts: { total: 45 },
    coverage_ratio: 0.92,
    last_success: "2024-10-24T08:00:00Z",
    evaluated_at: "2024-10-24T08:05:00Z",
  },
];

const org2Findings = [
  {
    finding_id: "finding-3",
    org_id: "org-2",
    account_id: "acct-9",
    provider: "slack",
    rule_id: "RULE_500",
    rule_version: 2,
    resource_id: "channel-1",
    principal_id: null,
    first_seen: "2024-10-21T09:00:00Z",
    last_seen: "2024-10-24T12:00:00Z",
    status: "open",
    severity: "high",
    fingerprint: "slack-alert",
    title: "Slack channel not archived",
    summary: "Sensitive channel not archived",
    evidence: {},
  },
];
