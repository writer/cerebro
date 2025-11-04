import { beforeEach, describe, expect, it, vi } from "vitest";

import HttpClient from "../src/httpClient";
import {
  SecurityCenterClient,
  type RegisterCustomerRequest,
  type RegisterVendorRequest,
} from "../src/clients/securityCenter";

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  // @ts-expect-error assign test double
  globalThis.fetch = fetchMock;
});

describe("SecurityCenterClient", () => {
  it("registers a vendor and normalizes the response", async () => {
    const request: RegisterVendorRequest = {
      name: "Acme Cloud",
      websiteUrl: "https://acme.example.com",
      category: "security_vendor",
      primaryContact: "security@acme.example.com",
      businessCriticality: "high",
    };

    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({
        success: true,
        message: "Vendor created",
        data: {
          vendor_id: "vendor_acme",
          name: "Acme Cloud",
          risk_level: "high",
          risk_score: 0.81,
          next_review_due: "2024-05-01T00:00:00Z",
        },
      }),
    });

    const client = new SecurityCenterClient(new HttpClient({ baseUrl: "https://api.test" }));
    const summary = await client.registerVendor("org-1", request);

    expect(summary.vendorId).toBe("vendor_acme");
    expect(summary.riskLevel).toBe("high");
    expect(summary.nextReviewDue).toBeInstanceOf(Date);

    const [, init] = fetchMock.mock.calls[0];
    expect(init?.method).toBe("POST");
    const body = JSON.parse(String(init?.body));
    expect(body.name).toBe("Acme Cloud");
    expect(body.website_url).toBe("https://acme.example.com");
    expect(body.business_criticality).toBe("high");
  });

  it("registers a customer and returns the summary", async () => {
    const request: RegisterCustomerRequest = {
      name: "Galaxy Industries",
      accountManager: "csm-jane",
      segment: "enterprise",
      seatsCommitted: 250,
      successPrograms: ["design_partner"],
    };

    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({
        success: true,
        customer_id: "customer_galaxy",
        lifecycle_stage: "active",
      }),
    });

    const client = new SecurityCenterClient(new HttpClient({ baseUrl: "https://api.test" }));
    const summary = await client.registerCustomer("org-2", request);

    expect(summary.customerId).toBe("customer_galaxy");
    expect(summary.lifecycleStage).toBe("active");

    const [, init] = fetchMock.mock.calls[0];
    expect(init?.method).toBe("POST");
    const body = JSON.parse(String(init?.body));
    expect(body.segment).toBe("enterprise");
    expect(body.seats_committed).toBe(250);
    expect(body.success_programs).toEqual(["design_partner"]);
  });

  it("fetches an overview and maps nested metadata envelopes", async () => {
    const vendorMetadata = {
      evidence: {
        id: "vendor-meta-1",
        category: "vendor_assessment",
        content_type: "application/json",
        collector_id: "vendor_registry",
        collector_type: "automated",
        collection_method: "integration",
        content_size: 0,
        created_at: "2024-01-01T00:00:00Z",
        status: "collected",
        retention_class: "standard",
        pii_detected: false,
        sensitivity_level: "internal",
        encryption_required: false,
        tags: {},
        related_evidence_ids: [],
        vendor_id: "vendor_acme",
        vendor_name: "Acme Cloud",
        risk_level: "medium",
        inherent_risk_score: 0.6,
        residual_risk_score: 0.4,
        business_criticality: "medium",
        data_types_processed: [],
        certifications: [],
        compliance_frameworks: [],
        lifecycle_stage: "active",
        relationship_owner: "security@app",
        service_regions: [],
        primary_contacts: [],
        access_monitoring_enabled: true,
        security_alerts_configured: true,
        incident_count_last_year: 1,
      },
      risk_summary: {
        level: "medium",
        inherent_score: 0.6,
        residual_score: 0.4,
        incident_count_last_year: 1,
        monitoring: {
          access_monitoring_enabled: true,
          security_alerts_configured: true,
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
        annual_spend: 10000,
        contract: {
          start_date: "2024-01-01T00:00:00Z",
          end_date: null,
          next_review_due: "2024-06-01T00:00:00Z",
        },
      },
      integration: {
        integration_type: "api",
        network_access: [],
        authentication_methods: [],
      },
      lifecycle_stage: "active",
    };

    const customerMetadata = {
      evidence: {
        id: "customer-meta-1",
        category: "customer_profile",
        content_type: "application/json",
        collector_id: "customer_registry",
        collector_type: "automated",
        collection_method: "integration",
        content_size: 0,
        created_at: "2024-02-01T00:00:00Z",
        status: "collected",
        retention_class: "standard",
        pii_detected: false,
        sensitivity_level: "internal",
        encryption_required: false,
        tags: {},
        related_evidence_ids: [],
        customer_id: "customer_galaxy",
        customer_name: "Galaxy Industries",
        segment: "enterprise",
        lifecycle_stage: "active",
        health_score: 0.9,
        churn_risk_score: 0.1,
        account_manager: "csm-jane",
        adoption_metrics: { automation: 0.9 },
        last_engagement_at: "2024-03-01T00:00:00Z",
        next_qbr_at: "2024-06-01T00:00:00Z",
        support_tickets_open: 1,
        advocacy_level: "champion",
        success_programs: ["design_partner"],
      },
      health: {
        score: 0.9,
        band: "healthy",
        churn_risk: 0.1,
        lifecycle_stage: "active",
      },
      adoption: {
        product_usage_score: 0.88,
        metrics: { automation: 0.9 },
        seats_committed: 250,
      },
      engagement: {
        last_engagement_at: "2024-03-01T00:00:00Z",
        next_qbr_at: "2024-06-01T00:00:00Z",
        open_support_tickets: 1,
      },
      success_programs: ["design_partner"],
    };

    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({
        metrics: [
          { label: "High-risk vendors", value: 2, trend: "1 overdue reviews" },
        ],
        recentActivity: [
          { name: "Vendor risk review · Acme", status: "Risk level Medium", timestamp: "Nov 04 · 10:00" },
        ],
        upcomingExpirations: [
          { control: "Vendor review · Acme", owner: "security@app", due: "Nov 10" },
        ],
        submissions: [
          {
            id: "vendor_review_vendor_acme",
            documentId: "vendor_acme",
            question: "Review vendor",
            ownerEmail: "security@app",
            ownerTeam: "security-operations",
            submittedAt: "2024-04-01T00:00:00Z",
            status: "pending",
            knowledgeBaseType: "known",
            infoSecApprover: "infosec",
            dueDate: "2024-05-01T00:00:00Z",
            requiresApproval: true,
            autoReleaseEligible: false,
            kbSummary: null,
            requesterEmail: "security@app",
          },
        ],
        vendorInsights: [
          {
            vendorId: "vendor_acme",
            name: "Acme Cloud",
            category: "security_vendor",
            riskLevel: "medium",
            inherentRiskScore: 0.6,
            residualRiskScore: 0.4,
            lifecycleStage: "active",
            nextReviewDue: "2024-06-01T00:00:00Z",
            businessCriticality: "medium",
            metadata: vendorMetadata,
          },
        ],
        customerInsights: [
          {
            customerId: "customer_galaxy",
            name: "Galaxy Industries",
            segment: "enterprise",
            healthBand: "healthy",
            healthScore: 0.9,
            churnRiskScore: 0.1,
            lifecycleStage: "active",
            accountManager: "csm-jane",
            nextQbrAt: "2024-06-01T00:00:00Z",
            lastEngagementAt: "2024-03-01T00:00:00Z",
            metadata: customerMetadata,
          },
        ],
      }),
    });

    const client = new SecurityCenterClient(new HttpClient({ baseUrl: "https://api.test" }));
    const overview = await client.getOverview("org-3");

    expect(overview.metrics[0].label).toBe("High-risk vendors");
    expect(overview.submissions[0].submittedAt).toBeInstanceOf(Date);
    expect(overview.vendorInsights[0].metadata?.evidence.vendorId).toBe("vendor_acme");
    expect(overview.customerInsights[0].metadata?.evidence.customerId).toBe("customer_galaxy");
  });

  it("lists vendors and customers for an organization", async () => {
    fetchMock
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => ({
          count: 1,
          vendors: [
            {
              vendorId: "vendor_acme",
              name: "Acme Cloud",
              category: "security_vendor",
              riskLevel: "medium",
              inherentRiskScore: 0.6,
              residualRiskScore: 0.4,
              lifecycleStage: "active",
              nextReviewDue: "2024-06-01T00:00:00Z",
              businessCriticality: "medium",
              metadata: null,
            },
          ],
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => ({
          count: 1,
          customers: [
            {
              customerId: "customer_galaxy",
              name: "Galaxy Industries",
              segment: "enterprise",
              healthBand: "healthy",
              healthScore: 0.9,
              churnRiskScore: 0.1,
              lifecycleStage: "active",
              accountManager: "csm-jane",
              nextQbrAt: null,
              lastEngagementAt: null,
              metadata: null,
            },
          ],
        }),
      });

    const client = new SecurityCenterClient(new HttpClient({ baseUrl: "https://api.test" }));
    const vendors = await client.listVendors("org-4");
    const customers = await client.listCustomers("org-4");

    expect(vendors.count).toBe(1);
    expect(vendors.vendors[0].vendorId).toBe("vendor_acme");
    expect(customers.customers[0].customerId).toBe("customer_galaxy");

    const [vendorCall] = fetchMock.mock.calls;
    expect(vendorCall[0]).toContain("/security-center/organizations/org-4/vendors");
  });
});
