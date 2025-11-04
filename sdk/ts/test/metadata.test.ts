import { describe, expect, it } from "vitest";

import {
  toCustomerMetadataEnvelope,
  toVendorMetadataEnvelope,
} from "../src/metadata";

describe("metadata helpers", () => {
  it("converts vendor metadata envelopes", () => {
    const rawVendor = {
      evidence: {
        id: "vendor-meta-1",
        category: "vendor_assessment",
        content_type: "application/json",
        collector_id: "vendor_registry",
        collector_type: "automated",
        collection_method: "integration",
        source_system: "vendor_registry",
        content_size: 0,
        created_at: "2024-01-01T00:00:00Z",
        status: "collected",
        retention_class: "standard",
        pii_detected: false,
        sensitivity_level: "internal",
        encryption_required: false,
        tags: { vendor_id: "vendor_acme" },
        related_evidence_ids: [],
        vendor_id: "vendor_acme",
        vendor_name: "Acme Cloud",
        risk_level: "high",
        inherent_risk_score: 0.82,
        residual_risk_score: 0.6,
        business_criticality: "critical",
        vendor_category: "cloud_provider",
        data_types_processed: ["PII"],
        certifications: ["SOC2"],
        compliance_frameworks: ["ISO27001"],
        last_assessment_date: "2024-03-01T00:00:00Z",
        next_review_due: "2024-09-01T00:00:00Z",
        contract_end_date: null,
        lifecycle_stage: "active",
        relationship_owner: "security-team",
        service_regions: ["us-east-1"],
        primary_contacts: ["security@acme.test"],
        access_monitoring_enabled: true,
        security_alerts_configured: true,
        incident_count_last_year: 2,
      },
      risk_summary: {
        level: "high",
        inherent_score: 0.82,
        residual_score: 0.6,
        incident_count_last_year: 2,
        monitoring: {
          access_monitoring_enabled: true,
          security_alerts_configured: true,
        },
      },
      compliance_summary: {
        certifications: ["SOC2"],
        frameworks: ["ISO27001"],
        data_processing_agreements: ["dpa-2024"],
        security_questionnaire_completed: true,
        vulnerability_disclosure_policy: true,
        penetration_test_results_present: false,
      },
      relationship: {
        business_criticality: "critical",
        annual_spend: 150000,
        contract: {
          start_date: "2023-03-01T00:00:00Z",
          end_date: null,
          next_review_due: "2024-09-01T00:00:00Z",
        },
      },
      integration: {
        integration_type: "API",
        network_access: ["10.1.0.0/16"],
        authentication_methods: ["oauth"],
      },
      lifecycle_stage: "active",
    };

    const envelope = toVendorMetadataEnvelope(rawVendor);

    expect(envelope.lifecycleStage).toBe("active");
    expect(envelope.evidence.vendorId).toBe("vendor_acme");
    expect(envelope.evidence.createdAt).toBeInstanceOf(Date);
    expect(envelope.riskSummary.inherentScore).toBeCloseTo(0.82);
    expect(envelope.complianceSummary.certifications).toContain("SOC2");
    expect(envelope.relationship.contract.nextReviewDue).toBeInstanceOf(Date);
    expect(envelope.integration.networkAccess).toHaveLength(1);
  });

  it("converts customer metadata envelopes", () => {
    const rawCustomer = {
      evidence: {
        id: "cust-meta-1",
        category: "customer_profile",
        content_type: "application/json",
        collector_id: "customer_registry",
        collector_type: "automated",
        collection_method: "integration",
        source_system: "customer_success",
        content_size: 0,
        created_at: "2024-02-01T00:00:00Z",
        status: "collected",
        retention_class: "standard",
        pii_detected: false,
        sensitivity_level: "internal",
        encryption_required: false,
        tags: { customer_id: "customer_galaxy" },
        related_evidence_ids: [],
        customer_id: "customer_galaxy",
        customer_name: "Galaxy Industries",
        segment: "enterprise",
        industry: "manufacturing",
        region: "na",
        lifecycle_stage: "expansion",
        health_score: 0.9,
        churn_risk_score: 0.1,
        account_manager: "csm-jane",
        annual_recurring_revenue: 1250000,
        seats_committed: 500,
        adoption_metrics: { automation: 0.85, assurance: 0.7 },
        last_engagement_at: "2024-03-10T00:00:00Z",
        next_qbr_at: "2024-06-10T00:00:00Z",
        support_tickets_open: 1,
        advocacy_level: "champion",
        success_programs: ["design_partner"],
      },
      health: {
        score: 0.9,
        band: "healthy",
        churn_risk: 0.1,
        lifecycle_stage: "expansion",
      },
      adoption: {
        product_usage_score: 0.88,
        metrics: { automation: 0.85, assurance: 0.7 },
        seats_committed: 500,
      },
      engagement: {
        last_engagement_at: "2024-03-10T00:00:00Z",
        next_qbr_at: "2024-06-10T00:00:00Z",
        open_support_tickets: 1,
      },
      success_programs: ["design_partner"],
    };

    const envelope = toCustomerMetadataEnvelope(rawCustomer);

    expect(envelope.evidence.customerId).toBe("customer_galaxy");
    expect(envelope.health.band).toBe("healthy");
    expect(envelope.adoption.productUsageScore).toBeCloseTo(0.88);
    expect(envelope.engagement.lastEngagementAt).toBeInstanceOf(Date);
    expect(envelope.successPrograms).toContain("design_partner");
    expect(envelope.evidence.adoptionMetrics.automation).toBeCloseTo(0.85);
  });
});
