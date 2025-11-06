import { describe, expect, it } from "vitest";

import {
  assessCustomerHealth,
  assessVendorHealth,
  summarizeCustomerPortfolio,
  summarizeVendorPortfolio,
} from "../src/securityCenter/analytics";
import type {
  SecurityCenterCustomerInsight,
  SecurityCenterVendorInsight,
} from "../src/clients/securityCenter";

const REFERENCE_NOW = new Date("2024-10-24T00:00:00Z");

describe("security center analytics", () => {
  const vendor: SecurityCenterVendorInsight = {
    vendorId: "vendor-acme",
    name: "Acme Cloud",
    category: "security",
    riskLevel: "medium",
    inherentRiskScore: 0.6,
    residualRiskScore: 0.4,
    lifecycleStage: "active",
    nextReviewDue: new Date(REFERENCE_NOW.getTime() + 10 * DAY_MS),
    businessCriticality: "high",
    metadata: null,
    rawMetadata: null,
  };

  const overdueVendor: SecurityCenterVendorInsight = {
    ...vendor,
    vendorId: "vendor-beta",
    name: "Beta Compliance",
    riskLevel: "high",
    nextReviewDue: new Date(REFERENCE_NOW.getTime() - 5 * DAY_MS),
    residualRiskScore: 0.8,
  };

  const customer: SecurityCenterCustomerInsight = {
    customerId: "customer-1",
    name: "Globex",
    segment: "enterprise",
    healthBand: "healthy",
    healthScore: 0.85,
    churnRiskScore: 0.2,
    lifecycleStage: "active",
    accountManager: "csm-jane",
    nextQbrAt: new Date(REFERENCE_NOW.getTime() + 45 * DAY_MS),
    lastEngagementAt: new Date(REFERENCE_NOW.getTime() - 14 * DAY_MS),
    metadata: null,
    rawMetadata: null,
  };

  const atRiskCustomer: SecurityCenterCustomerInsight = {
    ...customer,
    customerId: "customer-2",
    name: "Initech",
    segment: "midmarket",
    healthBand: "at_risk",
    healthScore: 0.55,
    churnRiskScore: 0.6,
    lastEngagementAt: new Date(REFERENCE_NOW.getTime() - 60 * DAY_MS),
    nextQbrAt: new Date(REFERENCE_NOW.getTime() - 5 * DAY_MS),
  };

  it("assesses vendor health with review status", () => {
    const assessment = assessVendorHealth(vendor, REFERENCE_NOW);
    expect(assessment.vendorId).toBe("vendor-acme");
    expect(assessment.reviewStatus).toBe("due_soon");
    expect(assessment.riskDelta).toBeCloseTo(-0.2);
    expect(assessment.warnings).toEqual([]);
  });

  it("summarizes vendor portfolio and flags overdue reviews", () => {
    const summary = summarizeVendorPortfolio([vendor, overdueVendor], REFERENCE_NOW);
    expect(summary.total).toBe(2);
    expect(summary.byRiskLevel.high).toBe(1);
    expect(summary.overdueReviews).toBe(1);
    expect(summary.dueSoonReviews).toBe(1);
    expect(summary.averageResidualRisk).toBeCloseTo((0.4 + 0.8) / 2);
  });

  it("assesses customer health and engagement", () => {
    const assessment = assessCustomerHealth(customer, REFERENCE_NOW);
    expect(assessment.customerId).toBe("customer-1");
    expect(assessment.engagementGapDays).toBe(14);
    expect(assessment.nextQbrInDays).toBe(45);
  });

  it("summarizes customer portfolio and counts at-risk accounts", () => {
    const summary = summarizeCustomerPortfolio([customer, atRiskCustomer], REFERENCE_NOW);
    expect(summary.total).toBe(2);
    expect(summary.bySegment.enterprise).toBe(1);
    expect(summary.bySegment.midmarket).toBe(1);
    expect(summary.atRiskCount).toBe(1);
    expect(summary.averageHealthScore).toBeCloseTo((0.85 + 0.55) / 2);
    expect(summary.averageChurnRisk).toBeCloseTo((0.2 + 0.6) / 2);
  });
});

const DAY_MS = 24 * 60 * 60 * 1000;
