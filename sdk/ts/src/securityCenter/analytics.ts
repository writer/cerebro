import type {
  SecurityCenterCustomerInsight,
  SecurityCenterVendorInsight,
} from "../clients/securityCenter.js";

export interface VendorHealthAssessment {
  vendorId: string;
  name: string;
  riskLevel: string;
  inherentRiskScore: number | null;
  residualRiskScore: number | null;
  riskDelta: number | null;
  reviewDueInDays: number | null;
  reviewStatus: "on_track" | "due_soon" | "overdue";
  businessCriticality: string | null;
  warnings: string[];
}

export interface VendorPortfolioSummary {
  total: number;
  byRiskLevel: Record<string, number>;
  overdueReviews: number;
  dueSoonReviews: number;
  averageResidualRisk: number | null;
}

export interface CustomerHealthAssessment {
  customerId: string;
  name: string;
  healthScore: number | null;
  healthBand: string | null;
  churnRiskScore: number | null;
  engagementGapDays: number | null;
  nextQbrInDays: number | null;
  accountManager: string | null;
  warnings: string[];
}

export interface CustomerPortfolioSummary {
  total: number;
  averageHealthScore: number | null;
  averageChurnRisk: number | null;
  bySegment: Record<string, number>;
  atRiskCount: number;
}

export interface VendorPortfolioSnapshot {
  timestamp: Date;
  vendors: SecurityCenterVendorInsight[];
}

export interface VendorTrendPoint {
  timestamp: Date;
  total: number;
  overdueReviews: number;
  dueSoonReviews: number;
  averageResidualRisk: number | null;
}

export interface VendorTrendSummary {
  points: VendorTrendPoint[];
  residualRiskChange: number | null;
  direction: "improving" | "declining" | "steady" | null;
}

export interface CustomerHealthSnapshot {
  timestamp: Date;
  customers: SecurityCenterCustomerInsight[];
}

export interface CustomerTrendPoint {
  timestamp: Date;
  total: number;
  atRiskCount: number;
  averageHealthScore: number | null;
  averageChurnRisk: number | null;
}

export interface CustomerTrendSummary {
  points: CustomerTrendPoint[];
  healthScoreChange: number | null;
  direction: "improving" | "declining" | "steady" | null;
}

const REVIEW_DUE_SOON_THRESHOLD_DAYS = 30;

export function assessVendorHealth(vendor: SecurityCenterVendorInsight, now = new Date()): VendorHealthAssessment {
  const warnings: string[] = [];
  const inherent = coerceNumber(vendor.inherentRiskScore, warnings, `vendor ${vendor.vendorId} inherent risk`);
  const residual = coerceNumber(vendor.residualRiskScore, warnings, `vendor ${vendor.vendorId} residual risk`);
  const riskDelta = inherent !== null && residual !== null ? residual - inherent : null;
  const reviewDueInDays = vendor.nextReviewDue ? daysBetween(now, vendor.nextReviewDue) : null;
  const reviewStatus = classifyReviewStatus(reviewDueInDays);

  return {
    vendorId: vendor.vendorId,
    name: vendor.name,
    riskLevel: vendor.riskLevel,
    inherentRiskScore: inherent,
    residualRiskScore: residual,
    riskDelta,
    reviewDueInDays,
    reviewStatus,
    businessCriticality: vendor.businessCriticality ?? null,
    warnings,
  } satisfies VendorHealthAssessment;
}

export function summarizeVendorPortfolio(vendors: SecurityCenterVendorInsight[], now = new Date()): VendorPortfolioSummary {
  if (!vendors.length) {
    return {
      total: 0,
      byRiskLevel: {},
      overdueReviews: 0,
      dueSoonReviews: 0,
      averageResidualRisk: null,
    } satisfies VendorPortfolioSummary;
  }

  const byRiskLevel: Record<string, number> = {};
  let overdueReviews = 0;
  let dueSoonReviews = 0;
  let residualAccumulator = 0;
  let residualCount = 0;

  for (const vendor of vendors) {
    const assessment = assessVendorHealth(vendor, now);
    const level = vendor.riskLevel?.toLowerCase() ?? "unknown";
    byRiskLevel[level] = (byRiskLevel[level] ?? 0) + 1;

    if (assessment.reviewStatus === "overdue") overdueReviews += 1;
    if (assessment.reviewStatus === "due_soon") dueSoonReviews += 1;

    if (assessment.residualRiskScore !== null) {
      residualAccumulator += assessment.residualRiskScore;
      residualCount += 1;
    }
  }

  return {
    total: vendors.length,
    byRiskLevel,
    overdueReviews,
    dueSoonReviews,
    averageResidualRisk: residualCount ? residualAccumulator / residualCount : null,
  } satisfies VendorPortfolioSummary;
}

export function assessCustomerHealth(customer: SecurityCenterCustomerInsight, now = new Date()): CustomerHealthAssessment {
  const warnings: string[] = [];
  const healthScore = coerceNumber(customer.healthScore, warnings, `customer ${customer.customerId} health`);
  const churnRisk = coerceNumber(customer.churnRiskScore, warnings, `customer ${customer.customerId} churn risk`);
  const engagementGapDays = customer.lastEngagementAt ? daysBetween(customer.lastEngagementAt, now) : null;
  const nextQbrInDays = customer.nextQbrAt ? daysBetween(now, customer.nextQbrAt) : null;

  return {
    customerId: customer.customerId,
    name: customer.name,
    healthScore,
    healthBand: customer.healthBand ?? null,
    churnRiskScore: churnRisk,
    engagementGapDays,
    nextQbrInDays,
    accountManager: customer.accountManager ?? null,
    warnings,
  } satisfies CustomerHealthAssessment;
}

export function summarizeCustomerPortfolio(customers: SecurityCenterCustomerInsight[], now = new Date()): CustomerPortfolioSummary {
  if (!customers.length) {
    return {
      total: 0,
      averageHealthScore: null,
      averageChurnRisk: null,
      bySegment: {},
      atRiskCount: 0,
    } satisfies CustomerPortfolioSummary;
  }

  const bySegment: Record<string, number> = {};
  let healthAccumulator = 0;
  let healthCount = 0;
  let churnAccumulator = 0;
  let churnCount = 0;
  let atRiskCount = 0;

  for (const customer of customers) {
    const assessment = assessCustomerHealth(customer, now);
    const segment = customer.segment?.toLowerCase() ?? "unknown";
    bySegment[segment] = (bySegment[segment] ?? 0) + 1;

    let customerAtRisk = false;
    if (assessment.healthScore !== null) {
      healthAccumulator += assessment.healthScore;
      healthCount += 1;
      if (assessment.healthScore < 0.6) customerAtRisk = true;
    }

    if (assessment.churnRiskScore !== null) {
      churnAccumulator += assessment.churnRiskScore;
      churnCount += 1;
      if (assessment.churnRiskScore >= 0.5) customerAtRisk = true;
    }

    if (assessment.healthBand?.toLowerCase() === "at_risk") customerAtRisk = true;
    if (customerAtRisk) atRiskCount += 1;
  }

  return {
    total: customers.length,
    averageHealthScore: healthCount ? healthAccumulator / healthCount : null,
    averageChurnRisk: churnCount ? churnAccumulator / churnCount : null,
    bySegment,
    atRiskCount,
  } satisfies CustomerPortfolioSummary;
}

export function computeVendorPortfolioTrend(snapshots: VendorPortfolioSnapshot[]): VendorTrendSummary {
  const points = snapshots
    .map((snapshot) => ({ ...snapshot }))
    .sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime())
    .map(({ timestamp, vendors }) => {
      const summary = summarizeVendorPortfolio(vendors, timestamp);
      return {
        timestamp,
        total: summary.total,
        overdueReviews: summary.overdueReviews,
        dueSoonReviews: summary.dueSoonReviews,
        averageResidualRisk: summary.averageResidualRisk,
      } satisfies VendorTrendPoint;
    });

  const residualRiskChange = computeChange(points.map((point) => point.averageResidualRisk));
  return {
    points,
    residualRiskChange,
    direction: deriveDirection(residualRiskChange, "lower_is_better"),
  } satisfies VendorTrendSummary;
}

export function computeCustomerHealthTrend(snapshots: CustomerHealthSnapshot[]): CustomerTrendSummary {
  const points = snapshots
    .map((snapshot) => ({ ...snapshot }))
    .sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime())
    .map(({ timestamp, customers }) => {
      const summary = summarizeCustomerPortfolio(customers, timestamp);
      return {
        timestamp,
        total: summary.total,
        atRiskCount: summary.atRiskCount,
        averageHealthScore: summary.averageHealthScore,
        averageChurnRisk: summary.averageChurnRisk,
      } satisfies CustomerTrendPoint;
    });

  const healthScoreChange = computeChange(points.map((point) => point.averageHealthScore));
  return {
    points,
    healthScoreChange,
    direction: deriveDirection(healthScoreChange, "higher_is_better"),
  } satisfies CustomerTrendSummary;
}

function coerceNumber(value: unknown, warnings: string[], context: string): number | null {
  if (value === null || value === undefined) {
    warnings.push(`Missing value for ${context}`);
    return null;
  }
  const num = Number(value);
  if (Number.isNaN(num)) {
    warnings.push(`Non-numeric value for ${context}`);
    return null;
  }
  return num;
}

function daysBetween(a: Date, b: Date): number {
  const diff = b.getTime() - a.getTime();
  return Math.round(diff / (1000 * 60 * 60 * 24));
}

function classifyReviewStatus(days: number | null): "on_track" | "due_soon" | "overdue" {
  if (days === null) return "on_track";
  if (days < 0) return "overdue";
  if (days <= REVIEW_DUE_SOON_THRESHOLD_DAYS) return "due_soon";
  return "on_track";
}

function computeChange(values: Array<number | null>): number | null {
  const filtered = values.filter((value): value is number => value !== null && !Number.isNaN(value));
  if (filtered.length < 2) {
    return null;
  }
  return filtered[filtered.length - 1]! - filtered[0]!;
}

function deriveDirection(
  change: number | null,
  preference: "higher_is_better" | "lower_is_better",
): "improving" | "declining" | "steady" | null {
  if (change === null) return null;
  const threshold = 0.01;
  if (Math.abs(change) < threshold) return "steady";
  if (preference === "higher_is_better") {
    return change > 0 ? "improving" : "declining";
  }
  return change < 0 ? "improving" : "declining";
}
