import type {
  SecurityCenterCustomerInsight,
  SecurityCenterVendorInsight,
} from "../clients/securityCenter.js";

const DAY_MS = 24 * 60 * 60 * 1000;

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

export interface TrendAlert {
  severity: "info" | "warning" | "critical";
  metric: string;
  message: string;
}

export interface VendorTrendWindow {
  window: "7d" | "30d";
  residualRiskChange: number | null;
  overdueReviewChange: number | null;
  direction: "improving" | "declining" | "steady" | null;
}

export interface CustomerTrendWindow {
  window: "7d" | "30d";
  healthScoreChange: number | null;
  atRiskChange: number | null;
  direction: "improving" | "declining" | "steady" | null;
}

export interface VendorTrendAnalysis {
  summary: VendorTrendSummary;
  windows: VendorTrendWindow[];
  alerts: TrendAlert[];
}

export interface CustomerTrendAnalysis {
  summary: CustomerTrendSummary;
  windows: CustomerTrendWindow[];
  alerts: TrendAlert[];
}

export interface VendorRiskDashboard {
  kpis: {
    totalVendors: number;
    highRiskVendors: number;
    mediumRiskVendors: number;
    lowRiskVendors: number;
    overdueReviews: number;
    dueSoonReviews: number;
    averageResidualRisk: number | null;
  };
  byRiskLevel: Record<string, number>;
  criticalVendors: VendorHealthAssessment[];
  assessments: VendorHealthAssessment[];
  warnings: string[];
}

export interface CustomerRiskDashboard {
  kpis: {
    totalCustomers: number;
    healthyCustomers: number;
    neutralCustomers: number;
    atRiskCustomers: number;
    averageHealthScore: number | null;
    averageChurnRisk: number | null;
  };
  byHealthBand: Record<string, number>;
  atRiskCustomers: CustomerHealthAssessment[];
  assessments: CustomerHealthAssessment[];
  warnings: string[];
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

export function buildVendorRiskDashboard(
  vendors: SecurityCenterVendorInsight[],
  now = new Date(),
  criticalLimit = 5,
): VendorRiskDashboard {
  const summary = summarizeVendorPortfolio(vendors, now);
  const assessments = vendors.map((vendor) => assessVendorHealth(vendor, now));

  const warnings = assessments.flatMap((assessment) => assessment.warnings);
  const highRisk = assessments.filter((assessment) => assessment.riskLevel.toLowerCase() === "high");
  const critical = assessments
    .filter(
      (assessment) =>
        assessment.reviewStatus === "overdue" ||
        assessment.riskLevel.toLowerCase() === "high" ||
        assessment.businessCriticality?.toLowerCase() === "high",
    )
    .sort((a, b) => (b.residualRiskScore ?? 0) - (a.residualRiskScore ?? 0))
    .slice(0, criticalLimit);

  return {
    kpis: {
      totalVendors: summary.total,
      highRiskVendors: highRisk.length,
      mediumRiskVendors: summary.byRiskLevel.medium ?? 0,
      lowRiskVendors: summary.byRiskLevel.low ?? 0,
      overdueReviews: summary.overdueReviews,
      dueSoonReviews: summary.dueSoonReviews,
      averageResidualRisk: summary.averageResidualRisk,
    },
    byRiskLevel: summary.byRiskLevel,
    criticalVendors: critical,
    assessments,
    warnings,
  } satisfies VendorRiskDashboard;
}

export function buildCustomerRiskDashboard(
  customers: SecurityCenterCustomerInsight[],
  now = new Date(),
  atRiskLimit = 5,
): CustomerRiskDashboard {
  const summary = summarizeCustomerPortfolio(customers, now);
  const assessments = customers.map((customer) => assessCustomerHealth(customer, now));
  const warnings = assessments.flatMap((assessment) => assessment.warnings);

  const byHealthBand: Record<string, number> = {};
  for (const customer of customers) {
    const band = (customer.healthBand ?? "unknown").toLowerCase();
    byHealthBand[band] = (byHealthBand[band] ?? 0) + 1;
  }

  const atRiskCustomers = assessments
    .filter((assessment) => {
      const band = assessment.healthBand?.toLowerCase();
      return band === "at_risk" || band === "critical" || (assessment.healthScore ?? 1) < 0.6 || (assessment.churnRiskScore ?? 0) >= 0.5;
    })
    .sort((a, b) => (b.churnRiskScore ?? 0) - (a.churnRiskScore ?? 0))
    .slice(0, atRiskLimit);

  const healthyCount = byHealthBand.healthy ?? 0;
  const neutralCount = (byHealthBand.neutral ?? 0) + (byHealthBand.stable ?? 0);
  const atRiskCount = summary.atRiskCount;

  return {
    kpis: {
      totalCustomers: summary.total,
      healthyCustomers: healthyCount,
      neutralCustomers: neutralCount,
      atRiskCustomers: atRiskCount,
      averageHealthScore: summary.averageHealthScore,
      averageChurnRisk: summary.averageChurnRisk,
    },
    byHealthBand,
    atRiskCustomers,
    assessments,
    warnings,
  } satisfies CustomerRiskDashboard;
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

export function analyzeVendorSnapshots(
  snapshots: VendorPortfolioSnapshot[],
  now = new Date(),
): VendorTrendAnalysis {
  const summary = computeVendorPortfolioTrend(snapshots);
  const points = summary.points;
  const windows: VendorTrendWindow[] = [7, 30].map((days) => {
    const windowPoints = filterPointsWithin(points, now, days * DAY_MS);
    const residualRiskChange = computeChange(windowPoints.map((point) => point.averageResidualRisk));
    const overdueChange = computeChange(windowPoints.map((point) => point.overdueReviews));
    return {
      window: `${days}d` as VendorTrendWindow["window"],
      residualRiskChange,
      overdueReviewChange: overdueChange,
      direction: deriveDirection(residualRiskChange, "lower_is_better"),
    } satisfies VendorTrendWindow;
  });

  const alerts: TrendAlert[] = [];
  const windowMap = Object.fromEntries(windows.map((win) => [win.window, win]));
  const last30 = windowMap["30d"];
  if (last30?.residualRiskChange !== null && last30.residualRiskChange > 0.05) {
    alerts.push({
      severity: "warning",
      metric: "vendor_residual_risk",
      message: `Vendor residual risk increased by ${(last30.residualRiskChange * 100).toFixed(1)}pts in 30d`,
    });
  }

  if (last30?.overdueReviewChange !== null && last30.overdueReviewChange > 0) {
    alerts.push({
      severity: last30.overdueReviewChange >= 3 ? "critical" : "warning",
      metric: "vendor_overdue_reviews",
      message: `${last30.overdueReviewChange} additional vendor reviews overdue over last 30d`,
    });
  }

  const last7 = windowMap["7d"];
  if (last7?.overdueReviewChange !== null && last7.overdueReviewChange > 0) {
    alerts.push({
      severity: "warning",
      metric: "vendor_overdue_reviews_7d",
      message: `${last7.overdueReviewChange} vendor reviews became overdue in the last 7d`,
    });
  }

  return {
    summary,
    windows,
    alerts,
  } satisfies VendorTrendAnalysis;
}

export function analyzeCustomerSnapshots(
  snapshots: CustomerHealthSnapshot[],
  now = new Date(),
): CustomerTrendAnalysis {
  const summary = computeCustomerHealthTrend(snapshots);
  const points = summary.points;
  const windows: CustomerTrendWindow[] = [7, 30].map((days) => {
    const windowPoints = filterPointsWithin(points, now, days * DAY_MS);
    const healthChange = computeChange(windowPoints.map((point) => point.averageHealthScore));
    const atRiskChange = computeChange(windowPoints.map((point) => point.atRiskCount));
    return {
      window: `${days}d` as CustomerTrendWindow["window"],
      healthScoreChange: healthChange,
      atRiskChange,
      direction: deriveDirection(healthChange, "higher_is_better"),
    } satisfies CustomerTrendWindow;
  });

  const alerts: TrendAlert[] = [];
  const windowMap = Object.fromEntries(windows.map((win) => [win.window, win]));
  const last30 = windowMap["30d"];
  if (last30?.healthScoreChange !== null && last30.healthScoreChange < -0.05) {
    alerts.push({
      severity: "warning",
      metric: "customer_health_score",
      message: `Customer health dropped ${(Math.abs(last30.healthScoreChange) * 100).toFixed(1)}pts over 30d`,
    });
  }

  if (last30?.atRiskChange !== null && last30.atRiskChange > 0) {
    alerts.push({
      severity: last30.atRiskChange >= 3 ? "critical" : "warning",
      metric: "customer_at_risk",
      message: `${last30.atRiskChange} more customers moved to at-risk in the last 30d`,
    });
  }

  const last7 = windowMap["7d"];
  if (last7?.atRiskChange !== null && last7.atRiskChange > 0) {
    alerts.push({
      severity: "warning",
      metric: "customer_at_risk_7d",
      message: `${last7.atRiskChange} customers became at-risk in the last 7d`,
    });
  }

  return {
    summary,
    windows,
    alerts,
  } satisfies CustomerTrendAnalysis;
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

function filterPointsWithin<T extends { timestamp: Date }>(
  points: T[],
  now: Date,
  windowMs: number,
): T[] {
  const minTime = now.getTime() - windowMs;
  return points.filter((point) => point.timestamp.getTime() >= minTime);
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
