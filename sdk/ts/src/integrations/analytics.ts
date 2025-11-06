import {
  CoverageAnomaly,
  IntegrationCoverageRecord,
  IntegrationCoverageTrend,
  IntegrationCoverageTrendPoint,
} from "../types.js";

export interface CoverageTrendOptions {
  windowSize?: number;
  anomalyThreshold?: number;
  criticalThreshold?: number;
}

export function groupCoverageByIntegration(records: IntegrationCoverageRecord[]): Record<string, IntegrationCoverageRecord[]> {
  return records.reduce<Record<string, IntegrationCoverageRecord[]>>((acc, record) => {
    const list = acc[record.integration] ?? (acc[record.integration] = []);
    list.push(record);
    return acc;
  }, {});
}

export function computeCoverageTrends(
  records: IntegrationCoverageRecord[],
  options: CoverageTrendOptions = {},
): IntegrationCoverageTrend[] {
  if (!records.length) {
    return [];
  }
  validateOptions(options);
  const grouped = groupCoverageByIntegration(records);
  return Object.entries(grouped).map(([integration, snapshots]) =>
    computeCoverageTrendForIntegration(integration, snapshots, options),
  );
}

export function computeCoverageTrendForIntegration(
  integration: string,
  records: IntegrationCoverageRecord[],
  options: CoverageTrendOptions = {},
): IntegrationCoverageTrend {
  validateOptions(options);
  const warnings: string[] = [];
  const sorted = [...records].sort((a, b) => a.evaluatedAt.getTime() - b.evaluatedAt.getTime());
  const points: IntegrationCoverageTrendPoint[] = sorted.map((record) => {
    const normalized = normalizeRatio(record.coverageRatio, integration, record.evaluatedAt, warnings);
    return {
      evaluatedAt: record.evaluatedAt,
      coverageRatio: normalized,
    };
  });

  if (!points.length) {
    return {
      integration,
      points,
      rollingAverage: [],
      latestChange: null,
      improving: null,
      anomaly: null,
      warnings,
    } satisfies IntegrationCoverageTrend;
  }

  const windowSize = Math.max(1, Math.min(options.windowSize ?? 3, points.length || 1));
  const rollingAverage = points.map((point, index) => ({
    evaluatedAt: point.evaluatedAt,
    coverageRatio: calculateWindowAverage(points, index, windowSize),
  }));

  const latest = points.at(-1) ?? null;
  const previous = points.length > 1 ? points.at(-2) ?? null : null;
  const latestChange = latest && previous && latest.coverageRatio !== null && previous.coverageRatio !== null
    ? latest.coverageRatio - previous.coverageRatio
    : null;
  const improving = latestChange === null ? null : latestChange >= 0;

  const anomaly = detectAnomaly(points, windowSize, options);

  return {
    integration,
    points,
    rollingAverage,
    latestChange,
    improving,
    anomaly,
    warnings,
  } satisfies IntegrationCoverageTrend;
}

function detectAnomaly(
  points: IntegrationCoverageTrendPoint[],
  windowSize: number,
  options: CoverageTrendOptions,
): CoverageAnomaly | null {
  if (points.length < 2) {
    return null;
  }

  const latest = points.at(-1);
  if (!latest || latest.coverageRatio === null) {
    return null;
  }

  const windowPoints = points.slice(-1 - (windowSize ?? 1), -1).filter((point) => point.coverageRatio !== null);
  if (!windowPoints.length) {
    return null;
  }

  const baseline = windowPoints.reduce((total, point) => total + (point.coverageRatio ?? 0), 0) / windowPoints.length;
  const delta = latest.coverageRatio - baseline;

  const threshold = options.anomalyThreshold ?? 0.15;
  const criticalThreshold = options.criticalThreshold ?? threshold * 1.75;

  if (delta >= -threshold) {
    return null;
  }

  return {
    threshold,
    delta,
    severity: delta <= -criticalThreshold ? "critical" : "warning",
  } satisfies CoverageAnomaly;
}

function calculateWindowAverage(
  points: IntegrationCoverageTrendPoint[],
  index: number,
  windowSize: number,
): number | null {
  const start = Math.max(0, index - windowSize + 1);
  const window = points.slice(start, index + 1);
  const ratios = window.map((point) => point.coverageRatio).filter((value): value is number => value !== null);
  if (!ratios.length) {
    return null;
  }
  const total = ratios.reduce((sum, value) => sum + value, 0);
  return total / ratios.length;
}

function normalizeRatio(
  value: number | null,
  integration: string,
  evaluatedAt: Date,
  warnings: string[],
): number | null {
  if (typeof value !== "number" || Number.isNaN(value)) {
    warnings.push(`Missing coverage ratio for ${integration} at ${evaluatedAt.toISOString()}`);
    return null;
  }

  if (!Number.isFinite(value)) {
    warnings.push(`Non-finite coverage ratio for ${integration} at ${evaluatedAt.toISOString()}`);
    return null;
  }

  if (value < 0) {
    warnings.push(`Coverage ratio below 0 clipped for ${integration} at ${evaluatedAt.toISOString()}`);
    return 0;
  }
  if (value > 1) {
    warnings.push(`Coverage ratio above 1 clipped for ${integration} at ${evaluatedAt.toISOString()}`);
    return 1;
  }
  return value;
}

function validateOptions(options: CoverageTrendOptions): void {
  if (options.windowSize !== undefined && options.windowSize <= 0) {
    throw new RangeError(`windowSize must be positive (received ${options.windowSize})`);
  }
  if (options.anomalyThreshold !== undefined && options.anomalyThreshold < 0) {
    throw new RangeError(`anomalyThreshold must be >= 0 (received ${options.anomalyThreshold})`);
  }
  if (options.criticalThreshold !== undefined && options.criticalThreshold < 0) {
    throw new RangeError(`criticalThreshold must be >= 0 (received ${options.criticalThreshold})`);
  }
}
