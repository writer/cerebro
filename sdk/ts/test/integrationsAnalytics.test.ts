import { describe, expect, it } from "vitest";

import {
  computeCoverageTrendForIntegration,
  computeCoverageTrends,
  groupCoverageByIntegration,
} from "../src/integrations/analytics";
import type { IntegrationCoverageRecord } from "../src/types";

const snapshots: IntegrationCoverageRecord[] = [
  createSnapshot("github", "2024-10-01T00:00:00Z", 0.92),
  createSnapshot("github", "2024-10-02T00:00:00Z", 0.9),
  createSnapshot("github", "2024-10-03T00:00:00Z", 0.82),
  createSnapshot("github", "2024-10-04T00:00:00Z", 0.7),
  createSnapshot("pagerduty", "2024-10-01T00:00:00Z", 0.6),
  createSnapshot("pagerduty", "2024-10-02T00:00:00Z", 0.64),
  createSnapshot("pagerduty", "2024-10-03T00:00:00Z", 0.62),
];

describe("integration coverage analytics", () => {
  it("groups snapshots by integration", () => {
    const grouped = groupCoverageByIntegration(snapshots);
    expect(Object.keys(grouped)).toEqual(["github", "pagerduty"]);
    expect(grouped.github).toHaveLength(4);
    expect(grouped.pagerduty).toHaveLength(3);
  });

  it("computes rolling averages and trend metadata", () => {
    const trend = computeCoverageTrendForIntegration("github", snapshots.filter((snap) => snap.integration === "github"), {
      windowSize: 2,
    });

    expect(trend.integration).toBe("github");
    expect(trend.points).toHaveLength(4);
    expect(trend.rollingAverage[3]?.coverageRatio).toBeCloseTo((0.82 + 0.7) / 2);
    expect(trend.latestChange).toBeCloseTo(0.7 - 0.82);
    expect(trend.improving).toBe(false);
    expect(trend.anomaly?.severity).toBe("warning");
    expect(trend.warnings).toHaveLength(0);
  });

  it("builds trends for all integrations with configurable thresholds", () => {
    const trends = computeCoverageTrends(snapshots, {
      windowSize: 3,
      anomalyThreshold: 0.1,
      criticalThreshold: 0.2,
    });

    expect(trends).toHaveLength(2);
    const pagerduty = trends.find((trend) => trend.integration === "pagerduty");
    expect(pagerduty?.latestChange).toBeCloseTo(0.62 - 0.64);
    expect(pagerduty?.anomaly ?? null).toBeNull();
    expect(pagerduty?.warnings ?? []).toHaveLength(0);
  });

  it("returns empty trend list when no records are provided", () => {
    expect(computeCoverageTrends([], { windowSize: 3 })).toEqual([]);
  });

  it("handles single-point history without anomalies", () => {
    const single = computeCoverageTrendForIntegration("github", [createSnapshot("github", "2024-10-05T00:00:00Z", 0.8)]);
    expect(single.latestChange).toBeNull();
    expect(single.improving).toBeNull();
    expect(single.anomaly).toBeNull();
  });

  it("collects warnings when ratios fall outside expected bounds", () => {
    const trend = computeCoverageTrendForIntegration("github", [
      createSnapshot("github", "2024-10-05T00:00:00Z", 1.2),
      createSnapshot("github", "2024-10-06T00:00:00Z", -0.3),
    ]);

    expect(trend.warnings.length).toBeGreaterThanOrEqual(2);
    expect(trend.points[0]?.coverageRatio).toBe(1);
    expect(trend.points[1]?.coverageRatio).toBe(0);
  });

  it("validates options", () => {
    expect(() => computeCoverageTrendForIntegration("github", snapshots, { windowSize: 0 })).toThrow(RangeError);
    expect(() => computeCoverageTrendForIntegration("github", snapshots, { anomalyThreshold: -0.1 })).toThrow(RangeError);
    expect(() => computeCoverageTrendForIntegration("github", snapshots, { criticalThreshold: -0.1 })).toThrow(RangeError);
  });
});

function createSnapshot(integration: string, evaluatedAtIso: string, ratio: number): IntegrationCoverageRecord {
  const evaluatedAt = new Date(evaluatedAtIso);
  return {
    integration,
    providers: [integration],
    status: "ok",
    scopes: {
      total: 10,
      healthy: Math.round(ratio * 10),
      warning: 2,
      critical: 1,
    },
    accounts: { total: 5 },
    coverageRatio: ratio,
    lastSuccess: evaluatedAt,
    evaluatedAt,
  };
}
