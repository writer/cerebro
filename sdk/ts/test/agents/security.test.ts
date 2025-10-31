import { describe, expect, it } from "vitest";

import {
  deriveSecurityInsights,
  summarizeSecurityHealth,
  scoreSecurityInsight,
  formatSecurityInsight,
  deriveHostSecurityInsights,
  summarizeFleetSecurity,
} from "../../src/agents/security";
import type { HostSecurityRecord } from "../../src/types";
import type { SecuritySoftwareRecord } from "../../src/types";

const sentinelRecord: SecuritySoftwareRecord = {
  vendor: "SentinelOne",
  product: "SentinelOne Agent",
  installed: true,
  running: true,
  installPath: "/Library/SentinelOne",
  notes: {
    health_ok: "true",
    health_issues: "",
    connectivity_ok: "true",
    anti_tamper_enabled: "true",
    agent_enabled: "true",
    service_active: "true",
    registration_token_present: "true",
    registration_token_stale: "false",
    registration_token_age_hours: "12.5",
    registration_token_size_bytes: "256",
    management_profile_present: "true",
    package_version_mismatch: "false",
    scan_recent: "true",
    scan_last_seen_hours: "3.25",
    package_version: "23.2.1-1",
    site_name: "Example Org",
    policy_name: "Default Policy",
    management_url_host: "sentinelone.example",
  },
};

const kandjiRecord: SecuritySoftwareRecord = {
  vendor: "Kandji",
  product: "Kandji Agent",
  installed: true,
  running: true,
  notes: {
    kandji_health_ok: "false",
    kandji_health_issues: "pending_items,last_run_stale",
    kandji_library_state_ok: "true",
    kandji_last_run_recent: "false",
    kandji_last_run_hours: "30",
    kandji_last_check_in_recent: "true",
    kandji_last_check_in_hours: "5",
    kandji_enforced: "true",
    kandji_has_pending: "true",
    kandji_pending_items: "2",
  },
};

const genericRecord: SecuritySoftwareRecord = {
  vendor: "CrowdStrike",
  product: "Falcon Sensor",
  installed: true,
  running: false,
  notes: {
    health_ok: "unknown",
    health_issues: "sensor_disabled",
  },
};

describe("deriveSecurityInsights", () => {
  it("extracts SentinelOne metadata", () => {
    const [insight] = deriveSecurityInsights([sentinelRecord]);

    expect(insight.vendor).toBe("SentinelOne");
    expect(insight.product).toBe("SentinelOne Agent");
    expect(insight.metadata.healthOk).toBe(true);
    expect(insight.metadata.healthIssues).toEqual([]);
    expect(insight.metadata.connectivityOk).toBe(true);
    expect(insight.metadata.registrationTokenAgeHours).toBeCloseTo(12.5);
    expect(insight.metadata.registrationTokenSizeBytes).toBe(256);
    expect(insight.metadata.scanLastSeenHours).toBeCloseTo(3.25);
    expect(insight.metadata.managementUrlHost).toBe("sentinelone.example");
    expect(insight.metadata.siteName).toBe("Example Org");
    expect(insight.metadata.packageVersion).toBe("23.2.1-1");
    expect(insight.metadata.packageVersionMismatch).toBe(false);
  });

  it("extracts Kandji metadata", () => {
    const [, insight] = deriveSecurityInsights([sentinelRecord, kandjiRecord]);

    expect(insight.vendor).toBe("Kandji");
    expect(insight.metadata.healthOk).toBe(false);
    expect(insight.metadata.healthIssues).toEqual(["pending_items", "last_run_stale"]);
    expect(insight.metadata.lastRunRecent).toBe(false);
    expect(insight.metadata.lastRunHours).toBe(30);
    expect(insight.metadata.lastCheckInRecent).toBe(true);
    expect(insight.metadata.lastCheckInHours).toBe(5);
    expect(insight.metadata.pendingItems).toBe(2);
    expect(insight.metadata.hasPending).toBe(true);
  });

  it("falls back to generic metadata for unknown vendors", () => {
    const [insight] = deriveSecurityInsights([genericRecord]);

    expect(insight.vendor).toBe("CrowdStrike");
    expect(insight.metadata.healthOk).toBeNull();
    expect(insight.metadata.healthIssues).toEqual(["sensor_disabled"]);
    expect(Object.keys(insight.metadata.rawNotes)).toContain("health_ok");
  });
});

describe("summarizeSecurityHealth", () => {
  it("aggregates health information across insights", () => {
    const insights = deriveSecurityInsights([sentinelRecord, kandjiRecord, genericRecord]);
    const summary = summarizeSecurityHealth(insights);

    expect(summary.total).toBe(3);
    expect(summary.healthy).toBe(1);
    expect(summary.degraded).toBe(1);
    expect(summary.unknown).toBe(1);
    expect(summary.vendors["SentinelOne"].healthy).toBe(1);
    expect(summary.vendors["Kandji"].degraded).toBe(1);
    expect(summary.vendors["CrowdStrike"].unknown).toBe(1);
  });
});

describe("scoreSecurityInsight", () => {
  it("awards full score for healthy SentinelOne insight", () => {
    const [insight] = deriveSecurityInsights([sentinelRecord]);
    const score = scoreSecurityInsight(insight);

    expect(score.score).toBe(100);
    expect(score.normalized).toBe(100);
    expect(score.issueLabels).toEqual([]);
  });

  it("applies penalties when issues are present", () => {
    const insights = deriveSecurityInsights([kandjiRecord]);
    const score = scoreSecurityInsight(insights[0]);

    expect(score.score).toBeLessThan(100);
    expect(score.issueLabels.length).toBeGreaterThan(0);
  });
});

describe("formatSecurityInsight", () => {
  it("produces a readable summary", () => {
    const [insight] = deriveSecurityInsights([sentinelRecord]);
    const summary = formatSecurityInsight(insight);

    expect(summary).toContain("SentinelOne");
    expect(summary).toContain("Healthy");
    expect(summary).toContain("score 100.0%");
  });
});

describe("deriveHostSecurityInsights", () => {
  it("summarizes host-level insights and scores", () => {
    const host: HostSecurityRecord = {
      hostId: "host-1",
      hostname: "example-host",
      securitySoftware: [sentinelRecord, kandjiRecord],
    };
    const result = deriveHostSecurityInsights(host);

    expect(result.hostId).toBe("host-1");
    expect(result.insights.length).toBe(2);
    expect(result.health.total).toBe(2);
    expect(result.scorecard.averageNormalized).not.toBeNull();
    expect(result.scorecard.worstScore).not.toBeNull();
  });
});

describe("summarizeFleetSecurity", () => {
  it("aggregates across multiple hosts", () => {
    const hosts: HostSecurityRecord[] = [
      { hostId: "host-1", securitySoftware: [sentinelRecord] },
      { hostId: "host-2", securitySoftware: [kandjiRecord] },
      { hostId: "host-3", securitySoftware: [] },
    ];

    const summary = summarizeFleetSecurity(hosts);

    expect(summary.totalHosts).toBe(3);
    expect(summary.hostsWithSecuritySoftware).toBe(2);
    expect(summary.totalInsights).toBe(2);
    expect(summary.health.total).toBe(2);
    expect(summary.averageNormalizedScore).not.toBeNull();
    expect(summary.worstInsight).not.toBeNull();
    expect(summary.worstScore).not.toBeNull();
  });
});
