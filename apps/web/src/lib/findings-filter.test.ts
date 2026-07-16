import { describe, expect, it } from "vitest";

import type { GRCFinding } from "@/lib/grc";
import { filterRiskInboxFindings } from "@/lib/findings-filter";

const finding = (overrides: Partial<GRCFinding> = {}): GRCFinding => ({
  id: "finding-1",
  title: "Open S3 bucket",
  severity: "HIGH",
  status: "open",
  evidence_count: 1,
  owner: "Security",
  risk_score: 80,
  sla_status: "due",
  ...overrides,
});

describe("filterRiskInboxFindings", () => {
  it("matches unassigned and named owner filters", () => {
    const findings = [
      finding({ id: "assigned", owner: "Security Operations" }),
      finding({ id: "empty-owner", owner: "" }),
      finding({ id: "literal-unassigned", owner: "Unassigned" }),
    ];

    expect(filterRiskInboxFindings(findings, { owner: "security" }).map((item) => item.id)).toEqual(["assigned"]);
    expect(filterRiskInboxFindings(findings, { owner: "unassigned" }).map((item) => item.id)).toEqual(["empty-owner", "literal-unassigned"]);
  });

  it("matches query text across finding metadata and sorts by risk", () => {
    const findings = [
      finding({ id: "lower-risk", policy_name: "Vendor review", risk_score: 40 }),
      finding({ id: "higher-risk", resource_urns: ["urn:vendor:acme"], risk_score: 95 }),
      finding({ id: "miss", title: "No match", risk_score: 100 }),
    ];

    expect(filterRiskInboxFindings(findings, { query: "vendor" }).map((item) => item.id)).toEqual(["higher-risk", "lower-risk"]);
  });
});
