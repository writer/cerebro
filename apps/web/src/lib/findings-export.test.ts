import { describe, expect, it } from "vitest";

import type { GRCFinding } from "@/lib/grc";
import { findingsToCSV } from "@/lib/findings-export";

const finding = (overrides: Partial<GRCFinding> = {}): GRCFinding => ({
  id: "finding-1",
  title: "Open S3 bucket",
  severity: "HIGH",
  status: "open",
  evidence_count: 2,
  owner: "Security",
  sla_status: "due",
  ...overrides,
});

describe("findingsToCSV", () => {
  it("serializes only the visible findings passed to export", () => {
    const csv = findingsToCSV([
      finding({
        id: "finding-2",
        title: "Vendor has missing SOC2",
        owner: "Third Party Risk",
        resource_urns: ["urn:vendor:acme", "urn:vendor:globex"],
        controls: [{ framework_name: "SOC2", control_id: "CC6.1" }],
      }),
    ]);

    expect(csv).toContain("finding-2,Vendor has missing SOC2");
    expect(csv).toContain("Third Party Risk");
    expect(csv).toContain("urn:vendor:acme; urn:vendor:globex");
    expect(csv).toContain("SOC2 CC6.1");
    expect(csv).not.toContain("finding-1");
  });

  it("quotes CSV values and neutralizes spreadsheet formulas", () => {
    const csv = findingsToCSV([
      finding({
        id: "finding-3",
        title: "Owner entered, with comma",
        owner: "=cmd|' /C calc'!A0",
      }),
    ]);

    expect(csv).toContain('"Owner entered, with comma"');
    expect(csv).toContain(",'=cmd|' /C calc'!A0,");
  });
});
