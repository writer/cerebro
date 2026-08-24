import { describe, expect, it } from "vitest";

import type { GRCControl } from "@/lib/grc";

import { deriveFrameworkReadiness, isControlAuditReady } from "./framework-readiness";

const control = (overrides: Partial<GRCControl> = {}): GRCControl => ({
  control_id: "CC1.1",
  critical_findings: 0,
  evidence_items: 1,
  framework_name: "SOC 2",
  high_findings: 0,
  open_findings: 0,
  status: "passing",
  ...overrides,
});

describe("framework readiness", () => {
  it("does not call a passing control ready when findings or evidence gaps remain", () => {
    expect(isControlAuditReady(control())).toBe(true);
    expect(isControlAuditReady(control({ open_findings: 1 }))).toBe(false);
    expect(isControlAuditReady(control({ missing_evidence_items: 1 }))).toBe(false);
    expect(isControlAuditReady(control({ stale_evidence_items: 1 }))).toBe(false);
  });

  it("derives the displayed score from the packet status ledger", () => {
    expect(deriveFrameworkReadiness({
      byStatus: { failing: 4, missing_evidence: 32 },
      controls: [],
      total: 36,
    })).toEqual({
      evidenceGapControls: 32,
      failingControls: 4,
      needsWorkControls: 36,
      readyControls: 0,
      score: 0,
      totalControls: 36,
    });
  });

  it("uses loaded controls when a summary is not available", () => {
    expect(deriveFrameworkReadiness({
      controls: [control(), control({ control_id: "CC1.2", status: "missing_evidence", missing_evidence_items: 1 })],
    })).toMatchObject({ readyControls: 1, totalControls: 2, score: 50, evidenceGapControls: 1 });
  });

  it("does not hide loaded evidence gaps behind a coarse status summary", () => {
    expect(deriveFrameworkReadiness({
      byStatus: { failing: 1, manual_review: 1 },
      controls: [
        control({ status: "failing", open_findings: 1 }),
        control({ control_id: "CC1.2", status: "manual_review", stale_evidence_items: 1 }),
      ],
      total: 2,
    })).toMatchObject({ readyControls: 0, totalControls: 2, score: 0, evidenceGapControls: 1, failingControls: 1 });
  });
});
