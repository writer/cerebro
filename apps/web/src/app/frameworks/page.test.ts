import { describe, expect, it } from "vitest";

import type { GRCFramework } from "@/lib/grc";

import { frameworkNeedsWork, frameworkPreview } from "./page";

const framework = (name: string, overrides: Partial<GRCFramework> = {}): GRCFramework => ({
  control_count: 1,
  family_count: 1,
  lifecycle: "active",
  name,
  ...overrides,
});

describe("framework program list", () => {
  it("keeps the default program view bounded until the user browses the full catalog", () => {
    const programs = Array.from({ length: 8 }, (_, index) => framework(`Program ${index + 1}`));

    expect(frameworkPreview(programs, false, false)).toHaveLength(6);
    expect(frameworkPreview(programs, true, false)).toHaveLength(8);
    expect(frameworkPreview(programs, false, true)).toHaveLength(8);
  });

  it("describes setup gaps as work without treating export as a blocker", () => {
    expect(frameworkNeedsWork(framework("Setup complete", { gap_actions: [{ code: "export_audit_packet", label: "Export", priority: 1 }] }))).toBe(false);
    expect(frameworkNeedsWork(framework("Needs setup", { readiness: { auditor_ready_controls: 0, needs_enrichment_controls: 1, placeholder_controls: 0 } }))).toBe(true);
    expect(frameworkNeedsWork(framework("Planned", { lifecycle: "upcoming" }))).toBe(true);
  });
});
