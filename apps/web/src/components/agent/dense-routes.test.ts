import { describe, expect, it } from "vitest";

import { routeLabelForPath } from "@/lib/route-labels";

import { denseAgentRouteLabels, isDenseAgentRouteLabel } from "./dense-routes";

// Every dense label paired with a path that resolves to it.
const denseRoutes: Record<string, string> = {
  "/grc": "Compliance",
  "/controls": "Controls",
  "/evidence": "Evidence",
  "/frameworks": "Frameworks",
  "/policies": "Policy Documents",
  "/reports": "Reports",
  "/reports/packages": "Audit Workspace",
  "/reports/shared/fixture-snapshot-1": "Shared Snapshot",
};

describe("dense agent route labels", () => {
  it("keeps the launcher compact on dense audit and GRC pages", () => {
    for (const [path, label] of Object.entries(denseRoutes)) {
      expect(routeLabelForPath(path), `${path} should resolve to ${label}`).toBe(label);
      expect(isDenseAgentRouteLabel(label), `${label} should be dense`).toBe(true);
    }
  });

  it("carries no label that a route cannot produce", () => {
    expect([...denseAgentRouteLabels].sort()).toEqual([...new Set(Object.values(denseRoutes))].sort());
  });

  it("uses the full launcher on lighter pages", () => {
    expect(isDenseAgentRouteLabel("Home")).toBe(false);
    expect(isDenseAgentRouteLabel(undefined)).toBe(false);
  });
});
