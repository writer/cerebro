import { describe, expect, it } from "vitest";

import { isDenseAgentRouteLabel } from "./dense-routes";

describe("dense agent route labels", () => {
  it("keeps the launcher compact on dense audit and GRC pages", () => {
    expect(isDenseAgentRouteLabel("Packet review")).toBe(true);
    expect(isDenseAgentRouteLabel("Audit packages")).toBe(true);
    expect(isDenseAgentRouteLabel("Shared snapshot")).toBe(true);
    expect(isDenseAgentRouteLabel("Reports")).toBe(true);
    expect(isDenseAgentRouteLabel("Compliance")).toBe(true);
  });

  it("uses the full launcher on lighter pages", () => {
    expect(isDenseAgentRouteLabel("Home")).toBe(false);
    expect(isDenseAgentRouteLabel(undefined)).toBe(false);
  });
});
