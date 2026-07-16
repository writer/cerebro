import { describe, expect, it } from "vitest";

import { routeLabelForPath } from "./route-labels";

describe("route labels", () => {
  it("uses curated labels for known app routes", () => {
    expect(routeLabelForPath("/")).toBe("Home");
    expect(routeLabelForPath("/impact")).toBe("Affected assets");
    expect(routeLabelForPath("/controls/builder")).toBe("Control builder");
    expect(routeLabelForPath("/connectors/builder")).toBe("Connector builder");
    expect(routeLabelForPath("/connectors/activation")).toBe("Source activation");
    expect(routeLabelForPath("/credential-stores")).toBe("Credential stores");
    expect(routeLabelForPath("/identity")).toBe("Members");
    expect(routeLabelForPath("/reports/audit-packages")).toBe("Packet review");
    expect(routeLabelForPath("/reports/shared/fixture-snapshot-1")).toBe("Shared snapshot");
    expect(routeLabelForPath("/developer/security-producers")).toBe("Security producers");
  });

  it("keeps unknown nested developer routes under the developer tools label", () => {
    expect(routeLabelForPath("/developer/runtime-diagnostics")).toBe("Developer Tools");
  });

  it("falls back only for truly unknown routes", () => {
    expect(routeLabelForPath("/custom-route")).toBe("custom route");
  });
});
