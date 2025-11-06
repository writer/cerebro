import { describe, expect, it } from "vitest";

import {
  customerFilterPresets,
  resolveCustomerPreset,
  resolveVendorPreset,
  vendorFilterPresets,
} from "../src/securityCenter/presets";

describe("security center presets", () => {
  it("provides immutable vendor presets", () => {
    expect(vendorFilterPresets.criticalVendors?.riskLevel).toBe("high");
    const options = resolveVendorPreset("criticalVendors", { region: "emea" });
    expect(options.businessCriticality).toBe("high");
    expect(options.region).toBe("emea");
  });

  it("resolves customer presets with overrides", () => {
    const preset = resolveCustomerPreset("atRiskRenewals", { accountManager: "csm-jane" });
    expect(preset.healthBand).toBe("at_risk");
    expect(preset.accountManager).toBe("csm-jane");
    expect(Object.isFrozen(customerFilterPresets)).toBe(false);
  });
});
