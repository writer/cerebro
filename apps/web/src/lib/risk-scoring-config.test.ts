import { describe, expect, it } from "vitest";

import {
  DEFAULT_RISK_SCORING_CONFIG,
  riskScoringConfigPath,
  riskScoringFormFromConfig,
  riskScoringPayloadFromForm,
  validateSignals,
  validateThresholds,
} from "@/lib/risk-scoring-config";

describe("riskScoringConfigPath", () => {
  it("encodes tenant IDs", () => {
    expect(riskScoringConfigPath("tenant with space")).toBe("/grc/risk-scoring-config?tenant_id=tenant%20with%20space");
  });
});

describe("riskScoringFormFromConfig", () => {
  it("serializes weight maps for editing", () => {
    const form = riskScoringFormFromConfig(DEFAULT_RISK_SCORING_CONFIG);
    expect(form.thresholds.critical).toBe(85);
    expect(JSON.parse(form.relationWeightsJSON).can_admin).toBe(10);
    expect(JSON.parse(form.factorWeightsJSON).external_exposure.likelihood).toBe(35);
  });
});

describe("riskScoringPayloadFromForm", () => {
  it("builds a validated payload", () => {
    const form = riskScoringFormFromConfig(DEFAULT_RISK_SCORING_CONFIG);
    form.tenantID = " writer ";
    const result = riskScoringPayloadFromForm(form);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.payload.tenant_id).toBe("writer");
    }
  });

  it("rejects invalid JSON", () => {
    const form = riskScoringFormFromConfig(DEFAULT_RISK_SCORING_CONFIG);
    form.relationWeightsJSON = "{";
    const result = riskScoringPayloadFromForm(form);
    expect(result.ok).toBe(false);
  });
});

describe("validateThresholds", () => {
  it("requires descending thresholds", () => {
    expect(validateThresholds({ critical: 60, high: 70, medium: 40 })).toContain("critical > high > medium");
  });
});

describe("validateSignals", () => {
  it("requires ordered EPSS and CVSS thresholds", () => {
    expect(validateSignals({ epss_high: 0.2, epss_elevated: 0.7, cvss_critical: 9, cvss_high: 7, private_network_likelihood_cap: 35 })).toContain("EPSS");
    expect(validateSignals({ epss_high: 0.7, epss_elevated: 0.2, cvss_critical: 6, cvss_high: 7, private_network_likelihood_cap: 35 })).toContain("CVSS");
  });
});
