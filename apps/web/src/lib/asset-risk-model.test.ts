import { beforeEach, describe, expect, it } from "vitest";

import { assetRiskFixtureResponse, resetAssetRiskFixturesForTests } from "@/lib/asset-risk-fixtures";
import {
  assetRiskFormFromModel,
  assetRiskModelPath,
  assetRiskPayloadFromForm,
  DEFAULT_ASSET_RISK_MODEL,
  exampleAttackPath,
  splitList,
  type AssetRiskForm,
  type AssetRiskModelResponse,
} from "@/lib/asset-risk-model";

const defaultForm = () => assetRiskFormFromModel(DEFAULT_ASSET_RISK_MODEL);

const payloadOf = (form: AssetRiskForm, tenantID = "") => {
  const result = assetRiskPayloadFromForm(form, tenantID);
  if (!result.ok) throw new Error(result.error);
  return result.payload;
};

const errorOf = (form: AssetRiskForm) => {
  const result = assetRiskPayloadFromForm(form);
  if (result.ok) throw new Error("expected a validation error");
  return result.error;
};

describe("asset risk model form", () => {
  it("round-trips the default model through percentages without drift", () => {
    const payload = payloadOf(defaultForm());
    const expected: Partial<typeof DEFAULT_ASSET_RISK_MODEL> = { ...DEFAULT_ASSET_RISK_MODEL };
    delete expected.model_version;
    delete expected.tenant_id;
    expect(payload).toEqual(expected);
  });

  it("includes the tenant only when one is given", () => {
    expect(payloadOf(defaultForm())).not.toHaveProperty("tenant_id");
    expect(payloadOf(defaultForm(), " writer ").tenant_id).toBe("writer");
    expect(assetRiskModelPath()).toBe("/grc/asset-risk-model");
    expect(assetRiskModelPath("a b")).toBe("/grc/asset-risk-model?tenant_id=a%20b");
  });

  it("normalizes names and derives countermeasure keys from labels", () => {
    const form = defaultForm();
    form.value.classifications = [{ id: "c", name: " Restricted ", percent: 95 }];
    form.countermeasures = [{ id: "m", key: "", label: "Hardware Keys", attributes: "FIDO2, fido2, webauthn", values: "", appliesTo: "", reductionPercent: 70 }];
    const payload = payloadOf(form);
    expect(payload.asset_value.classifications).toEqual({ restricted: 0.95 });
    expect(payload.countermeasures).toEqual([{ key: "hardware_keys", label: "Hardware Keys", attributes: ["fido2", "webauthn"], reduction: 0.7 }]);
  });

  it("rejects values the server would reject", () => {
    const outOfRange = defaultForm();
    outOfRange.exposure.entryPercent = 120;
    expect(errorOf(outOfRange)).toMatch(/Direct compromise probability/);

    const blank = defaultForm();
    blank.vulnerability.knownExploitedPercent = Number.NaN;
    expect(errorOf(blank)).toMatch(/Known exploited/);

    const cvss = defaultForm();
    cvss.vulnerability.cvssHigh = 9.5;
    expect(errorOf(cvss)).toMatch(/CVSS/);

    const duplicateStep = defaultForm();
    duplicateStep.relations.push({ ...duplicateStep.relations[0], id: "dup" });
    expect(errorOf(duplicateStep)).toMatch(/listed twice/);

    const vulnStep = defaultForm();
    vulnStep.relations[0] = { ...vulnStep.relations[0], name: "affected_by" };
    expect(errorOf(vulnStep)).toMatch(/vulnerability relation/);

    const noSteps = defaultForm();
    noSteps.relations = [];
    expect(errorOf(noSteps)).toMatch(/at least one attack step/);

    const noAttributes = defaultForm();
    noAttributes.countermeasures[0] = { ...noAttributes.countermeasures[0], attributes: " , " };
    expect(errorOf(noAttributes)).toMatch(/at least one attribute/);

    const depth = defaultForm();
    depth.traversal.maxDepth = 7;
    expect(errorOf(depth)).toMatch(/Maximum path length/);

    const levels = defaultForm();
    levels.thresholds = { critical: 20, high: 20, medium: 8 };
    expect(errorOf(levels)).toMatch(/Risk levels/);
  });

  it("splits comma lists into unique lowercase keys", () => {
    expect(splitList(" Public, public_ip ,, PUBLIC ")).toEqual(["public", "public_ip"]);
  });
});

describe("worked example", () => {
  it("matches the server's probability chain for the default model", () => {
    const example = exampleAttackPath(defaultForm());
    const entry = 1 - (1 - 0.2) * (1 - 0.85 * 0.4);
    expect(example.steps[0].probability).toBeCloseTo(entry, 9);
    const reached = entry * 0.7 * 0.95 * 0.9;
    expect(example.probability).toBeCloseTo(reached, 9);
    expect(example.targetValue).toBe(1);
    expect(example.score).toBe(28);
    expect(example.level).toBe("high");
  });

  it("reacts to edits", () => {
    const form = defaultForm();
    const baseline = exampleAttackPath(form).score;
    form.countermeasures = [];
    form.exposure.internalPercent = 100;
    expect(exampleAttackPath(form).score).toBeGreaterThan(baseline);
    form.relations = form.relations.filter((row) => row.name !== "same_actor");
    expect(exampleAttackPath(form).score).toBe(0);
  });
});

describe("asset risk fixtures", () => {
  beforeEach(() => resetAssetRiskFixturesForTests());

  it("serves defaults, saves sections, and resets", () => {
    const initial = assetRiskFixtureResponse("GET", "grc/asset-risk-model");
    expect((initial?.payload as AssetRiskModelResponse).persisted).toBe(false);

    const saved = assetRiskFixtureResponse("PUT", "grc/asset-risk-model", JSON.stringify({ countermeasures: [] }));
    const savedModel = (saved?.payload as AssetRiskModelResponse).model;
    expect((saved?.payload as AssetRiskModelResponse).persisted).toBe(true);
    expect(savedModel.countermeasures).toEqual([]);
    expect(savedModel.relations).toEqual(DEFAULT_ASSET_RISK_MODEL.relations);

    const reset = assetRiskFixtureResponse("DELETE", "grc/asset-risk-model");
    expect((reset?.payload as AssetRiskModelResponse).persisted).toBe(false);
    expect(assetRiskFixtureResponse("GET", "grc/other")).toBeNull();
    expect(assetRiskFixtureResponse("PUT", "grc/asset-risk-model", "{")?.status).toBe(400);
  });
});
