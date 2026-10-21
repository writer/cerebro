import { beforeEach, describe, expect, it } from "vitest";

import { findingRuleFixtureResponse, resetFindingRuleFixturesForTests } from "./finding-rule-fixtures";
import { type RuleCatalogResponse, type RuleTestResult, type RuleValidationResult, ruleTemplates } from "./finding-rules";

const body = (payload: unknown) => JSON.stringify(payload);
const template = ruleTemplates[0];

describe("finding rule fixtures", () => {
  beforeEach(() => resetFindingRuleFixturesForTests());

  it("lists built-ins across every domain", () => {
    const result = findingRuleFixtureResponse("GET", "finding-rules/catalog");
    const catalog = result?.payload as RuleCatalogResponse;
    expect(new Set(catalog.rules.map((rule) => rule.domain))).toEqual(new Set(["paas", "saas", "identity", "correlation"]));
    expect(JSON.stringify(catalog).toLowerCase()).not.toContain("wiz");
  });

  it("validates templates and rejects built-in ids", () => {
    const valid = findingRuleFixtureResponse("POST", "finding-rules/validate", body({ format: "yaml", content: template.document }))?.payload as RuleValidationResult;
    expect(valid.valid).toBe(true);
    expect(valid.preview?.domain).toBe("paas");
    const reserved = findingRuleFixtureResponse("POST", "finding-rules/validate", body({
      format: "yaml",
      content: template.document.replace("custom-s3-bucket-public-unencrypted", "okta-admin-dormant"),
    }))?.payload as RuleValidationResult;
    expect(reserved.valid).toBe(false);
  });

  it("tests a sample resource against simple conditions", () => {
    const matched = findingRuleFixtureResponse("POST", "finding-rules/test", body({ format: "yaml", content: template.document, resource: template.sampleResource }))?.payload as RuleTestResult;
    expect(matched).toMatchObject({ evaluated: true, matched: true });
    const passed = findingRuleFixtureResponse("POST", "finding-rules/test", body({ format: "yaml", content: template.document, resource: { public_access: false } }))?.payload as RuleTestResult;
    expect(passed).toMatchObject({ evaluated: true, matched: false });
  });

  it("saves, lists, and deletes custom rules", () => {
    const id = "custom-s3-bucket-public-unencrypted";
    expect(findingRuleFixtureResponse("PUT", "finding-rules/custom/other-id", body({ format: "yaml", content: template.document }))?.status).toBe(400);
    expect(findingRuleFixtureResponse("PUT", `finding-rules/custom/${id}`, body({ format: "yaml", content: template.document }))?.status).toBe(200);
    const catalog = findingRuleFixtureResponse("GET", "finding-rules/catalog")?.payload as RuleCatalogResponse;
    expect(catalog.rules.find((rule) => rule.id === id)?.origin).toBe("custom");
    expect(findingRuleFixtureResponse("GET", `finding-rules/catalog/${id}`)?.status).toBe(200);
    expect(findingRuleFixtureResponse("DELETE", `finding-rules/custom/${id}`)?.status).toBe(200);
    expect(findingRuleFixtureResponse("GET", `finding-rules/catalog/${id}`)?.status).toBe(404);
  });

  it("ignores unrelated paths", () => {
    expect(findingRuleFixtureResponse("GET", "finding-rules")).toBeNull();
  });
});
