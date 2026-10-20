import { parse as parseYAML } from "yaml";
import { describe, expect, it } from "vitest";

import {
  convertRuleDocument,
  customRulePath,
  defaultRuleCatalogFilters,
  duplicateRuleDocument,
  filterRuleCatalog,
  hasBlockingIssues,
  type RuleCatalogEntry,
  ruleCatalogPath,
  ruleDetailPath,
  ruleIDFromDocument,
  ruleTemplates,
  summarizeRuleCatalog,
} from "./finding-rules";

const entry = (overrides: Partial<RuleCatalogEntry>): RuleCatalogEntry => ({
  id: "rule",
  name: "Rule",
  summary: "",
  severity: "medium",
  origin: "builtin_policy",
  domain: "paas",
  posture: "cspm",
  provider: "aws",
  evaluation: "cel",
  detection: "posture",
  enabled: true,
  ...overrides,
});

const catalog = [
  entry({ id: "aws-low", name: "AWS low", severity: "low" }),
  entry({ id: "aws-critical", name: "AWS critical", severity: "critical", frameworks: ["SOC 2"] }),
  entry({ id: "okta-admin", name: "Okta admin", domain: "identity", posture: "ispm", provider: "okta", severity: "high" }),
  entry({ id: "github-repo", name: "GitHub repo", domain: "saas", posture: "sspm", provider: "github" }),
  entry({ id: "custom-low", name: "Custom low", origin: "custom", severity: "low" }),
  entry({ id: "graph-path", name: "Graph path", domain: "correlation", posture: "correlation", provider: "cerebro", origin: "correlation_pattern" }),
];

describe("filterRuleCatalog", () => {
  it("puts custom rules first, then orders by severity", () => {
    expect(filterRuleCatalog(catalog, { ...defaultRuleCatalogFilters, domain: "paas" }).map((rule) => rule.id))
      .toEqual(["custom-low", "aws-critical", "aws-low"]);
  });

  it("filters by domain, severity, origin, and provider", () => {
    expect(filterRuleCatalog(catalog, { ...defaultRuleCatalogFilters, domain: "identity" }).map((rule) => rule.id)).toEqual(["okta-admin"]);
    expect(filterRuleCatalog(catalog, { ...defaultRuleCatalogFilters, severity: "low" }).map((rule) => rule.id)).toEqual(["custom-low", "aws-low"]);
    expect(filterRuleCatalog(catalog, { ...defaultRuleCatalogFilters, origin: "correlation_pattern" }).map((rule) => rule.id)).toEqual(["graph-path"]);
    expect(filterRuleCatalog(catalog, { ...defaultRuleCatalogFilters, provider: "github" }).map((rule) => rule.id)).toEqual(["github-repo"]);
  });

  it("searches ids, names, and frameworks case-insensitively", () => {
    expect(filterRuleCatalog(catalog, { ...defaultRuleCatalogFilters, query: "soc 2" }).map((rule) => rule.id)).toEqual(["aws-critical"]);
    expect(filterRuleCatalog(catalog, { ...defaultRuleCatalogFilters, query: "OKTA" }).map((rule) => rule.id)).toEqual(["okta-admin"]);
  });
});

describe("summarizeRuleCatalog", () => {
  it("counts every domain but scopes severity, provider, and custom counts to the selected domain", () => {
    const summary = summarizeRuleCatalog(catalog, "paas");
    expect(summary.total).toBe(6);
    expect(summary.byDomain).toEqual({ paas: 3, identity: 1, saas: 1, correlation: 1 });
    expect(summary.bySeverity).toEqual({ low: 2, critical: 1 });
    expect(summary.providers).toEqual([{ provider: "aws", count: 3 }]);
    expect(summary.custom).toBe(1);
  });
});

describe("rule paths", () => {
  it("encodes rule ids and appends the tenant only when set", () => {
    expect(ruleCatalogPath()).toBe("/finding-rules/catalog");
    expect(ruleCatalogPath("tenant a")).toBe("/finding-rules/catalog?tenant_id=tenant%20a");
    expect(ruleDetailPath("a/b", "t")).toBe("/finding-rules/catalog/a%2Fb?tenant_id=t");
    expect(customRulePath("custom-x")).toBe("/finding-rules/custom/custom-x");
  });
});

describe("rule documents", () => {
  it("round-trips YAML and JSON without losing fields", () => {
    const toJSON = convertRuleDocument(ruleTemplates[0].document, "yaml", "json");
    expect(toJSON.ok).toBe(true);
    if (!toJSON.ok) return;
    const back = convertRuleDocument(toJSON.content, "json", "yaml");
    expect(back.ok).toBe(true);
    if (!back.ok) return;
    expect(parseYAML(back.content)).toEqual(parseYAML(ruleTemplates[0].document));
  });

  it("reports conversion errors instead of discarding the draft", () => {
    const result = convertRuleDocument("{not json", "json", "yaml");
    expect(result.ok).toBe(false);
    expect(convertRuleDocument("- a\n- b\n", "yaml", "json").ok).toBe(false);
  });

  it("reads metadata.id from either format", () => {
    expect(ruleIDFromDocument(ruleTemplates[1].document, "yaml")).toBe("custom-github-public-repo-unprotected");
    expect(ruleIDFromDocument('{"metadata":{"id":" custom-x "}}', "json")).toBe("custom-x");
    expect(ruleIDFromDocument("::", "yaml")).toBe("");
  });

  it("duplicates a built-in under a custom id", () => {
    const copy = duplicateRuleDocument("metadata:\n  id: okta-admin-dormant\n  name: Dormant admin\n  lastModified: x\nspec: {}\n", "okta-admin-dormant");
    const parsed = parseYAML(copy ?? "") as { metadata: Record<string, unknown> };
    expect(parsed.metadata.id).toBe("custom-okta-admin-dormant");
    expect(parsed.metadata.name).toBe("Dormant admin (custom)");
    expect(parsed.metadata.lastModified).toBeUndefined();
    expect(duplicateRuleDocument("not: [valid", "x")).toBeNull();
  });

  it("ships one template per domain with unique custom ids", () => {
    expect(ruleTemplates.map((template) => template.domain)).toEqual(["paas", "saas", "identity", "correlation"]);
    const ids = ruleTemplates.map((template) => ruleIDFromDocument(template.document, "yaml"));
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids.every((id) => id.startsWith("custom-"))).toBe(true);
  });

  it("treats only error issues as blocking", () => {
    expect(hasBlockingIssues([{ severity: "warning", message: "w" }])).toBe(false);
    expect(hasBlockingIssues([{ severity: "error", message: "e" }])).toBe(true);
    expect(hasBlockingIssues(undefined)).toBe(false);
  });
});
