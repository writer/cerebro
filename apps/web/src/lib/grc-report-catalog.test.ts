import { describe, expect, it } from "vitest";

import type { CustomDashboard, CustomDashboardWidget } from "./custom-dashboards";
import {
  buildWidgetReportQuery,
  catalogWidgetSourceID,
  extractReportTable,
  findSource,
  validateWidgetReportQuery,
  type ReportSource,
} from "./grc-report-catalog";

const findingsSource: ReportSource = {
  id: "findings",
  domain: "risk",
  title: "Findings",
  description: "Open findings",
  method: "GET",
  path: "/grc/findings",
  params: [
    { id: "runtime_id", type: "string", scope: true },
    { id: "severity", type: "enum", allowed_values: ["LOW", "MEDIUM", "HIGH", "CRITICAL"] },
    { id: "status", type: "string" },
    { id: "compare", type: "bool" },
    { id: "days", type: "int" },
  ],
  visualizations: ["table"],
  default_limit: 100,
  max_limit: 500,
};

const coverageSource: ReportSource = {
  id: "control-coverage",
  domain: "controls",
  title: "Control coverage",
  description: "Coverage by profile",
  method: "GET",
  path: "/grc/controls/coverage",
  params: [{ id: "profile", type: "string", required: true }],
  visualizations: ["table"],
  default_limit: 100,
  max_limit: 500,
};

const sources = [findingsSource, coverageSource];

const dashboard = (filters: CustomDashboard["filters"]): CustomDashboard => ({
  id: "dash",
  tenant_id: "tenant-a",
  name: "Dash",
  visibility: "private",
  schema_version: 1,
  layout: {},
  widgets: [],
  filters,
  created_at: "2026-06-23T00:00:00Z",
  updated_at: "2026-06-23T00:00:00Z",
});

describe("grc report catalog helpers", () => {
  it("finds sources by id and reads a widget's catalog binding", () => {
    expect(findSource(sources, "findings")?.title).toBe("Findings");
    expect(findSource(sources, "missing")).toBeUndefined();
    expect(catalogWidgetSourceID({ id: "w", type: "report", query: { source_id: " findings " } })).toBe("findings");
    expect(catalogWidgetSourceID({ id: "w", type: "report", query: { endpoint: "/grc/findings" } })).toBe("");
  });

  it("accepts a well-formed query and rejects unknown sources and params", () => {
    expect(validateWidgetReportQuery(findingsSource, { source_id: "findings", params: { severity: "HIGH" } })).toBeNull();
    expect(validateWidgetReportQuery(undefined, { source_id: "nope" })).toContain('Unknown report source "nope"');
    expect(validateWidgetReportQuery(findingsSource, { source_id: "findings", params: { framework: "soc2" } })).toContain(
      'does not support parameter "framework"',
    );
  });

  it("enforces parameter types, enums, required params, and the limit ceiling", () => {
    expect(validateWidgetReportQuery(findingsSource, { source_id: "findings", params: { days: "x" } })).toContain("must be an integer");
    expect(validateWidgetReportQuery(findingsSource, { source_id: "findings", params: { compare: "maybe" } })).toContain("true or false");
    expect(validateWidgetReportQuery(findingsSource, { source_id: "findings", params: { severity: "EXTREME" } })).toContain("must be one of");
    expect(validateWidgetReportQuery(coverageSource, { source_id: "control-coverage", params: {} })).toContain('requires parameter "profile"');
    expect(validateWidgetReportQuery(findingsSource, { source_id: "findings", limit: 9000 })).toContain("at most 500");
  });

  it("builds a query that merges declared dashboard filters with widget params", () => {
    const widget: CustomDashboardWidget = {
      id: "w",
      type: "report",
      query: { source_id: "findings", params: { status: "open" }, limit: 25 },
    };
    const query = buildWidgetReportQuery(findingsSource, dashboard({ runtime_id: "rt-1", severity: "HIGH", unrelated: "x" }).filters, widget);
    expect(query).toEqual({ source_id: "findings", params: { runtime_id: "rt-1", severity: "HIGH", status: "open" }, limit: 25 });
  });

  it("lets widget params override dashboard filters and drops empty or undeclared params", () => {
    const widget: CustomDashboardWidget = {
      id: "w",
      type: "report",
      query: { source_id: "findings", params: { severity: "CRITICAL", status: "", framework: "soc2" } },
    };
    const query = buildWidgetReportQuery(findingsSource, dashboard({ severity: "LOW" }).filters, widget);
    expect(query.params).toEqual({ severity: "CRITICAL" });
    expect(query.limit).toBeUndefined();
  });

  it("shapes a list-shaped envelope into a scalar-only table", () => {
    const table = extractReportTable({
      findings: [
        { id: "f-1", title: "A", severity: "HIGH", nested: { score: 1 } },
        { id: "f-2", title: "B", severity: "LOW" },
      ],
      generated_at: "2026-06-23T00:00:00Z",
    });
    expect(table?.columns).toEqual(["id", "title", "severity"]);
    expect(table?.rows).toHaveLength(2);
  });

  it("caps columns and returns null when nothing is tabular", () => {
    const wide = [Object.fromEntries(Array.from({ length: 12 }, (_, i) => [`c${i}`, i]))];
    expect(extractReportTable({ rows: wide })?.columns).toHaveLength(8);
    expect(extractReportTable({ summary: { open: 3 } })).toBeNull();
    expect(extractReportTable([])).toBeNull();
  });
});
