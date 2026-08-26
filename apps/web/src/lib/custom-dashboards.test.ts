import { describe, expect, it } from "vitest";

import {
  customDashboardCreatePayload,
  customDashboardFindingsPath,
  customDashboardFrameworksPath,
  customDashboardSummaryPath,
  customDashboardScopedPath,
  customDashboardTemplateWidgets,
  customDashboardTrendPath,
  sortCustomDashboards,
  validateCustomDashboardName,
  type CustomDashboard,
} from "./custom-dashboards";

const dashboard = (id: string, updated_at: string): CustomDashboard => ({
  id,
  tenant_id: "tenant-a",
  workspace_id: "workspace-a",
  name: id,
  visibility: "private",
  schema_version: 1,
  layout: {},
  widgets: [],
  filters: { tenant_id: "tenant-a", severity: "HIGH" },
  created_at: updated_at,
  updated_at,
});

describe("custom dashboard helpers", () => {
  it("validates names and builds clean create payloads", () => {
    expect(validateCustomDashboardName("  ")).toEqual({ ok: false, error: "Name is required." });
    const payload = customDashboardCreatePayload({
      name: " Trends ",
      tenantID: " tenant-a ",
      workspaceID: "",
      visibility: "workspace",
      filters: { tenant_id: "tenant-a", severity: "" },
    });
    expect(payload).toMatchObject({
      name: "Trends",
      tenant_id: "tenant-a",
      visibility: "workspace",
      filters: { tenant_id: "tenant-a" },
    });
  });

  it("sorts dashboards newest first", () => {
    expect(sortCustomDashboards([
      dashboard("old", "2026-06-22T00:00:00Z"),
      dashboard("new", "2026-06-23T00:00:00Z"),
    ]).map((item) => item.id)).toEqual(["new", "old"]);
  });

  it("builds trend widget paths from dashboard filters and widget params", () => {
    const path = customDashboardTrendPath(dashboard("dash", "2026-06-23T00:00:00Z"), {
      id: "trend",
      type: "trend_chart",
      query: { params: { interval: "month", days: 180, compare: false } },
    });
    expect(path).toContain("/grc/trends?");
    expect(path).toContain("tenant_id=tenant-a");
    expect(path).toContain("workspace_id=workspace-a");
    expect(path).toContain("severity=HIGH");
    expect(path).toContain("interval=month");
    expect(path).not.toContain("compare=");
  });

  it("builds broadened widget paths from dashboard filters", () => {
    const dash = dashboard("dash", "2026-06-23T00:00:00Z");
    const summary = customDashboardSummaryPath(dash, { id: "s", type: "summary_metrics" });
    expect(summary).toContain("/grc/dashboard?");
    expect(summary).toContain("view=summary");
    expect(summary).toContain("tenant_id=tenant-a");
    expect(summary).toContain("workspace_id=workspace-a");
    const findings = customDashboardFindingsPath(dash, { id: "f", type: "findings_table", query: { params: { limit: 5 } } });
    expect(findings).toContain("/grc/findings?");
    expect(findings).toContain("severity=HIGH");
    expect(findings).toContain("tenant_id=tenant-a");
    expect(findings).toContain("workspace_id=workspace-a");
    expect(findings).toContain("status=open");
    expect(findings).toContain("limit=5");
    const frameworks = customDashboardFrameworksPath(dash);
    expect(frameworks).toContain("/grc/frameworks?");
    expect(frameworks).toContain("tenant_id=tenant-a");
    expect(frameworks).toContain("workspace_id=workspace-a");
  });

  it("uses immutable dashboard scope instead of mutable widget filters", () => {
    const dash = dashboard("dash", "2026-06-23T00:00:00Z");
    dash.filters.tenant_id = "tenant-other";
    const path = customDashboardFindingsPath(dash, {
      id: "f",
      type: "findings_table",
      query: { params: { tenant_id: "tenant-widget" } },
    });
    expect(path).toContain("tenant_id=tenant-a");
    expect(path).toContain("workspace_id=workspace-a");
    expect(path).not.toContain("tenant-other");
    expect(path).not.toContain("tenant-widget");
  });

  it("preserves dashboard scope on drilldown links", () => {
    const path = customDashboardScopedPath("/findings/finding-a", dashboard("dash", "2026-06-23T00:00:00Z"));
    expect(path).toBe("/findings/finding-a?tenant_id=tenant-a&workspace_id=workspace-a");
  });

  it("resolves template widget sets with known widget types", () => {
    expect(customDashboardTemplateWidgets("trends").map((w) => w.type)).toContain("trend_chart");
    const overview = customDashboardTemplateWidgets("overview").map((w) => w.type);
    expect(overview).toEqual(expect.arrayContaining(["summary_metrics", "findings_table", "framework_progress", "connector_health"]));
  });
});
