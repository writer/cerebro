import { grcDashboardPath, grcPath } from "@/lib/grc-client";

export type CustomDashboardVisibility = "private" | "workspace" | "organization";

export type CustomDashboardWidgetType =
  | "trend_metric_cards"
  | "trend_chart"
  | "trend_aging_table"
  | "trend_period_comparison"
  | "summary_metrics"
  | "findings_table"
  | "framework_progress"
  | "connector_health"
  | "markdown_note";

export const CUSTOM_DASHBOARD_SCHEMA_VERSION = 1;

export type CustomDashboardWidget = {
  id: string;
  type: CustomDashboardWidgetType | string;
  title?: string;
  query?: {
    endpoint?: string;
    source_id?: string;
    params?: Record<string, string | number | boolean | undefined>;
    limit?: number;
  };
  layout?: {
    x?: number;
    y?: number;
    w?: number;
    h?: number;
  };
};

export type CustomDashboard = {
  id: string;
  tenant_id: string;
  organization_id?: string;
  workspace_id?: string;
  owner_user_id?: string;
  name: string;
  description?: string;
  visibility: CustomDashboardVisibility;
  schema_version: number;
  layout: Record<string, unknown>;
  widgets: CustomDashboardWidget[];
  filters: Record<string, string | number | boolean | undefined>;
  created_by?: string;
  updated_by?: string;
  created_at: string;
  updated_at: string;
};

export type CustomDashboardResponse = { dashboard: CustomDashboard };
export type CustomDashboardListResponse = { dashboards: CustomDashboard[] };

export const CUSTOM_DASHBOARD_MAX_NAME_LENGTH = 200;

export type CustomDashboardNameValidation = { ok: true; name: string } | { ok: false; error: string };

export const validateCustomDashboardName = (name: string): CustomDashboardNameValidation => {
  const trimmed = name.trim();
  if (trimmed === "") {
    return { ok: false, error: "Name is required." };
  }
  if (trimmed.length > CUSTOM_DASHBOARD_MAX_NAME_LENGTH) {
    return { ok: false, error: `Name must be at most ${CUSTOM_DASHBOARD_MAX_NAME_LENGTH} characters.` };
  }
  return { ok: true, name: trimmed };
};

export const sortCustomDashboards = (dashboards: CustomDashboard[]): CustomDashboard[] =>
  [...dashboards].sort((a, b) => (b.updated_at ?? "").localeCompare(a.updated_at ?? ""));

export const customDashboardListPath = (params: { tenantID?: string; workspaceID?: string } = {}) =>
  grcPath("/grc/dashboards", {
    tenant_id: params.tenantID,
    workspace_id: params.workspaceID,
  });

export const customDashboardPath = (dashboardID: string) => `/grc/dashboards/${encodeURIComponent(dashboardID)}`;

export const customDashboardClonePath = (dashboardID: string) => `${customDashboardPath(dashboardID)}/clone`;

export const customDashboardTrendPath = (dashboard: CustomDashboard, widget: CustomDashboardWidget) => {
  const params = {
    ...dashboard.filters,
    ...(widget.query?.params ?? {}),
  };
  return grcPath("/grc/trends", {
    interval: stringParam(params.interval, "week"),
    days: numberParam(params.days, 90),
    tenant_id: stringParam(params.tenant_id),
    runtime_id: stringParam(params.runtime_id),
    source_id: stringParam(params.source_id),
    severity: stringParam(params.severity),
    framework: stringParam(params.framework),
    compare: booleanParam(params.compare, true) ? "true" : undefined,
    mttr_target_days: stringParam(params.mttr_target_days, "30"),
    backlog_target: stringParam(params.backlog_target),
    sla_target_days: stringParam(params.sla_target_days, "30"),
  });
};

const mergedWidgetParams = (dashboard: CustomDashboard, widget: CustomDashboardWidget) => ({
  ...dashboard.filters,
  ...(widget.query?.params ?? {}),
});

export const customDashboardSummaryPath = (dashboard: CustomDashboard, widget: CustomDashboardWidget) => {
  const params = mergedWidgetParams(dashboard, widget);
  return grcDashboardPath({
    tenant_id: stringParam(params.tenant_id),
    limit: numberParam(params.limit, 100),
  });
};

export const customDashboardFindingsPath = (dashboard: CustomDashboard, widget: CustomDashboardWidget) => {
  const params = mergedWidgetParams(dashboard, widget);
  return grcPath("/grc/findings", {
    tenant_id: stringParam(params.tenant_id),
    runtime_id: stringParam(params.runtime_id),
    source_id: stringParam(params.source_id),
    severity: stringParam(params.severity),
    framework: stringParam(params.framework),
    status: stringParam(params.status, "open"),
    limit: numberParam(params.limit, 10),
  });
};

export const customDashboardFrameworksPath = (dashboard: CustomDashboard, widget: CustomDashboardWidget) => {
  const params = mergedWidgetParams(dashboard, widget);
  return grcPath("/grc/frameworks", {
    tenant_id: stringParam(params.tenant_id),
  });
};

export const defaultTrendDashboardWidgets = (): CustomDashboardWidget[] => [
  {
    id: "trend-metrics",
    type: "trend_metric_cards",
    title: "Trend metrics",
    query: { endpoint: "/grc/trends", params: { interval: "week", days: 90, compare: true, mttr_target_days: 30, sla_target_days: 30 } },
    layout: { x: 0, y: 0, w: 12, h: 2 },
  },
  {
    id: "trend-flow",
    type: "trend_chart",
    title: "Finding flow",
    query: { endpoint: "/grc/trends", params: { interval: "week", days: 90, compare: true, mttr_target_days: 30, sla_target_days: 30 } },
    layout: { x: 0, y: 2, w: 8, h: 4 },
  },
  {
    id: "open-aging",
    type: "trend_aging_table",
    title: "Open aging",
    query: { endpoint: "/grc/trends", params: { interval: "week", days: 90 } },
    layout: { x: 8, y: 2, w: 4, h: 4 },
  },
  {
    id: "period-comparison",
    type: "trend_period_comparison",
    title: "Period comparison",
    query: { endpoint: "/grc/trends", params: { interval: "week", days: 90, compare: true } },
    layout: { x: 0, y: 6, w: 6, h: 3 },
  },
];

export const defaultOverviewDashboardWidgets = (): CustomDashboardWidget[] => [
  {
    id: "overview-summary",
    type: "summary_metrics",
    title: "Program summary",
    query: { endpoint: "/grc/dashboard", params: { limit: 100 } },
    layout: { x: 0, y: 0, w: 12, h: 2 },
  },
  {
    id: "overview-findings",
    type: "findings_table",
    title: "Top open findings",
    query: { endpoint: "/grc/findings", params: { status: "open", limit: 10 } },
    layout: { x: 0, y: 2, w: 8, h: 4 },
  },
  {
    id: "overview-connectors",
    type: "connector_health",
    title: "Connector health",
    query: { endpoint: "/grc/dashboard", params: { limit: 100 } },
    layout: { x: 8, y: 2, w: 4, h: 4 },
  },
  {
    id: "overview-frameworks",
    type: "framework_progress",
    title: "Framework coverage",
    query: { endpoint: "/grc/frameworks", params: {} },
    layout: { x: 0, y: 6, w: 12, h: 3 },
  },
];

export type CustomDashboardTemplateID = "trends" | "overview";

export const customDashboardTemplates: Array<{ id: CustomDashboardTemplateID; label: string; widgets: () => CustomDashboardWidget[] }> = [
  { id: "trends", label: "Trends", widgets: defaultTrendDashboardWidgets },
  { id: "overview", label: "Program overview", widgets: defaultOverviewDashboardWidgets },
];

export const customDashboardTemplateWidgets = (template: CustomDashboardTemplateID): CustomDashboardWidget[] =>
  (customDashboardTemplates.find((entry) => entry.id === template) ?? customDashboardTemplates[0]).widgets();

export const customDashboardCreatePayload = (input: {
  name: string;
  description?: string;
  tenantID?: string;
  organizationID?: string;
  workspaceID?: string;
  visibility?: CustomDashboardVisibility;
  filters?: Record<string, string | number | boolean | undefined>;
  widgets?: CustomDashboardWidget[];
}) => {
  const payload: Record<string, unknown> = {
    name: input.name.trim(),
    visibility: input.visibility ?? "private",
    schema_version: 1,
    layout: { columns: 12 },
    widgets: input.widgets ?? defaultTrendDashboardWidgets(),
    filters: pruneEmptyValues(input.filters ?? {}),
  };
  if (input.description?.trim()) payload.description = input.description.trim();
  if (input.tenantID?.trim()) payload.tenant_id = input.tenantID.trim();
  if (input.organizationID?.trim()) payload.organization_id = input.organizationID.trim();
  if (input.workspaceID?.trim()) payload.workspace_id = input.workspaceID.trim();
  return payload;
};

const pruneEmptyValues = (values: Record<string, string | number | boolean | undefined>) =>
  Object.fromEntries(Object.entries(values).filter(([, value]) => value !== undefined && String(value).trim() !== ""));

const stringParam = (value: unknown, fallback = "") => {
  if (typeof value === "string") return value.trim() || fallback;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return fallback;
};

const numberParam = (value: unknown, fallback: number) => {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};

const booleanParam = (value: unknown, fallback: boolean) => {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (value === "true") return true;
    if (value === "false") return false;
  }
  return fallback;
};
