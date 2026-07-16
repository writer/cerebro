"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";

import { ErrorBlock, LoadingBlock, PageHeader, Panel } from "@/components/grc/Primitives";
import {
  type CustomDashboardListResponse,
  type CustomDashboardResponse,
  type CustomDashboardTemplateID,
  customDashboardCreatePayload,
  customDashboardListPath,
  customDashboardTemplates,
  customDashboardTemplateWidgets,
  sortCustomDashboards,
  validateCustomDashboardName,
} from "@/lib/custom-dashboards";
import { useDebouncedValue, useGRCMutation, useGRCQuery } from "@/lib/grc-client";
import { useQueryParamState } from "@/lib/query-params";

const inputClass = "mt-1 w-full rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] text-slate-900 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30";
const selectClass = "mt-1 w-full rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] text-slate-900 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30";
const labelClass = "text-[11px] font-medium uppercase tracking-wider text-slate-500";

export default function CustomDashboardsPage() {
  const router = useRouter();
  const [tenantID, setTenantID] = useQueryParamState("tenant_id");
  const [workspaceID, setWorkspaceID] = useState("");
  const [name, setName] = useState("GRC trends dashboard");
  const [description, setDescription] = useState("");
  const [visibility, setVisibility] = useState<"private" | "workspace" | "organization">("private");
  const [template, setTemplate] = useState<CustomDashboardTemplateID>("trends");
  const [severity, setSeverity] = useQueryParamState("severity");
  const [framework, setFramework] = useQueryParamState("framework");
  const [formError, setFormError] = useState<string | null>(null);
  const debouncedTenantID = useDebouncedValue(tenantID.trim());
  const debouncedWorkspaceID = useDebouncedValue(workspaceID.trim());
  const listPath = useMemo(() => customDashboardListPath({ tenantID: debouncedTenantID, workspaceID: debouncedWorkspaceID }), [debouncedTenantID, debouncedWorkspaceID]);
  const dashboardsQuery = useGRCQuery<CustomDashboardListResponse>(listPath);
  const createMutation = useGRCMutation<CustomDashboardResponse>();
  const dashboards = sortCustomDashboards(dashboardsQuery.data?.dashboards ?? []);

  const createDashboard = async () => {
    const validation = validateCustomDashboardName(name);
    if (!validation.ok) {
      setFormError(validation.error);
      return;
    }
    setFormError(null);
    const response = await createMutation.mutate("/grc/dashboards", customDashboardCreatePayload({
      name: validation.name,
      description,
      tenantID,
      workspaceID,
      visibility,
      widgets: customDashboardTemplateWidgets(template),
      filters: {
        tenant_id: tenantID,
        framework,
        severity,
      },
    }));
    router.push(`/trends/dashboards/${encodeURIComponent(response.dashboard.id)}`);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        contractId="grc-custom-dashboards"
        title="Custom dashboards"
        description="Create saved GRC trend dashboards with reusable filters, widgets, and sharing scope."
        action={
          <Link href="/trends" className="rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] font-medium text-slate-700 transition hover:border-indigo-300 hover:text-indigo-600">
            Back to trends
          </Link>
        }
      />

      <Panel title="Create dashboard">
        <div className="grid gap-3 md:grid-cols-3">
          <label className={labelClass}>Name<input value={name} onChange={(event) => setName(event.target.value)} className={inputClass} /></label>
          <label className={labelClass}>Tenant<input value={tenantID} onChange={(event) => setTenantID(event.target.value)} placeholder="Default tenant" className={inputClass} /></label>
          <label className={labelClass}>Workspace<input value={workspaceID} onChange={(event) => setWorkspaceID(event.target.value)} placeholder="Optional" className={inputClass} /></label>
          <label className={`${labelClass} md:col-span-2`}>Description<input value={description} onChange={(event) => setDescription(event.target.value)} placeholder="Optional" className={inputClass} /></label>
          <label className={labelClass}>Visibility<select value={visibility} onChange={(event) => setVisibility(event.target.value as typeof visibility)} className={selectClass}><option value="private">Private</option><option value="workspace">Workspace</option><option value="organization">Organization</option></select></label>
          <label className={labelClass}>Template<select value={template} onChange={(event) => setTemplate(event.target.value as CustomDashboardTemplateID)} className={selectClass}>{customDashboardTemplates.map((entry) => <option key={entry.id} value={entry.id}>{entry.label}</option>)}</select></label>
          <label className={labelClass}>Framework<input value={framework} onChange={(event) => setFramework(event.target.value)} placeholder="All frameworks" className={inputClass} /></label>
          <label className={labelClass}>Severity<select value={severity} onChange={(event) => setSeverity(event.target.value)} className={selectClass}><option value="">All severities</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option></select></label>
        </div>
        {(formError || createMutation.error) && <div className="mt-3 rounded-md border border-rose-200 bg-rose-50 p-2 text-[12px] text-rose-700">{formError ?? createMutation.error}</div>}
        <div className="mt-4">
          <button
            type="button"
            onClick={() => void createDashboard()}
            disabled={createMutation.saving}
            className="rounded-md bg-indigo-500 px-3 py-1.5 text-[13px] font-medium text-white transition hover:bg-indigo-600 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {createMutation.saving ? "Creating..." : "Create dashboard"}
          </button>
        </div>
      </Panel>

      {dashboardsQuery.loading && <LoadingBlock label="Loading dashboards..." />}
      {dashboardsQuery.error && <ErrorBlock error={dashboardsQuery.error} onRetry={() => void dashboardsQuery.reload()} recoveryDetail="Dashboards will appear when the API is reachable." />}

      {!dashboardsQuery.loading && !dashboardsQuery.error && (
        <Panel title="Saved dashboards">
          {dashboards.length === 0 ? (
            <div className="rounded-lg border border-dashed border-slate-300 p-8 text-center text-[13px] text-slate-500">
              No custom dashboards yet.
            </div>
          ) : (
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              {dashboards.map((dashboard) => (
                <Link key={dashboard.id} href={`/trends/dashboards/${encodeURIComponent(dashboard.id)}`} className="rounded-lg border border-slate-200 bg-slate-50/60 p-4 transition hover:border-indigo-300 hover:bg-white">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="truncate text-[14px] font-semibold text-slate-900">{dashboard.name}</div>
                      <div className="mt-1 text-[12px] text-slate-500">{dashboard.description || "No description"}</div>
                    </div>
                    <span className="rounded-full bg-indigo-50 px-2 py-0.5 text-[11px] font-medium text-indigo-700">{dashboard.visibility}</span>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-2 text-[11px] text-slate-500">
                    {dashboard.tenant_id && <span>Tenant: {dashboard.tenant_id}</span>}
                    {dashboard.workspace_id && <span>Workspace: {dashboard.workspace_id}</span>}
                    <span>{dashboard.widgets.length} widgets</span>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </Panel>
      )}
    </div>
  );
}
