"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useState } from "react";

import CustomDashboardBuilder from "@/components/grc/CustomDashboardBuilder";
import CustomDashboardRenderer from "@/components/grc/CustomDashboardRenderer";
import { ErrorBlock, LoadingBlock, PageHeader, Panel } from "@/components/grc/Primitives";
import {
  type CustomDashboard,
  type CustomDashboardResponse,
  customDashboardClonePath,
  customDashboardPath,
  validateCustomDashboardName,
} from "@/lib/custom-dashboards";
import { useGRCMutation, useGRCQuery } from "@/lib/grc-client";

const inputClass = "mt-1 w-full rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] text-slate-900 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30";
const selectClass = "mt-1 w-full rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] text-slate-900 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30";
const labelClass = "text-[11px] font-medium uppercase tracking-wider text-slate-500";

export default function CustomDashboardDetailPage() {
  const router = useRouter();
  const params = useParams<{ dashboardID: string }>();
  const dashboardID = Array.isArray(params.dashboardID) ? params.dashboardID[0] : params.dashboardID;
  const dashboardQuery = useGRCQuery<CustomDashboardResponse>(dashboardID ? customDashboardPath(dashboardID) : null);
  const updateMutation = useGRCMutation<CustomDashboardResponse>();
  const cloneMutation = useGRCMutation<CustomDashboardResponse>();
  const deleteMutation = useGRCMutation<void>();
  const dashboard = dashboardQuery.data?.dashboard;

  const cloneDashboard = async () => {
    if (!dashboard) return;
    const response = await cloneMutation.mutate(customDashboardClonePath(dashboard.id), { name: `Copy of ${dashboard.name}` });
    router.push(`/trends/dashboards/${encodeURIComponent(response.dashboard.id)}`);
  };

  const deleteDashboard = async () => {
    if (!dashboard) return;
    await deleteMutation.mutate(customDashboardPath(dashboard.id), {}, "DELETE");
    router.push("/trends/dashboards");
  };

  if (dashboardQuery.loading) {
    return <LoadingBlock label="Loading dashboard..." />;
  }
  if (dashboardQuery.error) {
    return <ErrorBlock error={dashboardQuery.error} onRetry={() => void dashboardQuery.reload()} recoveryDetail="Dashboard details will appear when the API is reachable." />;
  }
  if (!dashboard) {
    return <div className="rounded-lg border border-slate-200 bg-white p-6 text-[13px] text-slate-500">Dashboard not found.</div>;
  }

  return (
    <div className="space-y-6">
      <PageHeader
        contractId="grc-custom-dashboard-detail"
        title={dashboard.name}
        description={dashboard.description || "Saved GRC dashboard."}
        action={
          <div className="flex flex-wrap gap-2">
            <Link href="/trends/dashboards" className="rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] font-medium text-slate-700 transition hover:border-indigo-300 hover:text-indigo-600">
              All dashboards
            </Link>
            <button
              type="button"
              onClick={() => void cloneDashboard()}
              disabled={cloneMutation.saving}
              className="rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] font-medium text-slate-700 transition hover:border-indigo-300 hover:text-indigo-600 disabled:cursor-not-allowed disabled:opacity-50"
            >
              Clone
            </button>
          </div>
        }
      />

      <DashboardSettings
        key={dashboard.id}
        dashboard={dashboard}
        updateMutation={updateMutation}
        cloneError={cloneMutation.error}
        deleteMutation={deleteMutation}
        onReload={() => dashboardQuery.reload()}
        onDelete={() => void deleteDashboard()}
      />

      <CustomDashboardBuilder key={`${dashboard.id}:${dashboard.updated_at}`} dashboard={dashboard} onSaved={() => dashboardQuery.reload()} />

      <CustomDashboardRenderer dashboard={dashboard} />
    </div>
  );
}

function DashboardSettings({
  dashboard,
  updateMutation,
  cloneError,
  deleteMutation,
  onReload,
  onDelete,
}: {
  dashboard: CustomDashboard;
  updateMutation: ReturnType<typeof useGRCMutation<CustomDashboardResponse>>;
  cloneError: string | null;
  deleteMutation: ReturnType<typeof useGRCMutation<void>>;
  onReload: () => Promise<void>;
  onDelete: () => void;
}) {
  const [name, setName] = useState(dashboard.name);
  const [description, setDescription] = useState(dashboard.description ?? "");
  const [visibility, setVisibility] = useState<"private" | "workspace" | "organization">(dashboard.visibility);
  const [workspaceID, setWorkspaceID] = useState(dashboard.workspace_id ?? "");
  const [formError, setFormError] = useState<string | null>(null);

  const saveDashboard = async () => {
    const validation = validateCustomDashboardName(name);
    if (!validation.ok) {
      setFormError(validation.error);
      return;
    }
    setFormError(null);
    await updateMutation.mutate(customDashboardPath(dashboard.id), {
      name: validation.name,
      description,
      visibility,
      workspace_id: workspaceID,
    }, "PATCH");
    await onReload();
  };

  return (
    <Panel title="Dashboard settings">
      <div className="grid gap-3 md:grid-cols-4">
        <label className={labelClass}>Name<input value={name} onChange={(event) => setName(event.target.value)} className={inputClass} /></label>
        <label className={`${labelClass} md:col-span-2`}>Description<input value={description} onChange={(event) => setDescription(event.target.value)} placeholder="Optional" className={inputClass} /></label>
        <label className={labelClass}>Visibility<select value={visibility} onChange={(event) => setVisibility(event.target.value as typeof visibility)} className={selectClass}><option value="private">Private</option><option value="workspace">Workspace</option><option value="organization">Organization</option></select></label>
        <label className={labelClass}>Workspace<input value={workspaceID} onChange={(event) => setWorkspaceID(event.target.value)} placeholder="Optional" className={inputClass} /></label>
        <div className="flex items-end gap-2 md:col-span-3">
          <button
            type="button"
            onClick={() => void saveDashboard()}
            disabled={updateMutation.saving}
            className="rounded-md bg-indigo-500 px-3 py-1.5 text-[13px] font-medium text-white transition hover:bg-indigo-600 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {updateMutation.saving ? "Saving..." : "Save settings"}
          </button>
          <button
            type="button"
            onClick={onDelete}
            disabled={deleteMutation.saving}
            className="rounded-md border border-rose-200 bg-white px-3 py-1.5 text-[13px] font-medium text-rose-700 transition hover:border-rose-300 disabled:cursor-not-allowed disabled:opacity-50"
          >
            Delete
          </button>
        </div>
      </div>
      {(formError || updateMutation.error || cloneError || deleteMutation.error) && (
        <div className="mt-3 rounded-md border border-rose-200 bg-rose-50 p-2 text-[12px] text-rose-700">
          {formError ?? updateMutation.error ?? cloneError ?? deleteMutation.error}
        </div>
      )}
    </Panel>
  );
}
