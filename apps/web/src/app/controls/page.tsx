"use client";

import Link from "next/link";
import { useCallback, useMemo, useState } from "react";

import { type TableColumn, WorklistTable } from "@/components/grc/DataTable";
import { useApiKey } from "@/components/providers";
import { AppliedFilterChips, Badge, DataStateBanner, MetricCard, PageHeader, RiskBadge } from "@/components/grc/Primitives";
import ReviewDrawer from "@/components/grc/ReviewDrawer";
import { countLabel } from "@/lib/format";
import { displayDate, GRCControl, GRCControlEvidencePacketResponse, GRCFinding, riskSort } from "@/lib/grc";
import { downloadGRCExport, grcExportFilename, grcPath, useDebouncedValue, useGRCQuery } from "@/lib/grc-client";
import { useGRCFilterState } from "@/lib/grc-filters";
import { GRC_WORKLIST_LIMIT, grcBoundedRows } from "@/lib/grc-list";
import { controlMatchesFrameworkSegment, frameworkOptionLabel, isUpcomingGRCFramework, supportedGRCFrameworkNames } from "@/lib/grc-frameworks";
import { useQueryParamState } from "@/lib/query-params";
import type { RuntimeState } from "@/lib/runtime-state";

const DEFAULT_CONTROL_PROFILE_ID = "soc2-security-core";
const CONTROL_PROFILE_OPTIONS = [
  "soc2-security-core",
  "soc2-availability",
  "iso-technology-controls",
  "cloud-security-benchmarks",
  "pci-operational-security",
  "dora-operational-resilience",
  "fedramp-rev5-core",
  "nist-csf-20-core",
  "privacy-ai-governance",
];
const WORK_QUEUE_LIMIT = 12;
const inputClass = "mt-1 w-full rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] text-slate-900 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30";
const labelClass = "text-[11px] font-medium uppercase tracking-wider text-slate-500";

const controlKey = (control: GRCControl) => `${control.framework_name}-${control.control_id}`;

const controlOwner = (control: GRCControl) =>
  control.owner_domain || control.findings?.find((finding) => finding.owner && finding.owner !== "Unassigned")?.owner || "Unassigned";

const earliestDueAt = (findings: GRCFinding[] | undefined) => {
  const timestamps = (findings ?? [])
    .map((finding) => finding.due_at ? Date.parse(finding.due_at) : Number.NaN)
    .filter((value) => Number.isFinite(value));
  if (timestamps.length === 0) return undefined;
  return new Date(Math.min(...timestamps)).toISOString();
};

const dueState = (dueAt?: string) => {
  if (!dueAt) return "no_due_date";
  const dueTime = Date.parse(dueAt);
  if (!Number.isFinite(dueTime)) return "no_due_date";
  const now = Date.now();
  if (dueTime < now) return "overdue";
  if (dueTime - now <= 1000 * 60 * 60 * 24 * 14) return "due_soon";
  return "on_track";
};

const evidenceProgress = (control: GRCControl) => {
  const expected = Math.max(control.evidence_expectations ?? 0, control.evidence_items + (control.missing_evidence_items ?? 0));
  if (expected <= 0) return { current: control.evidence_items, expected: 0, percent: 100 };
  return {
    current: Math.min(control.evidence_items, expected),
    expected,
    percent: Math.round((Math.min(control.evidence_items, expected) / expected) * 100),
  };
};

const evidenceRequestState = (control: GRCControl) => {
  if ((control.missing_evidence_items ?? 0) > 0) return "missing";
  if ((control.stale_evidence_items ?? 0) > 0) return "needs_refresh";
  if (control.status === "manual_review") return "manual";
  return "ready";
};

const controlRecommendation = (control: GRCControl) => {
  if (control.status === "failing" && control.open_findings > 0) return "Remediate mapped findings";
  if ((control.missing_evidence_items ?? 0) > 0) return "Request missing evidence";
  if ((control.stale_evidence_items ?? 0) > 0) return "Refresh stale proof";
  if (control.status === "manual_review") return "Confirm manual assessment";
  if (control.status === "exception") return "Review exception";
  return "Keep audit-ready";
};

const workQueueRank = (control: GRCControl) => {
  const statusWeight: Record<string, number> = {
    failing: 0,
    missing_evidence: 1,
    stale_evidence: 2,
    manual_review: 3,
    exception: 4,
    passing: 8,
  };
  return [
    statusWeight[control.status] ?? 5,
    -(control.critical_findings * 100 + control.open_findings * 10 + (control.missing_evidence_items ?? 0)),
    Date.parse(earliestDueAt(control.findings) ?? "9999-12-31"),
  ] as const;
};

export default function ControlsPage() {
  const [tenantID, setTenantID] = useQueryParamState("tenant_id");
  const [profileID, setProfileID] = useQueryParamState("profile");
  const [framework, setFramework] = useQueryParamState("framework");
  const [controlID, setControlID] = useQueryParamState("control");
  const [selectedControlKey, setSelectedControlKey] = useState<string | null>(null);
  const [reviewControlKey, setReviewControlKey] = useState<string | null>(null);
  const debouncedTenantID = useDebouncedValue(tenantID.trim());
  const selectedProfileID = profileID.trim() || DEFAULT_CONTROL_PROFILE_ID;
  const { data, error, loading, lastSuccessfulAt, reload, state: queryState } = useGRCQuery<GRCControlEvidencePacketResponse>(
    grcPath("/grc/control-packets", { tenant_id: debouncedTenantID, profile: selectedProfileID, framework, control: controlID, limit: GRC_WORKLIST_LIMIT }),
  );
  const { apiKey } = useApiKey();
  const [exportState, setExportState] = useState<"idle" | "working" | "failed">("idle");
  const exportControls = useCallback(async () => {
    setExportState("working");
    const result = await downloadGRCExport(
      grcPath("/grc/controls/export", { tenant_id: debouncedTenantID }),
      apiKey,
      grcExportFilename("controls"),
    );
    setExportState(result.ok ? "idle" : "failed");
  }, [apiKey, debouncedTenantID]);
  const isRefreshing = loading && Boolean(data);
  const metricState: RuntimeState = queryState === "stale" ? "ready" : queryState === "empty" ? "ready" : queryState;
  const boundedControlRows = useMemo(
    () => grcBoundedRows({ rows: data?.controls, limit: GRC_WORKLIST_LIMIT, total: data?.packet?.summary?.total }),
    [data?.controls, data?.packet?.summary?.total],
  );
  const loadedControls = boundedControlRows.rows;
  const loadedControlMeta = data ? boundedControlRows.meta : undefined;
  const controlView = useMemo(() => {
    const fw = framework.trim().toLowerCase();
    const cf = controlID.trim().toLowerCase();
    const visible: GRCControl[] = [];
    let failing = 0, openFindings = 0, critical = 0, missingEvidence = 0;
    loadedControls.forEach((c) => {
      if (fw && !controlMatchesFrameworkSegment(c, framework)) return;
      if (cf && !c.control_id.toLowerCase().includes(cf)) return;
      visible.push(c);
      if (c.status === "failing") failing += 1;
      openFindings += c.open_findings;
      critical += c.critical_findings;
      missingEvidence += c.missing_evidence_items ?? 0;
    });
    return { controls: visible, critical, failing, missingEvidence, openFindings };
  }, [controlID, framework, loadedControls]);
  const { controls, critical, failing, missingEvidence, openFindings } = controlView;
  const selectedUpcomingFramework = isUpcomingGRCFramework(framework);
  const selectedControl = controls.find((control) => controlKey(control) === selectedControlKey) ?? controls[0] ?? null;
  const selectedRegisterKey = selectedControl ? controlKey(selectedControl) : null;
  const reviewControl = controls.find((control) => controlKey(control) === reviewControlKey) ?? null;
  const queueControls = useMemo(
    () => controls.slice().sort((left, right) => {
      const leftRank = workQueueRank(left);
      const rightRank = workQueueRank(right);
      for (let index = 0; index < leftRank.length; index += 1) {
        const diff = leftRank[index] - rightRank[index];
        if (diff !== 0) return diff;
      }
      return controlKey(left).localeCompare(controlKey(right));
    }).slice(0, WORK_QUEUE_LIMIT),
    [controls],
  );
  const frameworkOptions = useMemo(
    () => Array.from(new Set([
      ...supportedGRCFrameworkNames,
      ...loadedControls.map((control) => control.framework_name).filter(Boolean),
    ])),
    [loadedControls],
  );
  const filterState = useGRCFilterState([
    { key: "tenant_id", label: "Tenant", value: tenantID, setValue: setTenantID },
    { key: "profile", label: "Profile", value: selectedProfileID === DEFAULT_CONTROL_PROFILE_ID && !profileID ? "" : selectedProfileID, setValue: setProfileID },
    { key: "framework", label: "Framework", value: framework, setValue: setFramework },
    { key: "control", label: "Control", value: controlID, setValue: setControlID },
  ]);
  const auditPacketHref = useCallback((control: GRCControl) => {
    const params = new URLSearchParams({
      profile: selectedProfileID,
      framework: control.framework_name,
      control: control.control_id,
    });
    if (tenantID.trim()) params.set("tenant_id", tenantID.trim());
    return `/reports?${params.toString()}`;
  }, [selectedProfileID, tenantID]);
  const controlDetailHref = useCallback((control: GRCControl) => {
    const params = new URLSearchParams({
      profile: selectedProfileID,
      framework: control.framework_name,
      control: control.control_id,
    });
    if (tenantID.trim()) params.set("tenant_id", tenantID.trim());
    return `/controls/detail?${params.toString()}`;
  }, [selectedProfileID, tenantID]);
  const controlRegisterColumns = useMemo<TableColumn<GRCControl>[]>(() => [
    {
      key: "control_id",
      label: "Control",
      render: (_value, control) => (
        <div className="min-w-[16rem]">
          <Link href={controlDetailHref(control)} className="font-mono text-[12px] font-semibold text-[var(--text-primary)] hover:text-[var(--primary)]">
            {control.framework_name} {control.control_id}
          </Link>
          <div className="mt-0.5 line-clamp-2 text-[12px] text-[var(--text-muted)]">{control.title || control.family_name || "Control objective"}</div>
        </div>
      ),
    },
    { key: "status", label: "Status", render: (_value, control) => <Badge value={control.status} /> },
    { key: "owner_domain", label: "Owner", render: (_value, control) => controlOwner(control) },
    {
      key: "evidence_items",
      label: "Evidence",
      render: (_value, control) => {
        const progress = evidenceProgress(control);
        return (
          <div className="w-32">
            <div className="flex items-center justify-between text-[12px] text-[var(--text-muted)]">
              <span>{progress.current}/{progress.expected || progress.current}</span>
              <span>{progress.percent}%</span>
            </div>
            <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-[var(--surface-muted)]">
              <div className="h-full rounded-full bg-[var(--primary)]" style={{ width: `${Math.max(0, Math.min(100, progress.percent))}%` }} />
            </div>
          </div>
        );
      },
    },
    {
      key: "open_findings",
      label: "Findings",
      render: (_value, control) => (
        <div className="text-[12px] text-[var(--text-secondary)]">
          <div>{control.open_findings} open</div>
          <div className="text-[var(--text-muted)]">{control.critical_findings} critical</div>
        </div>
      ),
    },
    { key: "evidence_quality", label: "Request", render: (_value, control) => <Badge value={evidenceRequestState(control)} /> },
    {
      key: "due_at",
      label: "Due",
      render: (_value, control) => {
        const dueAt = earliestDueAt(control.findings);
        return (
          <div className="space-y-1">
            <Badge value={dueState(dueAt)} />
            <div className="text-[12px] text-[var(--text-muted)]">{dueAt ? displayDate(dueAt) : "No date"}</div>
          </div>
        );
      },
    },
    { key: "recommendation", label: "Action", render: (_value, control) => <span className="text-[12px] text-[var(--text-secondary)]">{controlRecommendation(control)}</span> },
  ], [controlDetailHref]);
  const rawControlCount = loadedControls.length;
  const controlListMeta = data && controls.length === rawControlCount
    ? loadedControlMeta
    : undefined;
  const packetParams = new URLSearchParams({ profile: selectedProfileID });
  if (tenantID.trim()) packetParams.set("tenant_id", tenantID.trim());
  if (framework.trim()) packetParams.set("framework", framework.trim());
  if (controlID.trim()) packetParams.set("control", controlID.trim());
  const packetHref = `/reports?${packetParams.toString()}`;

  return (
    <div className="space-y-6">
      <PageHeader
        contractId="controls"
        title="Controls"
        description="Control status, failing objectives, mapped findings, and evidence gaps."
        action={
          <div className="flex items-center gap-2">
            <Link href="/controls/builder" className="rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] font-medium text-slate-700 transition hover:border-slate-300 hover:text-slate-900">
              Build Pack
            </Link>
            <button type="button" onClick={() => void exportControls()} disabled={exportState === "working"} className="rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] font-medium text-slate-700 transition hover:border-slate-300 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50">
              {exportState === "working" ? "Exporting..." : exportState === "failed" ? "Export failed" : "Export CSV"}
            </button>
            <button type="button" onClick={() => void reload()} className="rounded-md border border-slate-200 bg-indigo-500 px-3 py-1.5 text-[13px] font-medium text-white transition hover:bg-indigo-600">
              Refresh
            </button>
          </div>
        }
      />

      <div className="rounded-lg border border-slate-200 bg-white px-5 py-4">
        <div className="grid gap-3 md:grid-cols-4">
          <label className={labelClass}>Tenant<input value={tenantID} onChange={(e) => setTenantID(e.target.value)} placeholder="All tenants" className={inputClass} /></label>
          <label className={labelClass}>
            Profile
            <input value={profileID} onChange={(e) => setProfileID(e.target.value)} placeholder={DEFAULT_CONTROL_PROFILE_ID} list="grc-profile-options" className={inputClass} />
            <datalist id="grc-profile-options">
              {CONTROL_PROFILE_OPTIONS.map((name) => <option key={name} value={name} />)}
            </datalist>
          </label>
          <label className={labelClass}>
            Framework
            <input value={framework} onChange={(e) => setFramework(e.target.value)} placeholder="SOC 2, DORA, FedRAMP Rev. 5" list="grc-framework-options" className={inputClass} />
            <datalist id="grc-framework-options">
              {frameworkOptions.map((name) => <option key={name} value={name} label={frameworkOptionLabel(name)} />)}
            </datalist>
          </label>
          <label className={labelClass}>Control<input value={controlID} onChange={(e) => setControlID(e.target.value)} placeholder="CC6.1" className={inputClass} /></label>
        </div>
        <AppliedFilterChips filters={filterState.chips} onClearAll={filterState.clearAll} />
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <MetricCard label="Controls" value={selectedUpcomingFramework ? "N/A" : controls.length} detail={selectedUpcomingFramework ? "upcoming" : "in scope"} state={metricState} />
        <MetricCard label="Failing" value={selectedUpcomingFramework ? "N/A" : failing} detail={selectedUpcomingFramework ? "not measured" : "with open findings"} intent={selectedUpcomingFramework ? "neutral" : failing > 0 ? "danger" : "success"} state={metricState} />
        <MetricCard label="Missing Evidence" value={selectedUpcomingFramework ? "N/A" : missingEvidence} detail={selectedUpcomingFramework ? "not measured" : "required items"} intent={selectedUpcomingFramework ? "neutral" : missingEvidence > 0 ? "warning" : "success"} state={metricState} />
        <MetricCard label="Open Findings" value={selectedUpcomingFramework ? "N/A" : openFindings} detail={selectedUpcomingFramework ? "not measured" : `${critical} critical`} intent={selectedUpcomingFramework ? "neutral" : openFindings > 0 ? "warning" : "success"} state={metricState} />
      </div>

      {data && queueControls.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-slate-200 bg-white">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 px-5 py-3.5">
            <div>
              <h2 className="text-[13px] font-semibold text-slate-900">Auditor work queue</h2>
              <p className="mt-0.5 text-[12px] text-slate-500">
                {isRefreshing ? "Refreshing controls..." : "Prioritized controls by findings, evidence gaps, freshness, and due dates."}
              </p>
            </div>
            <Link href={packetHref} className="rounded-md border border-slate-200 px-3 py-1.5 text-[12px] font-medium text-indigo-600 transition hover:border-indigo-200 hover:bg-indigo-50">
              Export packet
            </Link>
          </div>
          <table className="w-full min-w-[980px] text-left text-[13px]">
            <thead>
              <tr className="border-b border-slate-100 bg-slate-50/80">
                {["Control", "Owner", "Due", "Evidence", "Findings", "Request", "Recommendation", ""].map((label) => (
                  <th key={label} className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">{label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {queueControls.map((control) => {
                const dueAt = earliestDueAt(control.findings);
                const progress = evidenceProgress(control);
                return (
                  <tr key={controlKey(control)} className="border-b border-slate-50 last:border-b-0 hover:bg-slate-50/60">
                    <td className="px-3 py-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <Link href={controlDetailHref(control)} className="font-mono text-[12px] font-semibold text-slate-900 hover:text-indigo-600">
                          {control.framework_name} {control.control_id}
                        </Link>
                        <Badge value={control.status} />
                      </div>
                      <div className="mt-1 max-w-[24rem] truncate text-[12px] text-slate-500">{control.title || control.family_name || "Control objective"}</div>
                    </td>
                    <td className="px-3 py-3 text-[12px] text-slate-700">{controlOwner(control)}</td>
                    <td className="px-3 py-3">
                      <div className="flex flex-col items-start gap-1">
                        <Badge value={dueState(dueAt)} />
                        <span className="text-[12px] text-slate-500">{dueAt ? displayDate(dueAt) : "No date"}</span>
                      </div>
                    </td>
                    <td className="px-3 py-3">
                      <div className="w-32">
                        <div className="flex items-center justify-between text-[12px] text-slate-500">
                          <span>{progress.current}/{progress.expected || progress.current}</span>
                          <span>{progress.percent}%</span>
                        </div>
                        <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-slate-100">
                          <div className="h-full rounded-full bg-indigo-500" style={{ width: `${Math.max(0, Math.min(100, progress.percent))}%` }} />
                        </div>
                      </div>
                    </td>
                    <td className="px-3 py-3 text-[12px] text-slate-700">
                      <div>{control.open_findings} open</div>
                      <div className="text-slate-500">{control.critical_findings} critical</div>
                    </td>
                    <td className="px-3 py-3"><Badge value={evidenceRequestState(control)} /></td>
                    <td className="px-3 py-3 text-[12px] text-slate-700">{controlRecommendation(control)}</td>
                    <td className="px-3 py-3 text-right">
                      <div className="flex justify-end gap-2">
                        <button type="button" onClick={() => setReviewControlKey(controlKey(control))} className="rounded-md px-2 py-1 text-[12px] font-medium text-slate-600 transition hover:bg-slate-50">Review</button>
                        <Link href={controlDetailHref(control)} className="rounded-md px-2 py-1 text-[12px] font-medium text-indigo-600 transition hover:bg-indigo-50">Detail</Link>
                        <Link href={auditPacketHref(control)} className="rounded-md px-2 py-1 text-[12px] font-medium text-slate-600 transition hover:bg-slate-50">Packet</Link>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <DataStateBanner
        state={queryState}
        subject="Controls"
        error={error}
        lastSuccessfulAt={lastSuccessfulAt}
        onRetry={() => void reload()}
        detail={queryState === "loading" ? "Loading controls." : queryState === "unavailable" ? "Controls will appear when graph data is reachable." : undefined}
      />

      {data && (
        <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_360px]">
          <WorklistTable
            title="Control register"
            description={isRefreshing ? "Refreshing controls..." : "Select a row to inspect mapped findings and evidence gaps."}
            rows={controls}
            columns={controlRegisterColumns}
            emptyMessage={selectedUpcomingFramework ? `${framework.trim()} is upcoming. It is not included in measured control evidence packets yet.` : "No controls match the current filters."}
            searchPlaceholder="Filter loaded controls"
            filterKeys={["framework_name", "control_id", "title", "family_name", "status", "owner_domain", "audit_summary", "reasons", "mapped_rules"]}
            pageSize={25}
            getRowKey={(control) => controlKey(control)}
            selectedRowKey={selectedRegisterKey}
            onRowClick={(control) => setSelectedControlKey(controlKey(control))}
            rowActions={(control) => (
              <button
                type="button"
                onClick={(event) => {
                  event.stopPropagation();
                  setReviewControlKey(controlKey(control));
                }}
                className="rounded-md border border-[color:var(--border)] px-2 py-1 text-[12px] font-medium text-[var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[var(--text-primary)]"
              >
                Review
              </button>
            )}
            resultLimit={GRC_WORKLIST_LIMIT}
            resultMeta={controlListMeta}
            resultNoun="controls"
            tableContainerClassName="max-h-[38rem] overflow-auto"
            action={<Link href={packetHref} className="rounded-md border border-slate-200 px-3 py-1.5 text-[12px] font-medium text-indigo-600 transition hover:border-indigo-200 hover:bg-indigo-50">Export packet</Link>}
          />
          <ControlDetailPanel
            control={selectedControl}
            auditPacketHref={selectedControl ? auditPacketHref(selectedControl) : ""}
            controlDetailHref={selectedControl ? controlDetailHref(selectedControl) : ""}
          />
        </div>
      )}
      <ControlReviewDrawer
        auditPacketHref={reviewControl ? auditPacketHref(reviewControl) : ""}
        control={reviewControl}
        controlDetailHref={reviewControl ? controlDetailHref(reviewControl) : ""}
        onClose={() => setReviewControlKey(null)}
      />
    </div>
  );
}

function ControlReviewDrawer({
  auditPacketHref,
  control,
  controlDetailHref,
  onClose,
}: {
  auditPacketHref: string;
  control: GRCControl | null;
  controlDetailHref: string;
  onClose: () => void;
}) {
  const dueAt = control ? earliestDueAt(control.findings) : undefined;
  const findings = control ? (control.findings ?? []).slice().sort(riskSort) : [];
  const visibleFindings = findings.slice(0, 5);
  const progress = control ? evidenceProgress(control) : { current: 0, expected: 0, percent: 0 };
  const auditContext = control?.audit_summary || control?.reasons?.[0] || "No audit summary returned.";

  return (
    <ReviewDrawer
      open={Boolean(control)}
      onClose={onClose}
      title={control ? `${control.framework_name} ${control.control_id}` : "Control review"}
      subtitle={control?.title || control?.family_name || undefined}
      footer={control && (
        <div className="flex flex-wrap gap-2">
          <Link href={controlDetailHref} className="primary-button px-3 py-1.5 text-[12px]">Open detail</Link>
          <Link href={auditPacketHref} className="secondary-button px-3 py-1.5 text-[12px]">Open packet</Link>
        </div>
      )}
    >
      {control && (
        <div className="space-y-5">
          <section>
            <div className="flex flex-wrap items-center gap-2">
              <Badge value={control.status} />
              <Badge value={evidenceRequestState(control)} />
              <Badge value={dueState(dueAt)} />
            </div>
            <p className="mt-3 text-[13px] leading-5 text-[var(--text-secondary)]">{controlRecommendation(control)}</p>
          </section>

          <section className="grid gap-3 border-t border-[color:var(--border)] pt-4 sm:grid-cols-2">
            <div>
              <div className="text-[11px] font-medium uppercase tracking-wide text-[var(--text-muted)]">Owner</div>
              <div className="mt-1 text-[13px] font-medium text-[var(--text-primary)]">{controlOwner(control)}</div>
            </div>
            <div>
              <div className="text-[11px] font-medium uppercase tracking-wide text-[var(--text-muted)]">Due</div>
              <div className="mt-1 text-[13px] font-medium text-[var(--text-primary)]">{dueAt ? displayDate(dueAt) : "No due date"}</div>
            </div>
            <div>
              <div className="text-[11px] font-medium uppercase tracking-wide text-[var(--text-muted)]">Findings</div>
              <div className="mt-1 text-[13px] font-medium text-[var(--text-primary)]">{control.open_findings} open, {control.critical_findings} critical</div>
            </div>
            <div>
              <div className="text-[11px] font-medium uppercase tracking-wide text-[var(--text-muted)]">Evidence score</div>
              <div className="mt-1 text-[13px] font-medium text-[var(--text-primary)]">{typeof control.evidence_score === "number" ? control.evidence_score : "Not scored"}</div>
            </div>
          </section>

          <section className="border-t border-[color:var(--border)] pt-4">
            <div className="flex items-center justify-between text-[12px]">
              <h3 className="font-semibold text-[var(--text-primary)]">Evidence</h3>
              <span className="text-[var(--text-muted)]">{progress.percent}% complete</span>
            </div>
            <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-[var(--surface-muted)]">
              <div className="h-full rounded-full bg-[var(--primary)]" style={{ width: `${Math.max(0, Math.min(100, progress.percent))}%` }} />
            </div>
            <dl className="mt-3 grid grid-cols-3 gap-3 text-[12px]">
              <div>
                <dt className="text-[var(--text-muted)]">Attached</dt>
                <dd className="font-medium text-[var(--text-primary)]">{progress.current}</dd>
              </div>
              <div>
                <dt className="text-[var(--text-muted)]">Expected</dt>
                <dd className="font-medium text-[var(--text-primary)]">{progress.expected || progress.current}</dd>
              </div>
              <div>
                <dt className="text-[var(--text-muted)]">Stale</dt>
                <dd className="font-medium text-[var(--text-primary)]">{control.stale_evidence_items ?? 0}</dd>
              </div>
            </dl>
          </section>

          <section className="border-t border-[color:var(--border)] pt-4">
            <div className="flex items-center justify-between gap-3">
              <h3 className="text-[12px] font-semibold text-[var(--text-primary)]">Mapped findings</h3>
              <span className="text-[11px] text-[var(--text-muted)]">{findings.length.toLocaleString()} total</span>
            </div>
            {visibleFindings.length > 0 ? (
              <div className="mt-3 space-y-3">
                {visibleFindings.map((finding) => (
                  <div key={finding.id} className="rounded-md bg-[var(--surface-muted)] px-3 py-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <RiskBadge score={finding.risk_score} />
                      <Badge value={finding.severity} tone="severity" />
                      <Badge value={finding.sla_status} />
                    </div>
                    <Link href={`/findings/${encodeURIComponent(finding.id)}`} className="mt-2 line-clamp-2 text-[12px] font-medium text-[var(--text-primary)] hover:text-[var(--primary)]">
                      {finding.title}
                    </Link>
                  </div>
                ))}
              </div>
            ) : (
              <p className="mt-2 text-[13px] text-[var(--text-muted)]">No findings mapped to this control.</p>
            )}
          </section>

          <section className="border-t border-[color:var(--border)] pt-4">
            <h3 className="text-[12px] font-semibold text-[var(--text-primary)]">Audit context</h3>
            <p className="mt-2 text-[13px] leading-5 text-[var(--text-secondary)]">{auditContext}</p>
            <div className="mt-3 flex flex-wrap gap-2">
              {control.evidence_quality && <Badge value={control.evidence_quality} />}
              <span className="rounded-full border border-[color:var(--border)] px-2 py-0.5 text-[11px] text-[var(--text-muted)]">
                {countLabel(control.evidence_expectations ?? 0, "expectation")}
              </span>
              <span className="rounded-full border border-[color:var(--border)] px-2 py-0.5 text-[11px] text-[var(--text-muted)]">
                {countLabel(control.mapped_rules?.length ?? 0, "mapped rule")}
              </span>
            </div>
          </section>
        </div>
      )}
    </ReviewDrawer>
  );
}

function ControlDetailPanel({
  auditPacketHref,
  control,
  controlDetailHref,
}: {
  auditPacketHref: string;
  control: GRCControl | null;
  controlDetailHref: string;
}) {
  if (!control) {
    return (
      <aside className="surface-panel p-5">
        <h2 className="text-[13px] font-semibold text-[var(--text-primary)]">Control details</h2>
        <p className="mt-2 text-[13px] leading-5 text-[var(--text-muted)]">
          Select a control to inspect evidence gaps, mapped findings, and the next action.
        </p>
      </aside>
    );
  }

  const dueAt = earliestDueAt(control.findings);
  const findings = (control.findings ?? []).slice().sort(riskSort);
  const visibleFindings = findings.slice(0, 5);
  const hiddenFindingCount = findings.length - visibleFindings.length;
  const progress = evidenceProgress(control);
  const auditContext = control.audit_summary || control.reasons?.[0] || "No audit summary returned.";

  return (
    <aside className="surface-panel overflow-hidden xl:sticky xl:top-6 xl:self-start">
      <div className="border-b border-[color:var(--border)] px-5 py-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <h2 className="font-mono text-[13px] font-semibold text-[var(--text-primary)]">
              {control.framework_name} {control.control_id}
            </h2>
            <p className="mt-1 line-clamp-2 text-[12px] leading-5 text-[var(--text-muted)]">
              {control.title || control.family_name || "Control objective"}
            </p>
          </div>
          <Badge value={control.status} />
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          <Link href={controlDetailHref} className="rounded-md border border-[color:var(--border)] px-2.5 py-1.5 text-[12px] font-medium text-[var(--primary)] transition hover:border-[color:var(--border-strong)]">
            Detail
          </Link>
          <Link href={auditPacketHref} className="rounded-md border border-[color:var(--border)] px-2.5 py-1.5 text-[12px] font-medium text-[var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[var(--text-primary)]">
            Packet
          </Link>
        </div>
      </div>

      <div className="space-y-5 p-5">
        <section>
          <div className="flex items-center justify-between text-[12px]">
            <h3 className="font-semibold text-[var(--text-primary)]">Evidence</h3>
            <span className="text-[var(--text-muted)]">{progress.percent}% complete</span>
          </div>
          <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-[var(--surface-muted)]">
            <div className="h-full rounded-full bg-[var(--primary)]" style={{ width: `${Math.max(0, Math.min(100, progress.percent))}%` }} />
          </div>
          <dl className="mt-3 grid grid-cols-2 gap-3 text-[12px]">
            <div>
              <dt className="text-[var(--text-muted)]">Evidence</dt>
              <dd className="font-medium text-[var(--text-primary)]">{countLabel(control.evidence_items, "item")}</dd>
            </div>
            <div>
              <dt className="text-[var(--text-muted)]">Missing</dt>
              <dd className="font-medium text-[var(--text-primary)]">{countLabel(control.missing_evidence_items ?? 0, "item")}</dd>
            </div>
            <div>
              <dt className="text-[var(--text-muted)]">Stale</dt>
              <dd className="font-medium text-[var(--text-primary)]">{countLabel(control.stale_evidence_items ?? 0, "item")}</dd>
            </div>
            <div>
              <dt className="text-[var(--text-muted)]">Score</dt>
              <dd className="font-medium text-[var(--text-primary)]">{typeof control.evidence_score === "number" ? control.evidence_score : "Not scored"}</dd>
            </div>
          </dl>
        </section>

        <section className="border-t border-[color:var(--border)] pt-4">
          <h3 className="text-[12px] font-semibold text-[var(--text-primary)]">Next action</h3>
          <p className="mt-1 text-[13px] leading-5 text-[var(--text-secondary)]">{controlRecommendation(control)}</p>
          <div className="mt-3 flex flex-wrap gap-2">
            <Badge value={evidenceRequestState(control)} />
            <Badge value={dueState(dueAt)} />
            <span className="rounded-full border border-[color:var(--border)] px-2 py-0.5 text-[11px] text-[var(--text-muted)]">
              {dueAt ? displayDate(dueAt) : "No due date"}
            </span>
          </div>
        </section>

        <section className="border-t border-[color:var(--border)] pt-4">
          <div className="flex items-center justify-between gap-3">
            <h3 className="text-[12px] font-semibold text-[var(--text-primary)]">Mapped findings</h3>
            <span className="text-[11px] text-[var(--text-muted)]">{findings.length.toLocaleString()} total</span>
          </div>
          {visibleFindings.length > 0 ? (
            <div className="mt-3 space-y-3">
              {visibleFindings.map((finding) => (
                <div key={finding.id} className="border-t border-[color:var(--border)] pt-3 first:border-t-0 first:pt-0">
                  <div className="flex items-center gap-2">
                    <RiskBadge score={finding.risk_score} />
                    <Badge value={finding.severity} tone="severity" />
                  </div>
                  <Link href={`/findings/${encodeURIComponent(finding.id)}`} className="mt-1 line-clamp-2 text-[12px] font-medium text-[var(--text-primary)] hover:text-[var(--primary)]">
                    {finding.title}
                  </Link>
                  <div className="mt-1 truncate font-mono text-[11px] text-[var(--text-muted)]">{finding.id}</div>
                </div>
              ))}
              {hiddenFindingCount > 0 && (
                <p className="text-[12px] text-[var(--text-muted)]">
                  {hiddenFindingCount.toLocaleString()} more mapped findings in the detail view.
                </p>
              )}
            </div>
          ) : (
            <p className="mt-2 text-[13px] text-[var(--text-muted)]">No findings mapped to this control.</p>
          )}
        </section>

        <section className="border-t border-[color:var(--border)] pt-4">
          <h3 className="text-[12px] font-semibold text-[var(--text-primary)]">Audit context</h3>
          <p className="mt-1 text-[13px] leading-5 text-[var(--text-secondary)]">{auditContext}</p>
          <div className="mt-3 flex flex-wrap gap-2">
            {control.evidence_quality && <Badge value={control.evidence_quality} />}
            <span className="rounded-full border border-[color:var(--border)] px-2 py-0.5 text-[11px] text-[var(--text-muted)]">
              {countLabel(control.evidence_expectations ?? 0, "expectation")}
            </span>
            <span className="rounded-full border border-[color:var(--border)] px-2 py-0.5 text-[11px] text-[var(--text-muted)]">
              {countLabel(control.mapped_rules?.length ?? 0, "mapped rule")}
            </span>
          </div>
        </section>
      </div>
    </aside>
  );
}
