"use client";

import Link from "next/link";
import { useCallback, useMemo, useState } from "react";

import FindingTable from "@/components/grc/FindingTable";
import { AppliedFilterChips, Badge, DataStateBanner, MetricCard, PageHeader, ResultLimitNotice, RiskBadge, SeverityDot } from "@/components/grc/Primitives";
import ReviewDrawer from "@/components/grc/ReviewDrawer";
import { fetchCerebro } from "@/lib/cerebro-client";
import { countLabel } from "@/lib/format";
import { filterRiskInboxFindings } from "@/lib/findings-filter";
import { downloadFindingsCSV } from "@/lib/findings-export";
import { FINDING_DISPOSITION_OPTIONS, FindingDisposition, triageBatchesByTenant } from "@/lib/finding-triage";
import { displayDate, GRCFinding, GRCListMeta, humanize, shortEntity } from "@/lib/grc";
import { downloadGRCExport, grcExportFilename, grcPath, useDebouncedValue, useGRCMutation, useGRCQuery } from "@/lib/grc-client";
import { GRC_FILTERED_EXPORT_LIMIT, GRC_WORKLIST_LIMIT, grcBoundedRows } from "@/lib/grc-list";
import { useApiKey } from "@/components/providers";
import { frameworkOptionLabel, isUpcomingGRCFramework, supportedGRCFrameworkNames } from "@/lib/grc-frameworks";
import { useQueryParamState } from "@/lib/query-params";
import type { RuntimeState } from "@/lib/runtime-state";

type FindingsResponse = { findings: GRCFinding[]; meta?: GRCListMeta; generated_at: string };

const RISK_INBOX_LIST_LIMIT = GRC_WORKLIST_LIMIT;
const RISK_INBOX_FILTERED_EXPORT_LIMIT = GRC_FILTERED_EXPORT_LIMIT;
const inputClass = "mt-1 w-full rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] text-slate-900 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30";
const selectClass = "mt-1 w-full rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] text-slate-900 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30";
const labelClass = "text-[11px] font-medium uppercase tracking-wider text-slate-500";

export default function RiskInboxPage() {
  const [tenantID, setTenantID] = useQueryParamState("tenant_id");
  const [runtimeID, setRuntimeID] = useQueryParamState("runtime_id");
  const [sourceID, setSourceID] = useQueryParamState("source_id");
  const [severity, setSeverity] = useQueryParamState("severity");
  const [status, setStatus] = useQueryParamState("status", "open");
  const [framework, setFramework] = useQueryParamState("framework");
  const [openedAfter, setOpenedAfter] = useQueryParamState("opened_after");
  const [openedBefore, setOpenedBefore] = useQueryParamState("opened_before");
  const [closedAfter, setClosedAfter] = useQueryParamState("closed_after");
  const [closedBefore, setClosedBefore] = useQueryParamState("closed_before");
  const [ageMinDays, setAgeMinDays] = useQueryParamState("age_min_days");
  const [ageMaxDays, setAgeMaxDays] = useQueryParamState("age_max_days");
  const [slaStatus, setSLAStatus] = useQueryParamState("sla_status");
  const [owner, setOwner] = useQueryParamState("owner");
  const [query, setQuery] = useQueryParamState("q");
  const debouncedTenantID = useDebouncedValue(tenantID.trim());
  const debouncedRuntimeID = useDebouncedValue(runtimeID.trim());
  const debouncedSourceID = useDebouncedValue(sourceID.trim());

  const findingRequestParams = useMemo(() => ({
    tenant_id: debouncedTenantID,
    runtime_id: debouncedRuntimeID,
    source_id: debouncedSourceID,
    severity,
    status,
    framework,
    opened_after: openedAfter,
    opened_before: openedBefore,
    closed_after: closedAfter,
    closed_before: closedBefore,
    age_min_days: ageMinDays,
    age_max_days: ageMaxDays,
    sla_status: slaStatus,
  }), [ageMaxDays, ageMinDays, closedAfter, closedBefore, debouncedRuntimeID, debouncedSourceID, debouncedTenantID, framework, openedAfter, openedBefore, severity, slaStatus, status]);
  const path = useMemo(
    () => grcPath("/grc/findings", { ...findingRequestParams, limit: RISK_INBOX_LIST_LIMIT }),
    [findingRequestParams],
  );
  const { data, error, lastSuccessfulAt, reload, state: queryState } = useGRCQuery<FindingsResponse>(path);
  const { apiKey } = useApiKey();
  const [exportState, setExportState] = useState<"idle" | "working" | "failed">("idle");
  const metricState: RuntimeState = queryState === "stale" ? "ready" : queryState === "empty" ? "ready" : queryState;
  const boundedFindingRows = useMemo(
    () => grcBoundedRows({ rows: data?.findings, limit: RISK_INBOX_LIST_LIMIT, meta: data?.meta }),
    [data?.findings, data?.meta],
  );
  const loadedFindings = boundedFindingRows.rows;
  const loadedFindingMeta = data ? boundedFindingRows.meta : undefined;
  const findings = useMemo(
    () => filterRiskInboxFindings(loadedFindings, { framework, owner, query }),
    [framework, loadedFindings, owner, query],
  );
  const hasLoadedRowFilters = Boolean(owner.trim() || query.trim());
  const usesClientFilteredExport = Boolean(owner.trim() || query.trim());
  const exportFindings = useCallback(async () => {
    setExportState("working");
    const filename = grcExportFilename("findings");
    if (usesClientFilteredExport) {
      try {
        const response = await fetchCerebro<FindingsResponse>(
          grcPath("/grc/findings", { ...findingRequestParams, limit: RISK_INBOX_FILTERED_EXPORT_LIMIT }),
          apiKey,
        );
        if (!response.ok) {
          setExportState("failed");
          return;
        }
        const exportFindings = Array.isArray(response.data.findings) ? response.data.findings : [];
        downloadFindingsCSV(filterRiskInboxFindings(exportFindings, { framework, owner, query }), filename);
        setExportState("idle");
      } catch {
        setExportState("failed");
      }
      return;
    }

    const exportPath = grcPath("/grc/findings/export", findingRequestParams);
    const result = await downloadGRCExport(exportPath, apiKey, filename);
    setExportState(result.ok ? "idle" : "failed");
  }, [apiKey, findingRequestParams, framework, owner, query, usesClientFilteredExport]);
  const frameworkOptions = useMemo(
    () => Array.from(new Set([
      ...supportedGRCFrameworkNames,
      ...loadedFindings.flatMap((finding) => finding.controls?.map((control) => control.framework_name) ?? []).filter(Boolean),
    ])),
    [loadedFindings],
  );
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [previewFindingId, setPreviewFindingId] = useState<string | null>(null);
  const selectedUpcomingFramework = isUpcomingGRCFramework(framework);
  const { mutate, saving, error: mutationError, setError: setMutationError } = useGRCMutation();
  const selectedCount = useMemo(() => findings.reduce((count, f) => (selectedIds.has(f.id) ? count + 1 : count), 0), [findings, selectedIds]);
  const previewFinding = useMemo(
    () => findings.find((finding) => finding.id === previewFindingId) ?? null,
    [findings, previewFindingId],
  );
  const toggleSelect = useCallback((id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);
  const toggleSelectAll = useCallback((ids: string[], selected: boolean) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      ids.forEach((id) => (selected ? next.add(id) : next.delete(id)));
      return next;
    });
  }, []);
  const clearSelection = useCallback(() => setSelectedIds(new Set()), []);
  const applyDisposition = useCallback(async (disposition: FindingDisposition) => {
    const batches = triageBatchesByTenant(findings, selectedIds, disposition);
    if (batches.length === 0) {
      setMutationError("Selected findings are missing tenant context.");
      return;
    }
    try {
      for (const batch of batches) {
        await mutate("/grc/findings/triage", batch);
      }
      clearSelection();
      await reload();
    } catch {
      // error surfaced via mutationError
    }
  }, [clearSelection, findings, mutate, reload, selectedIds, setMutationError]);
  const metrics = useMemo(() => {
    let critical = 0, high = 0, criticalRisk = 0, overdue = 0, scored = 0, riskTotal = 0, unassigned = 0;
    findings.forEach((f) => {
      if (f.severity === "CRITICAL") critical += 1;
      if (f.severity === "HIGH") high += 1;
      if ((f.risk_score ?? 0) >= 85) criticalRisk += 1;
      if (typeof f.risk_score === "number") { scored += 1; riskTotal += f.risk_score; }
      if (f.sla_status === "overdue") overdue += 1;
      if (!f.owner || f.owner === "Unassigned") unassigned += 1;
    });
    return { averageRisk: scored === 0 ? 0 : Math.round(riskTotal / scored), critical, criticalRisk, high, overdue, unassigned };
  }, [findings]);
  const filterChips = [
    { label: "Search", value: query, onClear: () => setQuery("") },
    { label: "Tenant", value: tenantID, onClear: () => setTenantID("") },
    { label: "Runtime", value: runtimeID, onClear: () => setRuntimeID("") },
    { label: "Source", value: sourceID, onClear: () => setSourceID("") },
    { label: "Framework", value: framework, onClear: () => setFramework("") },
    { label: "Severity", value: severity, onClear: () => setSeverity("") },
    { label: "Status", value: status === "open" ? "" : status, onClear: () => setStatus("open") },
    { label: "Opened after", value: openedAfter, onClear: () => setOpenedAfter("") },
    { label: "Opened before", value: openedBefore, onClear: () => setOpenedBefore("") },
    { label: "Closed after", value: closedAfter, onClear: () => setClosedAfter("") },
    { label: "Closed before", value: closedBefore, onClear: () => setClosedBefore("") },
    { label: "Age min", value: ageMinDays, onClear: () => setAgeMinDays("") },
    { label: "Age max", value: ageMaxDays, onClear: () => setAgeMaxDays("") },
    { label: "SLA", value: slaStatus, onClear: () => setSLAStatus("") },
    { label: "Owner", value: owner, onClear: () => setOwner("") },
  ];
  const clearFilters = () => {
    setQuery("");
    setTenantID("");
    setRuntimeID("");
    setSourceID("");
    setFramework("");
    setSeverity("");
    setStatus("open");
    setOpenedAfter("");
    setOpenedBefore("");
    setClosedAfter("");
    setClosedBefore("");
    setAgeMinDays("");
    setAgeMaxDays("");
    setSLAStatus("");
    setOwner("");
  };

  return (
    <div className="space-y-6">
      <PageHeader
        contractId="risk-inbox"
        title="Risks"
        description="Triage findings by risk, severity, owner, entity, and SLA."
        action={
          <div className="flex items-center gap-2">
            <button type="button" onClick={() => void exportFindings()} disabled={exportState === "working"} title={usesClientFilteredExport ? `Exports up to ${RISK_INBOX_FILTERED_EXPORT_LIMIT} rows matching the owner/search filters.` : undefined} className="rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] font-medium text-slate-700 transition hover:border-slate-300 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50">
              {exportState === "working" ? "Exporting..." : exportState === "failed" ? "Export failed" : usesClientFilteredExport ? "Export filtered CSV" : "Export CSV"}
            </button>
            <button type="button" onClick={() => void reload()} className="rounded-md border border-slate-200 bg-indigo-500 px-3 py-1.5 text-[13px] font-medium text-white transition hover:bg-indigo-600">
              Refresh
            </button>
          </div>
        }
      />

      <div className="rounded-lg border border-slate-200 bg-white px-5 py-4">
        <div className="grid gap-3 md:grid-cols-8">
          <div className="md:col-span-2">
            <label className={labelClass}>
              Search
              <div className="relative">
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="absolute left-2.5 top-[11px] h-4 w-4 text-slate-400">
                  <path strokeLinecap="round" strokeLinejoin="round" d="m21 21-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z" />
                </svg>
                <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter loaded findings" className={`${inputClass} pl-8`} />
              </div>
            </label>
          </div>
          <label className={labelClass}>Tenant<input value={tenantID} onChange={(e) => setTenantID(e.target.value)} placeholder="All" className={inputClass} /></label>
          <label className={labelClass}>Runtime<input value={runtimeID} onChange={(e) => setRuntimeID(e.target.value)} placeholder="All" className={inputClass} /></label>
          <label className={labelClass}>Source<input value={sourceID} onChange={(e) => setSourceID(e.target.value)} placeholder="All" className={inputClass} /></label>
          <label className={labelClass}>Owner<input value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="Loaded rows" className={inputClass} /></label>
          <label className={labelClass}>
            Framework
            <input value={framework} onChange={(e) => setFramework(e.target.value)} placeholder="DORA" list="risk-framework-options" className={inputClass} />
            <datalist id="risk-framework-options">
              {frameworkOptions.map((name) => <option key={name} value={name} label={frameworkOptionLabel(name)} />)}
            </datalist>
          </label>
          <label className={labelClass}>Severity<select value={severity} onChange={(e) => setSeverity(e.target.value)} className={selectClass}><option value="">All</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option></select></label>
          <label className={labelClass}>Status<select value={status} onChange={(e) => setStatus(e.target.value)} className={selectClass}><option value="open">Open</option><option value="resolved">Resolved</option><option value="all">All</option></select></label>
          <label className={labelClass}>SLA<select value={slaStatus} onChange={(e) => setSLAStatus(e.target.value)} className={selectClass}><option value="">All</option><option value="overdue">Overdue</option><option value="due_soon">Due soon</option><option value="on_track">On track</option><option value="no_due_date">No due date</option><option value="closed">Closed</option></select></label>
          <label className={labelClass}>Opened after<input type="date" value={openedAfter} onChange={(e) => setOpenedAfter(e.target.value)} className={inputClass} /></label>
          <label className={labelClass}>Opened before<input type="date" value={openedBefore} onChange={(e) => setOpenedBefore(e.target.value)} className={inputClass} /></label>
          <label className={labelClass}>Closed after<input type="date" value={closedAfter} onChange={(e) => setClosedAfter(e.target.value)} className={inputClass} /></label>
          <label className={labelClass}>Closed before<input type="date" value={closedBefore} onChange={(e) => setClosedBefore(e.target.value)} className={inputClass} /></label>
          <label className={labelClass}>Age min days<input value={ageMinDays} onChange={(e) => setAgeMinDays(e.target.value)} placeholder="0" inputMode="numeric" className={inputClass} /></label>
          <label className={labelClass}>Age max days<input value={ageMaxDays} onChange={(e) => setAgeMaxDays(e.target.value)} placeholder="30" inputMode="numeric" className={inputClass} /></label>
        </div>
        <AppliedFilterChips filters={filterChips} onClearAll={clearFilters} />
      </div>

      <div className="grid gap-4 md:grid-cols-5">
        <MetricCard label="Findings" value={selectedUpcomingFramework ? "N/A" : findings.length} detail={selectedUpcomingFramework ? "upcoming" : "in scope"} state={metricState} />
        <MetricCard label="Avg Risk" value={selectedUpcomingFramework ? "N/A" : <RiskBadge score={metrics.averageRisk} />} detail={selectedUpcomingFramework ? "not measured" : `${metrics.criticalRisk} critical-risk`} intent={selectedUpcomingFramework ? "neutral" : metrics.criticalRisk > 0 ? "danger" : "neutral"} state={metricState} />
        <MetricCard label="Critical / High" value={selectedUpcomingFramework ? "N/A" : `${metrics.critical} / ${metrics.high}`} detail={selectedUpcomingFramework ? "not measured" : undefined} intent={selectedUpcomingFramework ? "neutral" : metrics.critical > 0 ? "danger" : "neutral"} state={metricState} />
        <MetricCard label="Overdue" value={selectedUpcomingFramework ? "N/A" : metrics.overdue} detail={selectedUpcomingFramework ? "not measured" : "past SLA"} intent={selectedUpcomingFramework ? "neutral" : metrics.overdue > 0 ? "danger" : "success"} state={metricState} />
        <MetricCard label="Unassigned" value={selectedUpcomingFramework ? "N/A" : metrics.unassigned} detail={selectedUpcomingFramework ? "not measured" : "needs owner"} intent={selectedUpcomingFramework ? "neutral" : metrics.unassigned > 0 ? "warning" : "success"} state={metricState} />
      </div>

      {selectedUpcomingFramework && (
        <div className="rounded-lg border border-dashed border-violet-200 bg-violet-50/60 p-6 text-center text-[13px] text-violet-700">
          {framework.trim()} is upcoming. It is discoverable for planning, but not yet included in measured finding posture.
        </div>
      )}

      <DataStateBanner
        state={queryState}
        subject="Findings"
        error={error}
        lastSuccessfulAt={lastSuccessfulAt}
        onRetry={() => void reload()}
        detail={queryState === "loading" ? "Loading findings." : queryState === "unavailable" ? "Findings will appear when graph data is reachable." : undefined}
      />
      {data && (
        <div>
          {selectedCount > 0 && (
            <div className="sticky top-2 z-10 mb-3 flex flex-wrap items-center gap-2 rounded-lg border border-indigo-200 bg-indigo-50 px-4 py-2.5">
              <span className="text-[13px] font-semibold text-indigo-900">{countLabel(selectedCount, "finding")} selected</span>
              <span className="text-[12px] text-indigo-700">Set disposition:</span>
              <div className="flex flex-wrap gap-1.5">
                {FINDING_DISPOSITION_OPTIONS.map((option) => (
                  <button
                    key={option.value}
                    type="button"
                    disabled={saving}
                    onClick={() => void applyDisposition(option.value)}
                    className="rounded-md border border-indigo-300 bg-white px-2.5 py-1 text-[12px] font-medium text-indigo-700 transition hover:bg-indigo-100 disabled:opacity-50"
                  >
                    {option.label}
                  </button>
                ))}
              </div>
              <button type="button" onClick={clearSelection} className="ml-auto text-[12px] font-medium text-slate-500 transition hover:text-slate-700">
                Clear
              </button>
              {saving && <span className="text-[12px] text-indigo-700">Saving...</span>}
              {mutationError && <span className="w-full text-[12px] text-red-600">{mutationError}</span>}
            </div>
          )}
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-[13px] font-semibold text-slate-900">{countLabel(findings.length, "finding")}</h2>
          </div>
          <ResultLimitNotice
            loaded={loadedFindings.length}
            meta={loadedFindingMeta}
            limit={RISK_INBOX_LIST_LIMIT}
            noun="findings"
            className="mb-3"
          />
          {hasLoadedRowFilters && (
            <div className="mb-3 rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2 text-[12px] text-[var(--text-muted)]">
              Search and owner filters apply to loaded findings.
            </div>
          )}
          <FindingTable
            findings={findings}
            selectable
            selectedIds={selectedIds}
            onToggleSelect={toggleSelect}
            onToggleSelectAll={toggleSelectAll}
            onPreviewFinding={(finding) => setPreviewFindingId(finding.id)}
          />
        </div>
      )}
      <FindingReviewDrawer finding={previewFinding} onClose={() => setPreviewFindingId(null)} />
    </div>
  );
}

function FindingReviewDrawer({
  finding,
  onClose,
}: {
  finding: GRCFinding | null;
  onClose: () => void;
}) {
  const entity = finding?.entity || finding?.resource_urns?.[0] || "";
  const controls = finding?.controls ?? [];
  const sourceCoverage = finding?.source_coverage_refs ?? [];

  return (
    <ReviewDrawer
      open={Boolean(finding)}
      onClose={onClose}
      title={finding?.title ?? "Finding review"}
      subtitle={finding ? finding.id : undefined}
      footer={finding && (
        <div className="flex flex-wrap gap-2">
          <Link href={`/findings/${encodeURIComponent(finding.id)}`} className="primary-button px-3 py-1.5 text-[12px]">Open finding</Link>
          {entity && <Link href={`/explore?root_urn=${encodeURIComponent(entity)}`} className="secondary-button px-3 py-1.5 text-[12px]">Relationships</Link>}
          {entity && <Link href={`/impact?root_urn=${encodeURIComponent(entity)}`} className="secondary-button px-3 py-1.5 text-[12px]">Affected assets</Link>}
        </div>
      )}
    >
      {finding && (
        <div className="space-y-5">
          <section>
            <div className="flex flex-wrap items-center gap-2">
              <RiskBadge score={finding.risk_score} />
              <span className="inline-flex items-center gap-1.5">
                <SeverityDot severity={finding.severity} />
                <Badge value={finding.severity} tone="severity" />
              </span>
              <Badge value={finding.status} />
              {finding.disposition && <Badge value={finding.disposition} />}
            </div>
            <p className="mt-3 text-[13px] leading-5 text-[var(--text-secondary)]">
              {finding.risk_statement || finding.summary || "No risk statement returned."}
            </p>
          </section>

          <section className="grid gap-3 border-t border-[color:var(--border)] pt-4 sm:grid-cols-2">
            <div>
              <div className="text-[11px] font-medium uppercase tracking-wide text-[var(--text-muted)]">Owner</div>
              <div className="mt-1 text-[13px] font-medium text-[var(--text-primary)]">{finding.owner || "Unassigned"}</div>
            </div>
            <div>
              <div className="text-[11px] font-medium uppercase tracking-wide text-[var(--text-muted)]">SLA</div>
              <div className="mt-1 flex flex-wrap items-center gap-2">
                <Badge value={finding.sla_status} />
                <span className="text-[12px] text-[var(--text-muted)]">{finding.due_at ? displayDate(finding.due_at) : "No due date"}</span>
              </div>
            </div>
            <div>
              <div className="text-[11px] font-medium uppercase tracking-wide text-[var(--text-muted)]">Entity</div>
              <div className="mt-1 truncate font-mono text-[12px] text-[var(--text-primary)]">{entity ? shortEntity(entity) : "No entity"}</div>
            </div>
            <div>
              <div className="text-[11px] font-medium uppercase tracking-wide text-[var(--text-muted)]">Evidence</div>
              <div className="mt-1 text-[13px] font-medium text-[var(--text-primary)]">{countLabel(finding.evidence_count, "item")}</div>
            </div>
          </section>

          <section className="border-t border-[color:var(--border)] pt-4">
            <h3 className="text-[12px] font-semibold text-[var(--text-primary)]">Source context</h3>
            <dl className="mt-3 grid gap-3 text-[12px] sm:grid-cols-2">
              <div>
                <dt className="text-[var(--text-muted)]">Source</dt>
                <dd className="mt-1 truncate text-[var(--text-primary)]">{finding.source_id || "Not returned"}</dd>
              </div>
              <div>
                <dt className="text-[var(--text-muted)]">Runtime</dt>
                <dd className="mt-1 truncate text-[var(--text-primary)]">{finding.runtime_id || "Not returned"}</dd>
              </div>
              <div>
                <dt className="text-[var(--text-muted)]">Rule</dt>
                <dd className="mt-1 truncate text-[var(--text-primary)]">{finding.rule_id || "Not returned"}</dd>
              </div>
              <div>
                <dt className="text-[var(--text-muted)]">Last seen</dt>
                <dd className="mt-1 text-[var(--text-primary)]">{displayDate(finding.last_observed_at)}</dd>
              </div>
            </dl>
          </section>

          <section className="border-t border-[color:var(--border)] pt-4">
            <div className="flex items-center justify-between gap-3">
              <h3 className="text-[12px] font-semibold text-[var(--text-primary)]">Mapped controls</h3>
              <span className="text-[11px] text-[var(--text-muted)]">{controls.length.toLocaleString()} total</span>
            </div>
            {controls.length > 0 ? (
              <div className="mt-3 flex flex-wrap gap-2">
                {controls.slice(0, 8).map((control) => (
                  <Link
                    key={`${control.framework_name}:${control.control_id}`}
                    href={`/controls?framework=${encodeURIComponent(control.framework_name)}&control=${encodeURIComponent(control.control_id)}`}
                    className="rounded-md border border-[color:var(--border)] px-2 py-1 text-[12px] font-medium text-[var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[var(--text-primary)]"
                  >
                    {control.framework_name} {control.control_id}
                  </Link>
                ))}
              </div>
            ) : (
              <p className="mt-2 text-[13px] text-[var(--text-muted)]">No mapped controls returned.</p>
            )}
          </section>

          <section className="border-t border-[color:var(--border)] pt-4">
            <div className="flex items-center justify-between gap-3">
              <h3 className="text-[12px] font-semibold text-[var(--text-primary)]">Coverage</h3>
              <span className="text-[11px] text-[var(--text-muted)]">{sourceCoverage.length.toLocaleString()} refs</span>
            </div>
            {sourceCoverage.length > 0 ? (
              <div className="mt-3 space-y-2">
                {sourceCoverage.slice(0, 5).map((coverage, index) => (
                  <div key={`${coverage.source_id ?? "source"}:${coverage.dimension_id ?? index}`} className="rounded-md bg-[var(--surface-muted)] px-3 py-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[12px] font-medium text-[var(--text-primary)]">{coverage.source_id || "Source"}</span>
                      {coverage.support_level && <Badge value={coverage.support_level} />}
                      {coverage.high_value && <Badge value="high_value" />}
                    </div>
                    <div className="mt-1 text-[12px] text-[var(--text-muted)]">
                      {[coverage.dimension_type, coverage.dimension_id, coverage.evidence_types?.map(humanize).join(", ")].filter(Boolean).join(" - ")}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="mt-2 text-[13px] text-[var(--text-muted)]">No source coverage refs returned.</p>
            )}
          </section>

          {finding.remediation_intent && (
            <section className="border-t border-[color:var(--border)] pt-4">
              <h3 className="text-[12px] font-semibold text-[var(--text-primary)]">Remediation</h3>
              <p className="mt-2 text-[13px] leading-5 text-[var(--text-secondary)]">{finding.remediation_intent}</p>
            </section>
          )}
        </div>
      )}
    </ReviewDrawer>
  );
}
