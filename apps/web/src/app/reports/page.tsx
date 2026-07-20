"use client";

import { CalendarClock, Copy, Download, FileDown, RefreshCw, Search, ShieldCheck } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";
import { useMemo, useState } from "react";

import { type TableColumn, WorklistTable } from "@/components/grc/DataTable";
import GraphViewer from "@/components/grc/LazyGraphViewer";
import { AppliedFilterChips, Badge, ErrorBlock, LoadingBlock, MetricCard, PageHeader, Panel, RiskBadge, RiskBreakdown } from "@/components/grc/Primitives";
import { countLabel } from "@/lib/format";
import {
  displayDate,
  GRCAuditPacket,
  GRCControlEvidencePacketResponse,
  GRCControlPacketControl,
  GRCFinding,
  GRCListMeta,
  GRCReportMetadata,
  riskSort,
  shortEntity,
} from "@/lib/grc";
import { findingMatchesFrameworkSegment, frameworkOptionLabel, isUpcomingGRCFramework, supportedGRCFrameworkNames } from "@/lib/grc-frameworks";
import { grcPath, useDebouncedValue, useGRCQuery } from "@/lib/grc-client";
import { GRC_PICKER_LIMIT, GRC_WORKLIST_LIMIT, grcBoundedRows, grcLoadedRowsCopy } from "@/lib/grc-list";
import {
  redactReportGraph,
  redactReportIdentifier,
  redactReportText,
  reportReadinessIntent,
  reportReadinessLabel,
  reportRedactionMode,
  ReportRedactionMode,
} from "@/lib/grc-report-packets";
import { useQueryParamState } from "@/lib/query-params";
import { runtimeStateForError, type RuntimeState } from "@/lib/runtime-state";

type FindingsResponse = { findings: GRCFinding[]; meta?: GRCListMeta; generated_at: string };
type ReportMode = "finding" | "control";
type CopyState = "idle" | "copied" | "failed";

const DEFAULT_CONTROL_PROFILE_ID = "soc2-security-core";
const FINDING_PICKER_LIMIT = GRC_PICKER_LIMIT;
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
const inputClass = "mt-1 w-full rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] text-slate-900 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30 dark:border-white/10 dark:bg-white/5 dark:text-slate-100";
const labelClass = "text-[11px] font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400";
const buttonClass = "inline-flex items-center gap-1.5 rounded-md border border-[color:var(--border)] bg-white px-3 py-1.5 text-[12px] font-medium text-[var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-50 dark:bg-white/5";

const findingPickerColumns: TableColumn<GRCFinding>[] = [
  { key: "risk_score", label: "Risk", render: (_value, finding) => <RiskBadge score={finding.risk_score} /> },
  { key: "severity", label: "Severity", render: (_value, finding) => <Badge value={finding.severity} tone="severity" /> },
  {
    key: "title",
    label: "Finding",
    render: (_value, finding) => (
      <div className="min-w-[18rem]">
        <div className="line-clamp-2 font-medium text-[var(--text-primary)]">{finding.title}</div>
        <div className="mt-0.5 truncate font-mono text-[11px] text-[var(--text-muted)]">{finding.id}</div>
      </div>
    ),
  },
  { key: "owner", label: "Owner", render: (_value, finding) => finding.owner || <span className="text-[var(--text-muted)]">Unassigned</span> },
  { key: "entity", label: "Entity", render: (_value, finding) => <span className="font-mono text-[12px]">{shortEntity(finding.entity)}</span> },
  {
    key: "controls",
    label: "Controls",
    render: (_value, finding) => {
      const controls = finding.controls ?? [];
      if (controls.length === 0) return <span className="text-[var(--text-muted)]">Not mapped</span>;
      return (
        <div className="max-w-[14rem] truncate">
          {controls.slice(0, 2).map((control) => `${control.framework_name} ${control.control_id}`).join(", ")}
          {controls.length > 2 ? ` +${controls.length - 2}` : ""}
        </div>
      );
    },
  },
  { key: "last_observed_at", label: "Last seen", render: (_value, finding) => <span className="text-[var(--text-muted)]">{displayDate(finding.last_observed_at)}</span> },
];

const findingPickerSearchKeys = [
  "id",
  "title",
  "summary",
  "owner",
  "entity",
  "runtime_id",
  "source_id",
  "rule_id",
  "severity",
  "status",
  "sla_status",
  "controls",
];

const controlPacketColumns: TableColumn<GRCControlPacketControl>[] = [
  {
    key: "control",
    label: "Control",
    render: (_value, control) => (
      <div className="min-w-[16rem]">
        <div className="font-mono text-[12px] font-semibold text-[var(--text-primary)]">{controlLabel(control)}</div>
        <div className="mt-0.5 line-clamp-2 text-[12px] text-[var(--text-muted)]">{control.control.title || control.control.family_name || "Control objective"}</div>
      </div>
    ),
  },
  { key: "status", label: "Status", render: (_value, control) => <Badge value={control.status} /> },
  { key: "readiness", label: "Packet score", render: (_value, control) => control.audit_readiness ? `${control.audit_readiness.score}/100` : "—" },
  { key: "evidence", label: "Evidence", render: (_value, control) => evidenceItemCount(control).toLocaleString() },
  { key: "findings", label: "Findings", render: (_value, control) => (control.findings?.length ?? 0).toLocaleString() },
  { key: "mapped_rules", label: "Rules", render: (_value, control) => (control.mapped_rules?.length ?? 0).toLocaleString() },
];

const controlPacketSearchKeys = [
  "selection_id",
  "control",
  "status",
  "reasons",
  "tags",
  "mapped_rules",
  "findings",
  "evidence",
  "audit_readiness",
];

const statusCount = (packet: GRCControlEvidencePacketResponse | null | undefined, status: string) =>
  packet?.packet.summary.by_status?.[status] ?? 0;

const evidenceItemCount = (control: GRCControlPacketControl) =>
  control.evidence.items?.length ?? control.evidence.summary?.evidence_ids?.length ?? 0;

const controlLabel = (control: GRCControlPacketControl) =>
  `${control.control.framework_name} ${control.control.control_id}`;

const controlPacketRowKey = (control: GRCControlPacketControl) =>
  control.selection_id || `${control.control.framework_name}:${control.control.control_id}`;

const modeFromState = (reportType: string, findingID: string, profileID: string, framework: string, controlID: string): ReportMode => {
  if (reportType === "control") return "control";
  if (reportType === "finding") return "finding";
  if (!findingID.trim() && (profileID.trim() || framework.trim() || controlID.trim())) return "control";
  return "finding";
};

export default function ReportsPage() {
  const [tenantID, setTenantID] = useQueryParamState("tenant_id");
  const [findingID, setFindingID] = useQueryParamState("finding_id");
  const [profileID, setProfileID] = useQueryParamState("profile");
  const [framework, setFramework] = useQueryParamState("framework");
  const [controlID, setControlID] = useQueryParamState("control");
  const [reportType, setReportType] = useQueryParamState("report_type");
  const [query, setQuery] = useQueryParamState("q");
  const [redactionMode, setRedactionMode] = useState<ReportRedactionMode>("share_safe");
  const [copyState, setCopyState] = useState<CopyState>("idle");
  const debouncedTenantID = useDebouncedValue(tenantID.trim());
  const debouncedQuery = useDebouncedValue(query.trim());
  const selectedProfileID = profileID.trim() || DEFAULT_CONTROL_PROFILE_ID;
  const reportMode = modeFromState(reportType, findingID, profileID, framework, controlID);

  const findingsPath = useMemo(
    () => grcPath("/grc/findings", { tenant_id: debouncedTenantID, status: "open", limit: FINDING_PICKER_LIMIT }),
    [debouncedTenantID],
  );
  const findingsQuery = useGRCQuery<FindingsResponse>(findingsPath);
  const boundedFindingRows = useMemo(
    () => grcBoundedRows({ rows: findingsQuery.data?.findings, limit: FINDING_PICKER_LIMIT, meta: findingsQuery.data?.meta }),
    [findingsQuery.data?.findings, findingsQuery.data?.meta],
  );
  const loadedFindings = boundedFindingRows.rows;
  const loadedFindingMeta = findingsQuery.data ? boundedFindingRows.meta : undefined;
  const findings = useMemo(() => {
    const q = debouncedQuery.toLowerCase();
    return loadedFindings
      .filter((finding) => findingMatchesFrameworkSegment(finding, framework))
      .filter((finding) => {
        if (!q) return true;
        return [
          finding.id,
          finding.title,
          finding.summary,
          finding.owner,
          finding.entity,
          finding.runtime_id,
          finding.source_id,
          finding.rule_id,
          ...(finding.controls ?? []).map((control) => `${control.framework_name} ${control.control_id}`),
        ].filter(Boolean).some((value) => String(value).toLowerCase().includes(q));
      })
      .slice()
      .sort(riskSort);
  }, [debouncedQuery, framework, loadedFindings]);
  const selectedFindingID = reportMode === "finding" ? findingID.trim() || findings[0]?.id || "" : "";
  const selectedFinding = findings.find((finding) => finding.id === selectedFindingID) ?? findings[0];
  const findingPacket = useGRCQuery<GRCAuditPacket>(
    reportMode === "finding" && selectedFindingID ? grcPath(`/grc/audit-packets/${encodeURIComponent(selectedFindingID)}`, { limit: 25 }) : null,
  );
  const controlPacket = useGRCQuery<GRCControlEvidencePacketResponse>(
    reportMode === "control"
      ? grcPath("/grc/control-packets", { tenant_id: debouncedTenantID, profile: selectedProfileID, framework, control: controlID, limit: GRC_WORKLIST_LIMIT })
      : null,
  );
  const boundedControlRows = useMemo(
    () => grcBoundedRows({ rows: controlPacket.data?.controls, limit: GRC_WORKLIST_LIMIT, total: controlPacket.data?.packet?.summary?.total }),
    [controlPacket.data?.controls, controlPacket.data?.packet?.summary?.total],
  );
  const loadedControlRows = boundedControlRows.rows;
  const frameworkOptions = useMemo(
    () => Array.from(new Set([
      ...supportedGRCFrameworkNames,
      ...loadedFindings.flatMap((finding) => finding.controls?.map((control) => control.framework_name) ?? []).filter(Boolean),
      ...loadedControlRows.map((control) => control.framework_name).filter(Boolean),
    ])),
    [loadedControlRows, loadedFindings],
  );
  const metadata = reportMode === "control" ? controlPacket.data?.metadata : findingPacket.data?.metadata;
  const selectedUpcomingFramework = reportMode === "control" && isUpcomingGRCFramework(framework);
  const effectiveRedactionMode = metadata ? redactionMode : reportRedactionMode(metadata);
  const rawReportBody = useMemo(() => {
    if (reportMode === "control") return buildControlReportBody(controlPacket.data, framework, controlID);
    return buildFindingReportBody(findingPacket.data);
  }, [controlID, controlPacket.data, findingPacket.data, framework, reportMode]);
  const displayReportBody = redactReportText(rawReportBody, effectiveRedactionMode);
  const exportHref = reportMode === "control"
    ? selectedUpcomingFramework
      ? ""
      : `/api/cerebro${grcPath("/grc/control-packets/export", { tenant_id: debouncedTenantID, profile: selectedProfileID, framework, control: controlID })}`
    : selectedFindingID
      ? `/api/cerebro/grc/audit-packets/${encodeURIComponent(selectedFindingID)}/export`
      : "";
  const error = reportMode === "control" ? controlPacket.error : findingsQuery.error || findingPacket.error;
  const loading = reportMode === "control" ? controlPacket.loading : findingsQuery.loading || findingPacket.loading;
  const runtimeState = runtimeStateForError(error);
  const metricState: RuntimeState = error ? runtimeState : loading && !(controlPacket.data || findingPacket.data) ? "loading" : "ready";
  const filterChips = [
    { label: "Type", value: reportMode === "control" ? "Control packet" : "Finding packet", onClear: () => setReportType("") },
    { label: "Search", value: query, onClear: () => setQuery("") },
    { label: "Tenant", value: tenantID, onClear: () => setTenantID("") },
    { label: "Profile", value: reportMode === "control" ? selectedProfileID : "", onClear: () => setProfileID("") },
    { label: "Framework", value: framework, onClear: () => setFramework("") },
    { label: "Control", value: controlID, onClear: () => setControlID("") },
    { label: "Finding", value: findingID, onClear: () => setFindingID("") },
  ];

  const setMode = (mode: ReportMode) => {
    setReportType(mode);
    setCopyState("idle");
    if (mode === "control") {
      setFindingID("");
      if (!profileID.trim()) setProfileID(DEFAULT_CONTROL_PROFILE_ID);
      return;
    }
    setProfileID("");
    setControlID("");
  };
  const reload = () => {
    void findingsQuery.reload();
    void findingPacket.reload();
    void controlPacket.reload();
  };
  const clearFilters = () => {
    setQuery("");
    setTenantID("");
    setFindingID("");
    setProfileID("");
    setFramework("");
    setControlID("");
    setReportType("");
  };
  const copyReport = async () => {
    if (!displayReportBody) return;
    try {
      await navigator.clipboard.writeText(displayReportBody);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  };
  const downloadReport = () => {
    if (!displayReportBody) return;
    const blob = new Blob([displayReportBody], { type: "text/markdown;charset=utf-8" });
    const href = window.URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = href;
    anchor.download = reportMode === "control" ? "control-evidence-packet.md" : "finding-audit-packet.md";
    anchor.click();
    window.URL.revokeObjectURL(href);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        contractId="reports"
        title="Reports"
        description="Create control evidence packets and finding packets with mapped evidence, scope exclusions, and source records."
        action={
          <div className="flex flex-wrap items-center justify-end gap-2">
            <PacketActions
              body={displayReportBody}
              exportHref={exportHref}
              copyState={copyState}
              redactionMode={effectiveRedactionMode}
              onCopy={() => void copyReport()}
              onDownload={downloadReport}
            />
            <Link href={`/reports/audit-packages?profile=${encodeURIComponent(selectedProfileID)}${framework ? `&framework=${encodeURIComponent(framework)}` : ""}${controlID ? `&control=${encodeURIComponent(controlID)}` : ""}`} className={buttonClass}>
              <ShieldCheck className="h-3.5 w-3.5" />
              Review packets
            </Link>
            <Link href="/reports/schedules" className={buttonClass}>
              <CalendarClock className="h-3.5 w-3.5" />
              Schedules
            </Link>
            <button type="button" onClick={reload} className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-indigo-500 px-3 py-1.5 text-[13px] font-medium text-white transition hover:bg-indigo-600">
              <RefreshCw className="h-3.5 w-3.5" />
              Refresh
            </button>
          </div>
        }
      />

      <div className="surface-panel p-5">
        <div className="flex flex-wrap items-center gap-2">
          <ModeButton active={reportMode === "finding"} label="Finding packet" onClick={() => setMode("finding")} />
          <ModeButton active={reportMode === "control"} label="Control packet" onClick={() => setMode("control")} />
        </div>
        <div className={`mt-4 grid gap-3 ${reportMode === "control" ? "md:grid-cols-5" : "md:grid-cols-6"}`}>
          <label className={labelClass}>Tenant<input value={tenantID} onChange={(event) => setTenantID(event.target.value)} placeholder="All" className={inputClass} /></label>
          <label className={`${labelClass} ${reportMode === "finding" ? "md:col-span-2" : ""}`}>
            Search
            <div className="relative">
              <Search className="absolute left-2.5 top-[11px] h-4 w-4 text-slate-400" />
              <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={reportMode === "control" ? "Filter context" : "Filter loaded findings"} className={`${inputClass} pl-8`} />
            </div>
          </label>
          {reportMode === "control" ? (
            <>
              <label className={labelClass}>
                Profile
                <input value={selectedProfileID} onChange={(event) => setProfileID(event.target.value)} list="grc-report-profile-options" className={inputClass} />
                <datalist id="grc-report-profile-options">
                  {CONTROL_PROFILE_OPTIONS.map((name) => <option key={name} value={name} />)}
                </datalist>
              </label>
              <label className={labelClass}>
                Framework
                <input value={framework} onChange={(event) => setFramework(event.target.value)} placeholder="SOC 2" list="grc-report-framework-options" className={inputClass} />
                <datalist id="grc-report-framework-options">
                  {frameworkOptions.map((name) => <option key={name} value={name} label={frameworkOptionLabel(name)} />)}
                </datalist>
              </label>
              <label className={labelClass}>Control<input value={controlID} onChange={(event) => setControlID(event.target.value)} placeholder="CC6.1" className={inputClass} /></label>
            </>
          ) : (
            <>
              <label className={labelClass}>
                Framework
                <input value={framework} onChange={(event) => setFramework(event.target.value)} placeholder="All frameworks" list="grc-report-framework-options" className={inputClass} />
                <datalist id="grc-report-framework-options">
                  {frameworkOptions.map((name) => <option key={name} value={name} label={frameworkOptionLabel(name)} />)}
                </datalist>
              </label>
              <label className="md:col-span-2 text-[11px] font-medium uppercase tracking-wider text-slate-500">
                Finding ID
                <input value={findingID} onChange={(event) => setFindingID(event.target.value)} placeholder={selectedFinding?.id || "Select from live findings"} className={inputClass} />
              </label>
            </>
          )}
        </div>
        <AppliedFilterChips filters={filterChips} onClearAll={clearFilters} />
      </div>

      {reportMode === "finding" && (
        <FindingPicker
          findings={findings}
          loadedCount={loadedFindings.length}
          meta={loadedFindingMeta}
          selectedFindingID={selectedFindingID}
          onSelect={setFindingID}
          loading={findingsQuery.loading}
        />
      )}

      {loading && <LoadingBlock label="Loading report packet..." />}
      {error && (
        <ErrorBlock
          error={error}
          onRetry={reload}
          recoveryDetail="Other risks, controls, and evidence remain available while this packet request recovers."
        />
      )}

      {reportMode === "control" && controlPacket.data && (
        <ControlPacketView
          packet={controlPacket.data}
          reportBody={displayReportBody}
          rawBody={rawReportBody}
          redactionMode={effectiveRedactionMode}
          onRedactionModeChange={setRedactionMode}
          state={metricState}
          upcomingFrameworkName={selectedUpcomingFramework ? framework.trim() : ""}
        />
      )}
      {reportMode === "finding" && !selectedFindingID && !findingsQuery.loading && !findingsQuery.error && (
        <div className="rounded-lg border border-dashed border-[color:var(--border-strong)] bg-white p-8 dark:bg-white/5">
          <div className="mx-auto max-w-2xl text-center">
            <h2 className="text-[15px] font-semibold text-[var(--text-primary)]">No finding packet is selected</h2>
            <p className="mt-2 text-[13px] leading-5 text-[var(--text-muted)]">
              Build a control evidence packet from the default profile, or enter a finding ID above for a finding-specific audit packet.
            </p>
            <div className="mt-4 flex flex-wrap justify-center gap-2">
              <Link href={`/reports?report_type=control&profile=${encodeURIComponent(DEFAULT_CONTROL_PROFILE_ID)}`} className="rounded-md border border-slate-200 bg-indigo-500 px-3 py-1.5 text-[13px] font-medium text-white transition hover:bg-indigo-600">
                Open control packet
              </Link>
              <Link href="/controls/builder" className={buttonClass}>
                Build custom pack
              </Link>
            </div>
          </div>
        </div>
      )}
      {reportMode === "finding" && findingPacket.data && (
        <FindingPacketView
          packet={findingPacket.data}
          reportBody={displayReportBody}
          rawBody={rawReportBody}
          redactionMode={effectiveRedactionMode}
          onRedactionModeChange={setRedactionMode}
          state={metricState}
        />
      )}
    </div>
  );
}

function ModeButton({ active, label, onClick }: { active: boolean; label: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-md px-3 py-1.5 text-[13px] font-medium transition ${active ? "bg-[var(--primary)] text-white" : "border border-[color:var(--border)] bg-white text-[var(--text-secondary)] hover:text-[var(--text-primary)] dark:bg-white/5"}`}
    >
      {label}
    </button>
  );
}

function PacketActions({
  body,
  exportHref,
  copyState,
  redactionMode,
  onCopy,
  onDownload,
}: {
  body: string;
  exportHref: string;
  copyState: CopyState;
  redactionMode: ReportRedactionMode;
  onCopy: () => void;
  onDownload: () => void;
}) {
  const disabled = body.trim() === "";
  const modeLabel = redactionMode === "internal" ? "internal" : "review copy";
  return (
    <>
      <button type="button" disabled={disabled} onClick={onCopy} className={buttonClass}>
        <Copy className="h-3.5 w-3.5" />
        {copyState === "copied" ? "Copied" : copyState === "failed" ? "Copy failed" : `Copy ${modeLabel}`}
      </button>
      <button type="button" disabled={disabled} onClick={onDownload} className={buttonClass}>
        <Download className="h-3.5 w-3.5" />
        Download {modeLabel}
      </button>
      {exportHref && (
        <a href={exportHref} className={buttonClass}>
          <FileDown className="h-3.5 w-3.5" />
          API export
        </a>
      )}
    </>
  );
}

function FindingPicker({
  findings,
  loadedCount,
  meta,
  selectedFindingID,
  onSelect,
  loading,
}: {
  findings: GRCFinding[];
  loadedCount: number;
  meta?: GRCListMeta;
  selectedFindingID: string;
  onSelect: (id: string) => void;
  loading: boolean;
}) {
  const facets = useMemo(() => {
    const severity = findings.reduce<Record<string, number>>((acc, finding) => {
      const key = finding.severity?.toLowerCase() || "unknown";
      acc[key] = (acc[key] ?? 0) + 1;
      return acc;
    }, {});
    const unassigned = findings.filter((finding) => !finding.owner || finding.owner === "Unassigned").length;
    const overdue = findings.filter((finding) => finding.sla_status?.toLowerCase().includes("overdue")).length;
    const frameworks = new Set(
      findings.flatMap((finding) => finding.controls?.map((control) => control.framework_name).filter(Boolean) ?? []),
    ).size;
    return [
      ["Critical", severity.critical ?? 0],
      ["High", severity.high ?? 0],
      ["Overdue", overdue],
      ["Unassigned", unassigned],
      ["Frameworks", frameworks],
    ] as const;
  }, [findings]);
  const scopeCopy = grcLoadedRowsCopy({ loaded: loadedCount, limit: FINDING_PICKER_LIMIT, meta, noun: "open findings" });
  if (loading && findings.length === 0) return null;
  return (
    <WorklistTable
      title="Open findings"
      description={(
        <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <span>{scopeCopy}</span>
          {facets.map(([label, value]) => (
            <span key={label}>{label}: {value.toLocaleString()}</span>
          ))}
        </span>
      )}
      rows={findings}
      columns={findingPickerColumns}
      emptyMessage="No open findings match the current filters."
      searchPlaceholder="Filter loaded finding rows"
      filterKeys={findingPickerSearchKeys}
      pageSize={12}
      getRowKey={(finding) => finding.id}
      selectedRowKey={selectedFindingID || null}
      onRowClick={(finding) => onSelect(finding.id)}
      resultNoun="findings"
      tableContainerClassName="max-h-[34rem] overflow-auto"
    />
  );
}

function ControlPacketView({
  packet,
  reportBody,
  rawBody,
  redactionMode,
  onRedactionModeChange,
  state,
  upcomingFrameworkName,
}: {
  packet: GRCControlEvidencePacketResponse;
  reportBody: string;
  rawBody: string;
  redactionMode: ReportRedactionMode;
  onRedactionModeChange: (mode: ReportRedactionMode) => void;
  state: RuntimeState;
  upcomingFrameworkName?: string;
}) {
  const boundedPacketControls = useMemo(
    () => grcBoundedRows({ rows: packet.packet.controls, limit: GRC_WORKLIST_LIMIT, total: packet.packet.summary.total }),
    [packet.packet.controls, packet.packet.summary.total],
  );
  const controls = boundedPacketControls.rows;
  const controlListMeta = boundedPacketControls.meta;
  const [selectedControlKey, setSelectedControlKey] = useState(() => controls[0] ? controlPacketRowKey(controls[0]) : "");
  const selectedControl =
    controls.find((control) => controlPacketRowKey(control) === selectedControlKey) ??
    controls[0] ??
    null;
  const evidenceCount = controls.reduce((sum, control) => sum + evidenceItemCount(control), 0);
  const readiness = packet.metadata?.readiness;
  const isUpcoming = Boolean(upcomingFrameworkName?.trim());
  const scopeCopy = grcLoadedRowsCopy({
    loaded: controls.length,
    limit: GRC_WORKLIST_LIMIT,
    meta: controlListMeta,
    noun: "controls",
  });
  return (
    <>
      <div className="grid gap-4 md:grid-cols-4">
        <MetricCard label="Packet score" value={isUpcoming ? "N/A" : readiness ? `${readiness.score}/100` : "—"} detail={isUpcoming ? "upcoming" : reportReadinessLabel(readiness?.status)} intent={isUpcoming ? "neutral" : reportReadinessIntent(readiness?.status)} state={state} />
        <MetricCard label="Controls" value={isUpcoming ? "N/A" : packet.packet.summary.total} detail={isUpcoming ? "not measured" : packet.profile.name || packet.profile.id} state={state} />
        <MetricCard label="Open Findings" value={isUpcoming ? "N/A" : statusCount(packet, "failing")} detail={isUpcoming ? "not measured" : "mapped to controls"} intent={isUpcoming ? "neutral" : statusCount(packet, "failing") > 0 ? "danger" : "success"} state={state} />
        <MetricCard label="Evidence" value={isUpcoming ? "N/A" : evidenceCount} detail={isUpcoming ? "not measured" : `${packet.metadata?.scope?.exclusions?.total ?? 0} exclusions`} state={state} />
      </div>

      <ReportBodyPanel
        title="Control evidence packet"
        body={reportBody}
        rawBody={rawBody}
        metadata={packet.metadata}
        redactionMode={redactionMode}
        onRedactionModeChange={onRedactionModeChange}
        sidecar={<ReportMetadataPanel metadata={packet.metadata} redactionMode={redactionMode} />}
      />

      <ScopePanel metadata={packet.metadata} redactionMode={redactionMode} />

      {controls.length === 0 ? (
        <Panel title="Control blockers">
          {isUpcoming ? (
            <div className="py-8 text-center text-[13px] text-violet-700">
              {upcomingFrameworkName} is upcoming. It is discoverable for planning, but not yet available for measured control evidence packets.
            </div>
          ) : (
            <div className="py-8 text-center text-[13px] text-[var(--text-muted)]">No controls match the selected packet filters.</div>
          )}
        </Panel>
      ) : (
        <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1.35fr)_minmax(320px,0.65fr)]">
          <WorklistTable
            title="Control blockers"
            description={scopeCopy}
            rows={controls}
            columns={controlPacketColumns}
            emptyMessage="No controls match the selected packet filters."
            searchPlaceholder="Filter loaded controls"
            filterKeys={controlPacketSearchKeys}
            pageSize={12}
            resultLimit={GRC_WORKLIST_LIMIT}
            resultMeta={controlListMeta}
            resultNoun="controls"
            getRowKey={(control) => controlPacketRowKey(control)}
            selectedRowKey={selectedControl ? controlPacketRowKey(selectedControl) : null}
            onRowClick={(control) => setSelectedControlKey(controlPacketRowKey(control))}
            tableContainerClassName="max-h-[34rem] overflow-auto"
          />
          <ControlReadinessDetail control={selectedControl} />
        </div>
      )}
    </>
  );
}

function ControlReadinessDetail({ control }: { control: GRCControlPacketControl | null }) {
  if (!control) {
    return (
      <Panel title="Control detail">
        <div className="py-8 text-center text-[13px] text-[var(--text-muted)]">Select a control.</div>
      </Panel>
    );
  }
  const expectations = control.evidence.expectations ?? [];
  const blockers = expectations.filter((expectation) => ["missing", "stale", "failed", "blocked"].includes(expectation.status.toLowerCase()));
  return (
    <Panel title="Control detail">
      <div className="flex flex-wrap items-center gap-2">
        <Badge value={control.status} />
        {control.audit_readiness && <Badge value={control.audit_readiness.rating} />}
      </div>
      <h3 className="mt-3 font-mono text-[13px] font-semibold text-[var(--text-primary)]">{controlLabel(control)}</h3>
      <p className="mt-1 text-[13px] leading-5 text-[var(--text-secondary)]">
        {control.control.title || control.control.family_name || "Control objective"}
      </p>
      <p className="mt-3 text-[12px] leading-5 text-[var(--text-muted)]">
        {control.audit_readiness?.summary || control.reasons?.[0] || "No packet blocker reported."}
      </p>
      <dl className="mt-4 space-y-2">
        <DetailRow label="Packet score" value={control.audit_readiness ? `${control.audit_readiness.score}/100` : "—"} />
        <DetailRow label="Findings" value={String(control.findings?.length ?? 0)} />
        <DetailRow label="Evidence" value={String(evidenceItemCount(control))} />
        <DetailRow label="Mapped rules" value={String(control.mapped_rules?.length ?? 0)} />
        <DetailRow label="Freshness" value={control.evidence.summary?.freshness_sla || "—"} />
      </dl>
      {blockers.length > 0 && (
        <div className="mt-5">
          <div className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">Blocked expectations</div>
          <div className="mt-2 space-y-2">
            {blockers.slice(0, 6).map((expectation) => (
              <div key={expectation.id} className="flex items-center justify-between gap-2 rounded-md bg-[var(--surface-muted)] px-3 py-2">
                <span className="truncate text-[12px] text-[var(--text-secondary)]">{expectation.title || expectation.id}</span>
                <Badge value={expectation.status} />
              </div>
            ))}
          </div>
        </div>
      )}
      {expectations.length > 0 && blockers.length === 0 && (
        <div className="mt-5 text-[12px] text-[var(--text-muted)]">{countLabel(expectations.length, "expectation")} reported.</div>
      )}
    </Panel>
  );
}

function FindingPacketView({
  packet,
  reportBody,
  rawBody,
  redactionMode,
  onRedactionModeChange,
  state,
}: {
  packet: GRCAuditPacket;
  reportBody: string;
  rawBody: string;
  redactionMode: ReportRedactionMode;
  onRedactionModeChange: (mode: ReportRedactionMode) => void;
  state: RuntimeState;
}) {
  const readiness = packet.metadata?.readiness;
  const graph = useMemo(() => redactReportGraph(packet.graph, redactionMode), [packet.graph, redactionMode]);
  return (
    <>
      <div className="grid gap-4 md:grid-cols-4">
        <MetricCard label="Packet score" value={readiness ? `${readiness.score}/100` : "—"} detail={reportReadinessLabel(readiness?.status)} intent={reportReadinessIntent(readiness?.status)} state={state} />
        <MetricCard label="Risk" value={<RiskBadge score={packet.finding.risk_score} />} detail={`L ${packet.finding.likelihood_score ?? "—"} / I ${packet.finding.impact_score ?? "—"}`} state={state} />
        <MetricCard label="Evidence" value={packet.evidence.length} detail="attached items" state={state} />
        <MetricCard label="Controls" value={(packet.controls ?? packet.finding.controls ?? []).length} detail={`${packet.metadata?.scope?.exclusions?.total ?? 0} exclusions`} state={state} />
      </div>

      <ReportBodyPanel
        title="Finding packet"
        body={reportBody}
        rawBody={rawBody}
        metadata={packet.metadata}
        redactionMode={redactionMode}
        onRedactionModeChange={onRedactionModeChange}
        sidecar={<FindingSidecar packet={packet} redactionMode={redactionMode} />}
      />

      <ScopePanel metadata={packet.metadata} redactionMode={redactionMode} />

      <Panel title="Impact path">
        <GraphViewer graph={graph} />
      </Panel>
    </>
  );
}

function ReportBodyPanel({
  title,
  body,
  rawBody,
  metadata,
  redactionMode,
  onRedactionModeChange,
  sidecar,
}: {
  title: string;
  body: string;
  rawBody: string;
  metadata?: GRCReportMetadata;
  redactionMode: ReportRedactionMode;
  onRedactionModeChange: (mode: ReportRedactionMode) => void;
  sidecar: ReactNode;
}) {
  const modeLabel = redactionMode === "internal" ? "Internal" : "Review copy";
  const modeDetail = redactionMode === "internal"
    ? "Copy and download include internal identifiers."
    : rawBody !== body
      ? "Copy and download use the redacted packet body."
      : "Copy and download use this packet body.";
  return (
    <Panel
      title={title}
      action={
        <div className="inline-flex rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] p-0.5">
          {(["share_safe", "internal"] as ReportRedactionMode[]).map((mode) => (
            <button
              key={mode}
              type="button"
              onClick={() => onRedactionModeChange(mode)}
              className={`rounded px-2 py-1 text-[11px] font-medium ${redactionMode === mode ? "bg-white text-[var(--text-primary)] shadow-sm dark:bg-white/10" : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"}`}
            >
              {mode === "share_safe" ? "Review copy" : "Internal"}
            </button>
          ))}
        </div>
      }
    >
      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_340px]">
        <div className="space-y-3">
          {metadata?.readiness?.summary && (
            <div className="rounded-lg bg-[var(--surface-muted)] px-4 py-3 text-[13px] text-[var(--text-secondary)]">
              {metadata.readiness.summary}
            </div>
          )}
          <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] px-4 py-3 text-[13px] text-[var(--text-secondary)]">
            <span className="font-semibold text-[var(--text-primary)]">{modeLabel}</span>
            <span className="ml-2 text-[12px] text-[var(--text-muted)]">{modeDetail}</span>
          </div>
          <pre className="max-h-[32rem] overflow-auto whitespace-pre-wrap rounded-lg border border-[color:var(--border)] bg-slate-950 p-4 font-mono text-[12px] leading-6 text-slate-100">{body}</pre>
        </div>
        {sidecar}
      </div>
    </Panel>
  );
}

function FindingSidecar({ packet, redactionMode }: { packet: GRCAuditPacket; redactionMode: ReportRedactionMode }) {
  const findingID = redactReportIdentifier(packet.finding.id, redactionMode, "[finding]");
  const entity = redactReportIdentifier(packet.finding.entity, redactionMode, "[resource]");
  const runtimeID = redactReportIdentifier(packet.finding.runtime_id, redactionMode, "[runtime]");
  return (
    <div className="space-y-4">
      <div>
        <div className="text-lg font-semibold text-[var(--text-primary)]">{redactReportText(packet.finding.title, redactionMode)}</div>
        <div className="mt-1 text-[13px] text-[var(--text-muted)]">{packet.finding.summary ? redactReportText(packet.finding.summary, redactionMode) : "No summary provided."}</div>
      </div>
      <div className="rounded-lg bg-indigo-50 p-4 text-[13px] text-indigo-900 dark:bg-indigo-500/10 dark:text-indigo-100">{redactReportText(packet.recommended_action, redactionMode)}</div>
      <RiskBreakdown finding={packet.finding} />
      <div className="space-y-2.5 text-[13px]">
        <DetailRow label="Finding ID" value={findingID} mono />
        <DetailRow label="Entity" value={shortEntity(entity)} mono />
        <DetailRow label="Runtime" value={shortEntity(runtimeID)} mono />
        <DetailRow label="Last seen" value={displayDate(packet.finding.last_observed_at)} />
        <DetailRow label="Generated" value={displayDate(packet.generated_at)} />
      </div>
      <Link href={`/findings/${encodeURIComponent(packet.finding.id)}`} className="inline-flex rounded-md px-2 py-1 text-[12px] font-medium text-[var(--primary)] hover:bg-[var(--surface-muted)]">
        Open finding
      </Link>
    </div>
  );
}

function ReportMetadataPanel({ metadata, redactionMode }: { metadata?: GRCReportMetadata; redactionMode: ReportRedactionMode }) {
  if (!metadata) {
    return <div className="text-[13px] text-[var(--text-muted)]">Packet metadata is not available from this API response.</div>;
  }
  const readiness = metadata.readiness;
  const provenance = metadata.provenance;
  const sources = provenance?.source_ids ?? [];
  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-[color:var(--border)] p-4">
        <div className="text-[11px] font-medium uppercase tracking-wider text-[var(--text-muted)]">Packet score</div>
        <div className="mt-2 flex items-center justify-between gap-2">
          <div className="text-2xl font-semibold text-[var(--text-primary)]">{readiness ? `${readiness.score}/100` : "—"}</div>
          <Badge value={readiness?.status || "unknown"} />
        </div>
        {readiness?.blockers && readiness.blockers.length > 0 && (
          <div className="mt-3 space-y-2">
            {readiness.blockers.map((blocker) => (
              <DetailRow key={blocker.code} label={blocker.label} value={String(blocker.count ?? 1)} />
            ))}
          </div>
        )}
      </div>
      <div className="space-y-2.5 text-[13px]">
        <DetailRow label="Profile" value={provenance?.profile_name || provenance?.profile_id || "—"} />
        <DetailRow label="Version" value={provenance?.packet_version || "—"} mono />
        <DetailRow label="Generated" value={displayDate(provenance?.generated_at)} />
        <DetailRow
          label="Sources"
          value={sources.length ? sources.map((sourceID) => redactReportIdentifier(sourceID, redactionMode, "[source]")).join(", ") : "—"}
          mono
        />
      </div>
    </div>
  );
}

function ScopePanel({ metadata, redactionMode }: { metadata?: GRCReportMetadata; redactionMode: ReportRedactionMode }) {
  const exclusions = metadata?.scope?.exclusions;
  const incremental = metadata?.scope?.incremental_fetch;
  const excludedItems = [
    ...(exclusions?.excluded_families ?? []),
    ...(exclusions?.excluded_asset_classes ?? []),
    ...(exclusions?.excluded_kinds ?? []),
    ...(exclusions?.excluded_resource_urns ?? []),
  ].slice(0, 10);
  return (
    <Panel title="Scope and source collection">
      <div className="grid gap-4 md:grid-cols-4">
        <MetricCard label="Exclusions" value={exclusions?.total ?? 0} detail="collection scope" intent={(exclusions?.total ?? 0) > 0 ? "warning" : "success"} />
        <MetricCard label="Runtimes" value={metadata?.provenance?.runtime_count ?? 0} detail="supporting packet" />
        <MetricCard label="Before fetch" value={incremental?.policy_applied_before_read ? "Yes" : "—"} detail={incremental?.status || "unknown"} intent={incremental?.policy_applied_before_read ? "success" : "warning"} />
        <MetricCard label="Before graph" value={exclusions?.filtered_before_graph_projection ? "Yes" : "—"} detail="projection filter" intent={exclusions?.filtered_before_graph_projection ? "success" : "warning"} />
      </div>
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div className="rounded-lg border border-[color:var(--border)] p-4 text-[13px] text-[var(--text-secondary)]">
          <div className="font-semibold text-[var(--text-primary)]">Incremental fetch</div>
          <div className="mt-1 text-[var(--text-muted)]">{incremental?.summary ? redactReportText(incremental.summary, redactionMode) : "No incremental fetch metadata was returned."}</div>
        </div>
        <div className="rounded-lg border border-[color:var(--border)] p-4 text-[13px] text-[var(--text-secondary)]">
          <div className="font-semibold text-[var(--text-primary)]">Excluded scope</div>
          {exclusions && exclusions.total > 0 ? (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {excludedItems.map((item, index) => (
                <span key={`${item}-${index}`} className="max-w-full truncate rounded-md bg-[var(--surface-muted)] px-2 py-0.5 font-mono text-[11px] text-[var(--text-secondary)]">
                  {redactionMode === "share_safe" ? redactReportIdentifier(item, redactionMode, "[scope]") : shortEntity(item)}
                </span>
              ))}
            </div>
          ) : (
            <div className="mt-1 text-[var(--text-muted)]">No exclusions are configured for this packet scope.</div>
          )}
        </div>
      </div>
    </Panel>
  );
}

function DetailRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-slate-100 pb-2 last:border-b-0 dark:border-white/10">
      <span className="text-[var(--text-muted)]">{label}</span>
      <span className={`min-w-0 truncate text-right text-[var(--text-primary)] ${mono ? "font-mono text-[12px]" : ""}`}>{value || "—"}</span>
    </div>
  );
}

function buildFindingReportBody(packet?: GRCAuditPacket | null) {
  if (!packet) return "";
  const f = packet.finding;
  const metadata = packet.metadata;
  const readiness = metadata?.readiness;
  return [
    "# Finding packet",
    "",
    `Finding: ${f.title}`,
    `Finding ID: ${f.id}`,
    `Packet score: ${readiness ? `${reportReadinessLabel(readiness.status)} (${readiness.score}/100)` : "Not reported"}`,
    `Risk score: ${f.risk_score ?? "Not scored"} (likelihood ${f.likelihood_score ?? "—"}, impact ${f.impact_score ?? "—"}, confidence ${f.confidence_score ?? "—"})`,
    `Risk drivers: ${(f.risk_reasons ?? []).join(", ") || "Not available"}`,
    `Severity: ${f.severity}`,
    `Owner: ${f.owner}`,
    `SLA: ${f.sla_status}`,
    `Entity: ${f.entity || "Not mapped"}`,
    `Controls: ${(packet.controls ?? f.controls ?? []).map((control) => `${control.framework_name} ${control.control_id}`).join(", ") || "Not mapped"}`,
    `Evidence items: ${packet.evidence.length}`,
    `Collection exclusions: ${metadata?.scope?.exclusions?.total ?? 0}`,
    `Incremental fetch scope: ${metadata?.scope?.incremental_fetch?.summary || "Not reported"}`,
    "",
    "Recommended action:",
    packet.recommended_action,
    "",
    "Packet blockers:",
    ...(readiness?.blockers?.length ? readiness.blockers.map((blocker) => `- ${blocker.label}: ${blocker.count ?? 1}`) : ["- None reported"]),
  ].join("\n");
}

function buildControlReportBody(packet?: GRCControlEvidencePacketResponse | null, framework = "", controlID = "") {
  if (!packet) return "";
  const summary = packet.packet.summary;
  const metadata = packet.metadata;
  const readiness = metadata?.readiness;
  return [
    "# Control evidence packet",
    "",
    `Profile: ${packet.profile.name || packet.profile.id}`,
    `Profile ID: ${packet.profile.id}`,
    `Packet score: ${readiness ? `${reportReadinessLabel(readiness.status)} (${readiness.score}/100)` : "Not reported"}`,
    `Controls: ${summary.total}`,
    `Failing: ${statusCount(packet, "failing")}`,
    `Missing evidence: ${statusCount(packet, "missing_evidence")}`,
    `Stale evidence: ${statusCount(packet, "stale_evidence")}`,
    `Framework filter: ${framework || "All"}`,
    `Control filter: ${controlID || "All"}`,
    `Generated: ${displayDate(packet.generated_at)}`,
    `Collection exclusions: ${metadata?.scope?.exclusions?.total ?? 0}`,
    `Incremental fetch scope: ${metadata?.scope?.incremental_fetch?.summary || "Not reported"}`,
    "",
    "Packet blockers:",
    ...(readiness?.blockers?.length ? readiness.blockers.map((blocker) => `- ${blocker.label}: ${blocker.count ?? 1}`) : ["- None reported"]),
    "",
    "Control details:",
    ...packet.packet.controls.slice(0, 25).map((control) => `- ${controlLabel(control)}: ${control.status}; evidence ${evidenceItemCount(control)}; ${control.audit_readiness?.summary || control.reasons?.[0] || "no blocker reported"}`),
  ].join("\n");
}
