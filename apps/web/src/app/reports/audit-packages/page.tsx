"use client";

import { ArrowUpRight, Download, FileCheck2, RefreshCw, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import DataTable, { type TableColumn } from "@/components/grc/DataTable";
import { AppliedFilterChips, Badge, ErrorBlock, LoadingBlock, MetricCard, PageHeader, Panel } from "@/components/grc/Primitives";
import {
  auditStatusLedgerStateLabel,
  auditWorkflowStateLabel,
  auditEvidenceDecisionLabel,
  auditEvidenceScopeLabel,
  auditEvidenceVisibilityLabel,
  auditPackageStateLabel,
  type AuditExportManifestRow,
  type AuditReadinessRow,
  type AuditStatusLedgerRow,
  type AuditorQuestionRow,
  type ControlOwnerRow,
  type EvidenceCurationRow,
  type FrameworkCoverageRow,
  type ScopeExceptionRow,
  type SourceTrustRow,
  type TeamQueueRow,
} from "@/lib/audit-packages";
import { CONTROL_PROFILE_OPTIONS, DEFAULT_CONTROL_PROFILE_ID, useAuditPackageParams, useAuditPackageView } from "@/lib/audit-package-view";
import { displayDate, humanize, shortEntity } from "@/lib/grc";
import { grcPath } from "@/lib/grc-client";

const inputClass = "mt-1 w-full rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-3 py-1.5 text-[13px] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:border-[color:var(--ring)] focus:outline-none focus:ring-1 focus:ring-[color:var(--ring)]";
const labelClass = "text-[11px] font-medium uppercase tracking-wider text-[var(--text-muted)]";
const buttonClass = "inline-flex items-center gap-1.5 rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-3 py-1.5 text-[12px] font-medium text-[var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[var(--text-primary)]";
const disabledButtonClass = "inline-flex cursor-not-allowed items-center gap-1.5 rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-1.5 text-[12px] font-medium text-[var(--text-muted)] opacity-70";

const decisionRank = (decision: EvidenceCurationRow["decision"]) => ({
  needs_replacement: 0,
  rejected: 1,
  needs_review: 2,
  candidate: 3,
  included: 4,
  accepted: 5,
  internal_only: 6,
  excluded: 7,
}[decision]);

const scopeRank = (scope: EvidenceCurationRow["scope"]) => ({
  included: 0,
  internal_only: 1,
  excluded: 2,
}[scope]);

const visibilityRank = (visibility: EvidenceCurationRow["visibility"]) => ({
  needs_owner: 0,
  needs_reviewer: 1,
  ready_for_auditor: 2,
  internal_only: 3,
  excluded: 4,
}[visibility]);

const readinessRank = (state: AuditReadinessRow["state"]) => ({
  blocked: 0,
  needs_review: 1,
  waiting: 2,
  ready: 3,
}[state]);

const statusNeedsAttention = (status: string) => /blocked|failed|missing|needs|overdue|rejected|stale/i.test(status);
const generatedPrefix = "Generated ";
const readinessDetail = (row: AuditReadinessRow) =>
  row.id === "snapshot" && row.detail.startsWith(generatedPrefix)
    ? `${generatedPrefix}${displayDate(row.detail.slice(generatedPrefix.length))}`
    : row.detail;
const manifestValue = (row: AuditExportManifestRow) =>
  row.id === "generated" && typeof row.value === "string" && row.value !== "Not generated"
    ? displayDate(row.value)
    : row.value;

const evidenceColumns: TableColumn<EvidenceCurationRow>[] = [
  { key: "scope", label: "Scope", render: (_value, row) => <Badge value={auditEvidenceScopeLabel(row.scope)} />, sortValue: (row) => scopeRank(row.scope) },
  { key: "visibility", label: "Visibility", render: (_value, row) => <Badge value={auditEvidenceVisibilityLabel(row.visibility)} />, sortValue: (row) => visibilityRank(row.visibility) },
  {
    key: "title",
    label: "Evidence",
    render: (_value, row) => (
      <div className="min-w-[18rem]">
        <div className="line-clamp-2 font-medium text-[var(--text-primary)]">{row.title}</div>
        <div className="mt-0.5 font-mono text-[11px] text-[var(--text-muted)]">{shortEntity(row.id)}</div>
      </div>
    ),
  },
  { key: "controlID", label: "Control", render: (_value, row) => <span className="font-mono text-[12px]">{row.controlID}</span> },
  { key: "decision", label: "Packet state", render: (_value, row) => <Badge value={auditEvidenceDecisionLabel(row.decision)} />, sortValue: (row) => decisionRank(row.decision) },
  {
    key: "reason",
    label: "Reason",
    render: (_value, row) => <div className="min-w-[16rem] line-clamp-2">{row.reason}</div>,
  },
  { key: "owner", label: "Owner" },
  { key: "reviewer", label: "Reviewer" },
  { key: "packets", label: "Packets" },
  { key: "source", label: "Source" },
];

const readinessColumns: TableColumn<AuditReadinessRow>[] = [
  {
    key: "title",
    label: "Gate",
    render: (_value, row) => (
      <div className="min-w-[14rem]">
        <div className="font-medium text-[var(--text-primary)]">{row.title}</div>
        <div className="mt-0.5 text-[12px] text-[var(--text-muted)]">{readinessDetail(row)}</div>
      </div>
    ),
  },
  { key: "state", label: "State", render: (_value, row) => <Badge value={auditWorkflowStateLabel(row.state)} />, sortValue: (row) => readinessRank(row.state) },
  { key: "owner", label: "Owner" },
  { key: "action", label: "Action" },
];

const auditorQuestionColumns: TableColumn<AuditorQuestionRow>[] = [
  { key: "area", label: "Area", render: (_value, row) => <Badge value={row.area} /> },
  {
    key: "question",
    label: "Question",
    render: (_value, row) => (
      <div className="min-w-[18rem]">
        <div className="line-clamp-2 font-medium text-[var(--text-primary)]">{row.question}</div>
        <div className="mt-0.5 line-clamp-1 text-[12px] text-[var(--text-muted)]">{row.source}</div>
      </div>
    ),
  },
  { key: "owner", label: "Owner" },
  { key: "status", label: "State", render: (_value, row) => <Badge value={row.status} />, sortValue: (row) => statusNeedsAttention(row.status) ? 0 : 1 },
];

const manifestColumns: TableColumn<AuditExportManifestRow>[] = [
  { key: "label", label: "Record" },
  { key: "value", label: "Value", render: (_value, row) => manifestValue(row) },
  { key: "state", label: "State", render: (_value, row) => <Badge value={row.state} />, sortValue: (row) => statusNeedsAttention(row.state) ? 0 : 1 },
];

const statusLedgerColumns: TableColumn<AuditStatusLedgerRow>[] = [
  { key: "area", label: "Area", render: (_value, row) => <Badge value={row.area} /> },
  {
    key: "title",
    label: "Work item",
    render: (_value, row) => (
      <div className="min-w-[18rem]">
        <div className="line-clamp-2 font-medium text-[var(--text-primary)]">{row.title}</div>
        <div className="mt-0.5 line-clamp-1 text-[12px] text-[var(--text-muted)]">{row.detail}</div>
      </div>
    ),
  },
  { key: "owner", label: "Owner" },
  { key: "reviewer", label: "Reviewer" },
  { key: "state", label: "State", render: (_value, row) => <Badge value={auditStatusLedgerStateLabel(row.state)} />, sortValue: (row) => row.rank },
  { key: "action", label: "Action" },
  {
    key: "proof",
    label: "Proof",
    render: (_value, row) => <div className="min-w-[14rem] line-clamp-2">{row.proof}</div>,
  },
];

const controlColumns: TableColumn<ControlOwnerRow>[] = [
  {
    key: "control",
    label: "Control",
    render: (_value, row) => (
      <div className="min-w-[16rem]">
        <div className="font-mono text-[12px] font-semibold text-[var(--text-primary)]">{row.control}</div>
        <div className="mt-0.5 line-clamp-2 text-[12px] text-[var(--text-muted)]">{row.title}</div>
      </div>
    ),
  },
  { key: "status", label: "State", render: (_value, row) => <Badge value={row.status} /> },
  { key: "owner", label: "Owner" },
  { key: "evidence", label: "Evidence" },
  { key: "missing", label: "Missing" },
  { key: "stale", label: "Stale" },
  { key: "findings", label: "Findings" },
  { key: "action", label: "Action" },
];

const teamColumns: TableColumn<TeamQueueRow>[] = [
  { key: "type", label: "Record", render: (_value, row) => <Badge value={row.type} /> },
  {
    key: "title",
    label: "Work item",
    render: (_value, row) => (
      <div className="min-w-[18rem]">
        <div className="line-clamp-2 font-medium text-[var(--text-primary)]">{row.title}</div>
        <div className="mt-0.5 line-clamp-1 text-[12px] text-[var(--text-muted)]">{row.detail}</div>
      </div>
    ),
  },
  { key: "owner", label: "Owner" },
  { key: "source", label: "Source" },
  { key: "status", label: "State", render: (_value, row) => <Badge value={row.status} /> },
  { key: "action", label: "Action" },
];

const frameworkColumns: TableColumn<FrameworkCoverageRow>[] = [
  { key: "framework", label: "Framework", render: (_value, row) => <span className="font-medium text-[var(--text-primary)]">{row.framework}</span> },
  { key: "status", label: "State", render: (_value, row) => <Badge value={row.status} /> },
  { key: "maturity", label: "Coverage", render: (_value, row) => row.maturity ? `${row.maturity}%` : "Planning" },
  { key: "controls", label: "Controls" },
  { key: "mapped", label: "Mapped" },
  { key: "needsAction", label: "Open gaps" },
];

const sourceColumns: TableColumn<SourceTrustRow>[] = [
  { key: "source", label: "Source", render: (_value, row) => <span className="font-mono text-[12px]">{row.source}</span> },
  { key: "status", label: "State", render: (_value, row) => <Badge value={row.status} /> },
  { key: "evidence", label: "Evidence" },
  { key: "findings", label: "Findings" },
  { key: "lastSynced", label: "Last synced", render: (_value, row) => displayDate(row.lastSynced) },
  { key: "action", label: "Action" },
];

const exceptionColumns: TableColumn<ScopeExceptionRow>[] = [
  { key: "kind", label: "Type", render: (_value, row) => <Badge value={row.kind} /> },
  { key: "value", label: "Record", render: (_value, row) => <span className="font-mono text-[12px]">{shortEntity(row.value)}</span> },
  { key: "reason", label: "Reason" },
];

export default function AuditPackagesPage() {
  const [exportAcknowledgedScopeKey, setExportAcknowledgedScopeKey] = useState<string | null>(null);
  const {
    clear: clearFilters,
    controlID,
    framework,
    profileID,
    setControlID,
    setFramework,
    setProfileID,
    setTenantID,
    tenantID,
  } = useAuditPackageParams();
  const view = useAuditPackageView({ controlID, framework, profileID, tenantID });
  const {
    actionableOwnerRows,
    auditorQuestionRows,
    debouncedTenantID,
    errors,
    evidenceRows,
    exceptionRows,
    exportManifestRows,
    frameworkOptions,
    frameworkRows,
    generatedAt,
    loaded,
    loading,
    metadata,
    ownerRows,
    readinessRows,
    reload,
    selectedProfileID,
    snapshotID,
    sourceRows,
    statusLedgerRows,
    summary,
    teamRows,
  } = view;
  const filterChips = [
    { label: "Tenant", value: tenantID, onClear: () => setTenantID("") },
    { label: "Profile", value: selectedProfileID === DEFAULT_CONTROL_PROFILE_ID && !profileID ? "" : selectedProfileID, onClear: () => setProfileID("") },
    { label: "Framework", value: framework, onClear: () => setFramework("") },
    { label: "Control", value: controlID, onClear: () => setControlID("") },
  ];
  const packetBlockerRows = readinessRows.filter((row) => row.state !== "ready");
  const exportHref = `/api/cerebro${grcPath("/grc/control-packets/export", { tenant_id: debouncedTenantID, profile: selectedProfileID, framework, control: controlID })}`;
  const packetScopeKey = `${debouncedTenantID}:${selectedProfileID}:${framework}:${controlID}`;
  const exportAcknowledged = exportAcknowledgedScopeKey === packetScopeKey;
  const canExport = packetBlockerRows.length === 0 || exportAcknowledged;

  return (
    <div className="space-y-6">
      <PageHeader
        contractId="audit-packages"
        title="Packet review"
        description="Review packet blockers, evidence gaps, source freshness, and shared snapshots."
        action={
          <div className="flex flex-wrap items-center justify-end gap-2">
            <Link href="/reports" className={buttonClass}>Packet builder</Link>
            <Link href="/evidence?view=package" className={buttonClass}>Evidence review</Link>
            <button type="button" onClick={reload} className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-indigo-500 px-3 py-1.5 text-[13px] font-medium text-white transition hover:bg-indigo-600">
              <RefreshCw className="h-3.5 w-3.5" />
              Refresh
            </button>
          </div>
        }
      />

      <Panel title="Packet filters">
        <div className="grid gap-3 md:grid-cols-4">
          <label className={labelClass}>Tenant<input value={tenantID} onChange={(event) => setTenantID(event.target.value)} placeholder="All tenants" className={inputClass} /></label>
          <label className={labelClass}>
            Profile
            <input value={selectedProfileID} onChange={(event) => setProfileID(event.target.value)} list="audit-package-profile-options" className={inputClass} />
            <datalist id="audit-package-profile-options">
              {CONTROL_PROFILE_OPTIONS.map((option) => <option key={option} value={option} />)}
            </datalist>
          </label>
          <label className={labelClass}>
            Framework
            <input value={framework} onChange={(event) => setFramework(event.target.value)} placeholder="All frameworks" list="audit-package-framework-options" className={inputClass} />
            <datalist id="audit-package-framework-options">
              {frameworkOptions.map((option) => <option key={option} value={option} />)}
            </datalist>
          </label>
          <label className={labelClass}>Control<input value={controlID} onChange={(event) => setControlID(event.target.value)} placeholder="CC6.1" className={inputClass} /></label>
        </div>
        <AppliedFilterChips filters={filterChips} onClearAll={clearFilters} />
      </Panel>

      {loading && !loaded && <LoadingBlock label="Loading packet records..." />}
      {errors.map((error) => (
        <ErrorBlock key={error} error={error} onRetry={reload} recoveryDetail="Other packet records remain available while this request recovers." />
      ))}

      <div className="grid gap-4 md:grid-cols-4 xl:grid-cols-8">
        <MetricCard label="Packet state" value={auditPackageStateLabel(summary.state)} detail={generatedAt ? `Generated ${displayDate(generatedAt)}` : "No packet generated"} intent={summary.state === "approved" || summary.state === "published" ? "success" : summary.state === "needs_evidence" || summary.state === "stale" ? "warning" : "neutral"} state={loading && !loaded ? "loading" : "ready"} />
        <MetricCard label="Packet score" value={`${summary.readinessScore}/100`} detail="export score" intent={summary.readinessScore >= 90 ? "success" : summary.readinessScore >= 70 ? "warning" : "danger"} state={loading && !loaded ? "loading" : "ready"} />
        <MetricCard label="Controls" value={summary.controls} detail={`${summary.failingControls} failing`} intent={summary.failingControls > 0 ? "danger" : "success"} state={loading && !loaded ? "loading" : "ready"} />
        <MetricCard label="Evidence" value={summary.evidenceItems} detail={`${summary.missingEvidence} missing`} intent={summary.missingEvidence > 0 ? "warning" : "success"} state={loading && !loaded ? "loading" : "ready"} />
        <MetricCard label="Stale evidence" value={summary.staleEvidence} detail="needs refresh" intent={summary.staleEvidence > 0 ? "warning" : "success"} state={loading && !loaded ? "loading" : "ready"} />
        <MetricCard label="Reviews" value={summary.openReviews} detail="open evidence reviews" intent={summary.openReviews > 0 ? "warning" : "success"} state={loading && !loaded ? "loading" : "ready"} />
        <MetricCard label="Sources" value={summary.sourceCount} detail={`${summary.staleSources} stale`} intent={summary.staleSources > 0 ? "warning" : "success"} state={loading && !loaded ? "loading" : "ready"} />
        <MetricCard label="Exclusions" value={summary.exclusions} detail="packet scope" intent={summary.exclusions > 0 ? "warning" : "success"} state={loading && !loaded ? "loading" : "ready"} />
      </div>

      <section id="packet-status-ledger">
        <Panel title="Packet status ledger">
          <DataTable
            key={`status-ledger:${packetScopeKey}`}
            rows={statusLedgerRows}
            columns={statusLedgerColumns}
            defaultSort={{ key: "state" }}
            emptyMessage="No packet work is queued for this scope."
            filterKeys={["area", "title", "detail", "owner", "reviewer", "state", "action", "proof"]}
            getRowHref={(row) => row.href}
            getRowKey={(row) => row.id}
            pageSize={8}
            resultNoun="ledger rows"
            showSearch={false}
          />
        </Panel>
      </section>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_360px]">
        <section id="packet-checklist">
          <Panel
            title="Packet checklist"
            action={
              <div className="flex flex-wrap gap-2">
                <Link href={`/reports?report_type=control&profile=${encodeURIComponent(selectedProfileID)}${framework ? `&framework=${encodeURIComponent(framework)}` : ""}${controlID ? `&control=${encodeURIComponent(controlID)}` : ""}`} className={buttonClass}>
                  <FileCheck2 className="h-3.5 w-3.5" />
                  Open packet
                </Link>
                {canExport ? (
                  <a href={exportHref} className={buttonClass}>
                    <Download className="h-3.5 w-3.5" />
                    Export
                  </a>
                ) : (
                  <span className={disabledButtonClass} aria-disabled="true">
                    <Download className="h-3.5 w-3.5" />
                    Export
                  </span>
                )}
              </div>
            }
          >
            <DataTable
              rows={readinessRows}
              columns={readinessColumns}
              defaultSort={{ key: "state" }}
              emptyMessage="No packet checks are available."
              filterKeys={["title", "state", "owner", "action"]}
              getRowKey={(row) => row.id}
              pageSize={5}
              resultNoun="packet checks"
              showSearch={false}
            />
            {packetBlockerRows.length > 0 && (
              <div className="mt-4 rounded-lg border border-amber-400/40 bg-amber-500/10 px-4 py-3 text-[13px] text-[var(--text-secondary)]">
                <div className="font-semibold text-[var(--text-primary)]">Export has {packetBlockerRows.length} {packetBlockerRows.length === 1 ? "blocker" : "blockers"}</div>
                <p className="mt-1 text-[12px] leading-5 text-[var(--text-muted)]">Export after you review the current blocker state for this packet.</p>
                <label className="mt-3 flex items-center gap-2 text-[12px] font-medium text-[var(--text-primary)]">
                  <input
                    type="checkbox"
                    checked={exportAcknowledged}
                    onChange={(event) => setExportAcknowledgedScopeKey(event.target.checked ? packetScopeKey : null)}
                    className="h-4 w-4 rounded border-[color:var(--border)]"
                  />
                  I reviewed the packet blockers
                </label>
              </div>
            )}
          </Panel>
        </section>

        <section id="shared-snapshot">
          <Panel
            title="Shared snapshot"
            action={
              <Link href={`/reports/shared/${encodeURIComponent(snapshotID)}`} className={buttonClass}>
                <ArrowUpRight className="h-3.5 w-3.5" />
                Open snapshot
              </Link>
            }
          >
            <div className="space-y-4 text-[13px] text-[var(--text-secondary)]">
              <div className="rounded-lg bg-[var(--surface-muted)] p-4">
                <div className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">Snapshot</div>
                <div className="mt-2 font-mono text-[12px] text-[var(--text-primary)]">{snapshotID}</div>
                <div className="mt-2 text-[12px] text-[var(--text-muted)]">Redacted identifiers, approved evidence, scope exclusions, and packet source records.</div>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <SmallStat label="Redaction" value={metadata?.redaction?.default_mode === "internal" ? "Internal" : "Review copy"} />
                <SmallStat label="Runtimes" value={metadata?.provenance?.runtime_count ?? 0} />
                <SmallStat label="Sources" value={metadata?.provenance?.source_ids?.length ?? summary.sourceCount} />
                <SmallStat label="Exclusions" value={summary.exclusions} />
              </div>
              <DataTable
                rows={exportManifestRows}
                columns={manifestColumns}
                defaultSort={{ key: "state" }}
                emptyMessage="No export manifest records are available."
                filterKeys={["label", "state", "value"]}
                getRowKey={(row) => row.id}
                pageSize={6}
                resultNoun="manifest records"
                showSearch={false}
              />
            </div>
          </Panel>
        </section>
      </div>

      <section id="reviewer-questions">
        <Panel title="Reviewer questions">
          <DataTable
            rows={auditorQuestionRows}
            columns={auditorQuestionColumns}
            defaultSort={{ key: "status" }}
            emptyMessage="No reviewer questions are queued for this packet."
            filterKeys={["area", "question", "owner", "source", "status"]}
            getRowKey={(row) => row.id}
            pageSize={10}
            resultNoun="questions"
          />
        </Panel>
      </section>

      <section id="evidence-review">
        <Panel title="Evidence review">
          <DataTable
            rows={evidenceRows}
            columns={evidenceColumns}
            emptyMessage="No evidence requests or expectations are available for this packet."
            filterKeys={["id", "title", "controlID", "decision", "reason", "status", "quality", "review", "source", "scope", "visibility", "owner", "reviewer"]}
            getRowKey={(row) => row.id}
            pageSize={10}
            resultLimit={25}
            resultNoun="evidence requests"
            defaultSort={{ key: "visibility" }}
          />
        </Panel>
      </section>

      <div className="grid gap-6 xl:grid-cols-2">
        <section id="control-status">
          <Panel title="Control status">
            <DataTable
              rows={ownerRows}
              columns={controlColumns}
              emptyMessage="No controls are available for this packet."
              filterKeys={["control", "title", "owner", "status", "action"]}
              getRowHref={(row) => `/controls/detail?profile=${encodeURIComponent(selectedProfileID)}&control=${encodeURIComponent(row.control.split(" ").slice(1).join(" "))}`}
              getRowKey={(row) => row.id}
              pageSize={8}
              resultLimit={25}
              resultNoun="controls"
              defaultSort={{ key: "missing", desc: true }}
            />
          </Panel>
        </section>

        <section id="control-owner-queue">
          <Panel title="Control owner queue">
            <DataTable
              rows={actionableOwnerRows}
              columns={controlColumns}
              emptyMessage="No owner work items are available."
              filterKeys={["control", "title", "owner", "status", "action"]}
              getRowKey={(row) => row.id}
              pageSize={8}
              resultLimit={25}
              resultNoun="owner items"
              defaultSort={{ key: "missing", desc: true }}
            />
          </Panel>
        </section>
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <Panel title="Team queue">
          <DataTable
            rows={teamRows}
            columns={teamColumns}
            emptyMessage="No team work items are available."
            filterKeys={["type", "title", "detail", "owner", "source", "status", "action"]}
            getRowKey={(row) => row.id}
            pageSize={8}
            resultLimit={25}
            resultNoun="team items"
            defaultSort={{ key: "status" }}
          />
        </Panel>

        <Panel title="Investigation">
          <div className="grid gap-3 sm:grid-cols-2">
            <InvestigationLink
              href={`/risk-inbox${framework ? `?framework=${encodeURIComponent(framework)}` : ""}`}
              title="Open risks"
              detail="Findings by owner, source, framework, severity, and SLA."
            />
            <InvestigationLink
              href="/explore"
              title="Trace relationships"
              detail="Start from an entity and expand assets, findings, owners, and sources."
            />
            <InvestigationLink
              href={`/ask?question=${encodeURIComponent(`Which controls need evidence for ${framework || selectedProfileID}?`)}`}
              title="Ask about evidence"
              detail="Ask for missing evidence, stale evidence, owner gaps, or affected assets."
            />
            <InvestigationLink
              href="/trends/dashboards"
              title="Save dashboard"
              detail="Persist reusable filters and trend widgets for repeated review."
            />
          </div>
        </Panel>
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <Panel title="Framework coverage">
          <DataTable
            rows={frameworkRows}
            columns={frameworkColumns}
            emptyMessage="No framework coverage records are available."
            filterKeys={["framework", "status"]}
            getRowKey={(row) => row.id}
            getRowHref={(row) => `/frameworks/${encodeURIComponent(row.id)}`}
            pageSize={8}
            resultLimit={25}
            resultNoun="frameworks"
            defaultSort={{ key: "needsAction", desc: true }}
          />
        </Panel>

        <section id="source-freshness">
          <Panel title="Source freshness">
            <DataTable
              rows={sourceRows}
              columns={sourceColumns}
              emptyMessage="No source freshness records are available."
              filterKeys={["source", "status", "action"]}
              getRowKey={(row) => row.id}
              getRowHref={(row) => `/connectors?source_id=${encodeURIComponent(row.source)}`}
              pageSize={8}
              resultLimit={25}
              resultNoun="sources"
              defaultSort={{ key: "status" }}
            />
          </Panel>
        </section>
      </div>

      <Panel title="Scope exclusions">
        {exceptionRows.length > 0 ? (
          <DataTable
            rows={exceptionRows}
            columns={exceptionColumns}
            emptyMessage="No scope exclusions are configured."
            filterKeys={["kind", "value", "reason"]}
            getRowKey={(row) => row.id}
            pageSize={8}
            resultLimit={25}
            resultNoun="exceptions"
            defaultSort={{ key: "kind" }}
          />
        ) : (
          <div className="rounded-lg border border-dashed border-[color:var(--border-strong)] px-4 py-8 text-center text-[13px] text-[var(--text-muted)]">
            No packet exclusions are configured for this scope.
          </div>
        )}
      </Panel>
    </div>
  );
}

function SmallStat({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-3 py-2">
      <div className="text-[10px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">{label}</div>
      <div className="mt-1 text-[13px] font-semibold text-[var(--text-primary)]">{typeof value === "number" ? value.toLocaleString() : humanize(value)}</div>
    </div>
  );
}

function InvestigationLink({ detail, href, title }: { detail: string; href: string; title: string }) {
  return (
    <Link href={href} className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-4 transition hover:border-[color:var(--border-strong)] hover:bg-[var(--surface-muted)]">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-[13px] font-semibold text-[var(--text-primary)]">
            <ShieldCheck className="h-4 w-4 text-[var(--primary)]" />
            {title}
          </div>
          <p className="mt-2 text-[12px] leading-5 text-[var(--text-muted)]">{detail}</p>
        </div>
        <ArrowUpRight className="h-3.5 w-3.5 shrink-0 text-[var(--text-muted)]" />
      </div>
    </Link>
  );
}
