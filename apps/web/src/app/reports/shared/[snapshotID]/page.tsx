"use client";

import { ArrowLeft, Download, RefreshCw } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useMemo } from "react";

import DataTable, { type TableColumn } from "@/components/grc/DataTable";
import { Badge, ErrorBlock, LoadingBlock, MetricCard, PageHeader, Panel } from "@/components/grc/Primitives";
import {
  auditEvidenceDecisionLabel,
  auditPackageStateLabel,
  buildAuditPackageSummary,
  buildEvidenceCurationRows,
  buildScopeExceptionRows,
  type EvidenceCurationRow,
  type ScopeExceptionRow,
} from "@/lib/audit-packages";
import type { GRCDashboard, GRCControlEvidencePacketResponse, GRCEvidencePacketsResponse } from "@/lib/grc";
import { displayDate, shortEntity } from "@/lib/grc";
import { grcDashboardPath, grcPath, useGRCQuery } from "@/lib/grc-client";

const buttonClass = "inline-flex items-center gap-1.5 rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-3 py-1.5 text-[12px] font-medium text-[var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[var(--text-primary)]";

const evidenceColumns: TableColumn<EvidenceCurationRow>[] = [
  { key: "decision", label: "Packet use", render: (_value, row) => <Badge value={auditEvidenceDecisionLabel(row.decision)} /> },
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
  {
    key: "sourceID",
    label: "Source",
    render: (_value, row) => (
      <div className="min-w-[10rem]">
        <div className="font-mono text-[12px] text-[var(--text-primary)]">{shortEntity(row.sourceID || row.source)}</div>
        <div className="mt-0.5 font-mono text-[11px] text-[var(--text-muted)]">{row.runtimeID ? shortEntity(row.runtimeID) : "No runtime"}</div>
      </div>
    ),
  },
  { key: "collectedAt", label: "Collected", render: (_value, row) => displayDate(row.collectedAt) },
  { key: "quality", label: "Quality", render: (_value, row) => <Badge value={row.quality} /> },
  { key: "freshness", label: "Freshness" },
  { key: "packets", label: "Attachments" },
];

const exceptionColumns: TableColumn<ScopeExceptionRow>[] = [
  { key: "kind", label: "Type", render: (_value, row) => <Badge value={row.kind} /> },
  { key: "value", label: "Record", render: (_value, row) => <span className="font-mono text-[12px]">{shortEntity(row.value)}</span> },
  { key: "reason", label: "Reason" },
];

export default function SharedAuditPackagePage() {
  const params = useParams<{ snapshotID?: string }>();
  const snapshotID = String(params.snapshotID ?? "current");
  const controlPacketQuery = useGRCQuery<GRCControlEvidencePacketResponse>(
    grcPath("/grc/control-packets", { limit: 200 }),
  );
  const evidencePacketsQuery = useGRCQuery<GRCEvidencePacketsResponse>(
    grcPath("/grc/evidence-packets", { limit: 200 }),
  );
  const dashboardQuery = useGRCQuery<GRCDashboard>(grcDashboardPath({ limit: 100 }));

  const summary = useMemo(
    () => buildAuditPackageSummary({
      controlPacket: controlPacketQuery.data,
      dashboard: dashboardQuery.data,
      evidencePackets: evidencePacketsQuery.data,
    }),
    [controlPacketQuery.data, dashboardQuery.data, evidencePacketsQuery.data],
  );
  const evidenceRows = useMemo(
    () => buildEvidenceCurationRows({ controlPacket: controlPacketQuery.data, evidencePackets: evidencePacketsQuery.data, limit: 50 })
      .filter((row) => ["accepted", "included"].includes(row.decision)),
    [controlPacketQuery.data, evidencePacketsQuery.data],
  );
  const metadata = controlPacketQuery.data?.metadata ?? evidencePacketsQuery.data?.metadata;
  const exceptionRows = useMemo(() => buildScopeExceptionRows(metadata, 25), [metadata]);
  const generatedAt = evidencePacketsQuery.data?.generated_at || controlPacketQuery.data?.generated_at || "";
  const loading = controlPacketQuery.loading || evidencePacketsQuery.loading || dashboardQuery.loading;
  const loaded = Boolean(controlPacketQuery.data || evidencePacketsQuery.data || dashboardQuery.data);
  const errors = [controlPacketQuery.error, evidencePacketsQuery.error, dashboardQuery.error].filter((error): error is string => Boolean(error));
  const reload = () => {
    void controlPacketQuery.reload();
    void evidencePacketsQuery.reload();
    void dashboardQuery.reload();
  };

  return (
    <div className="space-y-6">
      <PageHeader
        contractId="external-audit-review"
        title="Shared snapshot"
        description="Approved evidence, packet state, source records, and scope exclusions for review."
        action={
          <div className="flex flex-wrap items-center justify-end gap-2">
            <Link href="/reports/audit-packages" className={buttonClass}>
              <ArrowLeft className="h-3.5 w-3.5" />
              Packet review
            </Link>
            <a href={`/api/cerebro${grcPath("/grc/control-packets/export", { format: "markdown" })}`} className={buttonClass}>
              <Download className="h-3.5 w-3.5" />
              Download
            </a>
            <button type="button" onClick={reload} className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-indigo-500 px-3 py-1.5 text-[13px] font-medium text-white transition hover:bg-indigo-600">
              <RefreshCw className="h-3.5 w-3.5" />
              Refresh
            </button>
          </div>
        }
      />

      {loading && !loaded && <LoadingBlock label="Loading shared snapshot..." />}
      {errors.map((error) => (
        <ErrorBlock key={error} error={error} onRetry={reload} recoveryDetail="The shared snapshot will load when the packet API is reachable." />
      ))}

      <div className="grid gap-4 md:grid-cols-4">
        <MetricCard label="Snapshot" value={shortEntity(snapshotID)} detail={generatedAt ? `Generated ${displayDate(generatedAt)}` : "No generated time"} state={loading && !loaded ? "loading" : "ready"} />
        <MetricCard label="Packet state" value={auditPackageStateLabel(summary.state)} detail={`${summary.readinessScore}/100 export score`} intent={summary.state === "approved" || summary.state === "published" ? "success" : "warning"} state={loading && !loaded ? "loading" : "ready"} />
        <MetricCard label="Controls" value={summary.controls} detail={`${summary.failingControls} failing`} intent={summary.failingControls > 0 ? "warning" : "success"} state={loading && !loaded ? "loading" : "ready"} />
        <MetricCard label="Evidence" value={evidenceRows.length || summary.evidenceItems} detail={`${summary.exclusions} exclusions`} state={loading && !loaded ? "loading" : "ready"} />
      </div>

      <Panel title="Snapshot summary">
        <div className="grid gap-4 md:grid-cols-3">
          <SummaryBox label="Profile" value={controlPacketQuery.data?.profile.name || controlPacketQuery.data?.profile.id || "Control packet"} />
          <SummaryBox label="Redaction" value={metadata?.redaction?.default_mode === "internal" ? "Internal" : "Review copy"} />
          <SummaryBox label="Packet source" value={metadata?.provenance?.packet_version || metadata?.provenance?.report_type || "Packet"} />
          <SummaryBox label="Generated" value={generatedAt ? displayDate(generatedAt) : "No generated time"} />
          <SummaryBox label="Sources" value={String(metadata?.provenance?.source_ids?.length ?? summary.sourceCount)} />
          <SummaryBox label="Runtimes" value={String(metadata?.provenance?.runtime_count ?? 0)} />
        </div>
        {metadata?.readiness?.summary && (
          <p className="mt-4 rounded-lg bg-[var(--surface-muted)] px-4 py-3 text-[13px] leading-5 text-[var(--text-secondary)]">
            {metadata.readiness.summary}
          </p>
        )}
      </Panel>

      <Panel title="Approved evidence">
        <DataTable
          rows={evidenceRows}
          columns={evidenceColumns}
          emptyMessage="No approved evidence is available in this snapshot."
          filterKeys={["id", "title", "controlID", "decision", "quality", "freshness", "source", "sourceID", "runtimeID", "collectedAt"]}
          getRowKey={(row) => row.id}
          pageSize={12}
          resultLimit={50}
          resultNoun="evidence records"
        />
      </Panel>

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
            resultNoun="scope records"
          />
        ) : (
          <div className="rounded-lg border border-dashed border-[color:var(--border-strong)] px-4 py-8 text-center text-[13px] text-[var(--text-muted)]">
            No exclusions are configured for this snapshot.
          </div>
        )}
      </Panel>
    </div>
  );
}

function SummaryBox({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-4">
      <div className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">{label}</div>
      <div className="mt-2 text-[14px] font-semibold text-[var(--text-primary)]">{value}</div>
    </div>
  );
}
