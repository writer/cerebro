"use client";

import Link from "next/link";
import { useMemo, useState } from "react";

import { useApiKey } from "@/components/providers";
import { Badge, ErrorBlock, LoadingBlock, MetricCard, PageHeader, Panel, ResultLimitNotice } from "@/components/grc/Primitives";
import { fetchCerebro } from "@/lib/cerebro-client";
import {
  displayDate,
  GRCControlEvidencePacketItem,
  GRCControlEvidencePacketResponse,
  GRCControlEvidenceExpectationPosture,
  GRCControlPacketControl,
  GRCControlPacketFinding,
} from "@/lib/grc";
import { grcPath, useGRCQuery } from "@/lib/grc-client";
import { GRC_WORKLIST_LIMIT } from "@/lib/grc-list";
import { useQueryParamState } from "@/lib/query-params";
import { runtimeStateForError, type RuntimeState } from "@/lib/runtime-state";

const DEFAULT_CONTROL_PROFILE_ID = "soc2-security-core";
const CONTROL_DETAIL_LIMIT = GRC_WORKLIST_LIMIT;
const inputClass = "mt-1 w-full rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] text-slate-900 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30";
const labelClass = "text-[11px] font-medium uppercase tracking-wider text-slate-500";

const controlLabel = (control?: GRCControlPacketControl) =>
  control ? `${control.control.framework_name} ${control.control.control_id}` : "Control";

const evidenceItemCount = (control?: GRCControlPacketControl) =>
  control?.evidence.items?.length ?? control?.evidence.summary?.evidence_ids?.length ?? 0;

const downloadText = (name: string, body: string) => {
  const blob = new Blob([body], { type: "text/markdown;charset=utf-8" });
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  window.URL.revokeObjectURL(url);
};

export default function ControlDetailPage() {
  const { apiKey } = useApiKey();
  const [tenantID, setTenantID] = useQueryParamState("tenant_id");
  const [profileID, setProfileID] = useQueryParamState("profile");
  const [framework, setFramework] = useQueryParamState("framework");
  const [controlID, setControlID] = useQueryParamState("control");
  const [exportError, setExportError] = useState<string | null>(null);
  const [exportLoading, setExportLoading] = useState(false);
  const selectedProfileID = profileID.trim() || DEFAULT_CONTROL_PROFILE_ID;
  const queryPath = controlID.trim()
    ? grcPath("/grc/control-packets/detail", { tenant_id: tenantID, profile: selectedProfileID, framework, control: controlID, limit: CONTROL_DETAIL_LIMIT })
    : null;
  const { data, error, loading, reload } = useGRCQuery<GRCControlEvidencePacketResponse>(queryPath);
  const control = data?.packet.controls[0];
  const runtimeState: RuntimeState = error ? runtimeStateForError(error) : loading && !data ? "loading" : "ready";
  const markdownPath = useMemo(
    () => grcPath("/grc/control-packets/export", { tenant_id: tenantID, profile: selectedProfileID, framework, control: controlID, format: "markdown", limit: CONTROL_DETAIL_LIMIT }),
    [controlID, framework, selectedProfileID, tenantID],
  );
  const downloadMarkdown = async () => {
    setExportLoading(true);
    setExportError(null);
    try {
      const response = await fetchCerebro<string>(markdownPath, apiKey);
      if (!response.ok || typeof response.data !== "string") {
        setExportError(typeof response.data === "string" ? response.data : `Export failed (${response.status})`);
        return;
      }
      downloadText(`${control?.control.control_id || "control"}-evidence-packet.md`, response.data);
    } catch (error) {
      setExportError(error instanceof Error ? error.message : "Export failed");
    } finally {
      setExportLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        contractId="control-detail"
        title="Control Detail"
        description="Audit readiness, evidence expectations, attached proof, and open findings for one control."
        action={
          <div className="flex items-center gap-2">
            <Link href="/controls" className="rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] font-medium text-slate-700 transition hover:border-slate-300 hover:text-slate-900">
              Controls
            </Link>
            <button type="button" onClick={() => void reload()} className="rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] font-medium text-slate-700 transition hover:border-slate-300 hover:text-slate-900">
              Refresh
            </button>
            <button type="button" disabled={!control || exportLoading} onClick={() => void downloadMarkdown()} className="rounded-md border border-slate-200 bg-indigo-500 px-3 py-1.5 text-[13px] font-medium text-white transition hover:bg-indigo-600 disabled:cursor-not-allowed disabled:opacity-50">
              {exportLoading ? "Exporting..." : "Export"}
            </button>
          </div>
        }
      />

      <div className="rounded-lg border border-slate-200 bg-white px-5 py-4">
        <div className="grid gap-3 md:grid-cols-4">
          <label className={labelClass}>Tenant<input value={tenantID} onChange={(event) => setTenantID(event.target.value)} placeholder="All tenants" className={inputClass} /></label>
          <label className={labelClass}>Profile<input value={profileID} onChange={(event) => setProfileID(event.target.value)} placeholder={DEFAULT_CONTROL_PROFILE_ID} className={inputClass} /></label>
          <label className={labelClass}>Framework<input value={framework} onChange={(event) => setFramework(event.target.value)} placeholder="SOC 2" className={inputClass} /></label>
          <label className={labelClass}>Control<input value={controlID} onChange={(event) => setControlID(event.target.value)} placeholder="CC6.1" className={inputClass} /></label>
        </div>
      </div>

      {!controlID.trim() && (
        <div className="flex items-center justify-center rounded-lg border border-dashed border-slate-300 p-8 text-[13px] text-slate-500">
          Select a control to open its evidence detail.
        </div>
      )}
      {loading && <LoadingBlock label="Loading control detail..." />}
      {error && <ErrorBlock error={error} onRetry={() => void reload()} recoveryDetail="Control detail will appear when the API is reachable." />}
      {exportError && <ErrorBlock error={exportError} />}

      {control && (
        <>
          <div className="grid gap-4 md:grid-cols-4">
            <MetricCard label="Evidence Score" value={control.audit_readiness.score} detail={control.audit_readiness.rating} intent={control.audit_readiness.score >= 80 ? "success" : control.audit_readiness.score >= 50 ? "warning" : "danger"} state={runtimeState} />
            <MetricCard label="Evidence" value={evidenceItemCount(control)} detail={`${control.audit_readiness.required_expectations ?? 0} required expectations`} state={runtimeState} />
            <MetricCard label="Missing" value={control.audit_readiness.missing_evidence ?? 0} detail="required evidence" intent={(control.audit_readiness.missing_evidence ?? 0) > 0 ? "warning" : "success"} state={runtimeState} />
            <MetricCard label="Findings" value={control.findings?.length ?? 0} detail="open findings" intent={(control.findings?.length ?? 0) > 0 ? "danger" : "success"} state={runtimeState} />
          </div>

          <Panel title={controlLabel(control)}>
            <ResultLimitNotice
              loaded={data.packet.controls.length}
              limit={CONTROL_DETAIL_LIMIT}
              meta={{
                limit: CONTROL_DETAIL_LIMIT,
                returned: data.packet.controls.length,
                total: data.packet.summary.total,
                truncated: data.packet.summary.total > data.packet.controls.length,
              }}
              noun="controls"
              className="mb-5"
            />
            <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_320px]">
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <Badge value={control.status} />
                  <Badge value={control.audit_readiness.rating} />
                </div>
                <h2 className="mt-3 text-xl font-semibold text-slate-900">{control.control.title || control.control.family_name || "Control objective"}</h2>
                <p className="mt-2 text-[13px] leading-6 text-slate-600">{control.audit_readiness.summary || control.reasons?.[0] || "No assessment summary is available."}</p>
              </div>
              <div className="space-y-2 text-[13px]">
                {[
                  ["Framework", control.control.framework_name],
                  ["Control", control.control.control_id],
                  ["Family", control.control.family_name || "-"],
                  ["Owner", control.control.owner_domain || "-"],
                  ["Generated", displayDate(data.generated_at)],
                ].map(([label, value]) => (
                  <div key={label} className="flex items-center justify-between gap-3 border-b border-slate-100 pb-2">
                    <span className="text-slate-500">{label}</span>
                    <span className="text-right font-mono text-[12px] text-slate-800">{value}</span>
                  </div>
                ))}
              </div>
            </div>
          </Panel>

          <Panel title="Evidence Expectations">
            <ExpectationTable expectations={control.evidence.expectations ?? []} />
          </Panel>

          <Panel title="Evidence Items">
            <EvidenceTable items={control.evidence.items ?? []} />
          </Panel>

          <Panel title="Open Findings">
            <FindingTable findings={control.findings ?? []} />
          </Panel>
        </>
      )}
    </div>
  );
}

function ExpectationTable({ expectations }: { expectations: GRCControlEvidenceExpectationPosture[] }) {
  if (expectations.length === 0) {
    return <div className="py-8 text-center text-[13px] text-slate-500">No evidence expectations are declared for this control.</div>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-[13px]">
        <thead>
          <tr className="border-b border-slate-200 bg-slate-50">
            <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Expectation</th>
            <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Status</th>
            <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Quality</th>
            <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Evidence</th>
            <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Freshness</th>
          </tr>
        </thead>
        <tbody>
          {expectations.map((expectation) => (
            <tr key={expectation.id} className="border-b border-slate-100 last:border-b-0">
              <td className="px-3 py-3">
                <div className="font-semibold text-slate-900">{expectation.title || expectation.id}</div>
                <div className="mt-0.5 text-[12px] text-slate-500">{expectation.description || expectation.type || "Evidence expectation"}</div>
              </td>
              <td className="px-3 py-3"><Badge value={expectation.status} /></td>
              <td className="px-3 py-3"><Badge value={expectation.quality || expectation.status} /></td>
              <td className="px-3 py-3 font-mono text-[12px] text-slate-700">{expectation.evidence_ids?.join(", ") || "-"}</td>
              <td className="px-3 py-3 font-mono text-[12px] text-slate-700">{expectation.freshness_sla || "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function EvidenceTable({ items }: { items: GRCControlEvidencePacketItem[] }) {
  if (items.length === 0) {
    return <div className="py-8 text-center text-[13px] text-slate-500">No evidence items are attached to this control.</div>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-[13px]">
        <thead>
          <tr className="border-b border-slate-200 bg-slate-50">
            <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Evidence</th>
            <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Type</th>
            <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Quality</th>
            <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Observed</th>
            <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Collection</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item, index) => (
            <tr key={item.id || `${item.rule_id}-${index}`} className="border-b border-slate-100 last:border-b-0">
              <td className="px-3 py-3 font-mono text-[12px] text-slate-800">{item.id || "-"}</td>
              <td className="px-3 py-3 text-[12px] text-slate-600">{item.evidence_type || "-"}</td>
              <td className="px-3 py-3"><Badge value={item.quality || item.status || "unknown"} /></td>
              <td className="px-3 py-3 text-[12px] text-slate-600">{displayDate(item.observed_at)}</td>
              <td className="px-3 py-3 text-[12px] text-slate-600">{item.source || "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function FindingTable({ findings }: { findings: GRCControlPacketFinding[] }) {
  if (findings.length === 0) {
    return <div className="py-8 text-center text-[13px] text-slate-500">No open findings are mapped to this control.</div>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-[13px]">
        <thead>
          <tr className="border-b border-slate-200 bg-slate-50">
            <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Finding</th>
            <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Severity</th>
            <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Status</th>
            <th className="px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Last Observed</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding) => (
            <tr key={finding.id || finding.rule_id || finding.title} className="border-b border-slate-100 last:border-b-0">
              <td className="px-3 py-3">
                <div className="font-semibold text-slate-900">{finding.title || finding.id || "Finding"}</div>
                <div className="mt-0.5 font-mono text-[11px] text-slate-500">{finding.rule_id || finding.id || "-"}</div>
              </td>
              <td className="px-3 py-3"><Badge value={finding.severity || "unknown"} tone="severity" /></td>
              <td className="px-3 py-3"><Badge value={finding.status || "unknown"} /></td>
              <td className="px-3 py-3 text-[12px] text-slate-600">{displayDate(finding.last_observed_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
