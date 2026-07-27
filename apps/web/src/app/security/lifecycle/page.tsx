"use client";

import { useMemo, useState } from "react";

import { Badge, EmptyBlock, ErrorBlock, LoadingBlock, MetricCard, PageHeader, Panel } from "@/components/grc/Primitives";
import { withQuery } from "@/lib/cerebro-data";
import { useGRCQuery } from "@/lib/grc-client";
import {
  lifecycleEffectiveState,
  lifecycleExpiryLabel,
  lifecycleOwnerLabel,
  summarizeSecurityLifecycle,
  type SecurityLifecycleResponse,
} from "@/lib/security-lifecycle";

const inputClass = "control-input mt-1 w-full px-3 py-2 text-[13px]";

export default function SecurityLifecyclePage() {
  const [subjectKind, setSubjectKind] = useState("");
  const [state, setState] = useState("");
  const [findingsOnly, setFindingsOnly] = useState(false);
  const [pageToken, setPageToken] = useState("");
  const path = withQuery("/v1/security/lifecycle", {
    limit: 100,
    ...(subjectKind ? { subject_kind: subjectKind } : {}),
    ...(state ? { state } : {}),
    ...(findingsOnly ? { findings_only: "true" } : {}),
    ...(pageToken ? { page_token: pageToken } : {}),
  });
  const query = useGRCQuery<SecurityLifecycleResponse>(path);
  const records = useMemo(() => query.data?.records ?? [], [query.data?.records]);
  const summary = useMemo(() => summarizeSecurityLifecycle(records), [records]);

  const resetPage = () => setPageToken("");

  return (
    <div>
      <PageHeader
        title="Credential and certificate lifecycle"
        description="Track current material revisions against stable credential and certificate slots. Provider execution does not close a finding until a later complete observation verifies the result."
        contractId="security-lifecycle"
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Expired" value={summary.expired} detail="Action required" intent={summary.expired > 0 ? "danger" : "success"} state={query.state} />
        <MetricCard label="Expiring" value={summary.expiring} detail="Inside the warning window" intent={summary.expiring > 0 ? "warning" : "success"} state={query.state} />
        <MetricCard label="Open findings" value={summary.findings} detail="Linked to current observations" intent={summary.findings > 0 ? "warning" : "success"} state={query.state} />
        <MetricCard label="Owner required" value={summary.ownerRequired} detail="No canonical owner recorded" intent={summary.ownerRequired > 0 ? "warning" : "success"} state={query.state} />
      </div>

      <Panel title="Filters">
        <div className="grid gap-4 md:grid-cols-3">
          <label className="text-[11px] font-semibold text-[var(--text-muted)]">
            Resource
            <select
              className={inputClass}
              value={subjectKind}
              onChange={(event) => { setSubjectKind(event.target.value); resetPage(); }}
            >
              <option value="">Credentials and certificates</option>
              <option value="credential">Credentials</option>
              <option value="certificate">Certificates</option>
            </select>
          </label>
          <label className="text-[11px] font-semibold text-[var(--text-muted)]">
            State
            <select
              className={inputClass}
              value={state}
              onChange={(event) => { setState(event.target.value); resetPage(); }}
            >
              <option value="">All states</option>
              {["active", "expiring", "expired", "rotated", "revoked", "inactive", "unknown"].map((value) => (
                <option key={value} value={value}>{value[0].toUpperCase() + value.slice(1)}</option>
              ))}
            </select>
          </label>
          <label className="mt-6 flex items-center gap-2 text-[13px] text-[var(--text-secondary)]">
            <input
              type="checkbox"
              checked={findingsOnly}
              onChange={(event) => { setFindingsOnly(event.target.checked); resetPage(); }}
            />
            Show records with findings
          </label>
        </div>
      </Panel>

      <div className="mt-4">
        {query.loading && !query.data ? <LoadingBlock label="Loading credential and certificate lifecycle..." /> : null}
        {query.error ? <ErrorBlock error={query.error} onRetry={() => void query.reload()} recoveryDetail="Check the Rust organizational platform read service and try again." /> : null}
        {!query.loading && !query.error && records.length === 0 ? <EmptyBlock label="No credential or certificate records match these filters." /> : null}
        {records.length > 0 ? (
          <Panel
            title="Lifecycle records"
            action={<span className="text-[11px] text-[var(--text-muted)]">Observed {lifecycleExpiryLabel(query.data?.as_of)}</span>}
          >
            <div className="overflow-auto">
              <table className="w-full min-w-[980px] text-left text-[12px]">
                <thead className="border-b border-[color:var(--border)] bg-[var(--surface-muted)] text-[11px] uppercase tracking-wider text-[var(--text-muted)]">
                  <tr>
                    <th className="px-3 py-2 font-semibold">Resource</th>
                    <th className="px-3 py-2 font-semibold">State</th>
                    <th className="px-3 py-2 font-semibold">Expires</th>
                    <th className="px-3 py-2 font-semibold">Owner</th>
                    <th className="px-3 py-2 font-semibold">Finding</th>
                    <th className="px-3 py-2 font-semibold">Next action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[color:var(--border)]">
                  {records.map((record) => {
                    const observation = record.observation;
                    const finding = record.findings?.[0];
                    const action = record.action_routes?.[0];
                    return (
                      <tr key={`${observation.subject_ref.id}:${observation.subject_ref.revision ?? observation.observed_at}`} className="align-top">
                        <td className="px-3 py-3">
                          <div className="font-semibold text-[var(--text-primary)]">{observation.display_name}</div>
                          <div className="mt-1 text-[11px] text-[var(--text-muted)]">{observation.provider} / {observation.authority_id}</div>
                          <div className="mt-1 max-w-[24rem] truncate font-mono text-[10px] text-[var(--text-muted)]" title={observation.subject_ref.id}>{observation.subject_ref.id}</div>
                        </td>
                        <td className="px-3 py-3"><Badge value={lifecycleEffectiveState(record)} /></td>
                        <td className="px-3 py-3 text-[var(--text-secondary)]">{lifecycleExpiryLabel(observation.expires_at)}</td>
                        <td className="px-3 py-3 text-[var(--text-secondary)]">{lifecycleOwnerLabel(observation.owner_urn)}</td>
                        <td className="px-3 py-3">
                          {finding ? <Badge value={finding.status} /> : <span className="text-[var(--text-muted)]">No finding</span>}
                        </td>
                        <td className="px-3 py-3 text-[var(--text-secondary)]">
                          {action ? (
                            <>
                              <div>{action.action_type.replaceAll("_", " ")}</div>
                              <div className="mt-1 text-[11px] text-[var(--text-muted)]">{action.approval_required ? "Approval required" : "Ready for dispatch"}</div>
                            </>
                          ) : "No action"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {query.data?.next_page_token ? (
              <div className="mt-4 flex justify-end">
                <button type="button" className="secondary-button px-3 py-2 text-[12px]" onClick={() => setPageToken(query.data?.next_page_token ?? "")}>
                  Next page
                </button>
              </div>
            ) : null}
          </Panel>
        ) : null}
      </div>
    </div>
  );
}
