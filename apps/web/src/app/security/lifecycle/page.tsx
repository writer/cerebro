"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";

import { AppliedFilterChips, Badge, EmptyBlock, ErrorBlock, LoadingBlock, MetricCard, PageHeader, Panel } from "@/components/grc/Primitives";
import { withQuery } from "@/lib/cerebro-data";
import { useGRCQuery } from "@/lib/grc-client";
import { useQueryParamState } from "@/lib/query-params";
import {
  lifecycleCompleteness,
  lifecycleAggregateCount,
  lifecycleActionLabel,
  lifecycleEffectiveState,
  lifecycleEnumLabel,
  lifecycleExpiryLabel,
  lifecycleFindingID,
  lifecycleNextPageToken,
  lifecycleOwnerLabel,
  lifecyclePreviousPageToken,
  lifecycleTimestampLabel,
  summarizeSecurityLifecycle,
  type SecurityLifecycleRecord,
  type SecurityLifecycleResourceRef,
  type SecurityLifecycleResponse,
} from "@/lib/security-lifecycle";

const inputClass = "control-input mt-1 w-full px-3 py-2 text-[13px]";
const labelClass = "text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]";
const monoClass = "break-all font-mono text-[11px] leading-5 text-[var(--text-secondary)]";

function ReferenceValue({ label, reference }: { label: string; reference: SecurityLifecycleResourceRef }) {
  return (
    <div className="border-t border-[color:var(--border)] py-3 first:border-t-0 first:pt-0">
      <div className={labelClass}>{label}</div>
      <div className={`mt-1 ${monoClass}`}>{reference.id}</div>
      {reference.revision ? (
        <>
          <div className={`mt-2 ${labelClass}`}>Material revision</div>
          <div className={`mt-1 ${monoClass}`}>{reference.revision}</div>
        </>
      ) : null}
    </div>
  );
}

function LifecycleDrawer({
  onClose,
  record,
}: {
  onClose: () => void;
  record: SecurityLifecycleRecord;
}) {
  const { observation } = record;
  const finding = record.findings?.[0];
  const evidence = [
    ...(observation.evidence_claim_refs ?? []),
    ...(record.policy_evaluations ?? []).flatMap((evaluation) => evaluation.evidence_claim_refs ?? []),
    ...(record.findings ?? []).flatMap((binding) => binding.evidence_claim_refs ?? []),
  ].filter((reference, index, references) =>
    references.findIndex((candidate) => candidate.id === reference.id) === index,
  );

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-slate-950/30" role="presentation" onMouseDown={(event) => {
      if (event.currentTarget === event.target) onClose();
    }}>
      <aside
        aria-label={`${observation.display_name} lifecycle details`}
        className="h-full w-full overflow-y-auto border-l border-[color:var(--border)] bg-[var(--surface)] shadow-2xl sm:max-w-xl"
      >
        <div className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-[color:var(--border)] bg-[var(--surface)] px-5 py-4">
          <div className="min-w-0">
            <div className={labelClass}>{lifecycleEnumLabel(observation.subject_kind)} lifecycle</div>
            <h2 className="mt-1 text-lg font-semibold text-[var(--text-primary)]">{observation.display_name}</h2>
            <div className="mt-2 flex flex-wrap gap-2">
              <Badge value={lifecycleEffectiveState(record)} />
              {finding ? <Badge value={finding.status} /> : null}
            </div>
          </div>
          <button type="button" className="secondary-button shrink-0 px-3 py-1.5 text-[12px]" onClick={onClose} autoFocus>
            Close
          </button>
        </div>

        <div className="space-y-4 p-5">
          <Panel title="Canonical resource">
            <ReferenceValue label="Stable resource URN" reference={observation.subject_ref} />
            <div className="grid gap-3 border-t border-[color:var(--border)] pt-3 sm:grid-cols-2">
              <div>
                <div className={labelClass}>Authority</div>
                <div className="mt-1 text-[13px] text-[var(--text-secondary)]">{observation.provider} / {observation.authority_id}</div>
              </div>
              <div>
                <div className={labelClass}>Stable locator</div>
                <div className={`mt-1 ${monoClass}`}>{observation.stable_locator}</div>
              </div>
              <div>
                <div className={labelClass}>Owner</div>
                <div className="mt-1 text-[13px] text-[var(--text-secondary)]">{lifecycleOwnerLabel(observation.owner_urn)}</div>
              </div>
              <div>
                <div className={labelClass}>Expires</div>
                <div className="mt-1 text-[13px] text-[var(--text-secondary)]">{lifecycleTimestampLabel(observation.expires_at)}</div>
              </div>
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              <Link className="secondary-button px-3 py-1.5 text-[12px]" href={`/inventory/${encodeURIComponent(observation.subject_ref.id)}`}>
                Open inventory record
              </Link>
              <Link className="secondary-button px-3 py-1.5 text-[12px]" href={`/impact?root_urn=${encodeURIComponent(observation.subject_ref.id)}`}>
                View impact
              </Link>
            </div>
          </Panel>

          <Panel title="Observation and policy">
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <div className={labelClass}>Observed</div>
                <div className="mt-1 text-[13px] text-[var(--text-secondary)]">{lifecycleTimestampLabel(observation.observed_at)}</div>
              </div>
              <div>
                <div className={labelClass}>Projected</div>
                <div className="mt-1 text-[13px] text-[var(--text-secondary)]">{lifecycleTimestampLabel(record.projected_at)}</div>
              </div>
            </div>
            {(record.policy_evaluations ?? []).map((evaluation) => (
              <div key={`${evaluation.policy_id}:${evaluation.policy_version}`} className="mt-4 border-t border-[color:var(--border)] pt-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="font-medium text-[13px] text-[var(--text-primary)]">{evaluation.policy_id}</div>
                  <Badge value={evaluation.state} />
                </div>
                <div className="mt-1 text-[12px] text-[var(--text-muted)]">
                  Version {evaluation.policy_version} · {evaluation.warning_window_days}-day warning window · evaluated {lifecycleTimestampLabel(evaluation.evaluated_at)}
                </div>
              </div>
            ))}
          </Panel>

          <Panel title={`Evidence (${evidence.length})`}>
            {evidence.length > 0 ? (
              <div className="space-y-3">
                {evidence.map((reference) => (
                  <div key={reference.id} className="rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] p-3">
                    <div className={monoClass}>{reference.id}</div>
                    <Link
                      className="mt-2 inline-block text-[12px] font-medium text-[var(--primary)] hover:text-[var(--primary-hover)]"
                      href={finding ? `/evidence?finding_id=${encodeURIComponent(lifecycleFindingID(finding.finding_ref))}` : "/evidence"}
                    >
                      Open evidence register
                    </Link>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-[13px] text-[var(--text-muted)]">No evidence claim references were returned for this observation.</div>
            )}
          </Panel>

          <Panel title={`Findings (${record.findings?.length ?? 0})`}>
            {(record.findings ?? []).length > 0 ? (
              <div className="space-y-3">
                {(record.findings ?? []).map((binding) => {
                  const findingID = lifecycleFindingID(binding.finding_ref);
                  return (
                    <Link
                      key={binding.finding_ref.id}
                      href={`/findings/${encodeURIComponent(findingID)}`}
                      className="block rounded-md border border-[color:var(--border)] p-3 transition hover:border-[color:var(--ring)]"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <span className="font-medium text-[13px] text-[var(--text-primary)]">{findingID}</span>
                        <Badge value={binding.status} />
                      </div>
                      <div className="mt-1 text-[12px] text-[var(--text-muted)]">{lifecycleEnumLabel(binding.finding_kind)}</div>
                    </Link>
                  );
                })}
              </div>
            ) : (
              <div className="text-[13px] text-[var(--text-muted)]">No finding is bound to this observation.</div>
            )}
          </Panel>

          <Panel title="Approval, dispatch, and verification">
            {(record.action_routes ?? []).length > 0 ? (
              <div className="space-y-4">
                {(record.action_routes ?? []).map((route) => (
                  <div key={route.action_intent_ref.id} className="rounded-md border border-[color:var(--border)] p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="font-medium text-[13px] text-[var(--text-primary)]">{lifecycleActionLabel(route.action_type)}</div>
                      <Badge value={route.approval_required ? "approval required" : "approved route"} />
                    </div>
                    <p className="mt-2 text-[12px] leading-5 text-[var(--text-muted)]">
                      These opaque references route work to the external authority. Dispatch success is not finding closure; a later complete, non-truncated observation must verify the condition no longer matches.
                    </p>
                    <div className="mt-3">
                      <ReferenceValue label="Action intent" reference={route.action_intent_ref} />
                      <ReferenceValue label="Dispatch" reference={route.dispatch_ref} />
                      <ReferenceValue label="Verification" reference={route.verification_ref} />
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-[13px] text-[var(--text-muted)]">No external action route is available for this record.</div>
            )}
          </Panel>
        </div>
      </aside>
    </div>
  );
}

export default function SecurityLifecyclePage() {
  const [subjectKind, setSubjectKind] = useQueryParamState("kind");
  const [state, setState] = useQueryParamState("state");
  const [findingsParam, setFindingsParam] = useQueryParamState("findings");
  const [pageToken, setPageToken] = useQueryParamState("cursor");
  const [pageParam, setPageParam] = useQueryParamState("page");
  const [selectedRef, setSelectedRef] = useQueryParamState("record");
  const [fallbackPreviousTokens, setFallbackPreviousTokens] = useState<string[]>([]);
  const findingsOnly = findingsParam === "true";
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
  const aggregates = query.data?.aggregates;
  const expiredCount = lifecycleAggregateCount(aggregates?.state_counts, "expired") ?? summary.expired;
  const expiringCount = lifecycleAggregateCount(aggregates?.state_counts, "expiring") ?? summary.expiring;
  const findingCount = aggregates?.matched_findings ?? summary.findings;
  const aggregateDetail = aggregates
    ? aggregates.counts_are_exact === false ? "Filtered population estimate" : "Filtered population"
    : "On this page";
  const completeness = lifecycleCompleteness(query.data);
  const nextPageToken = lifecycleNextPageToken(query.data);
  const serverPreviousPageToken = lifecyclePreviousPageToken(query.data);
  const selectedRecord = records.find((record) => record.observation.subject_ref.id === selectedRef);
  const parsedPage = Number.parseInt(pageParam, 10);
  const currentPage = Number.isFinite(parsedPage) && parsedPage > 0 ? parsedPage : 1;
  const freshness = query.data?.metadata?.freshness;
  const coverage = query.data?.metadata?.coverage;

  const resetPage = () => {
    setPageToken("");
    setPageParam("");
    setFallbackPreviousTokens([]);
    setSelectedRef("");
  };
  const setFilter = (setter: (value: string) => void, value: string) => {
    setter(value);
    resetPage();
  };
  const goNext = () => {
    if (!nextPageToken) return;
    setFallbackPreviousTokens((tokens) => [...tokens.slice(-19), pageToken]);
    setPageToken(nextPageToken);
    setPageParam(String(currentPage + 1));
    setSelectedRef("");
  };
  const goBack = () => {
    const previousToken = serverPreviousPageToken || fallbackPreviousTokens.at(-1);
    if (previousToken === undefined || (!fallbackPreviousTokens.length && !serverPreviousPageToken)) return;
    setFallbackPreviousTokens((tokens) => tokens.slice(0, -1));
    setPageToken(previousToken);
    setPageParam(currentPage > 2 ? String(currentPage - 1) : "");
    setSelectedRef("");
  };

  return (
    <div>
      <PageHeader
        title="Credential and certificate lifecycle"
        description="Review stable resource slots, current material revisions, policy state, evidence, findings, and external action routing. Only a later complete observation can verify that a finding condition is gone."
        contractId="security-lifecycle"
        action={(
          <button type="button" className="secondary-button px-3 py-2 text-[12px]" onClick={() => void query.reload()} disabled={query.loading}>
            {query.loading && query.data ? "Refreshing…" : "Refresh"}
          </button>
        )}
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Expired" value={expiredCount} detail={aggregateDetail} intent={expiredCount > 0 ? "danger" : "success"} state={query.state} />
        <MetricCard
          label="Expiring"
          value={expiringCount}
          detail={aggregates
            ? aggregates.counts_are_exact === false
              ? "Filtered population estimate inside the warning window"
              : "Filtered population inside the warning window"
            : "Inside the warning window on this page"}
          intent={expiringCount > 0 ? "warning" : "success"}
          state={query.state}
        />
        <MetricCard label="Open findings" value={findingCount} detail={aggregateDetail} intent={findingCount > 0 ? "warning" : "success"} state={query.state} />
        <MetricCard label="Owner required" value={summary.ownerRequired} detail="On this page" intent={summary.ownerRequired > 0 ? "warning" : "success"} state={query.state} />
      </div>

      <div className="mt-4 grid gap-px overflow-hidden rounded-lg border border-[color:var(--border)] bg-[color:var(--border)] sm:grid-cols-3">
        <div className="bg-[var(--surface)] px-4 py-3">
          <div className={labelClass}>Page</div>
          <div className="mt-1 text-[13px] font-medium text-[var(--text-primary)]">
            {currentPage}{typeof completeness.total === "number"
              ? ` · ${records.length.toLocaleString()} of ${aggregates?.counts_are_exact === false ? "at least " : ""}${completeness.total.toLocaleString()} records`
              : ` · ${records.length.toLocaleString()} records`}
          </div>
        </div>
        <div className="bg-[var(--surface)] px-4 py-3">
          <div className={labelClass}>Completeness</div>
          <div className="mt-1 text-[13px] font-medium text-[var(--text-primary)]">
            {completeness.complete === true ? "Source coverage complete" : completeness.sourceTruncated ? "Source coverage truncated" : "Source coverage not reported"}
          </div>
          {completeness.reason ? <div className="mt-1 text-[11px] text-[var(--text-muted)]">{completeness.reason}</div> : null}
          {coverage?.graph_revision ? <div className="mt-1 truncate font-mono text-[10px] text-[var(--text-muted)]" title={String(coverage.graph_revision)}>Graph {coverage.graph_revision}</div> : null}
        </div>
        <div className="bg-[var(--surface)] px-4 py-3">
          <div className={labelClass}>Freshness</div>
          <div className="mt-1 text-[13px] font-medium text-[var(--text-primary)]">{lifecycleTimestampLabel(freshness?.as_of || query.data?.as_of)}</div>
          <div className="mt-1 text-[11px] text-[var(--text-muted)]">
            {freshness?.oldest_observed_at || freshness?.newest_observed_at
              ? `Observations ${lifecycleTimestampLabel(freshness.oldest_observed_at)} to ${lifecycleTimestampLabel(freshness.newest_observed_at)}`
              : query.loading && query.data ? "Refresh in progress" : query.lastSuccessfulAt ? `Loaded ${lifecycleTimestampLabel(new Date(query.lastSuccessfulAt).toISOString())}` : "Not loaded"}
          </div>
        </div>
      </div>

      <div className="mt-4">
        <Panel title="Filters">
          <div className="grid gap-4 md:grid-cols-3">
            <label className={labelClass}>
              Resource
              <select className={inputClass} value={subjectKind} onChange={(event) => setFilter(setSubjectKind, event.target.value)}>
                <option value="">Credentials and certificates</option>
                <option value="credential">Credentials</option>
                <option value="certificate">Certificates</option>
              </select>
            </label>
            <label className={labelClass}>
              State
              <select className={inputClass} value={state} onChange={(event) => setFilter(setState, event.target.value)}>
                <option value="">All states</option>
                {["active", "expiring", "expired", "rotated", "revoked", "inactive", "unknown"].map((value) => (
                  <option key={value} value={value}>{value[0].toUpperCase() + value.slice(1)}</option>
                ))}
              </select>
            </label>
            <label className="mt-6 flex items-center gap-2 text-[13px] text-[var(--text-secondary)]">
              <input type="checkbox" checked={findingsOnly} onChange={(event) => setFilter(setFindingsParam, event.target.checked ? "true" : "")} />
              Records with findings
            </label>
          </div>
          <AppliedFilterChips
            filters={[
              { label: "Resource", value: subjectKind, onClear: () => setFilter(setSubjectKind, "") },
              { label: "State", value: state, onClear: () => setFilter(setState, "") },
              { label: "Findings", value: findingsOnly ? "Records with findings" : "", onClear: () => setFilter(setFindingsParam, "") },
            ]}
            onClearAll={() => {
              setSubjectKind("");
              setState("");
              setFindingsParam("");
              resetPage();
            }}
          />
        </Panel>
      </div>

      <div className="mt-4">
        {query.loading && !query.data ? <LoadingBlock label="Loading credential and certificate lifecycle…" /> : null}
        {query.error ? <ErrorBlock error={query.error} onRetry={() => void query.reload()} recoveryDetail="Check the lifecycle read service and try again." /> : null}
        {!query.loading && !query.error && records.length === 0 ? <EmptyBlock label="No credential or certificate records match these filters." /> : null}
        {records.length > 0 ? (
          <Panel
            title="Lifecycle records"
            action={<span className="text-[11px] text-[var(--text-muted)]">{completeness.pageTruncated ? "Other pages available" : "Only page"} · observed {lifecycleExpiryLabel(query.data?.as_of)}</span>}
          >
            <div className="overflow-auto">
              <table className="w-full min-w-[980px] text-left text-[12px]">
                <thead className="border-b border-[color:var(--border)] bg-[var(--surface-muted)] text-[11px] uppercase tracking-wider text-[var(--text-muted)]">
                  <tr>
                    <th className="px-3 py-2 font-semibold">Resource</th>
                    <th className="px-3 py-2 font-semibold">Revision</th>
                    <th className="px-3 py-2 font-semibold">State</th>
                    <th className="px-3 py-2 font-semibold">Expires</th>
                    <th className="px-3 py-2 font-semibold">Owner</th>
                    <th className="px-3 py-2 font-semibold">Finding</th>
                    <th className="px-3 py-2 font-semibold">Route</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[color:var(--border)]">
                  {records.map((record) => {
                    const observation = record.observation;
                    const finding = record.findings?.[0];
                    const action = record.action_routes?.[0];
                    return (
                      <tr key={`${observation.subject_ref.id}:${observation.subject_ref.revision ?? observation.observed_at}`} className="align-top hover:bg-[var(--surface-hover)]">
                        <td className="px-3 py-3">
                          <button type="button" className="text-left font-semibold text-[var(--text-primary)] hover:text-[var(--primary)]" onClick={() => setSelectedRef(observation.subject_ref.id)}>
                            {observation.display_name}
                          </button>
                          <div className="mt-1 text-[11px] text-[var(--text-muted)]">{observation.provider} / {observation.authority_id}</div>
                          <div className="mt-1 max-w-[22rem] truncate font-mono text-[10px] text-[var(--text-muted)]" title={observation.subject_ref.id}>{observation.subject_ref.id}</div>
                        </td>
                        <td className="max-w-[11rem] px-3 py-3">
                          <div className="truncate font-mono text-[11px] text-[var(--text-secondary)]" title={observation.subject_ref.revision}>
                            {observation.subject_ref.revision || "Not reported"}
                          </div>
                        </td>
                        <td className="px-3 py-3"><Badge value={lifecycleEffectiveState(record)} /></td>
                        <td className="px-3 py-3 text-[var(--text-secondary)]">{lifecycleExpiryLabel(observation.expires_at)}</td>
                        <td className="px-3 py-3 text-[var(--text-secondary)]">{lifecycleOwnerLabel(observation.owner_urn)}</td>
                        <td className="px-3 py-3">
                          {finding ? (
                            <Link href={`/findings/${encodeURIComponent(lifecycleFindingID(finding.finding_ref))}`} className="inline-block">
                              <Badge value={finding.status} />
                            </Link>
                          ) : <span className="text-[var(--text-muted)]">No finding</span>}
                        </td>
                        <td className="px-3 py-3 text-[var(--text-secondary)]">
                          {action ? (
                            <>
                              <div>{lifecycleActionLabel(action.action_type)}</div>
                              <div className="mt-1 text-[11px] text-[var(--text-muted)]">{action.approval_required ? "Approval required" : "Approved route"}</div>
                            </>
                          ) : "No route"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-[color:var(--border)] pt-4">
              <div className="text-[12px] text-[var(--text-muted)]">
                Page {currentPage} · {records.length.toLocaleString()} loaded{nextPageToken ? " · additional records are available on the next page" : ""}
              </div>
              <div className="flex gap-2">
                <button type="button" className="secondary-button px-3 py-2 text-[12px]" onClick={goBack} disabled={fallbackPreviousTokens.length === 0 && !serverPreviousPageToken}>
                  Previous page
                </button>
                <button type="button" className="secondary-button px-3 py-2 text-[12px]" onClick={goNext} disabled={!nextPageToken}>
                  Next page
                </button>
              </div>
            </div>
          </Panel>
        ) : null}
      </div>

      {selectedRecord ? <LifecycleDrawer record={selectedRecord} onClose={() => setSelectedRef("")} /> : null}
    </div>
  );
}
