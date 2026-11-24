"use client";

import { useCallback, useMemo, useState } from "react";

import { AppliedFilterChips, Badge, DataStateBanner, EmptyBlock, MetricCard, PageHeader, Panel } from "@/components/grc/Primitives";
import { useCurrentUser } from "@/components/providers";
import { countLabel } from "@/lib/format";
import { displayDate, humanize } from "@/lib/grc";
import { grcPath, useDebouncedValue, useGRCMutation, useGRCQuery } from "@/lib/grc-client";
import { useQueryParamState } from "@/lib/query-params";
import { userHasAuthorizationPermission } from "@/lib/rbac";
import type { RuntimeState } from "@/lib/runtime-state";
import {
  observationAssetLabel,
  observationPackageLabel,
  percentLabel,
  profileNeedsAttention,
  severityCount,
  sortedDraftFields,
  VULNERABILITY_SEVERITIES,
  VULNERABILITY_STATUSES,
  vulnerabilityObservationsPath,
  vulnerabilityProfilePath,
  type VulnerabilityObservationPage,
  type VulnerabilityProfile,
  type VulnerabilitySummary,
} from "@/lib/vulnerabilities";

const selectClass = "mt-1 w-full rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-3 py-1.5 text-[13px] text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-indigo-400/30";
const labelClass = "text-[11px] font-medium uppercase tracking-wider text-[var(--text-muted)]";
const buttonClass = "inline-flex items-center rounded-md border border-[color:var(--border)] px-3 py-1.5 text-[12px] font-medium text-[var(--text-primary)] transition hover:border-[color:var(--border-strong)] disabled:opacity-50";

function SourceTag({ sourceID, onSelect }: { sourceID: string; onSelect?: (sourceID: string) => void }) {
  const className = "inline-flex items-center rounded-md bg-indigo-50 px-2 py-0.5 font-mono text-[11px] font-semibold text-indigo-700 dark:bg-indigo-500/15 dark:text-indigo-200";
  if (!onSelect) return <span className={className}>{sourceID}</span>;
  return (
    <button type="button" className={`${className} hover:bg-indigo-100`} onClick={() => onSelect(sourceID)} aria-label={`Filter by source ${sourceID}`}>
      {sourceID}
    </button>
  );
}

function ProfileCard({
  canWrite,
  onAction,
  profile,
  saving,
}: {
  canWrite: boolean;
  onAction: (profile: VulnerabilityProfile, action: "sync" | "mapping/activate") => void;
  profile: VulnerabilityProfile;
  saving: boolean;
}) {
  const report = profile.draft_mapping?.report;
  return (
    <div className="rounded-lg border border-[color:var(--border)] p-4" data-vulnerability-profile={profile.id}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <SourceTag sourceID={profile.source_id} />
          <span className="truncate text-[13px] font-semibold text-[var(--text-primary)]">{profile.display_name || profile.id}</span>
          {profile.last_status && <Badge value={profile.last_status} />}
          {!profile.enabled && <Badge value="disabled" />}
        </div>
        <div className="flex gap-2">
          {canWrite && profile.pull_kind && (
            <button type="button" className={buttonClass} disabled={saving} onClick={() => onAction(profile, "sync")}>Sync now</button>
          )}
          {canWrite && report && (
            <button type="button" className={buttonClass} disabled={saving || !report.ready_to_activate} onClick={() => onAction(profile, "mapping/activate")}>
              Activate mapping
            </button>
          )}
        </div>
      </div>
      <div className="mt-2 text-[12px] text-[var(--text-secondary)]">
        {humanize(profile.format || "auto")} format, mapping v{profile.mapping_version}, via {[...profile.transports, profile.pull_kind ? `${profile.pull_kind} pull` : ""].filter(Boolean).join(", ")}
        {profile.last_ingest_at && <> · last delivery {displayDate(profile.last_ingest_at)}</>}
      </div>
      {profile.last_error && <div className="mt-2 text-[12px] text-red-600 dark:text-red-300">{profile.last_error}</div>}
      {report && (
        <div className="mt-3 rounded-md bg-[var(--surface-muted)] p-3">
          <div className="text-[12px] font-semibold text-[var(--text-primary)]">
            Learned mapping for review: {humanize(report.detected_format)} records at <code>{report.records_path || "(root)"}</code>, {percentLabel(report.confidence)} confidence from {countLabel(report.sample_size, "sample record")}
          </div>
          {!report.ready_to_activate && (
            <div className="mt-1 text-[12px] text-amber-700 dark:text-amber-200">Confidence is too low to activate as-is. Edit the mapping through the API, then activate.</div>
          )}
          <table className="mt-2 w-full text-left text-[12px]">
            <thead className="text-[var(--text-muted)]">
              <tr><th className="py-1 font-medium">Field</th><th className="py-1 font-medium">Source path</th><th className="py-1 font-medium">Confidence</th><th className="py-1 font-medium">Coverage</th></tr>
            </thead>
            <tbody>
              {sortedDraftFields(report).map(([field, inference]) => (
                <tr key={field} className="border-t border-[color:var(--border)]">
                  <td className="py-1 font-mono">{field}</td>
                  <td className="py-1 font-mono">{inference.path}</td>
                  <td className="py-1">{percentLabel(inference.confidence)}</td>
                  <td className="py-1">{percentLabel(inference.coverage)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {(report.warnings ?? []).map((warning) => (
            <div key={warning} className="mt-1 text-[12px] text-amber-700 dark:text-amber-200">{warning}</div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function VulnerabilitiesPage() {
  const [tenantID] = useQueryParamState("tenant_id");
  const [sourceID, setSourceID] = useQueryParamState("source_id");
  const [severity, setSeverity] = useQueryParamState("severity");
  const [status, setStatus] = useQueryParamState("status", "open");
  const [query, setQuery] = useQueryParamState("q");
  const [cursors, setCursors] = useState<string[]>([]);
  const debouncedQuery = useDebouncedValue(query.trim());
  const tenant = tenantID.trim();
  const cursor = cursors.at(-1);
  const { user } = useCurrentUser();
  const canWrite = userHasAuthorizationPermission(user, "vulnerabilities:write");

  const summary = useGRCQuery<VulnerabilitySummary>(grcPath("/vulnerabilities/summary", { tenant_id: tenant }));
  const profiles = useGRCQuery<{ profiles: VulnerabilityProfile[] }>(grcPath("/vulnerabilities/profiles", { tenant_id: tenant }));
  const observationsPath = useMemo(
    () => vulnerabilityObservationsPath({ tenantID: tenant, sourceID, severity, status, query: debouncedQuery, cursor }),
    [cursor, debouncedQuery, severity, sourceID, status, tenant],
  );
  const observations = useGRCQuery<VulnerabilityObservationPage>(observationsPath);
  const { mutate, saving, error: mutationError } = useGRCMutation();

  const resetPaging = useCallback(() => setCursors([]), []);
  const selectSource = useCallback((value: string) => {
    setSourceID(value);
    resetPaging();
  }, [resetPaging, setSourceID]);
  const runProfileAction = useCallback(async (profile: VulnerabilityProfile, action: "sync" | "mapping/activate") => {
    try {
      await mutate(vulnerabilityProfilePath(profile.id, action, tenant || profile.tenant_id), {});
      await Promise.all([summary.reload(), profiles.reload(), observations.reload()]);
    } catch {
      // surfaced through mutationError
    }
  }, [mutate, observations, profiles, summary, tenant]);

  const metricState: RuntimeState = summary.state === "stale" || summary.state === "empty" ? "ready" : summary.state;
  const data = summary.data;
  const profileRows = useMemo(() => profiles.data?.profiles ?? [], [profiles.data?.profiles]);
  const attentionProfiles = useMemo(() => profileRows.filter(profileNeedsAttention), [profileRows]);
  const rows = observations.data?.observations ?? [];

  return (
    <div className="space-y-6" data-grc-page="vulnerabilities">
      <PageHeader
        title="Vulnerabilities"
        description="Scanner-reported vulnerabilities from every connected source, normalized to one format. Each record keeps the tag of the source that reported it."
        contractId="vulnerabilities"
      />
      <DataStateBanner state={summary.state} error={summary.error} lastSuccessfulAt={summary.lastSuccessfulAt} onRetry={summary.reload} subject="Vulnerability data" />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Open" value={data?.open ?? 0} detail={`${data?.distinct_open_vulnerabilities ?? 0} distinct vulnerabilities`} intent={(data?.open ?? 0) > 0 ? "warning" : "success"} state={metricState} />
        <MetricCard label="Critical and high" value={severityCount(data?.by_severity, "critical") + severityCount(data?.by_severity, "high")} detail={`${severityCount(data?.by_severity, "critical")} critical`} intent={severityCount(data?.by_severity, "critical") > 0 ? "danger" : "neutral"} state={metricState} />
        <MetricCard label="Reported by several sources" value={data?.multi_source_open ?? 0} detail="Open records sharing a correlation key" state={metricState} />
        <MetricCard label="Sources needing review" value={data?.profiles_needing_attention ?? 0} detail={`${data?.profiles ?? 0} configured sources`} intent={(data?.profiles_needing_attention ?? 0) > 0 ? "warning" : "success"} state={metricState} />
      </div>

      <Panel title="Sources" description="Open records by source tag. Select a tag to filter the list.">
        {(data?.by_source ?? []).length === 0 ? (
          <EmptyBlock label="No source has delivered vulnerability records yet." />
        ) : (
          <table className="w-full text-left text-[13px]">
            <thead className="text-[11px] uppercase tracking-wider text-[var(--text-muted)]">
              <tr><th className="py-2 font-medium">Source</th><th className="py-2 font-medium">Open</th><th className="py-2 font-medium">Critical</th><th className="py-2 font-medium">High</th><th className="py-2 font-medium">Total</th><th className="py-2 font-medium">Last delivery</th></tr>
            </thead>
            <tbody>
              {(data?.by_source ?? []).map((source) => (
                <tr key={source.source_id} className="border-t border-[color:var(--border)]">
                  <td className="py-2"><SourceTag sourceID={source.source_id} onSelect={selectSource} /></td>
                  <td className="py-2 tabular-nums">{source.open}</td>
                  <td className="py-2 tabular-nums">{severityCount(source.by_severity, "critical")}</td>
                  <td className="py-2 tabular-nums">{severityCount(source.by_severity, "high")}</td>
                  <td className="py-2 tabular-nums">{source.total}</td>
                  <td className="py-2 text-[var(--text-secondary)]">{source.last_ingest_at ? displayDate(source.last_ingest_at) : "Never"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      {attentionProfiles.length > 0 && (
        <Panel title="Source review" description="Sources with a learned mapping waiting for approval, or with failing deliveries. Records from an unapproved format are held until the mapping is activated.">
          <div className="space-y-3">
            {mutationError && <div className="text-[12px] text-red-600 dark:text-red-300">{mutationError}</div>}
            {attentionProfiles.map((profile) => (
              <ProfileCard key={profile.id} canWrite={canWrite} onAction={runProfileAction} profile={profile} saving={saving} />
            ))}
          </div>
        </Panel>
      )}

      <Panel title="Observations" description="One row per source record. The same vulnerability reported by two sources appears twice, each with its own source tag.">
        <div className="grid gap-3 sm:grid-cols-4">
          <label className={labelClass}>Severity
            <select className={selectClass} value={severity} onChange={(event) => { setSeverity(event.target.value); resetPaging(); }}>
              <option value="">All</option>
              {VULNERABILITY_SEVERITIES.map((value) => <option key={value} value={value}>{humanize(value)}</option>)}
            </select>
          </label>
          <label className={labelClass}>Status
            <select className={selectClass} value={status} onChange={(event) => { setStatus(event.target.value); resetPaging(); }}>
              <option value="">All</option>
              {VULNERABILITY_STATUSES.map((value) => <option key={value} value={value}>{humanize(value)}</option>)}
            </select>
          </label>
          <label className={labelClass}>Source
            <select className={selectClass} value={sourceID} onChange={(event) => selectSource(event.target.value)}>
              <option value="">All</option>
              {Array.from(new Set([...(data?.by_source ?? []).map((source) => source.source_id), ...profileRows.map((profile) => profile.source_id), sourceID].filter(Boolean))).sort().map((value) => (
                <option key={value} value={value}>{value}</option>
              ))}
            </select>
          </label>
          <label className={labelClass}>Search
            <input className={selectClass} value={query} placeholder="CVE, title, asset" onChange={(event) => { setQuery(event.target.value); resetPaging(); }} />
          </label>
        </div>
        <AppliedFilterChips
          filters={[
            { label: "Source", value: sourceID, onClear: () => selectSource("") },
            { label: "Severity", value: severity, onClear: () => { setSeverity(""); resetPaging(); } },
            { label: "Status", value: status, onClear: () => { setStatus(""); resetPaging(); } },
            { label: "Search", value: query, onClear: () => { setQuery(""); resetPaging(); } },
          ]}
        />
        <div className="mt-4">
          <DataStateBanner state={observations.state} error={observations.error} lastSuccessfulAt={observations.lastSuccessfulAt} onRetry={observations.reload} subject="Vulnerability observations" />
          {observations.state !== "loading" && rows.length === 0 ? (
            <EmptyBlock label="No vulnerability observations match these filters." />
          ) : (
            <table className="w-full text-left text-[13px]">
              <thead className="text-[11px] uppercase tracking-wider text-[var(--text-muted)]">
                <tr><th className="py-2 font-medium">Severity</th><th className="py-2 font-medium">Vulnerability</th><th className="py-2 font-medium">Asset</th><th className="py-2 font-medium">Source</th><th className="py-2 font-medium">Status</th><th className="py-2 font-medium">Last seen</th></tr>
              </thead>
              <tbody>
                {rows.map((observation) => (
                  <tr key={observation.id} className="border-t border-[color:var(--border)] align-top" data-vulnerability-observation={observation.id}>
                    <td className="py-2"><Badge value={observation.severity} tone="severity" /></td>
                    <td className="py-2">
                      <div className="font-medium text-[var(--text-primary)]">{observation.title}</div>
                      <div className="text-[12px] text-[var(--text-muted)]">
                        {[observation.primary_vulnerability_id, observation.cvss_score !== undefined ? `CVSS ${observation.cvss_score}` : "", observationPackageLabel(observation)].filter(Boolean).join(" · ")}
                      </div>
                    </td>
                    <td className="py-2 text-[var(--text-secondary)]">{observationAssetLabel(observation)}</td>
                    <td className="py-2"><SourceTag sourceID={observation.source_id} onSelect={selectSource} /></td>
                    <td className="py-2"><Badge value={observation.status} /></td>
                    <td className="py-2 text-[var(--text-secondary)]">{displayDate(observation.last_seen_at ?? observation.observed_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <div className="mt-3 flex gap-2">
            {cursors.length > 0 && (
              <button type="button" className={buttonClass} onClick={() => setCursors((previous) => previous.slice(0, -1))}>Previous page</button>
            )}
            {observations.data?.next_cursor && (
              <button type="button" className={buttonClass} onClick={() => setCursors((previous) => [...previous, observations.data?.next_cursor ?? ""])}>Next page</button>
            )}
          </div>
        </div>
      </Panel>
    </div>
  );
}
