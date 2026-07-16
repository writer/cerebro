"use client";

import Link from "next/link";
import { useCallback, useMemo, useRef, useState, useTransition } from "react";
import { useRouter } from "next/navigation";

import { AppliedFilterChips, AttentionBanner, ErrorBlock, LoadingBlock, MetricCard, PageHeader, Panel } from "@/components/grc/Primitives";
import TrendsChart from "@/components/grc/LazyTrendsChart";
import type { GRCTrendAgingBucket, GRCTrendPoint, GRCTrends } from "@/lib/grc";
import { grcExportFilename, grcPath, useDebouncedValue, useGRCQuery } from "@/lib/grc-client";
import { buildSeverityFlow, buildTrendSignals, downloadTrendPNG, downloadTrendsCSV, formatTrendDuration, formatTrendPercent, hasTrendActivity, summarizeTrends, trendBucketEndDate } from "@/lib/trends";
import { useQueryParamState } from "@/lib/query-params";

const INTERVALS = [
  { value: "day", label: "Daily" },
  { value: "week", label: "Weekly" },
  { value: "month", label: "Monthly" },
] as const;

const WINDOWS = [
  { value: 30, label: "30d" },
  { value: 90, label: "90d" },
  { value: 180, label: "180d" },
  { value: 365, label: "1y" },
] as const;

type IntervalValue = (typeof INTERVALS)[number]["value"];

const inputClass = "mt-1 w-full rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] text-slate-900 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30";
const selectClass = "mt-1 w-full rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] text-slate-900 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30";
const labelClass = "text-[11px] font-medium uppercase tracking-wider text-slate-500";
const actionButtonClass = "rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] font-medium text-slate-700 transition hover:border-indigo-300 hover:text-indigo-600 disabled:cursor-not-allowed disabled:opacity-50";
const EMPTY_POINTS: GRCTrendPoint[] = [];
const EMPTY_AGING_BUCKETS: GRCTrendAgingBucket[] = [];

const toggleClass = (active: boolean) =>
  `rounded px-2.5 py-1 text-[12px] font-medium transition ${
    active ? "bg-indigo-500 text-white" : "text-slate-600 hover:text-indigo-600"
  }`;

const deltaLabel = (value: number, formatter = (n: number) => `${n > 0 ? "+" : ""}${n}`) => {
  if (!Number.isFinite(value) || value === 0) return "no change";
  return `${formatter(value)} vs previous`;
};

const signedDurationLabel = (seconds: number) => `${seconds > 0 ? "+" : "-"}${formatTrendDuration(Math.abs(seconds))}`;

const signalValueClass = (intent: "neutral" | "danger" | "warning" | "success") => {
  const classes = {
    danger: "text-red-700",
    warning: "text-amber-700",
    success: "text-emerald-700",
    neutral: "text-slate-900",
  };
  return classes[intent];
};

export default function TrendsPage() {
  const router = useRouter();
  const chartRef = useRef<HTMLDivElement | null>(null);
  const [bucket, setBucket] = useState<IntervalValue>("week");
  const [days, setDays] = useState<number>(90);
  const [isPending, startTransition] = useTransition();
  const [tenantID, setTenantID] = useQueryParamState("tenant_id");
  const [runtimeID, setRuntimeID] = useQueryParamState("runtime_id");
  const [sourceID, setSourceID] = useQueryParamState("source_id");
  const [severity, setSeverity] = useQueryParamState("severity");
  const [framework, setFramework] = useQueryParamState("framework");
  const [compare, setCompare] = useQueryParamState("compare", "true");
  const [mttrTargetDays, setMTTRTargetDays] = useQueryParamState("mttr_target_days", "30");
  const [backlogTarget, setBacklogTarget] = useQueryParamState("backlog_target");
  const [slaTargetDays, setSLATargetDays] = useQueryParamState("sla_target_days", "30");
  const debouncedTenantID = useDebouncedValue(tenantID.trim());
  const debouncedRuntimeID = useDebouncedValue(runtimeID.trim());
  const debouncedSourceID = useDebouncedValue(sourceID.trim());
  const debouncedFramework = useDebouncedValue(framework.trim());
  const compareEnabled = compare !== "false";
  const trendsPath = useMemo(
    () => grcPath("/grc/trends", {
      interval: bucket,
      days,
      tenant_id: debouncedTenantID,
      runtime_id: debouncedRuntimeID,
      source_id: debouncedSourceID,
      severity,
      framework: debouncedFramework,
      compare: compareEnabled ? "true" : undefined,
      mttr_target_days: mttrTargetDays,
      backlog_target: backlogTarget,
      sla_target_days: slaTargetDays,
    }),
    [backlogTarget, bucket, compareEnabled, days, debouncedFramework, debouncedRuntimeID, debouncedSourceID, debouncedTenantID, mttrTargetDays, severity, slaTargetDays],
  );
  const trendsQuery = useGRCQuery<GRCTrends>(trendsPath);
  const trends = trendsQuery.data;
  const summary = useMemo(() => summarizeTrends(trends), [trends]);
  const signals = useMemo(() => buildTrendSignals(trends), [trends]);
  const severityFlow = useMemo(() => buildSeverityFlow(summary), [summary]);
  const points = trends?.points ?? EMPTY_POINTS;
  const agingBuckets = trends?.aging_buckets ?? EMPTY_AGING_BUCKETS;
  const metricState = trendsQuery.loading || isPending ? "loading" : "ready";
  const showChart = !trendsQuery.loading && !trendsQuery.error && hasTrendActivity(trends);
  const comparison = trends?.comparison;
  const filterParams = useMemo(() => ({
    tenant_id: debouncedTenantID,
    runtime_id: debouncedRuntimeID,
    source_id: debouncedSourceID,
    severity,
    framework: debouncedFramework,
  }), [debouncedFramework, debouncedRuntimeID, debouncedSourceID, debouncedTenantID, severity]);
  const riskInboxPath = useCallback((params: Record<string, string | number | undefined>) => grcPath("/risk-inbox", { ...filterParams, ...params }), [filterParams]);
  const bucketDrilldownPath = useCallback((date: string, kind: "opened" | "closed") => {
    const before = trendBucketEndDate(date, bucket);
    return kind === "opened"
      ? riskInboxPath({ status: "all", opened_after: date, opened_before: before })
      : riskInboxPath({ status: "all", closed_after: date, closed_before: before });
  }, [bucket, riskInboxPath]);
  const setBucketTransition = useCallback((nextBucket: IntervalValue) => {
    startTransition(() => setBucket(nextBucket));
  }, []);
  const setDaysTransition = useCallback((nextDays: number) => {
    startTransition(() => setDays(nextDays));
  }, []);
  const clearFilters = useCallback(() => {
    setTenantID("");
    setRuntimeID("");
    setSourceID("");
    setSeverity("");
    setFramework("");
  }, [setFramework, setRuntimeID, setSeverity, setSourceID, setTenantID]);
  const filterChips = useMemo(() => [
    { label: "Tenant", value: tenantID, onClear: () => setTenantID("") },
    { label: "Runtime", value: runtimeID, onClear: () => setRuntimeID("") },
    { label: "Source", value: sourceID, onClear: () => setSourceID("") },
    { label: "Framework", value: framework, onClear: () => setFramework("") },
    { label: "Severity", value: severity, onClear: () => setSeverity("") },
  ], [framework, runtimeID, setFramework, setRuntimeID, setSeverity, setSourceID, setTenantID, severity, sourceID, tenantID]);
  const exportCSV = useCallback(() => {
    if (trends) downloadTrendsCSV(trends, grcExportFilename("trends"));
  }, [trends]);
  const exportPNG = useCallback(async () => {
    await downloadTrendPNG(chartRef.current, grcExportFilename("trends").replace(/\.csv$/, ".png"));
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        contractId="grc-trends"
        title="Trends"
        description="Finding flow over time: opened versus closed and the running open backlog."
        action={
          <div className="flex flex-wrap items-center gap-2">
            <div className="inline-flex rounded-md border border-slate-200 bg-white p-0.5">
              {INTERVALS.map((option) => (
                <button key={option.value} type="button" onClick={() => setBucketTransition(option.value)} className={toggleClass(bucket === option.value)}>
                  {option.label}
                </button>
              ))}
            </div>
            <div className="inline-flex rounded-md border border-slate-200 bg-white p-0.5">
              {WINDOWS.map((option) => (
                <button key={option.value} type="button" onClick={() => setDaysTransition(option.value)} className={toggleClass(days === option.value)}>
                  {option.label}
                </button>
              ))}
            </div>
            <button
              type="button"
              onClick={() => void trendsQuery.reload()}
              className={actionButtonClass}
            >
              Refresh
            </button>
            <Link
              href={grcPath("/trends/dashboards", { tenant_id: tenantID, runtime_id: runtimeID, source_id: sourceID, severity, framework })}
              className={actionButtonClass}
            >
              Custom dashboards
            </Link>
            <button
              type="button"
              disabled={!trends}
              onClick={exportCSV}
              className={actionButtonClass}
            >
              Export CSV
            </button>
            <button
              type="button"
              disabled={!showChart}
              onClick={() => void exportPNG()}
              className={actionButtonClass}
            >
              Export PNG
            </button>
          </div>
        }
      />

      <div className="rounded-lg border border-slate-200 bg-white px-5 py-4">
        <div className="grid gap-3 md:grid-cols-6">
          <label className={labelClass}>Tenant<input value={tenantID} onChange={(event) => setTenantID(event.target.value)} placeholder="All" className={inputClass} /></label>
          <label className={labelClass}>Runtime<input value={runtimeID} onChange={(event) => setRuntimeID(event.target.value)} placeholder="All" className={inputClass} /></label>
          <label className={labelClass}>Source<input value={sourceID} onChange={(event) => setSourceID(event.target.value)} placeholder="All" className={inputClass} /></label>
          <label className={labelClass}>Framework<input value={framework} onChange={(event) => setFramework(event.target.value)} placeholder="SOC 2" className={inputClass} /></label>
          <label className={labelClass}>Severity<select value={severity} onChange={(event) => setSeverity(event.target.value)} className={selectClass}><option value="">All</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option></select></label>
          <label className={labelClass}>Compare<select value={compareEnabled ? "true" : "false"} onChange={(event) => setCompare(event.target.value)} className={selectClass}><option value="true">Previous period</option><option value="false">Off</option></select></label>
          <label className={labelClass}>MTTR target days<input value={mttrTargetDays} onChange={(event) => setMTTRTargetDays(event.target.value)} placeholder="30" inputMode="numeric" className={inputClass} /></label>
          <label className={labelClass}>Backlog target<input value={backlogTarget} onChange={(event) => setBacklogTarget(event.target.value)} placeholder="Optional" inputMode="numeric" className={inputClass} /></label>
          <label className={labelClass}>SLA target days<input value={slaTargetDays} onChange={(event) => setSLATargetDays(event.target.value)} placeholder="30" inputMode="numeric" className={inputClass} /></label>
        </div>
        <AppliedFilterChips filters={filterChips} onClearAll={clearFilters} />
      </div>

      {trends?.accuracy?.caveat && (
        <AttentionBanner>
          {trends.accuracy.caveat}
        </AttentionBanner>
      )}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
        <MetricCard label="Opened" value={summary.totalOpened} detail={`${summary.openedCritical} critical · ${summary.openedHigh} high`} intent={summary.openedCritical > 0 ? "danger" : "neutral"} state={metricState} />
        <MetricCard label="Closed" value={summary.totalClosed} detail="resolved in window" intent="success" state={metricState} />
        <MetricCard label="Net Change" value={`${summary.net > 0 ? "+" : ""}${summary.net}`} detail="opened minus closed" intent={summary.net > 0 ? "warning" : "success"} state={metricState} />
        <MetricCard label="Open Backlog" value={summary.currentOpen} detail={`peak ${summary.peakOpen}`} intent={summary.currentOpen > 0 ? "neutral" : "success"} state={metricState} />
        <MetricCard label="Avg Time to Close" value={formatTrendDuration(summary.avgTimeToCloseSeconds)} detail={comparison ? deltaLabel(comparison.avg_time_to_close_seconds_delta, signedDurationLabel) : "closed findings"} intent={trends?.targets?.mttr_seconds && summary.avgTimeToCloseSeconds > trends.targets.mttr_seconds ? "warning" : "success"} state={metricState} />
        <MetricCard label="SLA Misses" value={summary.closedSLABreached} detail={comparison ? deltaLabel(comparison.closed_sla_breached_delta) : "closed after due date"} intent={summary.closedSLABreached > 0 ? "danger" : "success"} state={metricState} />
      </div>

      {!trendsQuery.loading && !trendsQuery.error && (
        <div className="grid gap-6 xl:grid-cols-[minmax(0,1.2fr)_minmax(320px,0.8fr)]">
          <Panel title="Trend Signals">
            <div className="divide-y divide-slate-100">
              {signals.map((signal) => (
                <div key={signal.id} className="grid gap-2 py-3 first:pt-0 last:pb-0 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center">
                  <div>
                    <div className="text-[13px] font-semibold text-slate-900">{signal.label}</div>
                    <div className="mt-0.5 text-[12px] text-slate-500">{signal.detail}</div>
                  </div>
                  <div className={`text-left text-xl font-semibold sm:text-right ${signalValueClass(signal.intent)}`}>{signal.value}</div>
                </div>
              ))}
            </div>
          </Panel>

          <Panel title="Critical and High Flow">
            <div className="overflow-x-auto">
              <table className="min-w-full text-left text-[13px]">
                <caption className="sr-only">Critical and high severity finding flow</caption>
                <thead className="text-[11px] uppercase tracking-wider text-slate-500">
                  <tr>
                    <th scope="col" className="px-3 py-2">Severity</th>
                    <th scope="col" className="px-3 py-2 text-right">Opened</th>
                    <th scope="col" className="px-3 py-2 text-right">Closed</th>
                    <th scope="col" className="px-3 py-2 text-right">Net</th>
                    <th scope="col" className="px-3 py-2 text-right">Closure</th>
                  </tr>
                </thead>
                <tbody>
                  {severityFlow.map((row) => (
                    <tr key={row.severity} className="border-t border-slate-100">
                      <td className="px-3 py-2 font-medium text-slate-900">
                        <Link href={grcPath("/trends", { tenant_id: tenantID, runtime_id: runtimeID, source_id: sourceID, framework, severity: row.severity })} className="hover:text-indigo-700">{row.label}</Link>
                      </td>
                      <td className="px-3 py-2 text-right text-slate-700">{row.opened}</td>
                      <td className="px-3 py-2 text-right text-slate-700">{row.closed}</td>
                      <td className={`px-3 py-2 text-right font-medium ${row.net > 0 ? "text-amber-700" : row.net < 0 ? "text-emerald-700" : "text-slate-700"}`}>{row.net > 0 ? "+" : ""}{row.net}</td>
                      <td className="px-3 py-2 text-right text-slate-700">{formatTrendPercent(row.closureRate)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
        </div>
      )}

      {trendsQuery.loading && <LoadingBlock label="Loading trends..." />}
      {trendsQuery.error && <ErrorBlock error={trendsQuery.error} onRetry={() => void trendsQuery.reload()} recoveryDetail="Trends will appear when the API is reachable." />}

      {!trendsQuery.loading && !trendsQuery.error && (
        <Panel title="Finding Flow">
          {showChart ? (
            <TrendsChart
              ref={chartRef}
              points={points}
              height={340}
              targets={trends?.targets}
              onBucketSelect={(date, kind) => router.push(bucketDrilldownPath(date, kind))}
            />
          ) : (
            <div className="flex items-center justify-center rounded-lg border border-dashed border-slate-300 p-10 text-[13px] text-slate-500">
              No finding activity in this window.
            </div>
          )}
          {showChart && <div className="mt-2 text-[12px] text-slate-500">Click opened or closed bars to drill into matching findings.</div>}
        </Panel>
      )}

      {!trendsQuery.loading && !trendsQuery.error && (
        <div className="grid gap-6 xl:grid-cols-2">
          <Panel title="Open Aging">
            <div className="overflow-x-auto">
              <table className="min-w-full text-left text-[13px]">
                <caption className="sr-only">Open finding aging buckets</caption>
                <thead className="text-[11px] uppercase tracking-wider text-slate-500">
                  <tr><th scope="col" className="px-3 py-2">Age</th><th scope="col" className="px-3 py-2 text-right">Open</th><th scope="col" className="px-3 py-2 text-right">Action</th></tr>
                </thead>
                <tbody>
                  {agingBuckets.map((bucket) => (
                    <tr key={bucket.id} className="border-t border-slate-100">
                      <td className="px-3 py-2 font-medium text-slate-900">{bucket.label}</td>
                      <td className="px-3 py-2 text-right text-slate-700">{bucket.count}</td>
                      <td className="px-3 py-2 text-right">
                        <Link href={riskInboxPath({ status: "open", age_min_days: bucket.min_days || undefined, age_max_days: bucket.max_days && bucket.max_days > 0 ? bucket.max_days : undefined })} className="font-medium text-indigo-600 hover:text-indigo-800">View</Link>
                      </td>
                    </tr>
                  ))}
                  {agingBuckets.length === 0 && <tr><td colSpan={3} className="px-3 py-6 text-center text-slate-500">No open findings.</td></tr>}
                </tbody>
              </table>
            </div>
          </Panel>

          <Panel title="Period Comparison">
            {comparison ? (
              <div className="grid gap-3 md:grid-cols-2">
                <MetricCard label="Opened delta" value={deltaLabel(comparison.opened_delta)} state={metricState} />
                <MetricCard label="Closed delta" value={deltaLabel(comparison.closed_delta)} intent={comparison.closed_delta >= 0 ? "success" : "warning"} state={metricState} />
                <MetricCard label="Backlog delta" value={deltaLabel(comparison.current_open_delta)} intent={comparison.current_open_delta > 0 ? "warning" : "success"} state={metricState} />
                <MetricCard label="MTTR delta" value={deltaLabel(comparison.avg_time_to_close_seconds_delta, signedDurationLabel)} intent={comparison.avg_time_to_close_seconds_delta > 0 ? "warning" : "success"} state={metricState} />
              </div>
            ) : (
              <div className="rounded-lg border border-dashed border-slate-300 p-6 text-center text-[13px] text-slate-500">Enable comparison to see previous-period deltas.</div>
            )}
          </Panel>
        </div>
      )}

      {!trendsQuery.loading && !trendsQuery.error && points.length > 0 && (
        <Panel title="Trend Data">
          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-[13px]">
              <caption className="sr-only">Finding trend point data</caption>
              <thead className="text-[11px] uppercase tracking-wider text-slate-500">
                <tr>
                  <th scope="col" className="px-3 py-2">Date</th>
                  <th scope="col" className="px-3 py-2 text-right">Opened</th>
                  <th scope="col" className="px-3 py-2 text-right">Closed</th>
                  <th scope="col" className="px-3 py-2 text-right">Open backlog</th>
                  <th scope="col" className="px-3 py-2 text-right">Avg time to close</th>
                  <th scope="col" className="px-3 py-2 text-right">SLA misses</th>
                </tr>
              </thead>
              <tbody>
                {points.map((point) => (
                  <tr key={point.date} className="border-t border-slate-100">
                    <td className="px-3 py-2 font-medium text-slate-900">{point.date}</td>
                    <td className="px-3 py-2 text-right"><Link href={bucketDrilldownPath(point.date, "opened")} className="text-indigo-600 hover:text-indigo-800">{point.opened}</Link></td>
                    <td className="px-3 py-2 text-right"><Link href={bucketDrilldownPath(point.date, "closed")} className="text-indigo-600 hover:text-indigo-800">{point.closed}</Link></td>
                    <td className="px-3 py-2 text-right text-slate-700">{point.open_total}</td>
                    <td className="px-3 py-2 text-right text-slate-700">{formatTrendDuration(point.avg_time_to_close_seconds)}</td>
                    <td className="px-3 py-2 text-right text-slate-700">{point.closed_sla_breached}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
    </div>
  );
}
