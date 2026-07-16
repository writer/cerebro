"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMemo, useRef } from "react";

import { Badge, EmptyBlock, ErrorBlock, LoadingBlock, MetricCard, Panel, ProgressCard, RiskBadge } from "@/components/grc/Primitives";
import TrendsChart from "@/components/grc/LazyTrendsChart";
import type { CustomDashboard, CustomDashboardWidget } from "@/lib/custom-dashboards";
import {
  customDashboardFindingsPath,
  customDashboardFrameworksPath,
  customDashboardSummaryPath,
  customDashboardTrendPath,
} from "@/lib/custom-dashboards";
import type { GRCDashboard, GRCFinding, GRCFrameworksResponse, GRCTrends } from "@/lib/grc";
import { displayDurationSeconds, humanize, riskSort, shortEntity } from "@/lib/grc";
import { useGRCQuery } from "@/lib/grc-client";
import {
  buildWidgetReportQuery,
  catalogWidgetSourceID,
  extractReportTable,
  findSource,
  useReportCatalog,
  useReportQuery,
  type ReportSource,
} from "@/lib/grc-report-catalog";

type CatalogContext = { sources: ReportSource[]; loading: boolean; error: string | null };
import { formatTrendDuration, hasTrendActivity, summarizeTrends, trendBucketEndDate } from "@/lib/trends";

type FindingsResponse = { findings: GRCFinding[]; generated_at: string };

type Props = {
  dashboard: CustomDashboard;
};

const deltaLabel = (value: number, formatter = (n: number) => `${n > 0 ? "+" : ""}${n}`) => {
  if (!Number.isFinite(value) || value === 0) return "no change";
  return `${formatter(value)} vs previous`;
};

const signedDurationLabel = (seconds: number) => `${seconds > 0 ? "+" : "-"}${formatTrendDuration(Math.abs(seconds))}`;

export default function CustomDashboardRenderer({ dashboard }: Props) {
  const widgets = Array.isArray(dashboard.widgets) ? dashboard.widgets : [];
  const hasCatalogWidget = widgets.some((widget) => catalogWidgetSourceID(widget) !== "");
  const catalog = useReportCatalog(hasCatalogWidget);
  const catalogContext: CatalogContext = { sources: catalog.sources, loading: catalog.loading, error: catalog.error };
  if (widgets.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-slate-300 bg-white p-8 text-center text-[13px] text-slate-500">
        This dashboard has no widgets yet.
      </div>
    );
  }
  return (
    <div className="grid gap-6 xl:grid-cols-12">
      {widgets.map((widget) => (
        <DashboardWidget key={widget.id} dashboard={dashboard} widget={widget} catalog={catalogContext} />
      ))}
    </div>
  );
}

function DashboardWidget({ dashboard, widget, catalog }: { dashboard: CustomDashboard; widget: CustomDashboardWidget; catalog: CatalogContext }) {
  const width = Math.max(3, Math.min(12, Number(widget.layout?.w) || 12));
  const className = width >= 12 ? "xl:col-span-12" : width >= 8 ? "xl:col-span-8" : width >= 6 ? "xl:col-span-6" : "xl:col-span-4";
  return <div className={className}>{renderWidget(dashboard, widget, catalog)}</div>;
}

function renderWidget(dashboard: CustomDashboard, widget: CustomDashboardWidget, catalog: CatalogContext) {
  if (catalogWidgetSourceID(widget) !== "") {
    return <CatalogWidget dashboard={dashboard} widget={widget} catalog={catalog} />;
  }
  if (widget.type.startsWith("trend_")) {
    return <TrendWidget dashboard={dashboard} widget={widget} />;
  }
  switch (widget.type) {
    case "summary_metrics":
      return <SummaryMetricsWidget dashboard={dashboard} widget={widget} />;
    case "connector_health":
      return <ConnectorHealthWidget dashboard={dashboard} widget={widget} />;
    case "findings_table":
      return <FindingsTableWidget dashboard={dashboard} widget={widget} />;
    case "framework_progress":
      return <FrameworkProgressWidget dashboard={dashboard} widget={widget} />;
    case "markdown_note":
      return <MarkdownNoteWidget widget={widget} />;
    default:
      return (
        <Panel title={widget.title ?? "Unsupported widget"}>
          <div className="rounded-lg border border-dashed border-slate-300 p-6 text-[13px] text-slate-500">
            Widget type {widget.type} is not supported yet.
          </div>
        </Panel>
      );
  }
}

function TrendWidget({ dashboard, widget }: { dashboard: CustomDashboard; widget: CustomDashboardWidget }) {
  const router = useRouter();
  const chartRef = useRef<HTMLDivElement | null>(null);
  const trendsPath = useMemo(() => customDashboardTrendPath(dashboard, widget), [dashboard, widget]);
  const query = useGRCQuery<GRCTrends>(trendsPath);
  const trends = query.data;
  const summary = useMemo(() => summarizeTrends(trends), [trends]);
  const points = trends?.points ?? [];
  const metricState = query.loading ? "loading" : "ready";
  const interval = String(widget.query?.params?.interval ?? dashboard.filters.interval ?? "week");
  const filterParams = {
    tenant_id: stringValue(dashboard.filters.tenant_id),
    runtime_id: stringValue(dashboard.filters.runtime_id),
    source_id: stringValue(dashboard.filters.source_id),
    severity: stringValue(dashboard.filters.severity),
    framework: stringValue(dashboard.filters.framework),
  };
  const riskInboxPath = (params: Record<string, string | number | undefined>) => {
    const queryParams = new URLSearchParams();
    Object.entries({ ...filterParams, ...params }).forEach(([key, value]) => {
      if (value !== undefined && String(value).trim() !== "") queryParams.set(key, String(value));
    });
    const queryString = queryParams.toString();
    return queryString ? `/risk-inbox?${queryString}` : "/risk-inbox";
  };
  const bucketDrilldownPath = (date: string, kind: "opened" | "closed") => {
    const before = trendBucketEndDate(date, interval);
    return kind === "opened"
      ? riskInboxPath({ status: "all", opened_after: date, opened_before: before })
      : riskInboxPath({ status: "all", closed_after: date, closed_before: before });
  };

  if (query.loading) {
    return <LoadingBlock label={`Loading ${widget.title ?? "widget"}...`} />;
  }
  if (query.error) {
    return <ErrorBlock error={query.error} onRetry={() => void query.reload()} recoveryDetail="Refresh after the dashboard API is reachable." />;
  }

  switch (widget.type) {
    case "trend_metric_cards":
      return (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          <MetricCard label="Opened" value={summary.totalOpened} detail={`${summary.openedCritical} critical · ${summary.openedHigh} high`} intent={summary.openedCritical > 0 ? "danger" : "neutral"} state={metricState} />
          <MetricCard label="Closed" value={summary.totalClosed} detail="resolved in window" intent="success" state={metricState} />
          <MetricCard label="Net Change" value={`${summary.net > 0 ? "+" : ""}${summary.net}`} detail="opened minus closed" intent={summary.net > 0 ? "warning" : "success"} state={metricState} />
          <MetricCard label="Open Backlog" value={summary.currentOpen} detail={`peak ${summary.peakOpen}`} intent={summary.currentOpen > 0 ? "neutral" : "success"} state={metricState} />
          <MetricCard label="Avg Time to Close" value={formatTrendDuration(summary.avgTimeToCloseSeconds)} detail="closed findings" state={metricState} />
          <MetricCard label="SLA Misses" value={summary.closedSLABreached} detail="closed after due date" intent={summary.closedSLABreached > 0 ? "danger" : "success"} state={metricState} />
        </div>
      );
    case "trend_chart":
      return (
        <Panel title={widget.title ?? "Finding flow"}>
          {hasTrendActivity(trends) ? (
            <TrendsChart
              ref={chartRef}
              points={points}
              height={320}
              targets={trends?.targets}
              onBucketSelect={(date, kind) => router.push(bucketDrilldownPath(date, kind))}
            />
          ) : (
            <div className="flex items-center justify-center rounded-lg border border-dashed border-slate-300 p-10 text-[13px] text-slate-500">
              No finding activity in this window.
            </div>
          )}
        </Panel>
      );
    case "trend_aging_table":
      return (
        <Panel title={widget.title ?? "Open aging"}>
          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-[13px]">
              <caption className="sr-only">Open finding aging buckets</caption>
              <thead className="text-[11px] uppercase tracking-wider text-slate-500">
                <tr><th scope="col" className="px-3 py-2">Age</th><th scope="col" className="px-3 py-2 text-right">Open</th><th scope="col" className="px-3 py-2 text-right">Action</th></tr>
              </thead>
              <tbody>
                {(trends?.aging_buckets ?? []).map((bucket) => (
                  <tr key={bucket.id} className="border-t border-slate-100">
                    <td className="px-3 py-2 font-medium text-slate-900">{bucket.label}</td>
                    <td className="px-3 py-2 text-right text-slate-700">{bucket.count}</td>
                    <td className="px-3 py-2 text-right">
                      <Link href={riskInboxPath({ status: "open", age_min_days: bucket.min_days || undefined, age_max_days: bucket.max_days && bucket.max_days > 0 ? bucket.max_days : undefined })} className="font-medium text-indigo-600 hover:text-indigo-800">View</Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      );
    case "trend_period_comparison":
      return (
        <Panel title={widget.title ?? "Period comparison"}>
          {trends?.comparison ? (
            <div className="grid gap-3 md:grid-cols-2">
              <MetricCard label="Opened delta" value={deltaLabel(trends.comparison.opened_delta)} state={metricState} />
              <MetricCard label="Closed delta" value={deltaLabel(trends.comparison.closed_delta)} intent={trends.comparison.closed_delta >= 0 ? "success" : "warning"} state={metricState} />
              <MetricCard label="Backlog delta" value={deltaLabel(trends.comparison.current_open_delta)} intent={trends.comparison.current_open_delta > 0 ? "warning" : "success"} state={metricState} />
              <MetricCard label="MTTR delta" value={deltaLabel(trends.comparison.avg_time_to_close_seconds_delta, signedDurationLabel)} intent={trends.comparison.avg_time_to_close_seconds_delta > 0 ? "warning" : "success"} state={metricState} />
            </div>
          ) : (
            <div className="rounded-lg border border-dashed border-slate-300 p-6 text-center text-[13px] text-slate-500">Enable comparison to see previous-period deltas.</div>
          )}
        </Panel>
      );
    default:
      return null;
  }
}

function SummaryMetricsWidget({ dashboard, widget }: { dashboard: CustomDashboard; widget: CustomDashboardWidget }) {
  const path = useMemo(() => customDashboardSummaryPath(dashboard, widget), [dashboard, widget]);
  const query = useGRCQuery<GRCDashboard>(path);
  if (query.loading) return <LoadingBlock label={`Loading ${widget.title ?? "summary"}...`} />;
  if (query.error) return <ErrorBlock error={query.error} onRetry={() => void query.reload()} recoveryDetail="Summary will appear when the API is reachable." />;
  const summary = query.data?.summary;
  if (!summary) {
    return <Panel title={widget.title ?? "Program summary"}><EmptyBlock label="No summary available." /></Panel>;
  }
  return (
    <Panel title={widget.title ?? "Program summary"}>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        <MetricCard label="Open Findings" value={summary.open_findings} detail={`${summary.critical_findings} critical · ${summary.high_findings} high`} intent={summary.critical_findings > 0 ? "danger" : "neutral"} />
        <MetricCard label="Overdue" value={summary.overdue_findings} detail="past due date" intent={summary.overdue_findings > 0 ? "warning" : "success"} />
        <MetricCard label="Unassigned" value={summary.unassigned} detail="awaiting owner" intent={summary.unassigned > 0 ? "warning" : "success"} />
        <MetricCard label="Controls Failing" value={summary.controls_failing} intent={summary.controls_failing > 0 ? "warning" : "success"} />
        <MetricCard label="Evidence Items" value={summary.evidence_items} />
        <MetricCard label="Stale Sources" value={summary.stale_connectors} detail={`${summary.connectors} total`} intent={summary.stale_connectors > 0 ? "warning" : "success"} />
      </div>
    </Panel>
  );
}

function ConnectorHealthWidget({ dashboard, widget }: { dashboard: CustomDashboard; widget: CustomDashboardWidget }) {
  const path = useMemo(() => customDashboardSummaryPath(dashboard, widget), [dashboard, widget]);
  const query = useGRCQuery<GRCDashboard>(path);
  if (query.loading) return <LoadingBlock label={`Loading ${widget.title ?? "connectors"}...`} />;
  if (query.error) return <ErrorBlock error={query.error} onRetry={() => void query.reload()} recoveryDetail="Connector health will appear when the API is reachable." />;
  const connectors = query.data?.connectors ?? [];
  return (
    <Panel title={widget.title ?? "Connector health"}>
      {connectors.length === 0 ? (
        <EmptyBlock label="No connectors reporting." />
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-[13px]">
            <caption className="sr-only">Connector freshness</caption>
            <thead className="text-[11px] uppercase tracking-wider text-slate-500">
              <tr><th scope="col" className="px-3 py-2">Connector</th><th scope="col" className="px-3 py-2">Freshness</th><th scope="col" className="px-3 py-2 text-right">Sync lag</th></tr>
            </thead>
            <tbody>
              {connectors.map((connector) => (
                <tr key={connector.runtime_id} className="border-t border-slate-100">
                  <td className="px-3 py-2 font-medium text-slate-900">{shortEntity(connector.runtime_id)}</td>
                  <td className="px-3 py-2"><Badge value={connector.freshness || connector.status} tone="status" /></td>
                  <td className="px-3 py-2 text-right text-slate-700">{displayDurationSeconds(connector.sync_lag_seconds)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function FindingsTableWidget({ dashboard, widget }: { dashboard: CustomDashboard; widget: CustomDashboardWidget }) {
  const path = useMemo(() => customDashboardFindingsPath(dashboard, widget), [dashboard, widget]);
  const query = useGRCQuery<FindingsResponse>(path);
  if (query.loading) return <LoadingBlock label={`Loading ${widget.title ?? "findings"}...`} />;
  if (query.error) return <ErrorBlock error={query.error} onRetry={() => void query.reload()} recoveryDetail="Findings will appear when the API is reachable." />;
  const findings = [...(query.data?.findings ?? [])].sort(riskSort);
  return (
    <Panel title={widget.title ?? "Findings"}>
      {findings.length === 0 ? (
        <EmptyBlock label="No findings match this dashboard's filters." />
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-[13px]">
            <caption className="sr-only">Findings by risk</caption>
            <thead className="text-[11px] uppercase tracking-wider text-slate-500">
              <tr><th scope="col" className="px-3 py-2">Finding</th><th scope="col" className="px-3 py-2">Severity</th><th scope="col" className="px-3 py-2">Status</th><th scope="col" className="px-3 py-2 text-right">Risk</th></tr>
            </thead>
            <tbody>
              {findings.map((finding) => (
                <tr key={finding.id} className="border-t border-slate-100">
                  <td className="px-3 py-2"><Link href={`/findings/${encodeURIComponent(finding.id)}`} className="font-medium text-indigo-600 hover:text-indigo-800">{finding.title}</Link></td>
                  <td className="px-3 py-2"><Badge value={finding.severity} tone="severity" /></td>
                  <td className="px-3 py-2 text-slate-700">{humanize(finding.status)}</td>
                  <td className="px-3 py-2 text-right"><RiskBadge score={finding.risk_score} level={finding.likelihood_level} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function FrameworkProgressWidget({ dashboard, widget }: { dashboard: CustomDashboard; widget: CustomDashboardWidget }) {
  const path = useMemo(() => customDashboardFrameworksPath(dashboard, widget), [dashboard, widget]);
  const query = useGRCQuery<GRCFrameworksResponse>(path);
  if (query.loading) return <LoadingBlock label={`Loading ${widget.title ?? "frameworks"}...`} />;
  if (query.error) return <ErrorBlock error={query.error} onRetry={() => void query.reload()} recoveryDetail="Frameworks will appear when the API is reachable." />;
  const frameworks = (query.data?.frameworks ?? []).filter((framework) => framework.lifecycle !== "upcoming");
  return (
    <Panel title={widget.title ?? "Framework coverage"}>
      {frameworks.length === 0 ? (
        <EmptyBlock label="No active frameworks selected." />
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {frameworks.map((framework) => {
            const mapped = framework.coverage?.mapped_controls ?? 0;
            const total = mapped + (framework.coverage?.unmapped_controls ?? 0);
            const percent = total > 0 ? (mapped / total) * 100 : 0;
            return (
              <ProgressCard
                key={framework.id ?? framework.name}
                title={framework.name}
                percent={percent}
                detail={`${mapped}/${total} controls mapped`}
                total={`${framework.control_count} total`}
                href={framework.id ? `/frameworks/${encodeURIComponent(framework.id)}` : undefined}
              />
            );
          })}
        </div>
      )}
    </Panel>
  );
}

function CatalogWidget({ dashboard, widget, catalog }: { dashboard: CustomDashboard; widget: CustomDashboardWidget; catalog: CatalogContext }) {
  const sourceID = catalogWidgetSourceID(widget);
  const source = findSource(catalog.sources, sourceID);
  const reportQuery = source ? buildWidgetReportQuery(source, dashboard.filters, widget) : null;
  const result = useReportQuery(reportQuery);
  const title = widget.title ?? source?.title ?? "Report";

  if (catalog.loading) return <LoadingBlock label={`Loading ${title}...`} />;
  if (catalog.error) return <ErrorBlock error={catalog.error} recoveryDetail="The report catalog will load when the API is reachable." />;
  if (!source) {
    return (
      <Panel title={title}>
        <div className="rounded-lg border border-dashed border-slate-300 p-6 text-[13px] text-slate-500">
          Report source <span className="font-medium text-slate-700">{sourceID}</span> is no longer available.
        </div>
      </Panel>
    );
  }
  if (result.loading) return <LoadingBlock label={`Loading ${title}...`} />;
  if (result.error) {
    return <ErrorBlock error={result.error} onRetry={() => void result.reload()} recoveryDetail="Report data will appear when the API is reachable." />;
  }
  const table = extractReportTable(result.data?.data);
  return (
    <Panel title={title}>
      {table ? (
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-[13px]">
            <caption className="sr-only">{title}</caption>
            <thead className="text-[11px] uppercase tracking-wider text-slate-500">
              <tr>
                {table.columns.map((column) => (
                  <th key={column} scope="col" className="px-3 py-2">{humanize(column)}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {table.rows.slice(0, 50).map((row, index) => (
                <tr key={rowKey(row, index)} className="border-t border-slate-100">
                  {table.columns.map((column) => (
                    <td key={column} className="px-3 py-2 text-slate-700">{cellValue(row[column])}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyBlock label="No tabular results for this report." />
      )}
    </Panel>
  );
}

const rowKey = (row: Record<string, unknown>, index: number) => {
  const id = row.id ?? row.runtime_id ?? row.name;
  return typeof id === "string" || typeof id === "number" ? String(id) : `row-${index}`;
};

const cellValue = (value: unknown) => {
  if (value === null || value === undefined) return "";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return String(value);
};

function MarkdownNoteWidget({ widget }: { widget: CustomDashboardWidget }) {
  const text = stringValue(widget.query?.params?.text).trim();
  return (
    <Panel title={widget.title ?? "Note"}>
      {text ? (
        <div className="whitespace-pre-wrap text-[13px] leading-relaxed text-slate-600">{text}</div>
      ) : (
        <EmptyBlock label="Set this note's text in the widget params." />
      )}
    </Panel>
  );
}

const stringValue = (value: unknown) => {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return "";
};
