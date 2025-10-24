"use client";

import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { apiGet } from "@/lib/api";
import {
  ExecutiveDashboardResponse,
  ExecutiveSummaryResponse,
  OrganizationSummary,
  SecurityMetricsResponse,
} from "@/lib/types";
import { cn } from "@/lib/utils";
import { Panel } from "@/components/ui/panel";

const RISK_LEVEL_STYLES: Record<string, string> = {
  minimal: "text-emerald-400",
  low: "text-emerald-300",
  moderate: "text-amber-300",
  high: "text-orange-400",
  critical: "text-red-400",
};

export function ExecutiveDashboard() {
  const [selectedOrg, setSelectedOrg] = useState<string>("");

  const {
    data: organizations = [],
    isLoading: isLoadingOrganizations,
  } = useQuery({
    queryKey: ["organizations"],
    queryFn: () => apiGet<OrganizationSummary[]>("/organizations"),
    staleTime: 5 * 60_000,
  });

  useEffect(() => {
    if (!selectedOrg && organizations.length > 0) {
      setSelectedOrg(organizations[0].org_id);
    }
  }, [selectedOrg, organizations]);

  const {
    data: dashboard,
    isLoading: isLoadingDashboard,
    isFetching: isFetchingDashboard,
    refetch,
  } = useQuery({
    queryKey: ["executiveDashboard", selectedOrg],
    queryFn: () =>
      apiGet<ExecutiveDashboardResponse>(
        `/analytics/dashboard/organizations/${selectedOrg}/dashboard`
      ),
    enabled: Boolean(selectedOrg),
    staleTime: 60_000,
  });

  const summary: ExecutiveSummaryResponse | undefined = dashboard?.executive_summary;
  const metrics: SecurityMetricsResponse | undefined = dashboard?.security_metrics;

  const riskLevelClass = useMemo(() => {
    if (!summary) {
      return "text-zinc-300";
    }
    return RISK_LEVEL_STYLES[summary.risk_level] ?? "text-zinc-300";
  }, [summary]);

  return (
    <div className="space-y-6">
      <Panel
        title="Organization selection"
        description="Choose an organization to load its latest security posture."
        action={
          <div className="flex items-center gap-3 text-xs">
            <button
              type="button"
              onClick={() => refetch()}
              disabled={!selectedOrg || isFetchingDashboard}
              className={cn(
                "rounded-md border px-3 py-1 transition",
                !selectedOrg || isFetchingDashboard
                  ? "cursor-not-allowed border-zinc-800 text-zinc-600"
                  : "border-zinc-700 text-zinc-100 hover:border-zinc-500 hover:bg-zinc-900"
              )}
            >
              {isFetchingDashboard ? "Refreshing…" : "Refresh"}
            </button>
          </div>
        }
      >
        {isLoadingOrganizations ? (
          <p className="text-sm text-zinc-500">Loading organizations…</p>
        ) : organizations.length === 0 ? (
          <p className="text-sm text-zinc-500">
            No organizations available. Ingest data before viewing analytics.
          </p>
        ) : (
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <label htmlFor="executive-org-select" className="text-zinc-400">
              Organization
            </label>
            <select
              id="executive-org-select"
              value={selectedOrg}
              onChange={(event) => setSelectedOrg(event.target.value)}
              className="min-w-[18rem] rounded-md border border-zinc-800 bg-black px-3 py-2 text-sm text-zinc-100 focus:border-zinc-600 focus:outline-none"
            >
              {organizations.map((org) => (
                <option key={org.org_id} value={org.org_id}>
                  {org.name}
                </option>
              ))}
            </select>
            <span className="text-xs text-zinc-500">
              Updated {isFetchingDashboard ? "now" : "recently"}
            </span>
          </div>
        )}
      </Panel>

      <Panel
        title="Executive overview"
        description="High-level risk posture, trends, and top risks."
      >
        {isLoadingDashboard ? (
          <p className="text-sm text-zinc-500">Loading executive summary…</p>
        ) : !summary ? (
          <p className="text-sm text-zinc-500">
            Select an organization to view executive analytics.
          </p>
        ) : (
          <div className="grid gap-6 lg:grid-cols-2">
            <div className="space-y-4">
              <div className="rounded-lg border border-zinc-900 bg-black/60 p-4">
                <div className="text-xs uppercase tracking-wide text-zinc-500">Risk score</div>
                <div className="mt-2 flex items-baseline gap-3">
                  <span className="text-3xl font-semibold text-zinc-100">
                    {summary.overall_risk_score.toFixed(1)}
                  </span>
                  <span className={cn("text-sm font-medium", riskLevelClass)}>
                    {summary.risk_level}
                  </span>
                </div>
                <div className="mt-1 text-xs text-zinc-500">
                  Trend: {summary.risk_trend} • Report {new Date(summary.report_date).toLocaleString()}
                </div>
                <dl className="mt-4 grid grid-cols-2 gap-3 text-xs text-zinc-400">
                  {Object.entries(summary.dimension_scores).map(([dimension, score]) => (
                    <div key={dimension} className="rounded-md border border-zinc-900 bg-black/40 p-2">
                      <dt className="uppercase tracking-wide text-[10px] text-zinc-500">{dimension.replace(/_/g, " ")}</dt>
                      <dd className="mt-1 text-sm text-zinc-100">{score.toFixed(1)}</dd>
                    </div>
                  ))}
                </dl>
              </div>

              <div className="rounded-lg border border-zinc-900 bg-black/60 p-4">
                <div className="text-xs uppercase tracking-wide text-zinc-500">
                  Progress indicators (30 days)
                </div>
                <div className="mt-3 grid gap-3 sm:grid-cols-3">
                  <MetricStat
                    label="Findings burned down"
                    value={summary.progress_indicators.findings_burned_down_30d}
                  />
                  <MetricStat
                    label="New controls"
                    value={summary.progress_indicators.new_controls_implemented}
                  />
                  <MetricStat
                    label="Risk delta"
                    value={summary.progress_indicators.risk_score_change_30d}
                    formatter={(val) => `${val >= 0 ? "+" : ""}${val.toFixed(1)}`}
                  />
                </div>
              </div>
            </div>

            <div className="space-y-4">
              <div className="rounded-lg border border-zinc-900 bg-black/60 p-4">
                <div className="text-xs uppercase tracking-wide text-zinc-500">Top risks</div>
                <ol className="mt-3 space-y-2 text-sm text-zinc-200">
                  {summary.top_5_risks.length === 0 ? (
                    <li className="text-zinc-500">No prioritized risks available.</li>
                  ) : (
                    summary.top_5_risks.map((risk) => <li key={risk}>{risk}</li>)
                  )}
                </ol>
              </div>

              {dashboard?.investment_recommendations?.length ? (
                <div className="rounded-lg border border-zinc-900 bg-black/60 p-4">
                  <div className="text-xs uppercase tracking-wide text-zinc-500">
                    Investment recommendations
                  </div>
                  <ul className="mt-3 space-y-3 text-sm text-zinc-200">
                    {dashboard.investment_recommendations.map((rec, index) => (
                      <li key={`${rec.category}-${index}`} className="rounded-md border border-zinc-900 bg-black/40 p-3">
                        <div className="flex items-center justify-between text-xs uppercase tracking-wide text-zinc-500">
                          <span>{rec.category}</span>
                          <span className="text-zinc-400">{rec.priority} priority</span>
                        </div>
                        <div className="mt-1 font-medium text-zinc-100">{rec.recommendation}</div>
                        <p className="mt-1 text-xs text-zinc-400">{rec.rationale}</p>
                        <p className="mt-1 text-[11px] text-zinc-500">
                          Impact: {rec.estimated_impact} • Investment: {rec.investment_level}
                        </p>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          </div>
        )}
      </Panel>

      <Panel
        title="Findings and operations"
        description="Key findings volume and SLA adherence metrics."
      >
        {isLoadingDashboard ? (
          <p className="text-sm text-zinc-500">Loading metrics…</p>
        ) : !metrics ? (
          <p className="text-sm text-zinc-500">No metrics available.</p>
        ) : (
          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-lg border border-zinc-900 bg-black/60 p-4">
              <div className="text-xs uppercase tracking-wide text-zinc-500">Findings</div>
              <div className="mt-3 grid grid-cols-2 gap-3 text-sm text-zinc-200">
                <MetricStat label="Total" value={metrics.findings.total} />
                <MetricStat label="Critical" value={metrics.findings.critical} />
                <MetricStat label="High" value={metrics.findings.high} />
                <MetricStat label="Open" value={metrics.findings.open} />
              </div>
              <div className="mt-4 text-xs text-zinc-500">
                7-day trend: {metrics.findings.trend_7d.join(" • ") || "n/a"}
              </div>
              <div className="mt-1 text-xs text-zinc-500">
                Critical trend: {metrics.findings.critical_trend_7d.join(" • ") || "n/a"}
              </div>
            </div>

            <div className="rounded-lg border border-zinc-900 bg-black/60 p-4">
              <div className="text-xs uppercase tracking-wide text-zinc-500">SLA performance</div>
              <div className="mt-3 grid grid-cols-2 gap-3 text-sm text-zinc-200">
                <MetricStat label="SLA breaches" value={metrics.sla_performance.breaches} />
                <MetricStat
                  label="MTTR (hours)"
                  value={metrics.sla_performance.mttr_hours}
                  formatter={(val) => val.toFixed(1)}
                />
                <MetricStat label="New (24h)" value={metrics.sla_performance.new_24h} />
                <MetricStat label="Resolved (24h)" value={metrics.sla_performance.resolved_24h} />
              </div>
            </div>
          </div>
        )}
      </Panel>

      <Panel
        title="Compliance coverage"
        description="Framework compliance status derived from latest control assessments."
      >
        {isLoadingDashboard ? (
          <p className="text-sm text-zinc-500">Loading compliance data…</p>
        ) : !dashboard?.compliance_status ? (
          <p className="text-sm text-zinc-500">No compliance data available.</p>
        ) : (
          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
            {Object.entries(dashboard.compliance_status).map(([framework, stats]) => (
              <div
                key={framework}
                className="rounded-lg border border-zinc-900 bg-black/60 p-4 text-sm text-zinc-200"
              >
                <div className="text-xs uppercase tracking-wide text-zinc-500">{framework}</div>
                <div className="mt-2 text-2xl font-semibold text-zinc-100">
                  {stats.compliance_percentage.toFixed(1)}%
                </div>
                <div className="mt-1 text-xs text-zinc-500">
                  {stats.compliant_controls}/{stats.total_controls} controls compliant
                </div>
                <div className="mt-2 text-[11px] uppercase tracking-wide text-zinc-400">
                  Status: {stats.status.replace(/_/g, " ")}
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}

type MetricStatProps = {
  label: string;
  value: number;
  formatter?: (value: number) => string;
};

function MetricStat({ label, value, formatter }: MetricStatProps) {
  const formatted = Number.isFinite(value) ? (formatter ? formatter(value) : value.toString()) : "—";

  return (
    <div className="rounded-md border border-zinc-900 bg-black/40 p-3">
      <div className="text-[10px] uppercase tracking-wide text-zinc-500">{label}</div>
      <div className="mt-1 text-lg font-semibold text-zinc-100">{formatted}</div>
    </div>
  );
}
