"use client";

import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { apiGet } from "@/lib/api";
import {
  ExecutiveDashboardResponse,
  ExecutiveSummaryResponse,
  IdentityAnalyticsResponse,
  ComplianceTrendResponse,
  OrganizationSummary,
  RiskHeatmapResponse,
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

type TimeRangeOption = "7d" | "30d" | "90d";
type RiskFilterOption = "all" | "critical" | "high" | "medium" | "low";

const TIME_RANGE_OPTIONS: Array<{ label: string; value: TimeRangeOption }> = [
  { label: "Last 7 days", value: "7d" },
  { label: "Last 30 days", value: "30d" },
  { label: "Last 90 days", value: "90d" },
];

const RISK_FILTER_OPTIONS: Array<{ label: string; value: RiskFilterOption }> = [
  { label: "All risks", value: "all" },
  { label: "Critical", value: "critical" },
  { label: "High", value: "high" },
  { label: "Medium", value: "medium" },
  { label: "Low", value: "low" },
];

export function ExecutiveDashboard() {
  const [selectedOrg, setSelectedOrg] = useState<string>("");
  const [timeRange, setTimeRange] = useState<TimeRangeOption>("30d");
  const [riskFilter, setRiskFilter] = useState<RiskFilterOption>("all");

  const {
    data: organizations = [],
    isLoading: isLoadingOrganizations,
    isError: isOrganizationsError,
    error: organizationsError,
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
    isError: isDashboardError,
    error: dashboardError,
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
  const identity: IdentityAnalyticsResponse | undefined = dashboard?.identity_analytics;
  const heatmap: RiskHeatmapResponse | undefined = dashboard?.risk_heatmap;
  const complianceTrends: ComplianceTrendResponse | undefined = dashboard?.compliance_trends;
  const metadata = dashboard?.metadata;

  const filteredComplianceTrends = useMemo(() => {
    if (!complianceTrends) {
      return null;
    }

    const rangeInDays = timeRange === "7d" ? 7 : timeRange === "90d" ? 90 : 30;
    const cutoff = new Date();
    cutoff.setHours(0, 0, 0, 0);
    cutoff.setDate(cutoff.getDate() - (rangeInDays - 1));

    const filterPoints = (points: ComplianceTrendResponse["overall"]) =>
      points.filter((point) => {
        const pointDate = new Date(point.date);
        return Number.isNaN(pointDate.getTime()) ? true : pointDate >= cutoff;
      });

    const filteredFrameworks = Object.entries(complianceTrends.frameworks || {}).reduce(
      (acc, [framework, points]) => {
        acc[framework] = filterPoints(points);
        return acc;
      },
      {} as Record<string, typeof complianceTrends.overall>,
    );

    return {
      overall: filterPoints(complianceTrends.overall),
      frameworks: filteredFrameworks,
    };
  }, [complianceTrends, timeRange]);

  const filteredRiskyIdentities = useMemo(() => {
    if (!identity?.top_risky_identities) {
      return [];
    }
    if (riskFilter === "all") {
      return identity.top_risky_identities;
    }
    return identity.top_risky_identities.filter(
      (item) => item.risk_level?.toLowerCase() === riskFilter,
    );
  }, [identity, riskFilter]);

  const filteredDrilldownIdentities = useMemo(() => {
    if (!identity?.drilldown_identities) {
      return [];
    }
    if (riskFilter === "all") {
      return identity.drilldown_identities;
    }
    return identity.drilldown_identities.filter(
      (detail) => detail.risk_level?.toLowerCase() === riskFilter,
    );
  }, [identity, riskFilter]);

  const filteredRemediationQueue = useMemo(() => {
    if (!identity?.remediation_queue) {
      return [];
    }
    if (riskFilter === "all") {
      return identity.remediation_queue;
    }
    const priorityMap: Record<RiskFilterOption, "high" | "medium" | "low"> = {
      all: "high",
      critical: "high",
      high: "high",
      medium: "medium",
      low: "low",
    };
    const targetPriority = priorityMap[riskFilter];
    return identity.remediation_queue.filter((item) => item.priority === targetPriority);
  }, [identity, riskFilter]);

  const [selectedIdentity, setSelectedIdentity] = useState<string | null>(null);

  useEffect(() => {
    if (filteredDrilldownIdentities.length > 0) {
      setSelectedIdentity((current) =>
        current && filteredDrilldownIdentities.some((detail) => detail.principal_id === current)
          ? current
          : filteredDrilldownIdentities[0].principal_id,
      );
    } else {
      setSelectedIdentity(null);
    }
  }, [filteredDrilldownIdentities]);

  const selectedDrilldown = useMemo(() => {
    if (!filteredDrilldownIdentities.length) {
      return null;
    }
    return (
      filteredDrilldownIdentities.find((detail) => detail.principal_id === selectedIdentity) ??
      filteredDrilldownIdentities[0]
    );
  }, [filteredDrilldownIdentities, selectedIdentity]);

  const riskLevelClass = useMemo(() => {
    if (!summary) {
      return "text-zinc-300";
    }
    return RISK_LEVEL_STYLES[summary.risk_level] ?? "text-zinc-300";
  }, [summary]);

  const lastGeneratedAt = metadata?.generated_at;
  const identityGeneratedAt = identity?.generated_at;
  const complianceStatusEntries = dashboard?.compliance_status ?? {};
  const hasComplianceData = Object.keys(complianceStatusEntries).length > 0;

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
          <PanelSkeleton rows={2} />
        ) : isOrganizationsError ? (
          <ErrorState message={toErrorMessage(organizationsError, "Unable to load organizations.")} />
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
              Updated {isFetchingDashboard ? "now" : lastGeneratedAt ? formatTimestamp(lastGeneratedAt) : "recently"}
            </span>
          </div>
        )}
      </Panel>

      <Panel
        title="Dashboard filters"
        description="Focus analytics by timeframe and identity risk level."
      >
        <div className="flex flex-wrap items-start gap-6 text-sm text-zinc-300">
          <div>
            <div className="text-xs uppercase tracking-wide text-zinc-500">Time range</div>
            <div className="mt-2 flex flex-wrap gap-2">
              {TIME_RANGE_OPTIONS.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  onClick={() => setTimeRange(option.value)}
                  className={cn(
                    "rounded-md border px-3 py-1 text-xs transition",
                    timeRange === option.value
                      ? "border-zinc-500 bg-zinc-900 text-zinc-100"
                      : "border-zinc-900 bg-black/40 text-zinc-400 hover:border-zinc-700 hover:text-zinc-100",
                  )}
                >
                  {option.label}
                </button>
              ))}
            </div>
          </div>

          <div>
            <div className="text-xs uppercase tracking-wide text-zinc-500">Identity risk</div>
            <div className="mt-2 flex flex-wrap gap-2">
              {RISK_FILTER_OPTIONS.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  onClick={() => setRiskFilter(option.value)}
                  className={cn(
                    "rounded-md border px-3 py-1 text-xs transition",
                    riskFilter === option.value
                      ? "border-zinc-500 bg-zinc-900 text-zinc-100"
                      : "border-zinc-900 bg-black/40 text-zinc-400 hover:border-zinc-700 hover:text-zinc-100",
                  )}
                >
                  {option.label}
                </button>
              ))}
            </div>
          </div>

          <div className="min-w-[14rem] text-xs text-zinc-500">
            <div className="uppercase tracking-wide">Last refreshed</div>
            <div className="mt-2 text-sm text-zinc-200">
              {lastGeneratedAt ? formatTimestamp(lastGeneratedAt) : "—"}
              {isFetchingDashboard ? <span className="ml-1 text-xs text-zinc-500">(refreshing…)</span> : null}
            </div>
          </div>
        </div>
      </Panel>

      <Panel
        title="Executive overview"
        description="High-level risk posture, trends, and top risks."
      >
        {isLoadingDashboard ? (
          <ExecutiveOverviewSkeleton />
        ) : isDashboardError ? (
          <ErrorState message={toErrorMessage(dashboardError, "Unable to load dashboard data.")} />
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
          <MetricsPanelSkeleton />
        ) : isDashboardError ? (
          <ErrorState message={toErrorMessage(dashboardError, "Unable to load findings metrics.")} />
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
          <PanelSkeleton rows={4} />
        ) : isDashboardError ? (
          <ErrorState message={toErrorMessage(dashboardError, "Unable to load compliance data.")} />
        ) : !hasComplianceData ? (
          <p className="text-sm text-zinc-500">No compliance data available.</p>
        ) : (
          <div className="space-y-4">
            <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
              {Object.entries(complianceStatusEntries).map(([framework, stats]) => (
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
            {filteredComplianceTrends ? (
              <ComplianceTrendCard trend={filteredComplianceTrends} timeRange={timeRange} />
            ) : null}
          </div>
        )}
      </Panel>

      <Panel
        title="Identity risk posture"
        description="Privilege sprawl, risky identities, and MFA coverage across providers."
      >
        {isLoadingDashboard ? (
          <IdentityPanelSkeleton />
        ) : isDashboardError ? (
          <ErrorState message={toErrorMessage(dashboardError, "Unable to load identity analytics.")} />
        ) : !identity ? (
          <p className="text-sm text-zinc-500">Identity analytics will appear once data collection completes.</p>
        ) : (
          <div className="space-y-5">
            <div className="grid gap-3 sm:grid-cols-3">
              <MetricStat label="Total identities" value={identity.summary.total_identities} formatter={formatInteger} />
              <MetricStat
                label="High privilege"
                value={identity.summary.high_privilege_identities}
                formatter={formatInteger}
              />
              <MetricStat
                label="Cross-provider"
                value={identity.summary.cross_provider_identities}
                formatter={formatInteger}
              />
              <MetricStat
                label="Avg permissions"
                value={identity.summary.avg_permissions_per_identity}
                formatter={(val) => val.toFixed(1)}
              />
              <MetricStat
                label="Max permissions"
                value={identity.summary.max_permissions_per_identity}
                formatter={formatInteger}
              />
              <div className="rounded-md border border-zinc-900 bg-black/40 p-3">
                <div className="text-[10px] uppercase tracking-wide text-zinc-500">Privilege mix</div>
                <div className="mt-2 flex flex-wrap gap-2 text-xs">
                  {Object.entries(identity.privilege_distribution).map(([label, count]) => (
                    <span key={label} className="rounded-full border border-zinc-800 px-2 py-1 text-zinc-300">
                      {label.replace(/_/g, " ")} · {formatInteger(count)}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            {identityGeneratedAt ? (
              <div className="text-xs text-zinc-500">
                Last analyzed {formatTimestamp(identityGeneratedAt)}
              </div>
            ) : null}

            <div className="grid gap-4 lg:grid-cols-2">
              <div className="rounded-lg border border-zinc-900 bg-black/50 p-4">
                <div className="text-xs uppercase tracking-wide text-zinc-500">Top risky identities</div>
                <ul className="mt-3 space-y-3 text-sm text-zinc-200">
                  {filteredRiskyIdentities.length === 0 ? (
                    <li className="text-zinc-500">No identities match the current risk filter.</li>
                  ) : (
                    filteredRiskyIdentities.map((person) => (
                      <li key={person.principal_id} className="rounded-md border border-zinc-900 bg-black/40 p-3">
                        <div className="flex items-center justify-between text-xs uppercase tracking-wide text-zinc-500">
                          <span>{person.display_name ?? person.email ?? person.principal_id.slice(0, 8)}</span>
                          <span className={riskBadgeClass(person.risk_level)}>{person.risk_level}</span>
                        </div>
                        <div className="mt-1 text-[13px] text-zinc-200">Risk score {person.risk_score.toFixed(1)}</div>
                        <div className="mt-1 text-xs text-zinc-500">
                          Admin roles: {person.admin_access_count} · Providers: {person.cross_provider_access} · MFA: {person.mfa_status}
                        </div>
                        {person.top_risk_factor ? (
                          <div className="mt-1 text-xs text-zinc-400">{person.top_risk_factor}</div>
                        ) : null}
                      </li>
                    ))
                  )}
                </ul>
              </div>

              <div className="space-y-4">
                <div className="rounded-lg border border-zinc-900 bg-black/50 p-4">
                  <div className="text-xs uppercase tracking-wide text-zinc-500">MFA by provider</div>
                  <ul className="mt-3 space-y-2 text-xs text-zinc-300">
                    {Object.entries(identity.mfa_compliance_by_provider).map(([provider, stats]) => (
                      <li key={provider} className="flex items-center justify-between rounded-md border border-zinc-900 bg-black/40 px-3 py-2">
                        <span className="font-medium text-zinc-100">{provider}</span>
                        <span>
                          {stats.compliance_rate.toFixed(1)}% · {formatInteger(stats.mfa_enabled_users)}/{formatInteger(stats.total_users)}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="rounded-lg border border-zinc-900 bg-black/50 p-4">
                  <div className="text-xs uppercase tracking-wide text-zinc-500">Privilege anomalies</div>
                  <ul className="mt-3 space-y-2 text-xs text-zinc-300">
                    {identity.privilege_anomalies.slice(0, 4).map((anomaly) => (
                      <li key={`${anomaly.type}-${anomaly.principal_id}`} className="rounded-md border border-zinc-900 bg-black/40 p-3">
                        <div className="flex items-center justify-between text-[11px] uppercase tracking-wide text-zinc-500">
                          <span>{anomaly.type.replace(/_/g, " ")}</span>
                          <span className={riskBadgeClass(anomaly.risk_level)}>{anomaly.risk_level}</span>
                        </div>
                        <div className="mt-1 text-zinc-200">{anomaly.description}</div>
                        <div className="mt-1 text-[11px] text-zinc-500">{anomaly.recommendation}</div>
                      </li>
                    ))}
                    {identity.privilege_anomalies.length === 0 ? (
                      <li className="text-zinc-500">No anomalies detected.</li>
                    ) : null}
                  </ul>
                </div>
              </div>
            </div>

            {filteredDrilldownIdentities.length ? (
              <div className="rounded-lg border border-zinc-900 bg-black/60 p-4">
                <div className="text-xs uppercase tracking-wide text-zinc-500">Identity drill-down</div>
                {riskFilter !== "all" ? (
                  <div className="mt-1 text-[11px] text-zinc-500">
                    Showing identities with {riskFilter} risk level
                  </div>
                ) : null}
                <div className="mt-4 grid gap-4 lg:grid-cols-3">
                  <div className="space-y-2">
                    {filteredDrilldownIdentities.map((detail) => {
                      const isActive = detail.principal_id === selectedDrilldown?.principal_id;
                      return (
                        <button
                          key={detail.principal_id}
                          type="button"
                          onClick={() => setSelectedIdentity(detail.principal_id)}
                          className={cn(
                            "w-full rounded-md border px-3 py-2 text-left text-xs transition",
                            isActive
                              ? "border-zinc-500 bg-zinc-900 text-zinc-100"
                              : "border-zinc-900 bg-black/40 text-zinc-400 hover:border-zinc-700 hover:text-zinc-100",
                          )}
                        >
                          <div className="flex items-center justify-between">
                            <span>{detail.display_name ?? detail.email ?? detail.principal_id.slice(0, 8)}</span>
                            <span className={riskBadgeClass(detail.risk_level)}>{detail.risk_level}</span>
                          </div>
                          <div className="mt-1 text-[11px] text-zinc-500">
                            Providers: {detail.providers.join(", ")} · Risk {detail.risk_score.toFixed(1)}
                          </div>
                        </button>
                      );
                    })}
                  </div>

                  <div className="rounded-md border border-zinc-900 bg-black/40 p-3">
                    <div className="text-[11px] uppercase tracking-wide text-zinc-500">Permissions</div>
                    <ul className="mt-2 space-y-1 text-xs text-zinc-300">
                      {selectedDrilldown?.permissions.length ? (
                        selectedDrilldown.permissions.slice(0, 8).map((permission, index) => (
                          <li key={`${permission.provider}-${permission.permission}-${index}`} className="flex justify-between">
                            <span>
                              {permission.provider} · {permission.permission}
                            </span>
                            {permission.is_admin ? <span className="text-red-400">admin</span> : null}
                          </li>
                        ))
                      ) : (
                        <li className="text-zinc-500">No permissions recorded.</li>
                      )}
                    </ul>
                  </div>

                  <div className="rounded-md border border-zinc-900 bg-black/40 p-3">
                    <div className="text-[11px] uppercase tracking-wide text-zinc-500">Open findings & actions</div>
                    <ul className="mt-2 space-y-1 text-xs text-zinc-300">
                      {selectedDrilldown?.open_findings.length ? (
                        selectedDrilldown.open_findings.map((finding) => (
                          <li key={finding.finding_id}>
                            <span className={riskBadgeClass(finding.severity)}>{finding.severity}</span> · {finding.title}
                          </li>
                        ))
                      ) : (
                        <li className="text-zinc-500">No open findings for this identity.</li>
                      )}
                    </ul>
                    <div className="mt-3 text-[11px] uppercase tracking-wide text-zinc-500">Recommended actions</div>
                    <ul className="mt-1 space-y-1 text-xs text-zinc-300">
                      {selectedDrilldown?.recommended_actions.length ? (
                        selectedDrilldown.recommended_actions.map((action, index) => (
                          <li key={`${selectedDrilldown.principal_id}-action-${index}`}>{action}</li>
                        ))
                      ) : (
                        <li className="text-zinc-500">No recommended actions recorded.</li>
                      )}
                    </ul>
                  </div>
                </div>
              </div>
            ) : (
              <div className="rounded-lg border border-dashed border-zinc-900 bg-black/40 p-6 text-sm text-zinc-500">
                No drill-down data for the selected risk filter.
              </div>
            )}

            {filteredRemediationQueue.length ? (
              <div className="rounded-lg border border-zinc-900 bg-black/60 p-4">
                <div className="text-xs uppercase tracking-wide text-zinc-500">Remediation queue</div>
                <ul className="mt-3 space-y-2 text-xs text-zinc-300">
                  {filteredRemediationQueue.slice(0, 6).map((item, index) => (
                    <li key={`${item.principal_id}-${index}`} className="rounded-md border border-zinc-900 bg-black/40 p-3">
                      <div className="flex items-center justify-between text-[11px] uppercase tracking-wide text-zinc-500">
                        <span>{item.summary}</span>
                        <span className={riskBadgeClass(item.priority)}>{item.priority}</span>
                      </div>
                      <div className="mt-1 text-zinc-200">{item.recommended_action}</div>
                      {item.evidence.length ? (
                        <div className="mt-1 text-[11px] text-zinc-500">
                          Evidence: {item.evidence.join(", ")}
                        </div>
                      ) : null}
                    </li>
                  ))}
                </ul>
              </div>
            ) : (
              <div className="rounded-lg border border-dashed border-zinc-900 bg-black/40 p-6 text-sm text-zinc-500">
                No remediation actions match the current filter.
              </div>
            )}
          </div>
        )}
      </Panel>

      <Panel
        title="Risk heatmap"
        description="Risk concentration by provider and resource type with improvement suggestions."
      >
        {isLoadingDashboard ? (
          <PanelSkeleton rows={4} />
        ) : isDashboardError ? (
          <ErrorState message={toErrorMessage(dashboardError, "Unable to load risk heatmap data.")} />
        ) : !heatmap ? (
          <p className="text-sm text-zinc-500">Heatmap data is unavailable until metrics are collected.</p>
        ) : (
          <div className="grid gap-4 lg:grid-cols-2">
            <div className="rounded-lg border border-zinc-900 bg-black/50 p-4">
              <div className="text-xs uppercase tracking-wide text-zinc-500">High-risk areas</div>
              <ul className="mt-3 space-y-2 text-sm text-zinc-200">
                {heatmap.high_risk_areas.length === 0 ? (
                  <li className="text-zinc-500">No high-risk clusters detected.</li>
                ) : (
                  heatmap.high_risk_areas.map((area) => (
                    <li key={`${area.provider}-${area.resource_type}`} className="rounded-md border border-zinc-900 bg-black/40 p-3">
                      <div className="text-xs uppercase tracking-wide text-zinc-500">
                        {area.provider} · {area.resource_type}
                      </div>
                      <div className="mt-1 text-[13px] text-zinc-100">Risk score {area.risk_score.toFixed(1)}</div>
                      <div className="mt-1 text-xs text-zinc-500">Open findings: {formatInteger(area.finding_count)}</div>
                    </li>
                  ))
                )}
              </ul>
            </div>

            <div className="rounded-lg border border-zinc-900 bg-black/50 p-4">
              <div className="text-xs uppercase tracking-wide text-zinc-500">Improvement opportunities</div>
              <ul className="mt-3 space-y-2 text-sm text-zinc-200">
                {heatmap.improvement_opportunities.length === 0 ? (
                  <li className="text-zinc-500">No prioritized improvements suggested.</li>
                ) : (
                  heatmap.improvement_opportunities.map((item) => (
                    <li key={item.area} className="rounded-md border border-zinc-900 bg-black/40 p-3">
                      <div className="flex items-center justify-between text-xs uppercase tracking-wide text-zinc-500">
                        <span>{item.area}</span>
                        <span className={riskBadgeClass(item.impact)}>{item.impact}</span>
                      </div>
                      <div className="mt-1 text-[13px] text-zinc-100">
                        Current {item.current_risk.toFixed(1)} · Potential reduction {item.potential_reduction.toFixed(1)}
                      </div>
                    </li>
                  ))
                )}
              </ul>
            </div>
          </div>
        )}
      </Panel>
    </div>
  );
}

function formatTimestamp(value?: string): string {
  if (!value) {
    return "—";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
}

function toErrorMessage(error: unknown, fallback: string): string {
  if (!error) {
    return fallback;
  }
  if (error instanceof Error) {
    return error.message;
  }
  if (typeof error === "string") {
    return error;
  }
  try {
    return JSON.stringify(error);
  } catch (
    _error
  ) {
    return fallback;
  }
}

function PanelSkeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: rows }).map((_, index) => (
        <div key={index} className="h-10 animate-pulse rounded-md bg-zinc-900/60" />
      ))}
    </div>
  );
}

function ExecutiveOverviewSkeleton() {
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <div className="space-y-4">
        <PanelSkeleton rows={3} />
      </div>
      <PanelSkeleton rows={3} />
    </div>
  );
}

function MetricsPanelSkeleton() {
  return <PanelSkeleton rows={4} />;
}

function IdentityPanelSkeleton() {
  return <PanelSkeleton rows={6} />;
}

function ErrorState({ message }: { message: string }) {
  return (
    <div className="rounded-md border border-red-900/40 bg-red-950/20 p-4 text-sm text-red-200">
      {message}
    </div>
  );
}

type MetricStatProps = {
  label: string;
  value: number;
  formatter?: (value: number) => string;
  description?: string;
};

function MetricStat({ label, value, formatter, description }: MetricStatProps) {
  const formatted = Number.isFinite(value)
    ? formatter
      ? formatter(value)
      : value.toLocaleString()
    : "—";

  return (
    <div className="rounded-md border border-zinc-900 bg-black/40 p-3">
      <div className="text-[10px] uppercase tracking-wide text-zinc-500">{label}</div>
      <div className="mt-1 text-lg font-semibold text-zinc-100">{formatted}</div>
      {description ? <div className="mt-1 text-[11px] text-zinc-500">{description}</div> : null}
    </div>
  );
}

function ComplianceTrendCard({ trend, timeRange }: { trend: ComplianceTrendResponse; timeRange: TimeRangeOption }) {
  const points = trend.overall;
  if (!points.length) {
    return null;
  }

  const rangeLabel: Record<TimeRangeOption, string> = {
    "7d": "7 days",
    "30d": "30 days",
    "90d": "90 days",
  };

  const values = points.map((point) => point.score);
  const minValue = Math.min(...values, 0);
  const maxValue = Math.max(...values, 100);
  const valueRange = maxValue - minValue || 1;

  const width = 100;
  const height = 40;
  const step = points.length > 1 ? width / (points.length - 1) : 0;

  const coordinates = points.map((point, index) => {
    const x = index * step;
    const normalized = (point.score - minValue) / valueRange;
    const y = height - normalized * height;
    return { x, y, ...point };
  });

  const linePath = coordinates
    .map((coord, index) => `${index === 0 ? "M" : "L"}${coord.x},${coord.y}`)
    .join(" ");

  const areaPath = [
    `M0,${height}`,
    ...coordinates.map((coord) => `L${coord.x},${coord.y}`),
    `L${coordinates[coordinates.length - 1].x},${height}`,
    "Z",
  ].join(" ");

  const earliest = points[0];
  const latest = points[points.length - 1];
  const previous = points.length > 1 ? points[points.length - 2] : null;
  const delta = latest.score - (previous?.score ?? latest.score);

  const frameworkSummaries = Object.entries(trend.frameworks || {}).filter(
    ([, series]) => series.length,
  );

  return (
    <div className="rounded-lg border border-zinc-900 bg-black/50 p-4">
      <div className="flex items-center justify-between text-xs uppercase tracking-wide text-zinc-500">
        <span>Compliance trend ({rangeLabel[timeRange]})</span>
        <span className="text-[11px] text-zinc-600">{points.length} data points</span>
      </div>
      <div className="mt-3 h-32 overflow-hidden">
        <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" className="h-full w-full">
          <defs>
            <linearGradient id="trendGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#34d399" stopOpacity="0.4" />
              <stop offset="100%" stopColor="#34d399" stopOpacity="0" />
            </linearGradient>
          </defs>
          <path d={areaPath} fill="url(#trendGradient)" stroke="none" />
          <path d={linePath} fill="none" stroke="#34d399" strokeWidth={1.5} />
          {coordinates.map((coord) => (
            <circle
              key={coord.date}
              cx={coord.x}
              cy={coord.y}
              r={1.8}
              fill="#34d399"
            >
              <title>{`${coord.date}: ${coord.score.toFixed(1)}%`}</title>
            </circle>
          ))}
        </svg>
      </div>
      <div className="mt-3 text-xs text-zinc-400">
        Latest {formatPercentage(latest.score)} ({delta >= 0 ? "+" : ""}
        {delta.toFixed(1)} vs {previous ? previous.date : earliest.date}) ·
        Range {formatPercentage(minValue)} – {formatPercentage(maxValue)}
      </div>
      {frameworkSummaries.length ? (
        <div className="mt-2 space-y-1 text-[11px] text-zinc-500">
          {frameworkSummaries.map(([framework, series]) => {
            const frameworkPoints = series as { date: string; score: number }[];
            const latestPoint = frameworkPoints[frameworkPoints.length - 1];
            const previousPoint = frameworkPoints.length > 1 ? frameworkPoints[frameworkPoints.length - 2] : null;
            const frameworkDelta = latestPoint && previousPoint ? latestPoint.score - previousPoint.score : 0;

            return (
              <div key={framework} className="flex items-center justify-between">
                <span>{framework}</span>
                <span>
                  {latestPoint ? formatPercentage(latestPoint.score) : "—"}
                  {latestPoint && previousPoint ? ` (${frameworkDelta >= 0 ? "+" : ""}${frameworkDelta.toFixed(1)})` : ""}
                </span>
              </div>
            );
          })}
        </div>
      ) : null}
    </div>
  );
}

function formatInteger(value: number): string {
  return Number.isFinite(value) ? Math.round(value).toLocaleString() : "—";
}

function formatPercentage(value: number): string {
  return Number.isFinite(value) ? `${value.toFixed(1)}%` : "—";
}

function riskBadgeClass(level: string): string {
  switch (level?.toLowerCase()) {
    case "critical":
      return "text-red-400";
    case "high":
      return "text-orange-400";
    case "medium":
      return "text-amber-300";
    case "low":
    case "minimal":
      return "text-emerald-300";
    default:
      return "text-zinc-300";
  }
}
