"use client";

import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";

import { apiGet, apiPost } from "@/lib/api";
import {
  IntegrationIssue,
  IntegrationIssueHistory,
  IntegrationAdminOverview,
  IntegrationStatus,
  IntegrationSyncJob,
  IntegrationSyncStatus,
} from "@/lib/types";
import { cn } from "@/lib/utils";
import { Panel } from "@/components/ui/panel";

type DashboardEntry = {
  key: string;
  integration: string;
  scope: string;
  statusLabel: string;
  severity: "ok" | "warning" | "critical";
  metadata: Record<string, unknown>;
  lastTimestamp: Date | null;
  ageSeconds: number | null;
  isStale: boolean;
  issues: IntegrationIssue[];
  primaryIssue: IntegrationIssue | null;
  nextScheduled: Date | null;
  durationAverageSeconds: number | null;
  durationSamples: number[];
  recentErrors: Array<Record<string, unknown>>;
  confidence: string | null;
  statusConfidence: string | null;
  staleThresholdHours: number | null;
  errorCount24h: number;
};

const STALE_OPTIONS: Array<{ label: string; value: number }> = [
  { label: "15m", value: 900 },
  { label: "1h", value: 3600 },
  { label: "6h", value: 21_600 },
  { label: "Off", value: 0 },
];

const SEVERITY_FILTERS: Array<{ label: string; value: "all" | "ok" | "warning" | "critical" }> = [
  { label: "All", value: "all" },
  { label: "Critical", value: "critical" },
  { label: "Warning", value: "warning" },
  { label: "Healthy", value: "ok" },
];

const LOOKBACK_OPTIONS: Array<{ label: string; value: number | null }> = [
  { label: "Auto", value: null },
  { label: "30m", value: 30 },
  { label: "1h", value: 60 },
  { label: "6h", value: 360 },
];

const TREND_WINDOWS: Array<{ label: string; value: number }> = [
  { label: "6h", value: 6 },
  { label: "24h", value: 24 },
  { label: "7d", value: 168 },
];

const severityStyles: Record<"ok" | "warning" | "critical", string> = {
  ok: "bg-emerald-500/10 text-emerald-300 border-emerald-500/40",
  warning: "bg-amber-500/10 text-amber-300 border-amber-500/40",
  critical: "bg-rose-500/10 text-rose-300 border-rose-500/40",
};

const severityOrder: Record<string, number> = {
  critical: 3,
  warning: 2,
  ok: 1,
};

const severityLabels: Record<string, string> = {
  critical: "Critical",
  warning: "Warning",
  ok: "Healthy",
};

function parseTimestamp(value: unknown): Date | null {
  if (typeof value !== "string" || !value) {
    return null;
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function formatTimestamp(date: Date | null | undefined): string {
  if (!date) {
    return "Never";
  }
  return date.toLocaleString();
}

function formatAge(seconds: number | null): string {
  if (seconds === null) {
    return "n/a";
  }
  const minutes = Math.floor(seconds / 60);
  const remaining = Math.floor(seconds % 60);
  if (minutes <= 0 && remaining <= 0) {
    return "<1s";
  }
  if (minutes < 60) {
    return `${minutes}m ${remaining}s`;
  }
  const hours = Math.floor(minutes / 60);
  const mins = minutes % 60;
  return `${hours}h ${mins}m`;
}

function formatDurationSeconds(seconds: number | null | undefined): string {
  if (seconds == null) {
    return "n/a";
  }
  if (seconds < 60) {
    return `${Math.round(seconds)}s`;
  }
  const minutes = seconds / 60;
  if (minutes < 60) {
    return `${Math.round(minutes)}m`;
  }
  const hours = minutes / 60;
  return `${hours.toFixed(hours >= 10 ? 0 : 1)}h`;
}

function formatRange(startStr: string, endStr: string): string {
  const start = parseTimestamp(startStr);
  const end = parseTimestamp(endStr);
  if (!start || !end) {
    return startStr;
  }
  const sameDay = start.toDateString() === end.toDateString();
  if (sameDay) {
    return `${start.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })} – ${end.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
  }
  return `${start.toLocaleString()} → ${end.toLocaleString()}`;
}

function mapSeverity(statusLabel: string, isStale: boolean): "ok" | "warning" | "critical" {
  if (statusLabel === "error") {
    return "critical";
  }
  if (statusLabel === "skipped" || isStale) {
    return "warning";
  }
  return "ok";
}

function deriveConfidenceFromStatus(statusLabel: string): string {
  const normalized = (statusLabel ?? "").toLowerCase();
  if (normalized === "fresh" || normalized === "ok") {
    return "high";
  }
  if (normalized === "stale" || normalized === "warning") {
    return "medium";
  }
  if (normalized === "error" || normalized === "critical" || normalized === "skipped") {
    return "low";
  }
  return "unknown";
}

function primaryIssueForScope(issues: IntegrationIssue[]): IntegrationIssue | null {
  if (!issues.length) {
    return null;
  }
  const sorted = [...issues].sort((a, b) => (severityOrder[b.severity] ?? 0) - (severityOrder[a.severity] ?? 0));
  return sorted[0] ?? null;
}

export function IntegrationSyncDashboard() {
  const [staleThreshold, setStaleThreshold] = useState<number>(3600);
  const [integrationFilter, setIntegrationFilter] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<"all" | "ok" | "warning" | "critical">("all");
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [retryLookback, setRetryLookback] = useState<number | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [trendWindowHours, setTrendWindowHours] = useState<number>(24);
  const [pollingTaskId, setPollingTaskId] = useState<string | null>(null);

  const {
    data: statuses = [],
    isLoading,
    isError,
    error,
    refetch,
    isFetching,
    dataUpdatedAt,
  } = useQuery({
    queryKey: ["integrationSyncStatus"],
    queryFn: () => apiGet<IntegrationStatus[]>("/integrations/status"),
    refetchInterval: 60_000,
  });

  const {
    data: issues = [],
    isFetching: isFetchingIssues,
    refetch: refetchIssues,
  } = useQuery({
    queryKey: ["integrationSyncIssues", staleThreshold],
    queryFn: () => {
      const params = staleThreshold ? `?stale_seconds=${staleThreshold}` : "";
      return apiGet<IntegrationIssue[]>(`/integrations/status/issues${params}`);
    },
    refetchInterval: 60_000,
  });

  const {
    data: adminOverview = [],
    isFetching: isFetchingOverview,
  } = useQuery({
    queryKey: ["integrationAdminOverview"],
    queryFn: () => apiGet<IntegrationAdminOverview[]>("/integrations/admin/overview"),
    refetchInterval: 60_000,
  });

  const issuesByKey = useMemo(() => {
    const map = new Map<string, IntegrationIssue[]>();
    for (const issue of issues) {
      const key = `${issue.integration}:${issue.scope}`;
      const existing = map.get(key) ?? [];
      existing.push(issue);
      map.set(key, existing);
    }
    return map;
  }, [issues]);

  const overviewByKey = useMemo(() => {
    const map = new Map<string, IntegrationAdminOverview>();
    for (const item of adminOverview) {
      const key = `${item.integration}:${item.scope}`;
      map.set(key, item);
    }
    return map;
  }, [adminOverview]);

  const entries = useMemo<DashboardEntry[]>(() => {
    const now = Date.now();
    const out: DashboardEntry[] = [];
    for (const status of statuses) {
      const key = `${status.integration}:${status.scope}`;
      const metadata = (status.metadata ?? {}) as Record<string, unknown>;
      const issuesForScope = issuesByKey.get(key) ?? [];
      const primaryIssue = primaryIssueForScope(issuesForScope);
      const statusLabelRaw = (primaryIssue?.status ?? metadata?.last_status ?? "unknown") as string;
      const statusLabel = (statusLabelRaw || "unknown").toLowerCase();
      const lastTimestamp = parseTimestamp(
        primaryIssue?.last_timestamp ?? status.last_timestamp ?? (metadata?.last_sync_at as string | undefined),
      );
      const ageSeconds = primaryIssue?.age_seconds ?? (lastTimestamp ? Math.max((now - lastTimestamp.getTime()) / 1000, 0) : null);
      const isStale = Boolean(
        primaryIssue?.issue_type === "stale" || (staleThreshold > 0 && ageSeconds !== null && ageSeconds > staleThreshold),
      );
      const severity = (primaryIssue?.severity as "ok" | "warning" | "critical" | undefined) ?? mapSeverity(statusLabel, isStale);
      const overview = overviewByKey.get(key);
      const nextScheduled = parseTimestamp(overview?.next_scheduled_sync_at ?? null);
      const durationAverageSeconds = overview?.duration_average_seconds ?? null;
      const durationSamples = Array.isArray(overview?.duration_samples) ? overview.duration_samples : [];
      const recentErrors = Array.isArray(overview?.recent_errors) ? overview.recent_errors : [];
      const confidence = overview?.confidence ?? null;
      const staleThresholdHours = typeof overview?.stale_threshold_hours === "number"
        ? overview.stale_threshold_hours
        : typeof overview?.metadata?.stale_threshold_hours === "number"
          ? (overview.metadata.stale_threshold_hours as number)
          : null;
      const issuesCounts = (overview?.metadata?.issues_last_24h as Record<string, number> | undefined) ?? {};
      const errorCountFromMetadata = typeof overview?.metadata?.error_count_24h === "number"
        ? (overview.metadata.error_count_24h as number)
        : null;
      const errorCount24h = errorCountFromMetadata ?? Object.entries(issuesCounts).reduce((acc, [severityLabel, count]) => {
        const normalized = severityLabel.toLowerCase();
        const numeric = typeof count === "number" ? count : Number(count ?? 0);
        if (Number.isNaN(numeric)) {
          return acc;
        }
        if (normalized.includes("error") || normalized.includes("critical")) {
          return acc + numeric;
        }
        return acc;
      }, 0);
      const statusConfidence = overview?.metadata?.status_confidence
        ? String(overview.metadata.status_confidence)
        : deriveConfidenceFromStatus(statusLabel);

      out.push({
        key,
        integration: status.integration,
        scope: status.scope,
        statusLabel,
        severity,
        metadata,
        lastTimestamp,
        ageSeconds,
        isStale,
        issues: issuesForScope,
        primaryIssue,
        nextScheduled,
        durationAverageSeconds,
        durationSamples,
        recentErrors,
        confidence,
        statusConfidence,
        staleThresholdHours,
        errorCount24h,
      });
    }
    return out;
  }, [statuses, issuesByKey, staleThreshold, overviewByKey]);

  const filteredEntries = useMemo(() => {
    const needle = integrationFilter.trim().toLowerCase();
    return entries.filter((entry) => {
      if (needle) {
        if (!entry.integration.toLowerCase().includes(needle) && !entry.scope.toLowerCase().includes(needle)) {
          return false;
        }
      }
      if (severityFilter !== "all" && entry.severity !== severityFilter) {
        return false;
      }
      return true;
    });
  }, [entries, integrationFilter, severityFilter]);

  const sortedEntries = useMemo(() => {
    const rank: Record<"critical" | "warning" | "ok", number> = {
      critical: 3,
      warning: 2,
      ok: 1,
    };

    return [...filteredEntries].sort((a, b) => {
      const severityDelta = (rank[b.severity] ?? 0) - (rank[a.severity] ?? 0);
      if (severityDelta !== 0) {
        return severityDelta;
      }

      if (a.isStale !== b.isStale) {
        return a.isStale ? -1 : 1;
      }

      const ageA = a.ageSeconds ?? Number.POSITIVE_INFINITY;
      const ageB = b.ageSeconds ?? Number.POSITIVE_INFINITY;
      return ageB - ageA;
    });
  }, [filteredEntries]);

  const priorityEntries = useMemo(() => {
    return sortedEntries.filter((entry) => entry.severity !== "ok" || entry.isStale).slice(0, 5);
  }, [sortedEntries]);

  const counts = useMemo(() => {
    const tally = { total: sortedEntries.length, critical: 0, warning: 0, ok: 0, stale: 0 };
    for (const entry of sortedEntries) {
      tally[entry.severity] += 1;
      if (entry.isStale) {
        tally.stale += 1;
      }
    }
    return tally;
  }, [sortedEntries]);

  const selectedEntry = useMemo(
    () => sortedEntries.find((entry) => entry.key === selectedKey) ?? null,
    [sortedEntries, selectedKey],
  );

  const historyData = useMemo<IntegrationIssueHistory>(() => history ?? { events: [], buckets: [] }, [history]);

  const historyTotals = useMemo(() => {
    const totals: Record<string, number> = {};
    for (const event of historyData.events) {
      const key = event.severity.toLowerCase();
      totals[key] = (totals[key] ?? 0) + 1;
    }
    return totals;
  }, [historyData.events]);

  const recentEvents = useMemo(() => {
    return [...historyData.events].reverse().slice(0, 20);
  }, [historyData.events]);

  const trendBuckets = historyData.buckets;

  useEffect(() => {
    if (!pollingTaskId || !taskStatus?.finished) {
      return;
    }
    const resultText =
      taskStatus.result && typeof taskStatus.result === "object"
        ? JSON.stringify(taskStatus.result)
        : String(taskStatus.result ?? "");
    const completionMessage = resultText ? `Sync ${taskStatus.status.toLowerCase()}: ${resultText}` : `Sync ${taskStatus.status.toLowerCase()}`;
    setFeedback(completionMessage);
    setPollingTaskId(null);
    refetch();
    refetchIssues();
  }, [pollingTaskId, taskStatus, refetch, refetchIssues]);

  const {
    data: history,
    isFetching: isFetchingHistory,
  } = useQuery({
    queryKey: ["integrationSyncHistory", selectedEntry?.key, trendWindowHours],
    queryFn: async () => {
      if (!selectedEntry) {
        return { events: [], buckets: [] } satisfies IntegrationIssueHistory;
      }
      const params = new URLSearchParams({
        integration: selectedEntry.integration,
        scope: selectedEntry.scope,
        hours: String(trendWindowHours),
        bucket_minutes: "60",
        limit: "200",
      });
      return apiGet<IntegrationIssueHistory>(`/integrations/status/issues/history?${params.toString()}`);
    },
    enabled: Boolean(selectedEntry),
    refetchInterval: selectedEntry ? 60_000 : false,
  });

  const {
    data: taskStatus,
  } = useQuery({
    queryKey: ["integrationSyncTaskStatus", pollingTaskId],
    queryFn: () => apiGet<IntegrationSyncStatus>(`/integrations/sync/${pollingTaskId}`),
    enabled: Boolean(pollingTaskId),
    refetchInterval: pollingTaskId ? 5_000 : false,
  });

  const lastUpdated = useMemo(() => {
    if (!dataUpdatedAt) {
      return "—";
    }
    const ts = new Date(dataUpdatedAt);
    return ts.toLocaleTimeString();
  }, [dataUpdatedAt]);

  const retryMutation = useMutation({
    mutationFn: async (params: { integration: string; lookbackMinutes?: number | null }) =>
      apiPost<IntegrationSyncJob>("/integrations/sync", {
        integration: params.integration,
        lookback_minutes: params.lookbackMinutes ?? undefined,
      }),
    onSuccess: (job) => {
      setFeedback(`Queued ${job.integration} sync (task ${job.task_id})`);
      setPollingTaskId(job.task_id);
    },
    onError: (err: unknown) => {
      const message = err instanceof Error ? err.message : "Failed to queue sync";
      setFeedback(message);
    },
  });

  const handleRowSelect = (entry: DashboardEntry) => {
    setSelectedKey(entry.key === selectedKey ? null : entry.key);
    setFeedback(null);
    setPollingTaskId(null);
  };

  const handleRetry = () => {
    if (!selectedEntry) {
      return;
    }
    setFeedback(null);
    retryMutation.mutate({
      integration: selectedEntry.integration,
      lookbackMinutes: retryLookback ?? undefined,
    });
  };

  return (
    <div className="space-y-6">
      <Panel
        title="Integration Sync Health"
        description="Track freshness and error states across external telemetry integrations."
        action={
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
            <div className="flex items-center gap-2">
              <label className="text-xs text-zinc-500" htmlFor="integration-filter">Filter:</label>
              <input
                id="integration-filter"
                type="search"
                value={integrationFilter}
                onChange={(event) => setIntegrationFilter(event.target.value)}
                placeholder="Integration or scope"
                className="w-40 rounded-md border border-zinc-800 bg-zinc-950 px-2 py-1 text-xs text-zinc-100 focus:border-zinc-600 focus:outline-none"
              />
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-zinc-500">Severity:</span>
              <div className="flex gap-1">
                {SEVERITY_FILTERS.map((option) => {
                  const active = severityFilter === option.value;
                  return (
                    <button
                      key={option.value}
                      type="button"
                      onClick={() => setSeverityFilter(option.value)}
                      className={cn(
                        "rounded-md border px-2 py-1 text-xs transition",
                        active
                          ? "border-zinc-100 bg-zinc-800 text-zinc-100"
                          : "border-zinc-800 bg-zinc-900 text-zinc-400 hover:border-zinc-600 hover:text-zinc-200",
                      )}
                    >
                      {option.label}
                    </button>
                  );
                })}
              </div>
            </div>
            <div className="flex items-center gap-2">
              <span className="hidden text-xs text-zinc-500 sm:block">Stale threshold:</span>
              <div className="flex gap-1">
                {STALE_OPTIONS.map((option) => {
                  const active = staleThreshold === option.value;
                  return (
                    <button
                      key={option.value}
                      type="button"
                      onClick={() => setStaleThreshold(option.value)}
                      className={cn(
                        "rounded-md border px-2 py-1 text-xs transition",
                        active
                          ? "border-zinc-100 bg-zinc-800 text-zinc-100"
                          : "border-zinc-800 bg-zinc-900 text-zinc-400 hover:border-zinc-600 hover:text-zinc-200",
                      )}
                    >
                      {option.label}
                    </button>
                  );
                })}
              </div>
            </div>
            <button
              type="button"
              onClick={() => refetch()}
              className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-1 text-xs text-zinc-200 hover:border-zinc-500"
              disabled={isFetching || isFetchingIssues || isFetchingOverview}
            >
              {isFetching || isFetchingIssues || isFetchingOverview ? "Refreshing…" : "Refresh"}
            </button>
          </div>
        }
      >
        {isLoading ? (
          <p className="text-sm text-zinc-400">Loading integration status…</p>
        ) : isError ? (
          <p className="text-sm text-rose-400">
            {(error as Error)?.message ?? "Unable to load integration status."}
          </p>
        ) : (
          <div className="space-y-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex gap-3 text-xs text-zinc-400">
                <span>Total: {counts.total}</span>
                <span>Critical: {counts.critical}</span>
                <span>Warning: {counts.warning}</span>
                <span>Stale: {counts.stale}</span>
              </div>
              <div className="text-xs text-zinc-500">Last updated {lastUpdated}</div>
            </div>

            {priorityEntries.length ? (
              <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-100 shadow-inner">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h3 className="text-sm font-semibold uppercase tracking-wide text-rose-200">Attention needed</h3>
                    <p className="text-xs text-rose-100/80">
                      Critical or stale integrations require action. Review the most recent issues below.
                    </p>
                  </div>
                  <span className="text-[11px] uppercase text-rose-200/80">{priorityEntries.length} affected scope{priorityEntries.length === 1 ? "" : "s"}</span>
                </div>
                <ul className="mt-3 space-y-2">
                  {priorityEntries.map((entry) => (
                    <li
                      key={`priority-${entry.key}`}
                      className="rounded-md border border-rose-500/40 bg-black/40 px-3 py-2"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                        <div className="font-medium text-rose-100">
                          {entry.integration}
                          <span className="ml-2 text-rose-200/70">{entry.scope || "default"}</span>
                        </div>
                        <span
                          className={cn(
                            "inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold capitalize",
                            severityStyles[entry.severity],
                          )}
                        >
                          {entry.primaryIssue?.issue_type ?? entry.statusLabel}
                        </span>
                      </div>
                      <div className="mt-1 flex flex-wrap items-center gap-3 text-[11px] text-rose-100/80">
                        <span>Last sync {formatTimestamp(entry.lastTimestamp)}</span>
                        <span>Age {formatAge(entry.ageSeconds)}</span>
                        <span>Errors 24h {entry.errorCount24h}</span>
                      </div>
                      <button
                        type="button"
                        onClick={() => setSelectedKey(entry.key)}
                        className="mt-2 inline-flex items-center text-[11px] font-semibold uppercase tracking-wide text-rose-200 hover:text-rose-100"
                      >
                        View details
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}

            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-zinc-800 text-left text-xs text-zinc-300">
                <thead>
                  <tr className="bg-zinc-950/60">
                    <th scope="col" className="px-3 py-2 font-semibold">Integration</th>
                    <th scope="col" className="px-3 py-2 font-semibold">Scope</th>
                    <th scope="col" className="px-3 py-2 font-semibold">Severity</th>
                    <th scope="col" className="px-3 py-2 font-semibold">Status</th>
                    <th scope="col" className="px-3 py-2 font-semibold">Last Sync</th>
                    <th scope="col" className="px-3 py-2 font-semibold">Next Sync</th>
                    <th scope="col" className="px-3 py-2 font-semibold">Age</th>
                    <th scope="col" className="px-3 py-2 font-semibold">Confidence</th>
                    <th scope="col" className="px-3 py-2 font-semibold">Errors (24h)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-900">
                  {sortedEntries.map((entry) => {
                    const selected = entry.key === selectedKey;
                    return (
                      <tr
                        key={entry.key}
                        className={cn(
                          "cursor-pointer transition",
                          entry.severity === "critical"
                            ? "bg-rose-500/5 hover:bg-rose-500/10"
                            : entry.severity === "warning"
                            ? "bg-amber-500/5 hover:bg-amber-500/10"
                            : "hover:bg-zinc-900/80",
                          selected && "outline outline-1 outline-zinc-200",
                        )}
                        onClick={() => handleRowSelect(entry)}
                      >
                        <td className="px-3 py-2 font-medium text-zinc-100">
                          {entry.integration}
                        </td>
                        <td className="px-3 py-2">{entry.scope || "default"}</td>
                        <td className="px-3 py-2">
                          <span
                            className={cn(
                              "inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium capitalize",
                              severityStyles[entry.severity],
                            )}
                          >
                            {entry.severity}
                          </span>
                        </td>
                        <td className="px-3 py-2 capitalize">
                          {entry.primaryIssue?.issue_type ?? entry.statusLabel.replace(/_/g, " ")}
                        </td>
                        <td className="px-3 py-2">{formatTimestamp(entry.lastTimestamp)}</td>
                        <td className="px-3 py-2">{formatTimestamp(entry.nextScheduled)}</td>
                        <td className="px-3 py-2">{formatAge(entry.ageSeconds)}</td>
                        <td className="px-3 py-2 capitalize">{entry.confidence ?? "unknown"}</td>
                        <td className="px-3 py-2">{entry.errorCount24h}</td>
                      </tr>
                    );
                  })}
                  {sortedEntries.length === 0 ? (
                    <tr>
                      <td colSpan={9} className="px-3 py-6 text-center text-sm text-zinc-500">
                        No integration sync state matches the selected filters.
                      </td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>

            {selectedEntry ? (
              <div className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-4 text-sm text-zinc-200">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                  <div>
                    <h3 className="text-base font-semibold text-zinc-100">
                      {selectedEntry.integration} · {selectedEntry.scope || "default"}
                    </h3>
                    <p className="text-xs text-zinc-400">
                      Last sync {formatTimestamp(selectedEntry.lastTimestamp)} • Age {formatAge(selectedEntry.ageSeconds)}
                    </p>
                    <p className="mt-1 text-[11px] text-zinc-500">
                      Confidence {selectedEntry.confidence ?? "unknown"} • Status confidence {selectedEntry.statusConfidence ?? "unknown"}
                    </p>
                  </div>
                  <div className="flex flex-col items-start gap-2 sm:items-end">
                    <span
                      className={cn(
                        "inline-flex items-center rounded-full border px-2 py-0.5 text-xs capitalize",
                        severityStyles[selectedEntry.severity],
                      )}
                    >
                      {selectedEntry.primaryIssue?.issue_type ?? selectedEntry.statusLabel}
                    </span>
                    <div className="flex flex-wrap items-center gap-2">
                      <select
                        value={retryLookback ?? "auto"}
                        onChange={(event) => {
                          const value = event.target.value;
                          setRetryLookback(value === "auto" ? null : Number(value));
                        }}
                        className="rounded-md border border-zinc-800 bg-zinc-950 px-2 py-1 text-xs text-zinc-100 focus:border-zinc-600 focus:outline-none"
                        disabled={!selectedEntry.integration.includes("sentinelone")}
                        aria-label="Select sync retry lookback"
                      >
                        {LOOKBACK_OPTIONS.map((option) => (
                          <option key={option.label} value={option.value === null ? "auto" : option.value}>
                            {option.label}
                          </option>
                        ))}
                      </select>
                      <button
                        type="button"
                        onClick={handleRetry}
                        className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-1 text-xs text-zinc-200 hover:border-zinc-500 disabled:cursor-not-allowed disabled:opacity-60"
                        disabled={retryMutation.isLoading}
                      >
                        {retryMutation.isLoading ? "Queuing…" : "Retry sync"}
                      </button>
                      {pollingTaskId ? (
                        <span className="text-[11px] text-zinc-400">
                          Sync {(taskStatus?.status ?? "queued").toLowerCase()}
                          {taskStatus?.finished ? " · complete" : ""}
                        </span>
                      ) : null}
                    </div>
                    {feedback ? (
                      <p className="text-[11px] text-emerald-300">{feedback}</p>
                    ) : null}
                  </div>
                </div>

                {selectedEntry.primaryIssue ? (
                  <div className="mt-4 rounded-md border border-rose-500/30 bg-rose-500/5 p-3 text-sm text-rose-100">
                    <p className="font-semibold">{selectedEntry.primaryIssue.message}</p>
                    <p className="mt-1 text-xs text-rose-200/80">
                      Observed {formatTimestamp(parseTimestamp(selectedEntry.primaryIssue.observed_at))} • Type {selectedEntry.primaryIssue.issue_type}
                    </p>
                  </div>
                ) : (
                  <p className="mt-4 text-sm text-zinc-400">No active issues detected for this scope.</p>
                )}

                <div className="mt-4 grid gap-3 text-[11px] text-zinc-400 md:grid-cols-2">
                  <span>Next scheduled: {formatTimestamp(selectedEntry.nextScheduled)}</span>
                  <span>Stale threshold: {selectedEntry.staleThresholdHours ?? "n/a"}h</span>
                  <span>Errors last 24h: {selectedEntry.errorCount24h}</span>
                  <span>Duration avg: {formatDurationSeconds(selectedEntry.durationAverageSeconds)}</span>
                </div>

                <div className="mt-4 space-y-3">
                  <details open className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3">
                    <summary className="cursor-pointer text-xs font-semibold uppercase tracking-wide text-zinc-400">
                      Active issues ({selectedEntry.issues.length})
                    </summary>
                    <div className="mt-2 space-y-2 text-xs text-zinc-200">
                      {selectedEntry.issues.length ? (
                        selectedEntry.issues.map((issue) => (
                          <div key={`${issue.issue_type}-${issue.observed_at}`} className="rounded-md border border-zinc-800 bg-zinc-950/70 p-2">
                            <div className="flex items-center justify-between text-[11px] uppercase text-zinc-500">
                              <span>{issue.issue_type}</span>
                              <span>{formatTimestamp(parseTimestamp(issue.observed_at))}</span>
                            </div>
                            <p className="mt-1 text-zinc-300">{issue.message}</p>
                          </div>
                        ))
                      ) : (
                        <p className="text-zinc-500">No active issues recorded.</p>
                      )}
                    </div>
                  </details>

                  <details className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3">
                    <summary className="cursor-pointer text-xs font-semibold uppercase tracking-wide text-zinc-400">
                      Recent sync history
                    </summary>
                    <div className="mt-2 space-y-2 text-xs text-zinc-200">
                      {recentEvents.length ? (
                        recentEvents.map((event) => (
                          <div key={`${event.issue_type}-${event.observed_at}`} className="rounded-md border border-zinc-800 bg-zinc-950/70 p-2">
                            <div className="flex items-center justify-between text-[11px] uppercase text-zinc-500">
                              <span>{event.issue_type}</span>
                              <span>{formatTimestamp(parseTimestamp(event.observed_at))}</span>
                            </div>
                            <p className="mt-1 text-zinc-300">{event.message}</p>
                          </div>
                        ))
                      ) : (
                        <p className="text-zinc-500">No recent issue history in the selected window.</p>
                      )}
                    </div>
                  </details>

                  <details className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3">
                    <summary className="cursor-pointer text-xs font-semibold uppercase tracking-wide text-zinc-400">
                      Trend summary & controls
                    </summary>
                    <div className="mt-2 space-y-2 text-xs text-zinc-200">
                      <div className="flex flex-wrap items-center gap-2 text-[11px] text-zinc-500">
                        <span>Trend window:</span>
                        <div className="flex gap-1">
                          {TREND_WINDOWS.map((option) => {
                            const active = trendWindowHours === option.value;
                            return (
                              <button
                                key={option.value}
                                type="button"
                                onClick={() => setTrendWindowHours(option.value)}
                                className={cn(
                                  "rounded-md border px-2 py-1 text-xs transition",
                                  active
                                    ? "border-zinc-100 bg-zinc-800 text-zinc-100"
                                    : "border-zinc-800 bg-zinc-900 text-zinc-400 hover:border-zinc-600 hover:text-zinc-200",
                                )}
                              >
                                {option.label}
                              </button>
                            );
                          })}
                        </div>
                        {isFetchingHistory ? <span className="text-[11px] text-zinc-400">Loading trends…</span> : null}
                      </div>
                      {Object.keys(historyTotals).length ? (
                        <ul className="space-y-1 text-xs text-zinc-300">
                          {Object.entries(historyTotals).map(([severity, count]) => (
                            <li key={severity} className="flex items-center justify-between">
                              <span className="capitalize text-zinc-400">{severityLabels[severity] ?? severity}</span>
                              <span>{count}</span>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className="text-zinc-500">No issues observed in this window.</p>
                      )}
                      {trendBuckets.length ? (
                        <table className="w-full table-fixed border-separate border-spacing-y-1 text-[11px]">
                          <tbody>
                            {trendBuckets.map((bucket) => (
                              <tr key={bucket.bucket_start} className="rounded border border-zinc-800 bg-zinc-950/70">
                                <td className="px-2 py-1 text-zinc-400">{formatRange(bucket.bucket_start, bucket.bucket_end)}</td>
                                <td className="px-2 py-1 text-right text-zinc-200">
                                  {Object.entries(bucket.counts)
                                    .map(([sev, count]) => `${sev}:${count}`)
                                    .join("  ")}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      ) : null}
                    </div>
                  </details>

                  <details className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3">
                    <summary className="cursor-pointer text-xs font-semibold uppercase tracking-wide text-zinc-400">
                      Raw metadata
                    </summary>
                    <pre className="mt-2 max-h-48 overflow-auto rounded-md border border-zinc-800 bg-zinc-950/80 p-2 text-[11px] text-zinc-300">
                      {JSON.stringify(selectedEntry.metadata, null, 2)}
                    </pre>
                  </details>

                  <details className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-3">
                    <summary className="cursor-pointer text-xs font-semibold uppercase tracking-wide text-zinc-400">
                      Recent sync errors
                    </summary>
                    {selectedEntry.recentErrors.length ? (
                      <ul className="mt-2 space-y-2 text-xs text-zinc-200">
                        {selectedEntry.recentErrors.slice(0, 6).map((err, index) => {
                          const record = err as Record<string, unknown>;
                          const messageValue = record.message;
                          const message = typeof messageValue === "string"
                            ? messageValue
                            : JSON.stringify(record).slice(0, 140);
                          const timestampValue = record.timestamp as string | undefined;
                          const observed = formatTimestamp(parseTimestamp(timestampValue));
                          return (
                            <li key={index} className="rounded border border-zinc-800 bg-zinc-950/80 px-2 py-1">
                              <p className="truncate text-[11px] text-zinc-100">{message}</p>
                              <p className="text-[10px] text-zinc-500">{observed}</p>
                            </li>
                          );
                        })}
                      </ul>
                    ) : (
                      <p className="mt-2 text-xs text-zinc-500">No recent errors recorded.</p>
                    )}
                  </details>
                </div>
              </div>
            ) : null}
          </div>
        )}
      </Panel>
    </div>
  );
}
