"use client";

import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";

import { apiGet, apiPost } from "@/lib/api";
import { OperationalHealthSnapshot } from "@/lib/types";
import { cn } from "@/lib/utils";
import { Panel } from "@/components/ui/panel";

type RetryParams = {
  integration: string;
};

function formatTimestamp(value: string | null | undefined): string {
  if (!value) {
    return "Never";
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return parsed.toLocaleString();
}

function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null) {
    return "n/a";
  }
  if (seconds < 60) {
    return `${Math.round(seconds)}s`;
  }
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) {
    return `${minutes}m`;
  }
  const hours = Math.floor(minutes / 60);
  const mins = minutes % 60;
  return mins ? `${hours}h ${mins}m` : `${hours}h`;
}

function formatBytes(bytes: number | null | undefined): string {
  if (bytes == null) {
    return "n/a";
  }
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toFixed(1)} ${units[unitIndex]}`;
}

const statusStyles: Record<string, string> = {
  fresh: "border-emerald-500/40 bg-emerald-500/10 text-emerald-200",
  stale: "border-amber-500/40 bg-amber-500/10 text-amber-200",
  error: "border-rose-500/50 bg-rose-500/10 text-rose-200",
  unknown: "border-zinc-700 bg-black/60 text-zinc-200",
};

export function OperationalHealthDashboard() {
  const [feedback, setFeedback] = useState<string | null>(null);

  const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ["operationalHealth"],
    queryFn: () => apiGet<OperationalHealthSnapshot>("/analytics/monitoring/operations/health"),
    refetchInterval: 60_000,
  });

  const retryMutation = useMutation({
    mutationFn: ({ integration }: RetryParams) =>
      apiPost("/integrations/sync", { integration }),
    onSuccess: (result: any, variables) => {
      setFeedback(`Queued sync for ${variables.integration}`);
      refetch();
    },
    onError: (err: unknown) => {
      const message = err instanceof Error ? err.message : "Failed to queue sync";
      setFeedback(message);
    },
  });

  const summaryCards = useMemo(() => {
    if (!data) {
      return [] as Array<{ label: string; value: string; accent: string; description?: string }>;
    }
    const integrations = data.integrations.summary;
    const queueDepth = data.jobs.summary.total_queue_depth;
    const failedTasks = data.jobs.summary.failed_tasks ?? 0;
    const rpm = data.api.requests_per_minute;
    return [
      {
        label: "Integrations",
        value: `${integrations.total - integrations.error - integrations.stale} healthy`,
        accent: "emerald",
        description: `${integrations.stale} stale · ${integrations.error} failing`,
      },
      {
        label: "Queue depth",
        value: String(queueDepth),
        accent: queueDepth > 100 ? "rose" : queueDepth > 20 ? "amber" : "sky",
        description: `${data.jobs.summary.total_workers} workers · ${failedTasks} failed tasks`,
      },
      {
        label: "API RPM",
        value: data.api.requests_per_minute.toFixed(2),
        accent: data.api.error_rate > 0.05 ? "rose" : "sky",
        description: `${(data.api.error_rate * 100).toFixed(1)}% error rate`,
      },
      {
        label: "Weekly active users",
        value: String(data.usage.weekly_active_users ?? 0),
        accent: "emerald",
        description: `${data.usage.top_features.slice(0, 1).map((item) => item.component).join(" ") || "Top feature"}`,
      },
    ];
  }, [data]);

  return (
    <div className="space-y-6">
      <Panel
        title="Operational Overview"
        description="Real-time status across integrations, jobs, database, and usage."
        action={
          <span className="text-xs text-zinc-500">
            {isFetching ? "Refreshing…" : data ? `Updated ${formatTimestamp(data.generated_at)}` : null}
          </span>
        }
      >
        {isLoading ? (
          <div className="text-sm text-zinc-400">Loading operational health…</div>
        ) : isError ? (
          <div className="text-sm text-rose-300">
            Failed to load health snapshot: {error instanceof Error ? error.message : String(error)}
          </div>
        ) : data ? (
          <div className="space-y-6">
            {feedback ? (
              <div className="rounded-md border border-sky-500/40 bg-sky-500/10 px-3 py-2 text-xs text-sky-100">
                {feedback}
              </div>
            ) : null}

            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              {summaryCards.map((card) => (
                <div
                  key={card.label}
                  className={cn(
                    "rounded-lg border px-4 py-3",
                    card.accent === "emerald" && "border-emerald-500/40 bg-emerald-500/10 text-emerald-100",
                    card.accent === "amber" && "border-amber-500/40 bg-amber-500/10 text-amber-100",
                    card.accent === "rose" && "border-rose-500/40 bg-rose-500/10 text-rose-100",
                    card.accent === "sky" && "border-sky-500/40 bg-sky-500/10 text-sky-100",
                  )}
                >
                  <p className="text-[11px] uppercase tracking-wide text-zinc-400">{card.label}</p>
                  <p className="mt-1 text-2xl font-semibold leading-tight">{card.value}</p>
                  {card.description ? (
                    <p className="mt-1 text-xs text-zinc-200/80">{card.description}</p>
                  ) : null}
                </div>
              ))}
            </div>

            <div className="grid gap-6 xl:grid-cols-2">
              <section className="space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-semibold uppercase tracking-wide text-zinc-500">
                    Integrations
                  </h3>
                  <button
                    type="button"
                    onClick={() => refetch()}
                    className="rounded-md border border-zinc-800 bg-zinc-950 px-2 py-1 text-xs text-zinc-300 hover:border-zinc-600 hover:text-zinc-100"
                  >
                    Refresh
                  </button>
                </div>
                <div className="space-y-2">
                  {data.integrations.items.map((item) => {
                    const statusStyle = statusStyles[item.status] ?? statusStyles.unknown;
                    const nextScheduled = item.next_scheduled_at ? formatTimestamp(item.next_scheduled_at) : "n/a";
                    return (
                      <div
                        key={`${item.integration}:${item.scope}`}
                        className="rounded-lg border border-zinc-800 bg-black/60 p-3"
                      >
                        <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                          <div>
                            <p className="text-sm font-medium text-zinc-100">
                              {item.integration}
                              <span className="ml-2 text-xs text-zinc-500">{item.scope}</span>
                            </p>
                            <div className="mt-1 flex flex-wrap gap-2 text-xs text-zinc-400">
                              <span>Last synced: {formatTimestamp(item.last_synced_at)}</span>
                              <span>Age: {item.age_human ?? "n/a"}</span>
                              <span>Next scheduled: {nextScheduled}</span>
                              <span>Avg duration: {formatDuration(item.duration_average_seconds ?? null)}</span>
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className={cn("rounded-md border px-2 py-1 text-xs capitalize", statusStyle)}>
                              {item.status}
                            </span>
                            <button
                              type="button"
                              onClick={() => retryMutation.mutate({ integration: item.integration })}
                              className="rounded-md border border-sky-500/60 bg-sky-500/10 px-2 py-1 text-xs text-sky-100 hover:border-sky-400"
                              disabled={retryMutation.isPending && retryMutation.variables?.integration === item.integration}
                            >
                              {retryMutation.isPending && retryMutation.variables?.integration === item.integration
                                ? "Queuing…"
                                : "Retry now"}
                            </button>
                          </div>
                        </div>
                        <div className="mt-2 grid gap-2 md:grid-cols-4">
                          <div className="rounded-md border border-zinc-900 bg-zinc-950/60 px-2 py-1 text-xs text-zinc-400">
                            Issues (24h):
                            <span className="ml-1 text-zinc-200">
                              {Object.entries(item.issues_last_24h).length
                                ? Object.entries(item.issues_last_24h)
                                    .map(([severity, count]) => `${severity}:${count}`)
                                    .join(" · ")
                                : "None"}
                            </span>
                          </div>
                          <div className="rounded-md border border-zinc-900 bg-zinc-950/60 px-2 py-1 text-xs text-zinc-400">
                            Errors (24h):
                            <span className="ml-1 text-zinc-200">{item.error_count_24h ?? 0}</span>
                          </div>
                          <div className="rounded-md border border-zinc-900 bg-zinc-950/60 px-2 py-1 text-xs text-zinc-400">
                            Data confidence:
                            <span className="ml-1 capitalize text-zinc-200">{item.confidence_level ?? "unknown"}</span>
                          </div>
                          <div className="rounded-md border border-zinc-900 bg-zinc-950/60 px-2 py-1 text-xs text-zinc-400">
                            Status confidence:
                            <span className="ml-1 capitalize text-zinc-200">{item.status_confidence ?? "unknown"}</span>
                          </div>
                        </div>
                        <div className="mt-2 flex flex-wrap gap-2 text-[11px] text-zinc-400">
                          <span>Stale threshold: {item.stale_threshold_hours ?? "n/a"}h</span>
                          <span>Recent errors: {item.recent_errors.length}</span>
                        </div>
                        {item.warning ? (
                          <p className="mt-2 text-xs text-amber-300">{item.warning}</p>
                        ) : null}
                      </div>
                    );
                  })}
                </div>
              </section>

              <section className="space-y-3">
                <h3 className="text-xs font-semibold uppercase tracking-wide text-zinc-500">
                  Job processors
                </h3>
                <div className="space-y-2">
                  <div className="rounded-lg border border-zinc-800 bg-black/60 p-3">
                    <p className="text-sm text-zinc-200">
                      {data.jobs.summary.healthy_workers}/{data.jobs.summary.total_workers} workers healthy ·
                      Queue depth {data.jobs.summary.total_queue_depth} · Failed tasks {data.jobs.summary.failed_tasks ?? 0}
                    </p>
                    <div className="mt-2 grid gap-2 md:grid-cols-2">
                      {data.jobs.workers.map((worker) => (
                        <div key={worker.name} className="rounded-md border border-zinc-900 bg-zinc-950/60 px-3 py-2 text-xs">
                          <div className="flex items-center justify-between text-zinc-300">
                            <span>{worker.name}</span>
                            <span className={cn(
                              "text-[11px] uppercase",
                              worker.status === "healthy" ? "text-emerald-300" : "text-amber-300",
                            )}
                            >
                              {worker.status}
                            </span>
                          </div>
                          <div className="mt-1 flex justify-between text-zinc-500">
                            <span>Active {worker.active_tasks}</span>
                            <span>Reserved {worker.reserved_tasks}</span>
                            <span>Completed {worker.total_completed}</span>
                          </div>
                          <div className="mt-1 text-[11px] text-zinc-500">Failed {worker.failed_tasks ?? 0}</div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="rounded-lg border border-zinc-800 bg-black/60 p-3 space-y-2">
                    <h4 className="text-xs font-semibold uppercase tracking-wide text-zinc-500">Database</h4>
                    <div className="grid gap-2 md:grid-cols-2">
                      <div className="rounded-md border border-zinc-900 bg-zinc-950/60 px-3 py-2 text-xs text-zinc-400">
                        Pool utilization:
                        <span className="ml-1 text-zinc-200">
                          {data.database.pool.utilization != null
                            ? `${(data.database.pool.utilization * 100).toFixed(1)}%`
                            : "n/a"}
                        </span>
                      </div>
                      <div className="rounded-md border border-zinc-900 bg-zinc-950/60 px-3 py-2 text-xs text-zinc-400">
                        Pool size:
                        <span className="ml-1 text-zinc-200">{data.database.pool.size ?? "n/a"}</span>
                      </div>
                    </div>
                    <div>
                      <p className="text-xs text-zinc-500">Top tables</p>
                      <ul className="mt-1 space-y-1 text-xs text-zinc-300">
                        {data.database.table_sizes.map((table) => (
                          <li key={table.table} className="flex justify-between border-b border-zinc-900/60 pb-1 last:border-transparent">
                            <span>{table.table}</span>
                            <span>{formatBytes(table.size_bytes)}</span>
                          </li>
                        ))}
                        {!data.database.table_sizes.length ? (
                          <li className="text-zinc-500">No table stats available</li>
                        ) : null}
                      </ul>
                    </div>
                  </div>
                </div>
              </section>
            </div>

            <div className="grid gap-6 xl:grid-cols-2">
              <section className="space-y-3">
                <h3 className="text-xs font-semibold uppercase tracking-wide text-zinc-500">
                  API traffic
                </h3>
                <div className="rounded-lg border border-zinc-800 bg-black/60 p-3 space-y-2 text-sm text-zinc-200">
                  <div className="flex justify-between text-xs text-zinc-400">
                    <span>p95 latency</span>
                    <span>{data.api.p95_latency_ms.toFixed(1)} ms</span>
                  </div>
                  <div>
                    <p className="text-xs text-zinc-500">Top endpoints</p>
                    <ul className="mt-1 space-y-1 text-xs text-zinc-300">
                      {data.api.top_endpoints.map((entry) => (
                        <li key={`${entry.method}-${entry.path}`} className="flex justify-between">
                          <span>
                            <span className="mr-2 rounded border border-zinc-700 bg-zinc-900 px-2 py-[2px] text-[10px] uppercase text-zinc-400">
                              {entry.method}
                            </span>
                            {entry.path}
                          </span>
                          <span>{entry.count}</span>
                        </li>
                      ))}
                      {!data.api.top_endpoints.length ? (
                        <li className="text-zinc-500">No requests observed in window</li>
                      ) : null}
                    </ul>
                  </div>
                </div>
              </section>

              <section className="space-y-3">
                <h3 className="text-xs font-semibold uppercase tracking-wide text-zinc-500">
                  Agent activity
                </h3>
                <div className="rounded-lg border border-zinc-800 bg-black/60 p-3 space-y-3 text-sm text-zinc-200">
                  <div className="flex gap-4 text-xs text-zinc-400">
                    <span>Active sessions: <span className="text-zinc-100">{data.agents.active_sessions}</span></span>
                    <span>Messages/hour: <span className="text-zinc-100">{data.agents.messages_per_hour}</span></span>
                    <span>Tool error rate: <span className="text-zinc-100">{(data.agents.tool_error_rate * 100).toFixed(1)}%</span></span>
                  </div>
                  <div>
                    <p className="text-xs text-zinc-500">Runtime warnings</p>
                    <ul className="mt-1 space-y-1 text-xs text-zinc-300">
                      {data.agents.runtime_health.map((runtime) => {
                        const runtimeObj = runtime as Record<string, any>;
                        const label = runtimeObj.runtime ?? "runtime";
                        const warnings = (runtimeObj.warnings ?? {}) as Record<string, { count?: number }>;
                        const warningCount = Object.values(warnings).reduce((acc, entry) => acc + (entry?.count ?? 0), 0);
                        return (
                          <li key={String(label)} className="flex justify-between">
                            <span>{String(label)}</span>
                            <span>{warningCount} warnings</span>
                          </li>
                        );
                      })}
                      {!data.agents.runtime_health.length ? (
                        <li className="text-zinc-500">No runtime summaries available</li>
                      ) : null}
                    </ul>
                  </div>
                </div>
              </section>
            </div>

            <section className="space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-zinc-500">
                Product usage
              </h3>
              <div className="rounded-lg border border-zinc-800 bg-black/60 p-3">
                <div className="grid gap-3 md:grid-cols-2">
                  <div>
                    <p className="text-xs text-zinc-500">Top features (events)</p>
                    <ul className="mt-1 space-y-1 text-xs text-zinc-300">
                      {data.usage.top_features.map((item) => (
                        <li key={item.component} className="flex justify-between">
                          <span>{item.component}</span>
                          <span>{item.events}</span>
                        </li>
                      ))}
                      {!data.usage.top_features.length ? (
                        <li className="text-zinc-500">No feature usage recorded</li>
                      ) : null}
                    </ul>
                  </div>
                  <div>
                    <p className="text-xs text-zinc-500">Unused candidates</p>
                    <ul className="mt-1 space-y-1 text-xs text-zinc-300">
                      {data.usage.unused_features.map((feature) => (
                        <li key={feature}>{feature}</li>
                      ))}
                      {!data.usage.unused_features.length ? (
                        <li className="text-zinc-500">All tracked features active</li>
                      ) : null}
                    </ul>
                  </div>
                </div>
                <div className="mt-3 rounded-md border border-zinc-900 bg-zinc-950/60 px-3 py-2 text-xs text-zinc-400">
                  <p className="font-semibold uppercase tracking-wide text-[11px] text-zinc-500">Key feature usage</p>
                  <ul className="mt-1 space-y-1 text-zinc-300">
                    {Object.entries(data.usage.feature_breakdown).map(([feature, value]) => (
                      <li key={feature} className="flex justify-between">
                        <span className="capitalize">{feature.replace(/_/g, " ")}</span>
                        <span>{value}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </section>
          </div>
        ) : null}
      </Panel>
    </div>
  );
}
