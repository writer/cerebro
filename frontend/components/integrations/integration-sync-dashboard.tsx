"use client";

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { apiGet } from "@/lib/api";
import { IntegrationStatus } from "@/lib/types";
import { cn } from "@/lib/utils";
import { Panel } from "@/components/ui/panel";

type EnrichedStatus = IntegrationStatus & {
  lastTimestamp?: Date | null;
  ageSeconds: number | null;
  statusLabel: string;
  isStale: boolean;
  severity: "ok" | "warning" | "critical";
};

const STALE_OPTIONS: Array<{ label: string; value: number }> = [
  { label: "15m", value: 900 },
  { label: "1h", value: 3600 },
  { label: "6h", value: 21_600 },
  { label: "Off", value: 0 },
];

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

function mapSeverity(statusLabel: string, isStale: boolean): "ok" | "warning" | "critical" {
  if (statusLabel === "error") {
    return "critical";
  }
  if (statusLabel === "skipped" || isStale) {
    return "warning";
  }
  return "ok";
}

const severityStyles: Record<"ok" | "warning" | "critical", string> = {
  ok: "bg-emerald-500/10 text-emerald-300 border-emerald-500/40",
  warning: "bg-amber-500/10 text-amber-300 border-amber-500/40",
  critical: "bg-rose-500/10 text-rose-300 border-rose-500/40",
};

export function IntegrationSyncDashboard() {
  const [staleThreshold, setStaleThreshold] = useState<number>(3600);

  const {
    data,
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

  const enriched = useMemo<EnrichedStatus[]>(() => {
    if (!data) {
      return [];
    }
    const now = Date.now();
    return data.map((entry) => {
      const metadata = entry.metadata ?? {};
      const statusRaw = metadata?.last_status;
      const statusLabel = typeof statusRaw === "string" ? statusRaw.toLowerCase() : "unknown";
      const lastTimestamp = parseTimestamp(entry.last_timestamp ?? metadata?.last_sync_at);
      const ageSeconds = lastTimestamp ? Math.max((now - lastTimestamp.getTime()) / 1000, 0) : null;
      const isStale = Boolean(
        staleThreshold > 0 && ageSeconds !== null && ageSeconds > staleThreshold,
      );
      const severity = mapSeverity(statusLabel, isStale);
      return {
        ...entry,
        lastTimestamp,
        ageSeconds,
        statusLabel,
        isStale,
        severity,
      };
    });
  }, [data, staleThreshold]);

  const counts = useMemo(() => {
    let stale = 0;
    let critical = 0;
    let warning = 0;
    for (const item of enriched) {
      if (item.severity === "critical") {
        critical += 1;
      }
      if (item.severity === "warning") {
        warning += 1;
      }
      if (item.isStale) {
        stale += 1;
      }
    }
    return { stale, critical, warning };
  }, [enriched]);

  const lastUpdated = useMemo(() => {
    if (!dataUpdatedAt) {
      return "—";
    }
    const ts = new Date(dataUpdatedAt);
    return ts.toLocaleTimeString();
  }, [dataUpdatedAt]);

  return (
    <div className="space-y-6">
      <Panel
        title="Integration Sync Health"
        description="Track freshness and error states across external telemetry integrations."
        action={
          <div className="flex items-center gap-2">
            <div className="hidden text-xs text-zinc-500 sm:block">Stale threshold:</div>
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
            <button
              type="button"
              onClick={() => refetch()}
              className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-1 text-xs text-zinc-200 hover:border-zinc-500"
              disabled={isFetching}
            >
              {isFetching ? "Refreshing…" : "Refresh"}
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
                <span>Total: {enriched.length}</span>
                <span>Warnings: {counts.warning}</span>
                <span>Critical: {counts.critical}</span>
                <span>Stale: {counts.stale}</span>
              </div>
              <div className="text-xs text-zinc-500">Last updated {lastUpdated}</div>
            </div>

            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-zinc-800 text-left text-xs text-zinc-300">
                <thead>
                  <tr className="bg-zinc-950/60">
                    <th scope="col" className="px-3 py-2 font-semibold">Integration</th>
                    <th scope="col" className="px-3 py-2 font-semibold">Scope</th>
                    <th scope="col" className="px-3 py-2 font-semibold">Status</th>
                    <th scope="col" className="px-3 py-2 font-semibold">Last Sync</th>
                    <th scope="col" className="px-3 py-2 font-semibold">Age</th>
                    <th scope="col" className="px-3 py-2 font-semibold">Events</th>
                    <th scope="col" className="px-3 py-2 font-semibold">Last Alert</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-900">
                  {enriched.map((item) => {
                    const metadata = item.metadata ?? {};
                    const lastEventCount = metadata?.last_event_count ?? metadata?.last_ingested_count;
                    const lastAlertIssue = metadata?.last_alert_issue_type;
                    const lastAlertAt = metadata?.last_alert_sent_at;
                    const rowHighlight =
                      item.severity === "critical"
                        ? "bg-rose-500/5"
                        : item.severity === "warning"
                        ? "bg-amber-500/5"
                        : undefined;

                    return (
                      <tr key={`${item.integration}:${item.scope}`} className={rowHighlight}>
                        <td className="px-3 py-2 font-medium text-zinc-100">{item.integration}</td>
                        <td className="px-3 py-2">{item.scope || "default"}</td>
                        <td className="px-3 py-2">
                          <span className={cn("inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] capitalize", severityStyles[item.severity])}>
                            {item.statusLabel.replace(/_/g, " ")}
                          </span>
                        </td>
                        <td className="px-3 py-2">{formatTimestamp(item.lastTimestamp)}</td>
                        <td className="px-3 py-2">{formatAge(item.ageSeconds)}</td>
                        <td className="px-3 py-2">{typeof lastEventCount === "number" ? lastEventCount : "—"}</td>
                        <td className="px-3 py-2 text-zinc-400">
                          {lastAlertIssue ? (
                            <div className="flex flex-col">
                              <span className="capitalize text-zinc-300">{String(lastAlertIssue)}</span>
                              {typeof lastAlertAt === "string" ? (
                                <span className="text-[10px]">{formatTimestamp(parseTimestamp(lastAlertAt))}</span>
                              ) : null}
                            </div>
                          ) : (
                            <span>—</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                  {enriched.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="px-3 py-6 text-center text-sm text-zinc-500">
                        No integration sync state recorded yet.
                      </td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </Panel>
    </div>
  );
}
