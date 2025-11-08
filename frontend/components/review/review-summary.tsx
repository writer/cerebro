"use client";

import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";

import { apiGet } from "@/lib/api";
import {
  IntegrationAdminOverview,
  ReviewQueuePrioritySummary,
  ReviewQueueStatusSummary,
  ReviewQueueSummary,
} from "@/lib/types";
import { cn, formatRelative } from "@/lib/utils";
import { Panel } from "@/components/ui/panel";

function StatCard({
  label,
  value,
  description,
  accent,
}: {
  label: string;
  value: string;
  description?: string;
  accent?: "emerald" | "amber" | "sky" | "zinc";
}) {
  const accentClasses: Record<string, string> = {
    emerald: "border-emerald-500/40 bg-emerald-500/5 text-emerald-100",
    amber: "border-amber-500/40 bg-amber-500/5 text-amber-100",
    sky: "border-sky-500/40 bg-sky-500/5 text-sky-100",
    zinc: "border-zinc-700 bg-black/60 text-zinc-100",
  };

  return (
    <div
      className={cn(
        "rounded-lg border px-4 py-3 shadow-inner",
        accent ? accentClasses[accent] : accentClasses["zinc"],
      )}
    >
      <p className="text-[11px] uppercase tracking-wide text-zinc-400">{label}</p>
      <p className="mt-1 text-2xl font-semibold leading-tight">{value}</p>
      {description ? <p className="mt-1 text-xs text-zinc-400">{description}</p> : null}
    </div>
  );
}

function StatusList({ statuses }: { statuses: ReviewQueueStatusSummary[] }) {
  if (!statuses.length) {
    return <p className="text-sm text-zinc-400">No recent review activity.</p>;
  }

  const sorted = [...statuses].sort((a, b) => b.count - a.count);

  return (
    <div className="space-y-3">
      {sorted.map((status) => {
        const label = status.status.replace(/_/g, " ");
        return (
          <div key={status.status} className="flex items-center justify-between rounded-lg border border-zinc-900 bg-black/60 px-3 py-2">
            <div>
              <p className="text-sm font-medium capitalize text-zinc-100">{label}</p>
              <p className="text-xs text-zinc-500">
                {status.unassigned} unassigned · {status.overdue} overdue
              </p>
            </div>
            <span className="text-lg font-semibold text-zinc-100">{status.count}</span>
          </div>
        );
      })}
    </div>
  );
}

function PriorityList({ priorities }: { priorities: ReviewQueuePrioritySummary[] }) {
  if (!priorities.length) {
    return <p className="text-sm text-zinc-400">No priority labels assigned yet.</p>;
  }

  const sorted = [...priorities].sort((a, b) => (b.priority ?? "").localeCompare(a.priority ?? ""));

  return (
    <div className="space-y-2">
      {sorted.map((item) => (
        <div key={item.priority ?? "none"} className="flex items-center justify-between rounded-md border border-zinc-900 bg-black/50 px-3 py-2">
          <span className="text-sm font-medium text-zinc-200">{item.priority ?? "Unprioritized"}</span>
          <span className="text-sm text-zinc-400">{item.count}</span>
        </div>
      ))}
    </div>
  );
}

function summarizePending(summary: ReviewQueueSummary) {
  const pending = summary.pending;
  const nextDue = formatRelative(pending.next_due);
  const oldest = formatRelative(pending.oldest_created);

  return {
    total: pending.total.toString(),
    unassigned: pending.unassigned.toString(),
    overdue: pending.overdue.toString(),
    nextDue,
    oldest,
  };
}

export function ReviewSummary() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["reviewQueueSummary"],
    queryFn: () => apiGet<ReviewQueueSummary>("/agents/review-tasks/summary"),
    staleTime: 30_000,
  });

  const { data: freshness = [] } = useQuery({
    queryKey: ["integrationAdminOverview", "review"],
    queryFn: () => apiGet<IntegrationAdminOverview[]>("/integrations/admin/overview"),
    staleTime: 60_000,
  });

  const summary = useMemo(() => data ?? null, [data]);
  const freshnessAlerts = useMemo(() => {
    const alerts = freshness
      .filter((entry) => entry.status !== "fresh")
      .sort((a, b) => (b.age_seconds ?? 0) - (a.age_seconds ?? 0));
    return alerts.slice(0, 3);
  }, [freshness]);

  return (
    <Panel
      title="Queue health overview"
      description="Track reviewer workload, ownership, and backlog risk."
    >
      {isLoading ? (
        <div className="space-y-3 text-sm text-zinc-400">Loading queue summary…</div>
      ) : error ? (
        <div className="space-y-2 text-sm text-amber-400">
          <p>Unable to load the review summary right now.</p>
          <p className="text-xs text-zinc-500">{(error as Error)?.message ?? "Unknown error"}</p>
        </div>
      ) : summary ? (
        <div className="space-y-6">
          <div className="grid gap-3 md:grid-cols-3">
            {(() => {
              const metrics = summarizePending(summary);
              return (
                <>
                  <StatCard
                    label="Pending"
                    value={metrics.total}
                    description={`Oldest created ${metrics.oldest}`}
                    accent="emerald"
                  />
                  <StatCard
                    label="Unassigned"
                    value={metrics.unassigned}
                    description="Requires analyst pickup"
                    accent="sky"
                  />
                  <StatCard
                    label="Overdue"
                    value={metrics.overdue}
                    description={`Next due ${metrics.nextDue}`}
                    accent="amber"
                  />
                </>
              );
            })()}
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            <div>
              <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-zinc-500">
                Status distribution
              </h3>
              <StatusList statuses={summary.status_counts} />
            </div>
            <div>
              <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-zinc-500">
                Priority mix
              </h3>
              <PriorityList priorities={summary.priority_breakdown} />
            </div>
          </div>

          <div className="rounded-lg border border-amber-500/40 bg-amber-500/5 p-4">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-amber-300">
              Data freshness
            </h3>
            {freshnessAlerts.length ? (
              <ul className="mt-2 space-y-1 text-xs text-amber-100">
                {freshnessAlerts.map((item) => (
                  <li key={`${item.integration}:${item.scope}`} className="flex flex-wrap justify-between gap-x-3">
                    <span>
                      {item.integration}
                      <span className="ml-1 text-amber-200/70">({item.scope})</span>
                    </span>
                    <span>
                      {item.age_human ?? "unknown"}
                      <span className="ml-2 capitalize text-amber-200/70">{item.status}</span>
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mt-2 text-xs text-amber-200/70">All tracked integrations are fresh.</p>
            )}
          </div>

          <p className="text-[11px] uppercase tracking-wide text-zinc-500">
            Generated {formatRelative(summary.generated_at)}
          </p>
        </div>
      ) : (
        <p className="text-sm text-zinc-400">No review activity recorded yet.</p>
      )}
    </Panel>
  );
}
