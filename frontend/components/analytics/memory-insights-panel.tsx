"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { apiGet } from "@/lib/api";
import { MemoryStats } from "@/lib/types";
import { formatRelative } from "@/lib/utils";
import { Panel } from "@/components/ui/panel";

const RECENT_THRESHOLD_HOURS = 24;

export function MemoryInsightsPanel() {
  const [sessionId, setSessionId] = useState("");

  const { data, isFetching, refetch } = useQuery({
    queryKey: ["memoryStats", sessionId],
    queryFn: () =>
      sessionId
        ? apiGet<MemoryStats>(`/agents/sessions/${sessionId}/memory/stats`)
        : Promise.resolve({
            total_entries: 0,
            recent_entries: 0,
            presented_entries: 0,
            average_decay: 0,
            token_total: 0,
            role_distribution: {},
            scope_distribution: {},
            top_memories: [],
          }),
    enabled: false,
  });

  const stats = data;

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    await refetch();
  };

  return (
    <Panel
      title="Memory intelligence"
      description="Understand what the agent remembers, how relevance decays, and which scopes are most enriched."
      action={
        <form onSubmit={handleSubmit} className="flex items-center gap-2">
          <input
            type="text"
            placeholder="Session UUID"
            value={sessionId}
            onChange={(event) => setSessionId(event.target.value)}
            className="w-56 rounded-md border border-slate-700 bg-slate-900 px-3 py-1 text-xs text-slate-100"
            required
          />
          <button
            type="submit"
            className="rounded-md border border-slate-600 bg-slate-900 px-3 py-1 text-xs font-semibold text-slate-100 hover:border-slate-500 hover:bg-slate-800"
          >
            {isFetching ? "Loading…" : "Load"}
          </button>
        </form>
      }
    >
      {!stats ? (
        <p className="text-sm text-slate-500">Provide a session ID to view memory analytics.</p>
      ) : (
        <div className="grid gap-5 lg:grid-cols-2">
          <div className="space-y-4">
            <InsightCard title="Totals">
              <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-xs">
                <InsightRow label="Entries" value={String(stats.total_entries)} />
                <InsightRow
                  label={`&lt;${RECENT_THRESHOLD_HOURS}h`}
                  value={String(stats.recent_entries)}
                />
                <InsightRow label="Presented" value={String(stats.presented_entries)} />
                <InsightRow label="Avg decay" value={stats.average_decay.toFixed(2)} />
                <InsightRow label="Tokens" value={String(stats.token_total)} />
              </dl>
            </InsightCard>

            <InsightCard title="Roles">
              {Object.keys(stats.role_distribution).length === 0 ? (
                <p className="text-xs text-slate-500">No role metadata captured yet.</p>
              ) : (
                <ul className="space-y-1 text-xs text-slate-300">
                  {Object.entries(stats.role_distribution).map(([role, count]) => (
                    <li key={role} className="flex justify-between">
                      <span className="uppercase text-slate-500">{role}</span>
                      <span>{count}</span>
                    </li>
                  ))}
                </ul>
              )}
            </InsightCard>

            <InsightCard title="Scopes">
              {Object.keys(stats.scope_distribution).length === 0 ? (
                <p className="text-xs text-slate-500">No scoped memories for this session.</p>
              ) : (
                <ul className="space-y-1 text-xs text-slate-300">
                  {Object.entries(stats.scope_distribution).map(([scope, count]) => (
                    <li key={scope} className="flex justify-between">
                      <span className="uppercase text-slate-500">{scope}</span>
                      <span>{count}</span>
                    </li>
                  ))}
                </ul>
              )}
            </InsightCard>
          </div>

          <InsightCard title="Top retained memories" description="Highest decay scores surface the facts the agent revisits most frequently.">
            {stats.top_memories.length === 0 ? (
              <p className="text-xs text-slate-500">No highlights yet—add more memory or run the session.</p>
            ) : (
              <ul className="space-y-3">
                {stats.top_memories.map((memory) => (
                  <li key={memory.id} className="rounded-md bg-slate-900/80 p-3 text-xs text-slate-200">
                    <div className="flex items-center justify-between text-[11px] uppercase text-slate-500">
                      <span>{memory.role ?? "memory"}</span>
                      <span>Decay {memory.decay_score.toFixed(2)}</span>
                    </div>
                    <p className="mt-2 text-sm text-slate-200">
                      {memory.summary ?? "No summary provided."}
                    </p>
                    <div className="mt-2 flex flex-wrap gap-1 text-[11px] text-slate-500">
                      {memory.scope_labels.length > 0
                        ? memory.scope_labels.map((label) => (
                            <span key={label} className="rounded bg-slate-900/80 px-2 py-0.5">
                              {label}
                            </span>
                          ))
                        : "Unscoped"}
                    </div>
                    <p className="mt-2 text-[11px] text-slate-500">
                      Last accessed {formatRelative(memory.last_accessed_at)}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </InsightCard>
        </div>
      )}
    </Panel>
  );
}

type InsightCardProps = {
  title: string;
  children: React.ReactNode;
  description?: string;
};

function InsightCard({ title, children, description }: InsightCardProps) {
  return (
    <section className="rounded-xl border border-slate-800 bg-slate-950/50 p-4 shadow-inner">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">{title}</h3>
      {description ? <p className="mt-1 text-[11px] text-slate-500">{description}</p> : null}
      <div className="mt-3 text-sm text-slate-200">{children}</div>
    </section>
  );
}

function InsightRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between">
      <span className="text-slate-500">{label}</span>
      <span className="font-medium text-slate-200">{value}</span>
    </div>
  );
}
