"use client";

import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { apiGet } from "@/lib/api";
import { AgentSessionListItem, MemoryStats, SessionListResponse } from "@/lib/types";
import { formatRelative } from "@/lib/utils";
import { Panel } from "@/components/ui/panel";

const RECENT_THRESHOLD_HOURS = 24;

export function MemoryInsightsPanel() {
  const [sessionInput, setSessionInput] = useState("");
  const [sessionId, setSessionId] = useState("");
  const [didAutoSelect, setDidAutoSelect] = useState(false);

  const { data: recentSessionsResponse } = useQuery({
    queryKey: ["recentAgentSessions", "memory"],
    queryFn: () => apiGet<SessionListResponse>("/agents/sessions", { limit: 12 }),
    staleTime: 60_000,
  });

  const recentSessions: AgentSessionListItem[] = useMemo(() => {
    const base = recentSessionsResponse?.sessions ?? [];
    return [...base].sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  }, [recentSessionsResponse]);

  useEffect(() => {
    if (didAutoSelect || sessionId || recentSessions.length === 0) {
      return;
    }

    const newest = recentSessions[0]?.session_id;
    if (!newest) {
      return;
    }

    setSessionInput(newest);
    setSessionId(newest);
    setDidAutoSelect(true);
  }, [didAutoSelect, recentSessions, sessionId]);

  const { data: stats, isFetching } = useQuery({
    queryKey: ["memoryStats", sessionId],
    queryFn: () => apiGet<MemoryStats>(`/agents/sessions/${sessionId}/memory/stats`),
    enabled: Boolean(sessionId),
  });

  const emptyStats: MemoryStats = {
    total_entries: 0,
    recent_entries: 0,
    presented_entries: 0,
    average_decay: 0,
    token_total: 0,
    role_distribution: {},
    scope_distribution: {},
    top_memories: [],
  };

  const resolvedStats = stats ?? emptyStats;

  const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmed = sessionInput.trim();
    if (!trimmed) {
      return;
    }
    setSessionId(trimmed);
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
            value={sessionInput}
            onChange={(event) => setSessionInput(event.target.value)}
            className="w-56 rounded-md border border-zinc-800 bg-zinc-900 px-3 py-1 text-xs text-zinc-100 focus:border-zinc-600 focus:outline-none"
            required
            list="memory-session-suggestions"
          />
          <datalist id="memory-session-suggestions">
            {recentSessions.map((session) => (
              <option key={session.session_id} value={session.session_id}>
                {session.title?.trim() ? session.title : session.session_id}
              </option>
            ))}
          </datalist>
          <button
            type="submit"
            className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-1 text-xs font-semibold text-zinc-100 transition hover:border-zinc-500 hover:bg-zinc-800"
          >
            {isFetching ? "Loading…" : "Load"}
          </button>
        </form>
      }
    >
      {!sessionId ? (
        <p className="text-sm text-zinc-500">
          Provide a session ID to view memory analytics. Recent sessions auto-populate once data is available, and you can paste any session UUID to override.
        </p>
      ) : !stats ? (
        <p className="text-sm text-zinc-500">Loading session memory statistics…</p>
      ) : (
        <div className="grid gap-5 lg:grid-cols-2">
          <div className="space-y-4">
            <InsightCard title="Totals">
              <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-xs">
                <InsightRow label="Entries" value={String(resolvedStats.total_entries)} />
                <InsightRow
                  label={`&lt;${RECENT_THRESHOLD_HOURS}h`}
                  value={String(resolvedStats.recent_entries)}
                />
                <InsightRow label="Presented" value={String(resolvedStats.presented_entries)} />
                <InsightRow label="Avg decay" value={resolvedStats.average_decay.toFixed(2)} />
                <InsightRow label="Tokens" value={String(resolvedStats.token_total)} />
              </dl>
            </InsightCard>

            <InsightCard title="Roles">
              {Object.keys(resolvedStats.role_distribution).length === 0 ? (
                <p className="text-xs text-zinc-500">No role metadata captured yet.</p>
              ) : (
                <ul className="space-y-1 text-xs text-zinc-200">
                  {Object.entries(resolvedStats.role_distribution).map(([role, count]) => (
                    <li key={role} className="flex justify-between text-zinc-300">
                      <span className="uppercase text-zinc-500">{role}</span>
                      <span>{count}</span>
                    </li>
                  ))}
                </ul>
              )}
            </InsightCard>

            <InsightCard title="Scopes">
              {Object.keys(resolvedStats.scope_distribution).length === 0 ? (
                <p className="text-xs text-zinc-500">No scoped memories for this session.</p>
              ) : (
                <ul className="space-y-1 text-xs text-zinc-200">
                  {Object.entries(resolvedStats.scope_distribution).map(([scope, count]) => (
                    <li key={scope} className="flex justify-between text-zinc-300">
                      <span className="uppercase text-zinc-500">{scope}</span>
                      <span>{count}</span>
                    </li>
                  ))}
                </ul>
              )}
            </InsightCard>
          </div>

          <InsightCard title="Top retained memories" description="Highest decay scores surface the facts the agent revisits most frequently.">
            {resolvedStats.top_memories.length === 0 ? (
              <p className="text-xs text-zinc-500">No highlights yet—add more memory or run the session.</p>
            ) : (
              <ul className="space-y-3">
                {resolvedStats.top_memories.map((memory) => (
                  <li key={memory.id} className="rounded-md border border-zinc-900 bg-black/70 p-3 text-xs text-zinc-200">
                    <div className="flex items-center justify-between text-[11px] uppercase text-zinc-500">
                      <span>{memory.role ?? "memory"}</span>
                      <span>Decay {memory.decay_score.toFixed(2)}</span>
                    </div>
                    <p className="mt-2 text-sm text-zinc-100">
                      {memory.summary ?? "No summary provided."}
                    </p>
                    <div className="mt-2 flex flex-wrap gap-1 text-[11px] text-zinc-400">
                      {memory.scope_labels.length > 0
                        ? memory.scope_labels.map((label) => (
                            <span key={label} className="rounded bg-zinc-900/70 px-2 py-0.5 text-zinc-100">
                              {label}
                            </span>
                          ))
                        : "Unscoped"}
                    </div>
                    <p className="mt-2 text-[11px] text-zinc-500">
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
    <section className="rounded-xl border border-zinc-900 bg-black/75 p-4 shadow-inner">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-zinc-500">{title}</h3>
      {description ? <p className="mt-1 text-[11px] text-zinc-500">{description}</p> : null}
      <div className="mt-3 text-sm text-zinc-200">{children}</div>
    </section>
  );
}

function InsightRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between text-zinc-300">
      <span className="text-zinc-500">{label}</span>
      <span className="font-medium text-zinc-100">{value}</span>
    </div>
  );
}
