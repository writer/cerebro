"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { apiGet } from "@/lib/api";
import { RuntimeEvent } from "@/lib/types";
import { formatRelative } from "@/lib/utils";
import { Panel } from "@/components/ui/panel";

export function RuntimeAnalyticsPanel() {
  const [sessionId, setSessionId] = useState("");

  const { data, isFetching, refetch, isPlaceholderData } = useQuery({
    queryKey: ["runtimeAnalytics", sessionId],
    queryFn: () =>
      sessionId
        ? apiGet<RuntimeEvent[]>(`/agents/sessions/${sessionId}/analytics`)
        : Promise.resolve([]),
    enabled: false
  });

  const events = data ?? [];

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    await refetch();
  };

  return (
    <Panel
      title="Runtime analytics"
      description="Inspect agent routing, memory retrieval, and tool ordering decisions captured from runtime events."
      action={
        <form onSubmit={handleSubmit} className="flex items-center gap-2">
          <input
            type="text"
            required
            value={sessionId}
            onChange={(event) => setSessionId(event.target.value)}
            placeholder="Session UUID"
            className="w-56 rounded-md border border-zinc-800 bg-black px-3 py-1 text-xs text-zinc-200 focus:border-zinc-600 focus:outline-none"
          />
          <button
            type="submit"
            className="rounded-md border border-zinc-700 bg-black px-3 py-1 text-xs font-semibold text-zinc-200 transition hover:border-zinc-500 hover:bg-zinc-900"
          >
            {isFetching ? "Loading…" : "Load"}
          </button>
        </form>
      }
    >
      {sessionId === "" ? (
        <p className="text-sm text-zinc-500">Provide a session ID to view its runtime event stream.</p>
      ) : isFetching && events.length === 0 ? (
        <p className="text-sm text-zinc-500">Fetching analytics…</p>
      ) : events.length === 0 ? (
        <p className="text-sm text-zinc-500">No events recorded for this session (yet).</p>
      ) : (
        <ul className="space-y-3">
          {events.map((event) => (
            <li
              key={event.id}
              className="rounded-lg border border-zinc-900 bg-black/75 p-4 text-sm shadow-inner"
            >
              <div className="flex items-center justify-between text-xs text-zinc-500">
                <span className="uppercase tracking-wide text-zinc-300">{event.event_type}</span>
                <span className="text-zinc-400">{formatRelative(event.created_at)}</span>
              </div>
              <pre className="mt-2 overflow-x-auto rounded-md bg-zinc-900/70 p-3 text-[11px] text-zinc-200">
                {JSON.stringify(event.payload, null, 2)}
              </pre>
            </li>
          ))}
        </ul>
      )}
      {isPlaceholderData ? (
        <p className="mt-3 text-xs text-zinc-500">
          Showing cached events. Refresh to fetch the latest analytics snapshot.
        </p>
      ) : null}
    </Panel>
  );
}
