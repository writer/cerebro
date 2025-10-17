"use client";

import { useEffect, useMemo, useState } from "react";
import { useInfiniteQuery, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiGet } from "@/lib/api";
import {
  AgentSessionListItem,
  RuntimeEvent,
  RuntimeEventSummary,
  SessionListResponse,
} from "@/lib/types";
import { formatRelative } from "@/lib/utils";
import { Panel } from "@/components/ui/panel";

const DEFAULT_EVENT_TYPES = Object.freeze([
  "tool_execution",
  "memory_recall",
  "routing_decision",
  "runtime_switch",
  "policy_evaluation",
  "context_snapshot"
]);

const PAGE_SIZE = 25;

type AnalyticsCursor = {
  createdAt: string;
  eventId?: string;
};

export function RuntimeAnalyticsPanel() {
  const [sessionId, setSessionId] = useState("");
  const [eventType, setEventType] = useState("");
  const [discoveredTypes, setDiscoveredTypes] = useState<string[]>([...DEFAULT_EVENT_TYPES]);
  const [hasSubmitted, setHasSubmitted] = useState(false);

  const queryClient = useQueryClient();
  const queryEnabled = sessionId.trim().length > 0;

  const { data: recentSessionsResponse } = useQuery({
    queryKey: ["recentAgentSessions"],
    queryFn: () => apiGet<SessionListResponse>("/agents/sessions", { limit: 12 }),
    staleTime: 60_000,
  });

  const recentSessions: AgentSessionListItem[] = useMemo(
    () => recentSessionsResponse?.sessions ?? [],
    [recentSessionsResponse],
  );

  const {
    data,
    isFetching,
    isError,
    error,
    refetch,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage
  } = useInfiniteQuery({
    queryKey: ["runtimeAnalytics", sessionId, eventType || null],
    enabled: false,
    initialPageParam: undefined as AnalyticsCursor | undefined,
    queryFn: async ({ pageParam }) => {
      if (!queryEnabled) {
        return [] as RuntimeEvent[];
      }

      const cursorParam = pageParam as AnalyticsCursor | undefined;
      const params: Record<string, unknown> = { limit: PAGE_SIZE };
      if (eventType) {
        params.event_type = eventType;
      }
      if (cursorParam?.createdAt) {
        params.cursor = cursorParam.createdAt;
      }
      if (cursorParam?.eventId) {
        params.cursor_id = cursorParam.eventId;
      }

      const events = await apiGet<RuntimeEvent[]>(
        `/agents/sessions/${sessionId}/analytics`,
        params
      );
      return events;
    },
    getNextPageParam: (lastPage) => {
      if (lastPage.length < PAGE_SIZE) {
        return undefined;
      }
      const tail = lastPage[lastPage.length - 1];
      if (!tail) {
        return undefined;
      }
      return {
        createdAt: tail.created_at,
        eventId: tail.id
      } satisfies AnalyticsCursor;
    }
  });

  useEffect(() => {
    setDiscoveredTypes([...DEFAULT_EVENT_TYPES]);
    setEventType("");
  }, [sessionId]);

  useEffect(() => {
    if (!data?.pages) {
      return;
    }

    const next = new Set(DEFAULT_EVENT_TYPES);
    for (const page of data.pages) {
      for (const evt of page) {
        next.add(evt.event_type);
      }
    }
    setDiscoveredTypes(Array.from(next).sort());
  }, [data]);

  useEffect(() => {
    if (!hasSubmitted || !queryEnabled) {
      return;
    }

    queryClient.removeQueries({
      queryKey: ["runtimeAnalytics", sessionId, eventType || null],
      exact: true
    });
    refetch();
  }, [eventType, hasSubmitted, queryEnabled, queryClient, refetch, sessionId]);

  const events = useMemo(() => (data?.pages ? data.pages.flat() : []), [data]);

  const { data: summaryData } = useQuery({
    queryKey: ["runtimeAnalyticsSummary", sessionId],
    queryFn: () =>
      queryEnabled
        ? apiGet<RuntimeEventSummary[]>(`/agents/sessions/${sessionId}/analytics/summary`)
        : Promise.resolve([]),
    enabled: queryEnabled,
  });

  const hasFilter = eventType.trim().length > 0;
  const isInitialLoading = isFetching && !data?.pages?.length;
  const isEmpty = !isInitialLoading && events.length === 0 && queryEnabled && hasSubmitted;

  const handleSubmit = async (submitEvent: React.FormEvent<HTMLFormElement>) => {
    submitEvent.preventDefault();
    if (!queryEnabled) {
      return;
    }
    setHasSubmitted(true);
    queryClient.removeQueries({
      queryKey: ["runtimeAnalytics", sessionId, eventType || null],
      exact: true
    });
    await refetch();
  };

  const handleResetFilter = () => {
    setEventType("");
  };

  const handleSelectSession = (selectedId: string) => {
    setSessionId(selectedId);
    setHasSubmitted(true);
  };

  return (
    <Panel
      title="Runtime analytics"
      description="Inspect agent routing, memory retrieval, and tool ordering decisions captured from runtime events."
      action={
        <form
          onSubmit={handleSubmit}
          className="flex flex-col gap-2 text-xs sm:flex-row sm:items-center"
        >
          <div className="flex items-center gap-2">
            <input
              type="text"
              required
              value={sessionId}
              onChange={(event) => setSessionId(event.target.value)}
              placeholder="Session UUID"
              list="session-id-suggestions"
              className="w-56 rounded-md border border-zinc-800 bg-black px-3 py-1 text-xs text-zinc-200 focus:border-zinc-600 focus:outline-none"
            />
            <datalist id="session-id-suggestions">
              {recentSessions.map((session) => (
                <option key={session.session_id} value={session.session_id} />
              ))}
            </datalist>
            <button
              type="submit"
              className="rounded-md border border-zinc-700 bg-black px-3 py-1 text-xs font-semibold text-zinc-200 transition hover:border-zinc-500 hover:bg-zinc-900"
            >
              {isInitialLoading ? "Loading…" : "Load"}
            </button>
          </div>
          <div className="flex items-center gap-2">
            <input
              type="text"
              list="runtime-event-type-options"
              value={eventType}
              onChange={(event) => setEventType(event.target.value)}
              placeholder="Filter by event type (optional)"
              className="w-56 rounded-md border border-zinc-800 bg-black px-3 py-1 text-xs text-zinc-200 focus:border-zinc-600 focus:outline-none"
            />
            <datalist id="runtime-event-type-options">
              {discoveredTypes.map((type) => (
                <option key={type} value={type} />
              ))}
            </datalist>
            <button
              type="button"
              onClick={handleResetFilter}
              className="rounded-md border border-zinc-800 px-3 py-1 text-xs text-zinc-300 transition hover:border-zinc-600 hover:bg-zinc-900 disabled:text-zinc-600"
              disabled={!hasFilter}
            >
              Clear filter
            </button>
          </div>
        </form>
      }
    >
      {recentSessions.length > 0 ? (
        <div className="mb-4 flex flex-wrap items-center gap-2 text-[11px] text-zinc-400">
          <span className="uppercase tracking-wide text-zinc-500">Recent sessions:</span>
          {recentSessions.map((session) => (
            <button
              key={session.session_id}
              type="button"
              onClick={() => handleSelectSession(session.session_id)}
              className={`rounded-full border px-3 py-1 transition ${
                sessionId === session.session_id
                  ? "border-zinc-200 bg-zinc-100/10 text-zinc-50"
                  : "border-zinc-800 text-zinc-300 hover:border-zinc-600"
              }`}
            >
              <span className="font-medium">
                {session.title?.trim() ? session.title : session.session_id.slice(0, 8)}
              </span>
              <span className="ml-2 text-zinc-500">{formatRelative(session.created_at)}</span>
            </button>
          ))}
        </div>
      ) : null}

      <div className="mb-4 flex flex-wrap items-center gap-2 text-[11px] text-zinc-400">
        <span className="uppercase tracking-wide text-zinc-500">Quick filters:</span>
        {discoveredTypes.map((type) => (
          <button
            key={type}
            type="button"
            onClick={() => setEventType(type)}
            className={`rounded-full border px-3 py-1 transition ${
              eventType === type
                ? "border-zinc-200 bg-zinc-100/10 text-zinc-50"
                : "border-zinc-800 text-zinc-300 hover:border-zinc-600"
            }`}
            aria-pressed={eventType === type}
          >
            {type.replace(/_/g, " ")}
          </button>
        ))}
      </div>

      {sessionId === "" ? (
        <p className="text-sm text-zinc-500">Provide a session ID to view its runtime event stream.</p>
      ) : isError ? (
        <p className="text-sm text-red-400">
          {(error as Error)?.message ?? "Failed to load runtime analytics. Please try again."}
        </p>
      ) : isInitialLoading ? (
        <p className="text-sm text-zinc-500">Fetching analytics…</p>
      ) : isEmpty ? (
        <p className="text-sm text-zinc-500">
          {hasFilter ? "No events match the selected type." : "No events recorded for this session (yet)."}
        </p>
      ) : (
        <>
          {summaryData && summaryData.length > 0 ? (
            <div className="mb-4 flex flex-wrap gap-2">
              {summaryData.map((summary) => (
                <div
                  key={summary.event_type}
                  className="rounded-lg border border-zinc-800 px-3 py-2 text-xs text-zinc-200"
                >
                  <div className="flex items-center justify-between gap-3 text-[11px] uppercase text-zinc-500">
                    <span>{summary.event_type.replace(/_/g, " ")}</span>
                    <span>{summary.event_count}</span>
                  </div>
                  <div className="mt-1 text-[11px] text-zinc-500">
                    <div>
                      First {summary.first_seen ? formatRelative(summary.first_seen) : "—"}
                    </div>
                    <div>
                      Last {summary.last_seen ? formatRelative(summary.last_seen) : "—"}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : null}
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

          {hasNextPage ? (
            <div className="mt-4 flex justify-center">
              <button
                type="button"
                onClick={() => fetchNextPage()}
                className="rounded-md border border-zinc-700 bg-black px-4 py-1 text-xs font-semibold text-zinc-200 transition hover:border-zinc-500 hover:bg-zinc-900 disabled:cursor-not-allowed disabled:border-zinc-900 disabled:text-zinc-600"
                disabled={isFetchingNextPage}
              >
                {isFetchingNextPage ? "Loading…" : "Load more"}
              </button>
            </div>
          ) : events.length > 0 ? (
            <p className="mt-4 text-center text-[11px] uppercase tracking-wide text-zinc-600">
              End of stream
            </p>
          ) : null}
        </>
      )}

      {hasFilter ? (
        <p className="mt-3 text-xs text-zinc-500">
          Showing events filtered by <span className="font-semibold text-zinc-300">{eventType}</span>.
        </p>
      ) : null}
    </Panel>
  );
}
