"use client";

import { useMemo, useState } from "react";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";

import { apiGet } from "@/lib/api";
import {
  MemoryEntry,
  MemoryStats,
  ReviewTask,
  RuntimeEvent,
  RuntimeEventSummary,
  SessionSummary,
} from "@/lib/types";
import { cn, formatRelative } from "@/lib/utils";

type ReviewDetailProps = {
  task: ReviewTask;
  onClose: () => void;
};

export function ReviewDetail({ task, onClose }: ReviewDetailProps) {
  const [eventType, setEventType] = useState("");
  const ANALYTICS_PAGE_SIZE = 20;
  type AnalyticsCursor = {
    createdAt: string;
    eventId?: string;
  };
  const { data: sessionData, isLoading: sessionLoading } = useQuery({
    queryKey: ["sessionDetail", task.session_id],
    queryFn: () => apiGet<SessionSummary>(`/agents/sessions/${task.session_id}`),
  });

  const sessionInfo = sessionData?.session;
  const toolInvocations = sessionData?.tool_invocations ?? [];
  const metrics = sessionData?.metrics ?? {};

  const { data: memoryEntries, isLoading: memoryLoading } = useQuery({
    queryKey: ["sessionMemory", task.session_id],
    queryFn: () =>
      apiGet<MemoryEntry[]>(`/agents/sessions/${task.session_id}/memory`, {
        limit: 5,
        include_content: true,
      }),
  });

  const { data: memoryStats, isLoading: statsLoading } = useQuery({
    queryKey: ["sessionMemoryStats", task.session_id],
    queryFn: () => apiGet<MemoryStats>(`/agents/sessions/${task.session_id}/memory/stats`),
  });

  const {
    data: runtimeEventPages,
    isFetching: analyticsFetching,
    fetchNextPage: fetchMoreRuntimeEvents,
    hasNextPage: hasMoreRuntimeEvents,
    isFetchingNextPage,
  } = useInfiniteQuery({
    queryKey: ["sessionAnalytics", task.session_id, eventType],
    enabled: Boolean(task.session_id),
    initialPageParam: undefined as AnalyticsCursor | undefined,
    queryFn: async ({ pageParam }) => {
      const params: Record<string, unknown> = { limit: ANALYTICS_PAGE_SIZE };
      if (eventType) {
        params.event_type = eventType;
      }
      const cursor = pageParam as AnalyticsCursor | undefined;
      if (cursor?.createdAt) {
        params.cursor = cursor.createdAt;
      }
      if (cursor?.eventId) {
        params.cursor_id = cursor.eventId;
      }
      return apiGet<RuntimeEvent[]>(`/agents/sessions/${task.session_id}/analytics`, params);
    },
    getNextPageParam: (lastPage) => {
      if (!lastPage || lastPage.length < ANALYTICS_PAGE_SIZE) {
        return undefined;
      }
      const tail = lastPage[lastPage.length - 1];
      if (!tail) {
        return undefined;
      }
      return {
        createdAt: tail.created_at,
        eventId: tail.id,
      } satisfies AnalyticsCursor;
    },
  });

  const runtimeEvents = useMemo(
    () => (runtimeEventPages?.pages ? runtimeEventPages.pages.flat() : []),
    [runtimeEventPages],
  );
  const analyticsLoading = analyticsFetching && !runtimeEventPages?.pages?.length;

  const { data: analyticsSummary } = useQuery({
    queryKey: ["sessionAnalyticsSummary", task.session_id],
    queryFn: () => apiGet<RuntimeEventSummary[]>(`/agents/sessions/${task.session_id}/analytics/summary`),
    enabled: Boolean(task.session_id),
  });

  const availableEventTypes = useMemo(() => {
    if (analyticsSummary && analyticsSummary.length > 0) {
      return analyticsSummary.map((item) => item.event_type);
    }
    const types = new Set<string>();
    runtimeEvents.forEach((event) => types.add(event.event_type));
    return Array.from(types);
  }, [analyticsSummary, runtimeEvents]);

  return (
    <section className="rounded-xl border border-slate-800 bg-slate-900/70 px-5 py-4 shadow-xl">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-[11px] uppercase tracking-wide text-slate-500">Task detail</p>
          <h2 className="mt-1 text-lg font-semibold text-slate-100">{task.title}</h2>
          <p className="mt-1 text-sm text-slate-300">{task.summary || "No summary provided."}</p>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="rounded-md border border-slate-700 bg-slate-900 px-3 py-1 text-xs font-semibold text-slate-200 hover:border-slate-600"
        >
          Close
        </button>
      </div>

      <div className="mt-5 grid gap-5 lg:grid-cols-3">
        <DetailCard title="Metadata" className="lg:col-span-1">
          <dl className="space-y-2 text-xs">
            <DetailRow label="Status" value={task.status} />
            <DetailRow label="Priority" value={task.priority ?? "—"} />
            <DetailRow label="Created" value={formatRelative(task.created_at)} />
            <DetailRow label="Resolved" value={formatRelative(task.resolved_at)} />
            <DetailRow label="Reviewer" value={task.resolved_by ?? "—"} />
            <DetailRow label="Escalated to" value={task.escalated_to ?? "—"} />
            <DetailRow label="Ticket ref" value={task.ticket_reference ?? "—"} />
            <DetailRow label="Notification" value={task.notification_channel ?? "—"} />
            <DetailRow label="Session" value={task.session_id} mono />
            {sessionInfo ? (
              <>
                <DetailRow label="Agent" value={sessionInfo.agent_type} />
                <DetailRow label="Session status" value={sessionInfo.status} />
                <DetailRow label="Started" value={formatRelative(sessionInfo.created_at)} />
              </>
            ) : null}
          </dl>
        </DetailCard>

        <DetailCard title="Agent payload" className="lg:col-span-2">
          <JSONPreview data={task.payload} />
        </DetailCard>
      </div>

      <div className="mt-5 grid gap-5 lg:grid-cols-2">
        <DetailCard
          title="Session context"
          description="Scope and configuration passed to the runtime."
        >
          {sessionInfo?.context && Object.keys(sessionInfo.context).length > 0 ? (
            <dl className="space-y-2 text-xs">
              {Object.entries(sessionInfo.context).map(([key, value]) => (
                <div key={key} className="flex flex-col gap-1 rounded-md bg-slate-900/70 p-2">
                  <span className="text-[11px] uppercase text-slate-500">{key}</span>
                  <span className="text-slate-200">
                    {Array.isArray(value) || typeof value === "object"
                      ? JSON.stringify(value, null, 2)
                      : String(value)}
                  </span>
                </div>
              ))}
            </dl>
          ) : (
            <p className="text-xs text-slate-500">No additional context captured for this session.</p>
          )}
        </DetailCard>

        <DetailCard
          title="Memory role distribution"
          description="Breakdown of roles represented in long-term memory."
        >
          {statsLoading ? (
            <p className="text-xs text-slate-400">Fetching distribution…</p>
          ) : memoryStats && Object.keys(memoryStats.role_distribution).length > 0 ? (
            <ul className="space-y-2 text-xs text-slate-200">
              {Object.entries(memoryStats.role_distribution).map(([role, count]) => (
                <li key={role} className="flex items-center justify-between">
                  <span className="uppercase text-slate-500">{role}</span>
                  <span className="rounded bg-slate-900/70 px-2 py-0.5 text-[11px]">{count}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-slate-500">Role distribution not available.</p>
          )}
        </DetailCard>
      </div>

      <div className="mt-5 grid gap-5 lg:grid-cols-2">
        <DetailCard
          title="Conversation excerpts"
          description="Last 5 messages recorded for this session."
        >
          {sessionLoading ? (
            <p className="text-xs text-slate-400">Loading session messages…</p>
          ) : sessionData?.messages && sessionData.messages.length > 0 ? (
            <ul className="space-y-3">
              {sessionData.messages.slice(-5).map((message) => (
                <li key={message.message_id} className="rounded-md bg-slate-900/80 p-3">
                  <div className="flex items-center justify-between text-[11px] uppercase text-slate-500">
                    <span>{message.role}</span>
                    <span>{formatRelative(message.timestamp)}</span>
                  </div>
                  <p className="mt-2 text-sm text-slate-200 whitespace-pre-wrap">{message.content}</p>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-slate-500">No messages available for this session.</p>
          )}
        </DetailCard>

        <DetailCard
          title="Relevant memory snippets"
          description="Highlights the context retrieved when the agent handled this task."
        >
          {memoryLoading ? (
            <p className="text-xs text-slate-400">Loading memory snippets…</p>
          ) : memoryEntries && memoryEntries.length > 0 ? (
            <ul className="space-y-3">
              {memoryEntries.map((entry) => (
                <li key={entry.id} className="rounded-md bg-slate-900/80 p-3">
                  <div className="flex items-center justify-between text-[11px] uppercase text-slate-500">
                    <span>{entry.role ?? "memory"}</span>
                    <span>Decay {entry.decay_score.toFixed(2)}</span>
                  </div>
                  <p className="mt-2 text-sm text-slate-200 whitespace-pre-wrap">
                    {entry.summary || entry.content || "No summary available."}
                  </p>
                  <div className="mt-2 text-[11px] text-slate-500">
                    {entry.scope_labels.length > 0 ? entry.scope_labels.join(" · ") : "Unscoped"}
                  </div>
                  {(entry.embedding_similarity ?? entry.lexical_similarity ?? entry.combined_similarity) ? (
                    <div className="mt-2 grid grid-cols-3 gap-2 text-[11px] text-slate-400">
                      <span>
                        Emb {entry.embedding_similarity?.toFixed(2) ?? "—"}
                      </span>
                      <span>
                        Lex {entry.lexical_similarity?.toFixed(2) ?? "—"}
                      </span>
                      <span>
                        Ann {entry.ann_selected ? "yes" : "no"}
                      </span>
                    </div>
                  ) : null}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-slate-500">No memory items were attached to this session.</p>
          )}
        </DetailCard>
      </div>

      <div className="mt-5 grid gap-5 lg:grid-cols-2">
        <DetailCard
          title="Memory statistics"
          description="Recency, scope coverage, and high-signal memories captured for this session."
        >
          {statsLoading ? (
            <p className="text-xs text-slate-400">Calculating memory statistics…</p>
          ) : memoryStats ? (
            <div className="space-y-3 text-xs text-slate-200">
              <div className="grid grid-cols-2 gap-3">
                <MetricPill label="Total" value={memoryStats.total_entries} />
                <MetricPill label="Recent" value={memoryStats.recent_entries} />
                <MetricPill label="Presented" value={memoryStats.presented_entries} />
                <MetricPill label="Tokens" value={memoryStats.token_total} />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <MetricPill label="Avg decay" value={memoryStats.average_decay.toFixed(2)} />
                <MetricPill label="Scopes" value={Object.keys(memoryStats.scope_distribution).length} />
              </div>
              {memoryStats.top_memories.length > 0 ? (
                <div>
                  <p className="text-[11px] uppercase text-slate-500">Top memories</p>
                  <ul className="mt-2 space-y-2">
                    {memoryStats.top_memories.map((memory) => (
                      <li key={memory.id} className="rounded-md bg-slate-900/70 p-2">
                        <div className="flex items-center justify-between text-[11px] text-slate-500">
                          <span>{memory.role ?? "memory"}</span>
                          <span>Decay {memory.decay_score.toFixed(2)}</span>
                        </div>
                        <p className="mt-1 text-xs text-slate-200">
                          {memory.summary ?? "No summary available."}
                        </p>
                        <p className="mt-1 text-[11px] text-slate-500">
                          Last accessed {formatRelative(memory.last_accessed_at)}
                        </p>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          ) : (
            <p className="text-xs text-slate-500">No memory statistics available.</p>
          )}
        </DetailCard>

        <DetailCard
          title="Recent runtime events"
          description="Latest routing, tool, and memory signals emitted by the runtime."
        >
        {analyticsLoading ? (
          <p className="text-xs text-slate-400">Fetching analytics…</p>
        ) : runtimeEvents && runtimeEvents.length > 0 ? (
          <>
            <div className="mb-3 flex flex-wrap items-center gap-2 text-[11px] text-slate-500">
              <span className="uppercase">Filter:</span>
              <select
                id="event-filter"
                value={eventType}
                onChange={(event) => setEventType(event.target.value)}
                className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-200"
              >
                <option value="">All events</option>
                {availableEventTypes.map((type) => (
                  <option key={type} value={type}>
                    {type.replace(/_/g, " ")}
                  </option>
                ))}
              </select>
              {analyticsSummary && analyticsSummary.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {analyticsSummary.map((summary) => (
                    <button
                      key={summary.event_type}
                      type="button"
                      onClick={() => setEventType(summary.event_type)}
                      className={`rounded-full border px-3 py-1 transition ${
                        eventType === summary.event_type
                          ? "border-slate-300 bg-slate-200/10 text-slate-50"
                          : "border-slate-800 text-slate-300 hover:border-slate-600"
                      }`}
                      title={`First ${summary.first_seen ? formatRelative(summary.first_seen) : "—"} · Last ${summary.last_seen ? formatRelative(summary.last_seen) : "—"}`}
                    >
                      <span className="font-semibold">{summary.event_type.replace(/_/g, " ")}</span>
                      <span className="ml-2 text-slate-500">{summary.event_count}</span>
                    </button>
                  ))}
                </div>
              ) : null}
            </div>

            <ul className="space-y-3">
              {runtimeEvents.map((event) => (
                <li key={event.id} className="rounded-md bg-slate-900/70 p-3">
                  <div className="flex items-center justify-between text-[11px] uppercase text-slate-500">
                    <span>{event.event_type}</span>
                    <span>{formatRelative(event.created_at)}</span>
                  </div>
                  <pre className="mt-2 max-h-40 overflow-auto rounded bg-slate-950/80 p-2 text-[11px] text-slate-300">
                    {JSON.stringify(event.payload, null, 2)}
                  </pre>
                </li>
              ))}
            </ul>

            {hasMoreRuntimeEvents ? (
              <div className="mt-3 flex justify-center">
                <button
                  type="button"
                  onClick={() => fetchMoreRuntimeEvents()}
                  className="rounded-md border border-slate-700 bg-slate-900 px-3 py-1 text-xs font-semibold text-slate-200 hover:border-slate-600"
                  disabled={isFetchingNextPage}
                >
                  {isFetchingNextPage ? "Loading…" : "Load more"}
                </button>
              </div>
            ) : null}
          </>
        ) : (
          <p className="text-xs text-slate-500">No runtime events recorded for this session yet.</p>
        )}
        </DetailCard>
      </div>

      <div className="mt-5 grid gap-5 lg:grid-cols-2">
        <DetailCard
          title="Tool invocation history"
          description="Recent tool calls issued during this session."
        >
          {toolInvocations.length === 0 ? (
            <p className="text-xs text-slate-500">No tool executions recorded for this session.</p>
          ) : (
            <ul className="space-y-3">
              {toolInvocations.map((invocation) => (
                <li key={invocation.id} className="rounded-md bg-slate-900/70 p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] uppercase text-slate-500">
                    <span>{invocation.tool_name}</span>
                    <span>{invocation.status}</span>
                  </div>
                  <p className="mt-1 text-[11px] text-slate-400">
                    Started {formatRelative(invocation.started_at)}
                    {invocation.completed_at ? ` · Completed ${formatRelative(invocation.completed_at)}` : ""}
                  </p>
                  {invocation.error_message ? (
                    <p className="mt-2 text-[11px] text-rose-400">{invocation.error_message}</p>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </DetailCard>

        <DetailCard
          title="Session metrics"
          description="Telemetry derived from runtime analytics and memory retrieval."
        >
          {Object.keys(metrics).length === 0 ? (
            <p className="text-xs text-slate-500">No metrics captured for this session.</p>
          ) : (
            <dl className="space-y-2 text-xs">
              {Object.entries(metrics).map(([key, value]) => (
                <MetricRow key={key} label={key} value={value} />
              ))}
            </dl>
          )}
        </DetailCard>
      </div>

      {task.resolution_notes ? (
        <div className="mt-5 rounded-lg border border-slate-800 bg-slate-950/70 p-4">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">
            Reviewer notes
          </h3>
          <p className="mt-2 text-sm text-slate-200 whitespace-pre-wrap">{task.resolution_notes}</p>
        </div>
      ) : null}
    </section>
  );
}

type DetailCardProps = {
  title: string;
  children: React.ReactNode;
  description?: string;
  className?: string;
};

function DetailCard({ title, description, children, className }: DetailCardProps) {
  return (
    <article
      className={cn("rounded-xl border border-slate-800 bg-slate-950/50 p-4 shadow-inner", className)}
    >
      <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">{title}</h3>
      {description ? <p className="mt-1 text-[11px] text-slate-500">{description}</p> : null}
      <div className="mt-3 text-sm text-slate-200">{children}</div>
    </article>
  );
}

type DetailRowProps = {
  label: string;
  value: string;
  mono?: boolean;
};

function DetailRow({ label, value, mono }: DetailRowProps) {
  return (
    <div className="flex justify-between gap-3">
      <span className="text-slate-500">{label}</span>
      <span className={cn("text-slate-200", mono && "font-mono text-[11px]")}>{value}</span>
    </div>
  );
}

function MetricPill({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-md border border-slate-800 bg-slate-900/70 px-3 py-2 text-[11px] uppercase text-slate-400">
      <div>{label}</div>
      <div className="mt-1 text-sm font-semibold text-slate-100">{value}</div>
    </div>
  );
}

function MetricRow({ label, value }: { label: string; value: unknown }) {
  const formattedLabel = label.replace(/_/g, " ");
  const formattedValue = (() => {
    if (typeof value === "number") {
      return value.toString();
    }
    if (typeof value === "boolean") {
      return value ? "true" : "false";
    }
    if (Array.isArray(value) || typeof value === "object") {
      return JSON.stringify(value, null, 2);
    }
    return String(value ?? "—");
  })();

  const isMultiline = formattedValue.includes("\n");

  return (
    <div className="flex flex-col gap-1 rounded-md bg-slate-900/60 p-2">
      <span className="text-[11px] uppercase text-slate-500">{formattedLabel}</span>
      {isMultiline ? (
        <pre className="max-h-36 overflow-auto whitespace-pre-wrap text-[11px] text-slate-200">
          {formattedValue}
        </pre>
      ) : (
        <span className="text-slate-200">{formattedValue}</span>
      )}
    </div>
  );
}

function JSONPreview({ data }: { data: Record<string, unknown> }) {
  if (!data || Object.keys(data).length === 0) {
    return <p className="text-xs text-slate-500">No payload provided.</p>;
  }
  return (
    <pre className="max-h-72 overflow-auto rounded-md bg-slate-900/80 p-3 text-[11px] text-slate-200">
      {JSON.stringify(data, null, 2)}
    </pre>
  );
}
