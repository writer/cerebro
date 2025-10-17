"use client";

import { useQuery } from "@tanstack/react-query";

import { apiGet } from "@/lib/api";
import { MemoryEntry, ReviewTask, SessionSummary } from "@/lib/types";
import { cn, formatRelative } from "@/lib/utils";

type ReviewDetailProps = {
  task: ReviewTask;
  onClose: () => void;
};

export function ReviewDetail({ task, onClose }: ReviewDetailProps) {
  const { data: sessionData, isLoading: sessionLoading } = useQuery({
    queryKey: ["sessionDetail", task.session_id],
    queryFn: () => apiGet<SessionSummary>(`/agents/sessions/${task.session_id}`),
  });

  const { data: memoryEntries, isLoading: memoryLoading } = useQuery({
    queryKey: ["sessionMemory", task.session_id],
    queryFn: () =>
      apiGet<MemoryEntry[]>(`/agents/sessions/${task.session_id}/memory`, {
        limit: 5,
        include_content: true,
      }),
  });

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
          </dl>
        </DetailCard>

        <DetailCard title="Agent payload" className="lg:col-span-2">
          <JSONPreview data={task.payload} />
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
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-slate-500">No memory items were attached to this session.</p>
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
