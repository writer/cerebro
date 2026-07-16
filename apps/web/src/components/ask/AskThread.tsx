"use client";

import { useEffect, useState } from "react";

import { type AskTurnState } from "@/lib/ask";
import GraphViewer from "@/components/grc/LazyGraphViewer";
import { EmptyBlock, ErrorBlock, LoadingBlock } from "@/components/grc/Primitives";
import CypherBlock from "./CypherBlock";
import MarkdownSummary from "./MarkdownSummary";
import RowsTable from "./RowsTable";
import TraceDrawer from "./TraceDrawer";

type Props = {
  turns: AskTurnState[];
  activeTurnId: string | null;
  onRetry: (turn: AskTurnState) => void;
  onStop: () => void;
};

const stepBadge = (label: string, active: boolean, done: boolean) => (
  <span
    className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
      done
        ? "border-emerald-200 bg-emerald-50 text-emerald-700"
        : active
          ? "border-indigo-200 bg-indigo-50 text-indigo-700"
          : "border-slate-200 bg-slate-50 text-slate-400"
    }`}
  >
    {label}
  </span>
);

const formatElapsed = (startedAt: number, now: number) => `${Math.max(0, Math.round((now - startedAt) / 1000))}s`;

const turnAnswerText = (turn: AskTurnState) =>
  turn.summary?.markdown ??
  turn.agentAnswerDraft ??
  turn.rationale ??
  (turn.rows ? JSON.stringify(turn.rows.rows, null, 2) : "") ??
  "";

const guidanceForError = (turn: AskTurnState) => {
  const code = turn.error?.code ?? "";
  if (code === "aborted") return "Stopped locally. Retry when you are ready to continue.";
  if (code === "stream_incomplete") return "The stream ended early. Retry usually fixes transient upstream disconnects.";
  if (code === "http_401" || code === "http_403") return "Check your API key and tenant scope.";
  if (code === "http_408" || code === "http_429" || code.startsWith("http_5")) return "This looks retryable. Try again or narrow the scope.";
  return "Review the trace and retry with a narrower question if needed.";
};

const sourcesFromTurn = (turn: AskTurnState) => {
  const seen = new Set<string>();
  return (turn.summary?.citations ?? []).filter((citation) => {
    if (seen.has(citation.urn)) return false;
    seen.add(citation.urn);
    return true;
  });
};

export default function AskThread({ turns, activeTurnId, onRetry, onStop }: Props) {
  const [traceTurn, setTraceTurn] = useState<AskTurnState | null>(null);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (!activeTurnId) return undefined;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [activeTurnId]);

  const copyAnswer = async (turn: AskTurnState) => {
    const text = turnAnswerText(turn);
    if (!text) return;
    await navigator.clipboard.writeText(text).catch(() => undefined);
  };

  const copyShareLink = async (turn: AskTurnState) => {
    const params = new URLSearchParams({ q: turn.question });
    if (turn.model) params.set("model", turn.model);
    if (turn.tenantId) params.set("tenant_id", turn.tenantId);
    if (turn.scopeUrn) params.set("scope_urn", turn.scopeUrn);
    const url = `${window.location.origin}/ask?${params.toString()}`;
    await navigator.clipboard.writeText(url).catch(() => undefined);
  };

  if (turns.length === 0) {
    return (
      <EmptyBlock label="Ask about a risk, owner, evidence item, source, or affected asset." />
    );
  }

  return (
    <div className="space-y-6">
      {turns.map((turn) => {
        const isActive = turn.id === activeTurnId;
        const hasQueryPlan = Boolean(turn.queryPlan);
        const hasCypher = Boolean(turn.cypher);
        const hasRows = Boolean(turn.rows);
        const displayedSummary = turn.summary ?? (turn.agentAnswerDraft ? { markdown: turn.agentAnswerDraft, citations: [] } : null);
        const hasSummary = Boolean(displayedSummary);
        const isDone = Boolean(turn.done);
        const isTerminal = turn.status === "completed" || turn.status === "error" || turn.status === "aborted";
        const isStalled = isActive && now - turn.updatedAt > 15_000;
        const sources = sourcesFromTurn(turn);
        return (
          <article
            key={turn.id}
            className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm"
          >
            <header className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-100 pb-3">
              <div>
                <div className="text-[11px] uppercase tracking-[0.22em] text-slate-500">
                  Question
                </div>
                <p className="mt-1 text-base font-semibold text-slate-900">{turn.question}</p>
                <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] text-slate-500">
                  <span>Model {turn.model ?? "default"}</span>
                  <span>Tenant {turn.tenantId ?? "writer"}</span>
                  {turn.scopeUrn && <span className="font-mono">Scope {turn.scopeUrn}</span>}
                  {isActive && <span>Elapsed {formatElapsed(turn.startedAt, now)}</span>}
                </div>
                {turn.queryPlan && (
                  <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] text-slate-500">
                    <span className="rounded-full border border-indigo-100 bg-indigo-50 px-2 py-0.5 font-semibold text-indigo-700">
                      Plan {turn.queryPlan.plan.intent}
                    </span>
                    <span>Source {turn.queryPlan.source}</span>
                    {turn.queryPlan.corrected && <span>Corrected draft Cypher</span>}
                    {turn.queryPlan.diagnostics?.length ? (
                      <span>{turn.queryPlan.diagnostics.length} diagnostics</span>
                    ) : null}
                  </div>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {stepBadge("Rationale", isActive && !turn.rationale, Boolean(turn.rationale))}
                {stepBadge("Plan", isActive && !hasQueryPlan && Boolean(turn.rationale), hasQueryPlan)}
                {stepBadge("Cypher", isActive && !hasCypher && hasQueryPlan, hasCypher)}
                {stepBadge("Rows", isActive && !hasRows && hasCypher, hasRows)}
                {stepBadge("Summary", isActive && !hasSummary && hasRows, hasSummary)}
                {turn.agentEvents?.length ? stepBadge(turn.agentMode === "legacy" ? "Ask" : "MCP", isActive, true) : null}
                <button
                  type="button"
                  onClick={() => setTraceTurn(turn)}
                  className="rounded-md border border-slate-200 bg-white px-2 py-1 text-[11px] font-semibold uppercase tracking-wide text-slate-600 transition hover:border-slate-300 hover:text-slate-900"
                >
                  Trace
                </button>
                {isActive ? (
                  <button
                    type="button"
                    onClick={onStop}
                    className="rounded-md border border-rose-200 bg-white px-2 py-1 text-[11px] font-semibold uppercase tracking-wide text-rose-700 transition hover:border-rose-300 hover:bg-rose-50"
                  >
                    Stop
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={() => onRetry(turn)}
                    className="rounded-md border border-slate-200 bg-white px-2 py-1 text-[11px] font-semibold uppercase tracking-wide text-slate-600 transition hover:border-indigo-300 hover:text-indigo-700"
                  >
                    Retry
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => void copyAnswer(turn)}
                  disabled={!turnAnswerText(turn)}
                  className="rounded-md border border-slate-200 bg-white px-2 py-1 text-[11px] font-semibold uppercase tracking-wide text-slate-600 transition hover:border-slate-300 hover:text-slate-900 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  Copy
                </button>
                <button
                  type="button"
                  onClick={() => void copyShareLink(turn)}
                  className="rounded-md border border-slate-200 bg-white px-2 py-1 text-[11px] font-semibold uppercase tracking-wide text-slate-600 transition hover:border-slate-300 hover:text-slate-900"
                >
                  Share
                </button>
              </div>
            </header>

            <div className="mt-4 space-y-4">
              {turn.error && (
                <div className="space-y-2">
                  <ErrorBlock error={`${turn.error.code}: ${turn.error.message}`} />
                  <p className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-[13px] text-amber-800">
                    {guidanceForError(turn)}
                  </p>
                </div>
              )}

              {isStalled && !turn.error && (
                <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-[13px] text-amber-800">
                  Still waiting for a response. You can stop this run and retry with a narrower scope.
                </div>
              )}

              {turn.agentEvents?.length ? (
                <section className="rounded-lg border border-slate-200 bg-slate-50 p-3">
                  <div className="text-[10px] uppercase tracking-[0.22em] text-slate-400">
                    Agent progress
                  </div>
                  <div className="mt-2 grid gap-1.5">
                    {turn.agentEvents.slice(-8).map((event, eventIndex) => (
                      <div key={`${event.at}:${event.type}:${eventIndex}:${"label" in event ? event.label : event.name}`} className="flex items-center gap-2 text-[12px] text-slate-600">
                        <span
                          className={`h-1.5 w-1.5 rounded-full ${
                            event.type === "tool"
                              ? event.status === "completed"
                                ? "bg-emerald-500"
                                : "bg-amber-500"
                              : "bg-indigo-500"
                          }`}
                        />
                        <span className="font-medium text-slate-700">
                          {event.type === "tool" ? event.name : event.label}
                        </span>
                        {event.type === "tool" ? (
                          <span className="text-slate-400">{event.status}</span>
                        ) : event.detail ? (
                          <span className="truncate text-slate-400">{event.detail}</span>
                        ) : null}
                      </div>
                    ))}
                  </div>
                </section>
              ) : null}

              {turn.rationale && (
                <section>
                  <div className="text-[10px] uppercase tracking-[0.22em] text-slate-400">
                    Rationale
                  </div>
                  <p className="mt-2 rounded-lg border border-slate-200 bg-slate-50 p-3 text-[13px] text-slate-800">
                    {turn.rationale}
                  </p>
                </section>
              )}

              {turn.cypher && (
                <section>
                  <CypherBlock cypher={turn.cypher.cypher} validator={turn.cypher.validator} />
                  {!turn.cypher.validator.ok && (
                    <div className="mt-2 rounded-lg border border-rose-200 bg-rose-50 p-3 text-[13px] text-rose-800">
                      Query execution was refused. Try asking for a read-only summary, adding an entity scope, or reducing the requested row count.
                    </div>
                  )}
                </section>
              )}

              {!turn.rows && hasCypher && !turn.error && !isDone && (
                <LoadingBlock label="Executing against Neo4j..." />
              )}

              {turn.rows && (
                <section className="space-y-3">
                  {turn.rows.graph?.root && (
                    <GraphViewer graph={turn.rows.graph} />
                  )}
                  <RowsTable rows={turn.rows.rows} execMs={turn.rows.exec_ms} />
                  {turn.rows.rows.length === 0 && isTerminal && (
                    <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-[13px] text-slate-600">
                      No rows came back. Try a broader scope, remove a strict filter, or ask for available entities first.
                    </div>
                  )}
                </section>
              )}

              {displayedSummary && (
                <section>
                  <div className="text-[10px] uppercase tracking-[0.22em] text-slate-400">
                    Summary
                  </div>
                  <div className="mt-2 rounded-lg border border-indigo-100 bg-indigo-50 p-4">
                    <MarkdownSummary
                      markdown={displayedSummary.markdown}
                      citations={displayedSummary.citations}
                    />
                  </div>
                  {sources.length > 0 && (
                    <div className="mt-3 rounded-lg border border-indigo-100 bg-white p-3">
                      <div className="text-[10px] uppercase tracking-[0.22em] text-slate-400">Sources</div>
                      <div className="mt-2 flex flex-wrap gap-2">
                        {sources.map((source) => (
                          <a
                            key={source.urn}
                            href={`/impact?root_urn=${encodeURIComponent(source.urn)}`}
                            className="rounded-md border border-indigo-100 bg-indigo-50 px-2 py-1 font-mono text-[11px] text-indigo-700 transition hover:border-indigo-300 hover:text-indigo-900"
                          >
                            {source.urn}
                          </a>
                        ))}
                      </div>
                    </div>
                  )}
                </section>
              )}

              {isDone && turn.done && (
                <footer className="flex flex-wrap items-center gap-4 border-t border-slate-100 pt-2 text-[11px] text-slate-500">
                  <span>Total {turn.done.total_ms} ms</span>
                  <span>Trace {turn.done.trace_id}</span>
                  {turn.done.cypher_refused && (
                    <span className="rounded-full border border-rose-200 bg-rose-50 px-2 py-0.5 font-semibold uppercase tracking-wide text-rose-700">
                      Cypher refused
                    </span>
                  )}
                  {turn.unknownEvents?.length ? <span>{turn.unknownEvents.length} extra stream events</span> : null}
                </footer>
              )}
            </div>
          </article>
        );
      })}
      <TraceDrawer turn={traceTurn} onClose={() => setTraceTurn(null)} />
    </div>
  );
}
