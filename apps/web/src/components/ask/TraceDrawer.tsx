"use client";

import type { AskTurnState } from "@/lib/ask";

type Props = {
  turn: AskTurnState | null;
  onClose: () => void;
};

const formatMs = (value?: number) => (typeof value === "number" ? `${value} ms` : "—");

const stringify = (value: unknown) => {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
};

export default function TraceDrawer({ turn, onClose }: Props) {
  if (!turn) return null;
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-slate-950/30 backdrop-blur-sm" onClick={onClose}>
      <aside
        className="flex h-full w-full max-w-xl flex-col border-l border-slate-200 bg-white shadow-2xl"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="flex items-start justify-between border-b border-slate-200 px-5 py-4">
          <div>
            <div className="text-[11px] uppercase tracking-[0.22em] text-slate-500">Trace</div>
            <div className="mt-1 text-[13px] font-semibold text-slate-900">{turn.question}</div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border border-slate-200 px-2 py-1 text-xs font-semibold uppercase tracking-wide text-slate-500 transition hover:border-slate-300 hover:text-slate-900"
          >
            Close
          </button>
        </header>
        <div className="flex-1 space-y-4 overflow-y-auto px-5 py-4 text-xs text-slate-700">
          <section>
            <div className="text-[10px] uppercase tracking-[0.22em] text-slate-400">Timing</div>
            <dl className="mt-2 grid grid-cols-2 gap-2">
              <div className="rounded-md border border-slate-200 bg-slate-50 p-2">
                <dt className="text-[10px] uppercase tracking-wide text-slate-500">Model</dt>
                <dd className="break-all font-mono text-[11px]">{turn.model ?? "default"}</dd>
              </div>
              <div className="rounded-md border border-slate-200 bg-slate-50 p-2">
                <dt className="text-[10px] uppercase tracking-wide text-slate-500">Tenant</dt>
                <dd className="break-all font-mono text-[11px]">{turn.tenantId ?? "writer"}</dd>
              </div>
              <div className="rounded-md border border-slate-200 bg-slate-50 p-2">
                <dt className="text-[10px] uppercase tracking-wide text-slate-500">Scope</dt>
                <dd className="break-all font-mono text-[11px]">{turn.scopeUrn ?? "—"}</dd>
              </div>
              <div className="rounded-md border border-slate-200 bg-slate-50 p-2">
                <dt className="text-[10px] uppercase tracking-wide text-slate-500">Status</dt>
                <dd className="font-mono text-[11px]">{turn.status}</dd>
              </div>
              <div className="rounded-md border border-slate-200 bg-slate-50 p-2">
                <dt className="text-[10px] uppercase tracking-wide text-slate-500">Cypher exec</dt>
                <dd className="text-[13px] font-semibold text-slate-900">{formatMs(turn.rows?.exec_ms)}</dd>
              </div>
              <div className="rounded-md border border-slate-200 bg-slate-50 p-2">
                <dt className="text-[10px] uppercase tracking-wide text-slate-500">Total</dt>
                <dd className="text-[13px] font-semibold text-slate-900">{formatMs(turn.done?.total_ms)}</dd>
              </div>
              <div className="rounded-md border border-slate-200 bg-slate-50 p-2">
                <dt className="text-[10px] uppercase tracking-wide text-slate-500">Tool connection</dt>
                <dd className="text-[13px] font-semibold text-slate-900">{formatMs(turn.done?.timings?.mcp_connect_ms)}</dd>
              </div>
              <div className="rounded-md border border-slate-200 bg-slate-50 p-2">
                <dt className="text-[10px] uppercase tracking-wide text-slate-500">First tool</dt>
                <dd className="text-[13px] font-semibold text-slate-900">{formatMs(turn.done?.timings?.first_tool_ms)}</dd>
              </div>
              <div className="rounded-md border border-slate-200 bg-slate-50 p-2">
                <dt className="text-[10px] uppercase tracking-wide text-slate-500">First text</dt>
                <dd className="text-[13px] font-semibold text-slate-900">{formatMs(turn.done?.timings?.first_delta_ms)}</dd>
              </div>
              <div className="rounded-md border border-slate-200 bg-slate-50 p-2">
                <dt className="text-[10px] uppercase tracking-wide text-slate-500">Tools</dt>
                <dd className="font-mono text-[11px]">{turn.done ? `${turn.done.tool_results ?? 0}/${turn.done.tool_calls ?? 0}` : "—"}</dd>
              </div>
              <div className="rounded-md border border-slate-200 bg-slate-50 p-2">
                <dt className="text-[10px] uppercase tracking-wide text-slate-500">Trace ID</dt>
                <dd className="break-all font-mono text-[11px]">{turn.done?.trace_id ?? "—"}</dd>
              </div>
              <div className="rounded-md border border-slate-200 bg-slate-50 p-2">
                <dt className="text-[10px] uppercase tracking-wide text-slate-500">Refused</dt>
                <dd className="font-mono text-[11px]">{turn.done?.cypher_refused ? "yes" : "no"}</dd>
              </div>
              <div className="rounded-md border border-slate-200 bg-slate-50 p-2">
                <dt className="text-[10px] uppercase tracking-wide text-slate-500">Plan source</dt>
                <dd className="break-all font-mono text-[11px]">{turn.queryPlan?.source ?? "—"}</dd>
              </div>
              <div className="rounded-md border border-slate-200 bg-slate-50 p-2">
                <dt className="text-[10px] uppercase tracking-wide text-slate-500">Corrected</dt>
                <dd className="font-mono text-[11px]">{turn.queryPlan?.corrected ? "yes" : "no"}</dd>
              </div>
            </dl>
          </section>

          {turn.queryPlan && (
            <section>
              <div className="text-[10px] uppercase tracking-[0.22em] text-slate-400">Query plan</div>
              <pre className="mt-2 overflow-x-auto rounded-md border border-slate-200 bg-slate-50 p-3 font-mono text-[11px] text-slate-800">
                {stringify(turn.queryPlan)}
              </pre>
            </section>
          )}

          {turn.summary?.citations?.length ? (
            <section>
              <div className="text-[10px] uppercase tracking-[0.22em] text-slate-400">Citations</div>
              <pre className="mt-2 overflow-x-auto rounded-md border border-slate-200 bg-slate-50 p-3 font-mono text-[11px] text-slate-800">
                {stringify(turn.summary.citations)}
              </pre>
            </section>
          ) : null}

          {turn.unknownEvents?.length ? (
            <section>
              <div className="text-[10px] uppercase tracking-[0.22em] text-slate-400">Extra stream events</div>
              <pre className="mt-2 overflow-x-auto rounded-md border border-slate-200 bg-slate-50 p-3 font-mono text-[11px] text-slate-800">
                {stringify(turn.unknownEvents)}
              </pre>
            </section>
          ) : null}

          <section>
            <div className="text-[10px] uppercase tracking-[0.22em] text-slate-400">Validator</div>
            <pre className="mt-2 overflow-x-auto rounded-md border border-slate-200 bg-slate-50 p-3 font-mono text-[11px] text-slate-800">
              {stringify(turn.cypher?.validator ?? null)}
            </pre>
          </section>

          <section>
            <div className="text-[10px] uppercase tracking-[0.22em] text-slate-400">Rationale</div>
            <p className="mt-2 rounded-md border border-slate-200 bg-slate-50 p-3">
              {turn.rationale || "—"}
            </p>
          </section>

          {turn.cypher?.cypher && (
            <section>
              <div className="text-[10px] uppercase tracking-[0.22em] text-slate-400">Cypher</div>
              <pre className="mt-2 overflow-x-auto rounded-md border border-slate-200 bg-[#0f172a] p-3 font-mono text-[11px] text-slate-100">
                {turn.cypher.cypher}
              </pre>
            </section>
          )}

          {turn.rows?.rows && (
            <section>
              <div className="text-[10px] uppercase tracking-[0.22em] text-slate-400">First 5 rows</div>
              <pre className="mt-2 overflow-x-auto rounded-md border border-slate-200 bg-slate-50 p-3 font-mono text-[11px] text-slate-800">
                {stringify(turn.rows.rows.slice(0, 5))}
              </pre>
            </section>
          )}

          {turn.error && (
            <section>
              <div className="text-[10px] uppercase tracking-[0.22em] text-rose-500">Error</div>
              <pre className="mt-2 overflow-x-auto rounded-md border border-rose-200 bg-rose-50 p-3 font-mono text-[11px] text-rose-700">
                {stringify(turn.error)}
              </pre>
            </section>
          )}
        </div>
      </aside>
    </div>
  );
}
