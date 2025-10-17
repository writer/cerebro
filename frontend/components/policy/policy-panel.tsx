"use client";

import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";

import { apiGet, apiPost } from "@/lib/api";
import { PolicySimulationResult, PolicySuggestion } from "@/lib/types";
import { formatRelative } from "@/lib/utils";
import { Panel } from "@/components/ui/panel";

export function PolicyPanel() {
  const [search, setSearch] = useState("");
  const [expression, setExpression] = useState("");
  const [simulationTool, setSimulationTool] = useState("");
  const [limit, setLimit] = useState(50);
  const { data, isLoading } = useQuery({
    queryKey: ["policySuggestions"],
    queryFn: () => apiGet<PolicySuggestion[]>("/agents/policy-suggestions")
  });

  const simulationMutation = useMutation({
    mutationFn: (payload: { expression: string; tool_name?: string; limit: number }) =>
      apiPost<PolicySimulationResult>("/agents/policy-suggestions/simulate", payload)
  });

  const suggestions = useMemo(() => {
    const entries = data ?? [];
    if (!search) return entries;
    return entries.filter((entry) =>
      `${entry.tool_name} ${entry.cel_expression}`.toLowerCase().includes(search.toLowerCase())
    );
  }, [data, search]);

  const onSimulate = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!expression.trim()) return;

    const payload = {
      expression,
      tool_name: simulationTool ? simulationTool : undefined,
      limit: Number.isNaN(limit) ? 50 : limit
    };
    await simulationMutation.mutateAsync(payload);
  };

  const simulation = simulationMutation.data;
  const simulationError = simulationMutation.error;

  return (
    <Panel
      title="Policy guardrail intelligence"
      description="Agent review outcomes automatically recommend CEL guardrails to harden future actions."
      action={
        <input
          type="search"
          placeholder="Filter suggestions"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          className="rounded-md border border-zinc-800 bg-black px-3 py-1 text-xs text-zinc-200 focus:border-zinc-600 focus:outline-none"
        />
      }
    >
      <div className="space-y-3">
        {isLoading ? (
          <p className="text-sm text-zinc-500">Loading policy suggestions…</p>
        ) : suggestions.length === 0 ? (
          <p className="text-sm text-zinc-500">No suggestions yet—resolve review tasks to generate guardrails.</p>
        ) : (
          <div className="space-y-4">
            {suggestions.map((suggestion) => (
              <article
                key={suggestion.id}
                className="rounded-lg border border-zinc-900 bg-black/75 p-4 text-sm shadow-inner"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <h3 className="text-sm font-semibold text-zinc-100">{suggestion.tool_name}</h3>
                    <p className="text-xs text-zinc-400">
                      Confidence {(suggestion.confidence * 100).toFixed(1)}% · Support {suggestion.support_count} · Reject {suggestion.reject_count}
                    </p>
                  </div>
                  <span className="text-[11px] uppercase text-zinc-500">
                    Updated {formatRelative(suggestion.last_seen)}
                  </span>
                </div>
                <pre className="mt-3 overflow-x-auto rounded-md bg-zinc-900/70 p-3 text-xs text-emerald-300">
                  {suggestion.cel_expression}
                </pre>
                {suggestion.metadata ? (
                  <details className="mt-3 text-xs text-zinc-300">
                    <summary className="cursor-pointer text-zinc-200">Example metadata</summary>
                    <pre className="mt-2 overflow-x-auto rounded-md bg-zinc-900/60 p-2 text-[11px] text-zinc-200">
                      {JSON.stringify(suggestion.metadata, null, 2)}
                    </pre>
                  </details>
                ) : null}
              </article>
            ))}
          </div>
        )}
      </div>

      <section className="mt-6 rounded-lg border border-zinc-900 bg-black/80 p-4">
        <header className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-zinc-100">Policy simulation</h3>
            <p className="text-xs text-zinc-500">
              Evaluate a CEL expression against recent tool invocations before enforcing it live.
            </p>
          </div>
        </header>

        <form className="mt-4 space-y-3" onSubmit={onSimulate}>
          <textarea
            value={expression}
            onChange={(event) => setExpression(event.target.value)}
            className="h-28 w-full rounded-md border border-zinc-800 bg-black px-3 py-2 text-sm text-zinc-200 focus:border-zinc-600 focus:outline-none"
            placeholder="resource.inputs.action == 'delete'"
            required
          />

          <div className="grid gap-3 sm:grid-cols-3">
            <input
              type="text"
              value={simulationTool}
              onChange={(event) => setSimulationTool(event.target.value)}
              placeholder="Tool name (optional)"
              className="rounded-md border border-zinc-800 bg-black px-3 py-1 text-xs text-zinc-200 focus:border-zinc-600 focus:outline-none"
            />
            <input
              type="number"
              min={1}
              max={200}
              value={limit}
              onChange={(event) => setLimit(Number(event.target.value))}
              className="rounded-md border border-zinc-800 bg-black px-3 py-1 text-xs text-zinc-200 focus:border-zinc-600 focus:outline-none"
            />
            <button
              type="submit"
              disabled={simulationMutation.isPending}
              className="rounded-md border border-zinc-700 bg-black px-3 py-1 text-xs font-semibold text-zinc-200 transition hover:border-zinc-500 hover:bg-zinc-900 disabled:opacity-60"
            >
              {simulationMutation.isPending ? "Evaluating…" : "Simulate"}
            </button>
          </div>
        </form>

        {simulationError ? (
          <p className="mt-3 text-xs text-rose-400">
            {simulationError instanceof Error ? simulationError.message : String(simulationError)}
          </p>
        ) : null}

        {simulation ? (
          <div className="mt-4 space-y-3 text-xs text-zinc-200">
            <p>
              Evaluated {simulation.evaluated_count} invocations · Matched {simulation.matched_count} ·
              Mismatched {simulation.mismatched_count} · Errors {simulation.error_count}
            </p>
            {simulation.examples.length > 0 ? (
              <ul className="space-y-3">
                {simulation.examples.map((example) => (
                  <li key={example.invocation_id} className="rounded-md border border-zinc-900 bg-black/70 p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] uppercase text-zinc-500">
                      <span>{example.tool_name}</span>
                      <span>{example.matched ? "MATCH" : "MISS"}</span>
                    </div>
                    <p className="mt-1 text-[11px] text-zinc-500">
                      {example.started_at ? `Started ${formatRelative(example.started_at)}` : "Start time unknown"}
                      {example.latency_ms ? ` · ${example.latency_ms.toFixed(1)}ms` : ""}
                    </p>
                    {example.error ? (
                      <p className="mt-2 text-[11px] text-rose-400">{example.error}</p>
                    ) : null}
                    <details className="mt-2 text-[11px] text-zinc-300">
                      <summary className="cursor-pointer text-zinc-200">Invocation payload</summary>
                      <pre className="mt-2 max-h-48 overflow-auto rounded bg-zinc-900/80 p-2 text-zinc-200">
                        {JSON.stringify(
                          {
                            inputs: example.input_data,
                            output: example.output_data,
                            context: example.cel_context
                          },
                          null,
                          2
                        )}
                      </pre>
                    </details>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-zinc-500">No representative examples captured yet.</p>
            )}
          </div>
        ) : null}
      </section>
    </Panel>
  );
}
