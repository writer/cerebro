"use client";

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { apiGet } from "@/lib/api";
import { PolicySuggestion } from "@/lib/types";
import { formatRelative } from "@/lib/utils";
import { Panel } from "@/components/ui/panel";

export function PolicyPanel() {
  const [search, setSearch] = useState("");
  const { data, isLoading } = useQuery({
    queryKey: ["policySuggestions"],
    queryFn: () => apiGet<PolicySuggestion[]>("/agents/policy-suggestions")
  });

  const suggestions = useMemo(() => {
    const entries = data ?? [];
    if (!search) return entries;
    return entries.filter((entry) =>
      `${entry.tool_name} ${entry.cel_expression}`.toLowerCase().includes(search.toLowerCase())
    );
  }, [data, search]);

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
          className="rounded-md border border-slate-700 bg-slate-900 px-3 py-1 text-xs text-slate-100"
        />
      }
    >
      <div className="space-y-3">
        {isLoading ? (
          <p className="text-sm text-slate-400">Loading policy suggestions…</p>
        ) : suggestions.length === 0 ? (
          <p className="text-sm text-slate-500">No suggestions yet—resolve review tasks to generate guardrails.</p>
        ) : (
          <div className="space-y-4">
            {suggestions.map((suggestion) => (
              <article
                key={suggestion.id}
                className="rounded-lg border border-slate-800 bg-slate-950/70 p-4 text-sm shadow-inner"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-100">{suggestion.tool_name}</h3>
                    <p className="text-xs text-slate-400">
                      Confidence {(suggestion.confidence * 100).toFixed(1)}% · Support {suggestion.support_count} · Reject {suggestion.reject_count}
                    </p>
                  </div>
                  <span className="text-[11px] uppercase text-slate-500">
                    Updated {formatRelative(suggestion.last_seen)}
                  </span>
                </div>
                <pre className="mt-3 overflow-x-auto rounded-md bg-slate-900/70 p-3 text-xs text-emerald-300">
                  {suggestion.cel_expression}
                </pre>
                {suggestion.metadata ? (
                  <details className="mt-3 text-xs text-slate-300">
                    <summary className="cursor-pointer text-slate-200">Example metadata</summary>
                    <pre className="mt-2 overflow-x-auto rounded-md bg-slate-900/60 p-2 text-[11px] text-slate-300">
                      {JSON.stringify(suggestion.metadata, null, 2)}
                    </pre>
                  </details>
                ) : null}
              </article>
            ))}
          </div>
        )}
      </div>
    </Panel>
  );
}
