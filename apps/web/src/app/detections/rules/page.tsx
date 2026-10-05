"use client";

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { EmptyBlock, ErrorBlock, LoadingBlock, MetricCard, PageHeader, Panel } from "@/components/grc/Primitives";
import { fetchCerebro } from "@/lib/cerebro-client";
import { awaitsExternalVerdict, type FindingRuleSpec } from "@/lib/detection-rules";

type ListFindingRulesResponse = { rules?: FindingRuleSpec[] };

type Binding = "all" | "live" | "external";

const inputClass =
  "w-full rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-2.5 py-1.5 text-[13px] text-[var(--text-primary)] outline-none focus:border-[color:var(--primary)]";

export default function DetectionRulesPage() {
  const [query, setQuery] = useState("");
  const [binding, setBinding] = useState<Binding>("all");

  const rulesQuery = useQuery<FindingRuleSpec[], Error>({
    queryFn: async ({ signal }) => {
      const response = await fetchCerebro<ListFindingRulesResponse>("/finding-rules", undefined, { signal });
      if (!response.ok) {
        throw new Error(`Detection rules are unavailable (HTTP ${response.status}).`);
      }
      return response.data?.rules ?? [];
    },
    queryKey: ["detection-rules"],
  });

  const rules = useMemo(() => rulesQuery.data ?? [], [rulesQuery.data]);

  const externalCount = useMemo(() => rules.filter(awaitsExternalVerdict).length, [rules]);

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return rules.filter((rule) => {
      if (binding === "live" && awaitsExternalVerdict(rule)) return false;
      if (binding === "external" && !awaitsExternalVerdict(rule)) return false;
      if (!needle) return true;
      return [rule.id, rule.name, rule.description, ...(rule.input_stream_ids ?? [])]
        .filter(Boolean)
        .some((field) => String(field).toLowerCase().includes(needle));
    });
  }, [binding, query, rules]);

  return (
    <div className="space-y-4">
      <PageHeader
        title="Detection rules"
        description="Every rule the runtime has registered, and the event streams each one listens to."
        contractId="detection-rules"
      />

      {rulesQuery.isPending && <LoadingBlock label="Loading detection rules..." />}
      {rulesQuery.isError && <ErrorBlock error={rulesQuery.error.message} onRetry={() => void rulesQuery.refetch()} />}

      {!rulesQuery.isPending && !rulesQuery.isError && (
        <>
          <div className="grid gap-3 sm:grid-cols-3">
            <MetricCard label="Registered rules" value={rules.length} />
            <MetricCard
              label="Fed by collected events"
              value={rules.length - externalCount}
              detail="Listening to a stream a source actually emits."
            />
            <MetricCard
              label="Awaiting an external verdict"
              value={externalCount}
              intent={externalCount > 0 ? "warning" : "neutral"}
              detail="Fires only when another system deposits a pass or fail result."
            />
          </div>

          <Panel title="Rules">
            <div className="mb-3 grid gap-2 sm:grid-cols-[1fr_auto]">
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Filter by rule, description, or stream"
                className={inputClass}
              />
              <select value={binding} onChange={(event) => setBinding(event.target.value as Binding)} className={inputClass}>
                <option value="all">All bindings</option>
                <option value="live">Fed by collected events</option>
                <option value="external">Awaiting an external verdict</option>
              </select>
            </div>

            {visible.length === 0 ? (
              <EmptyBlock label="No rule matches this filter." />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-[13px]">
                  <thead className="text-[11px] uppercase tracking-wide text-[var(--text-muted)]">
                    <tr>
                      <th className="py-2 pr-3">Rule</th>
                      <th className="py-2 pr-3">Listens to</th>
                      <th className="py-2 pr-3">Emits</th>
                    </tr>
                  </thead>
                  <tbody>
                    {visible.map((rule) => (
                      <tr key={rule.id} className="border-t border-[color:var(--border)] align-top">
                        <td className="py-2 pr-3">
                          <div className="font-medium text-[var(--text-primary)]">{rule.name || rule.id}</div>
                          <div className="text-[12px] text-[var(--text-muted)]">{rule.id}</div>
                          {rule.description && (
                            <div className="mt-1 max-w-xl text-[12px] text-[var(--text-muted)]">{rule.description}</div>
                          )}
                        </td>
                        <td className="py-2 pr-3">
                          <div className="font-mono text-[12px] text-[var(--text-primary)]">
                            {(rule.input_stream_ids ?? []).join(", ") || "-"}
                          </div>
                          {awaitsExternalVerdict(rule) && (
                            <div className="mt-1 text-[12px] text-[var(--text-muted)]">
                              No connector emits this stream today.
                            </div>
                          )}
                        </td>
                        <td className="py-2 pr-3 font-mono text-[12px] text-[var(--text-muted)]">
                          {(rule.output_kinds ?? []).join(", ") || "-"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </>
      )}
    </div>
  );
}
