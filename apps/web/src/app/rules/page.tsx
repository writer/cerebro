"use client";

import { useSearchParams } from "next/navigation";
import { useMemo, useState } from "react";

import { DataStateBanner, EmptyBlock, MetricCard, PageHeader, SeverityDot } from "@/components/grc/Primitives";
import { RuleChip, RuleDetailView } from "@/components/rules/RuleDetail";
import { RuleEditor } from "@/components/rules/RuleEditor";
import {
  defaultRuleCatalogFilters,
  duplicateRuleDocument,
  filterRuleCatalog,
  type RuleCatalogDetail,
  type RuleCatalogFilters,
  type RuleCatalogResponse,
  ruleCatalogPath,
  ruleDetailPath,
  ruleDomains,
  ruleOriginLabels,
  rulePostureLabels,
  ruleSeverities,
  ruleTemplates,
  summarizeRuleCatalog,
} from "@/lib/finding-rules";
import { useGRCQuery } from "@/lib/grc-client";

const PAGE_SIZE = 100;

const inputClass =
  "w-full rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-2.5 py-1.5 text-[13px] text-[var(--text-primary)] outline-none focus:border-[color:var(--primary)]";

type EditorState =
  | { kind: "view" }
  | { kind: "create"; content: string; sample: Record<string, unknown> }
  | { kind: "edit"; content: string };

export default function RulesPage() {
  const searchParams = useSearchParams();
  const tenantID = (searchParams.get("tenant_id") ?? "").trim();
  const [filters, setFilters] = useState<RuleCatalogFilters>(defaultRuleCatalogFilters);
  const [selectedID, setSelectedID] = useState<string | null>(() => searchParams.get("rule"));
  const [editor, setEditor] = useState<EditorState>({ kind: "view" });
  const [limit, setLimit] = useState(PAGE_SIZE);

  const catalogQuery = useGRCQuery<RuleCatalogResponse>(ruleCatalogPath(tenantID));
  const detailQuery = useGRCQuery<RuleCatalogDetail>(selectedID ? ruleDetailPath(selectedID, tenantID) : null);

  const rules = useMemo(() => catalogQuery.data?.rules ?? [], [catalogQuery.data?.rules]);
  const summary = useMemo(() => summarizeRuleCatalog(rules, filters.domain), [filters.domain, rules]);
  const visible = useMemo(() => filterRuleCatalog(rules, filters), [filters, rules]);
  const customReady = catalogQuery.data?.custom_rules_ready ?? false;
  const detail = detailQuery.data && detailQuery.data.id === selectedID ? detailQuery.data : null;

  const updateFilters = (patch: Partial<RuleCatalogFilters>) => {
    setFilters((current) => ({ ...current, ...patch }));
    setLimit(PAGE_SIZE);
  };

  const startCreate = (content = ruleTemplates[0].document, sample = ruleTemplates[0].sampleResource) => {
    setEditor({ kind: "create", content, sample });
  };

  const afterSave = (saved: RuleCatalogDetail) => {
    setEditor({ kind: "view" });
    setSelectedID(saved.id);
    void catalogQuery.reload();
    void detailQuery.reload();
  };

  const loading = catalogQuery.loading && !catalogQuery.data;

  return (
    <div className="space-y-5">
      <PageHeader
        title="Rules"
        description="Posture and correlation rules for cloud (CSPM), SaaS (SSPM), and identity (ISPM), plus your own custom rules."
        contractId="finding-rules"
        action={catalogQuery.data ? (
          <button
            type="button"
            onClick={() => startCreate()}
            disabled={!customReady}
            title={customReady ? undefined : "Custom rules need a tenant and a configured state store."}
            className="rounded-md bg-[var(--primary)] px-3 py-1.5 text-[13px] font-medium text-white disabled:opacity-50"
          >
            New rule
          </button>
        ) : undefined}
      />

      <DataStateBanner
        state={catalogQuery.error ? "error" : loading ? "loading" : "ready"}
        subject="Rule catalog"
        error={catalogQuery.error}
        onRetry={() => void catalogQuery.reload()}
      />

      {catalogQuery.data && (
        <>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            <MetricCard label="Rules" value={summary.total} detail="Built-in policies, detections, and correlation patterns." />
            <MetricCard label="Critical in view" value={summary.bySeverity.critical ?? 0} intent={(summary.bySeverity.critical ?? 0) > 0 ? "warning" : "neutral"} />
            <MetricCard label="Custom in view" value={summary.custom} detail={customReady ? "Authored by your team." : "Custom rules are unavailable without a state store."} />
          </div>

          <div role="tablist" aria-label="Rule domain" className="flex flex-wrap gap-1 border-b border-[color:var(--border)]">
            {[{ id: "all" as const, label: "All", description: "Every rule" }, ...ruleDomains].map((domain) => {
              const count = domain.id === "all" ? rules.length : summary.byDomain[domain.id] ?? 0;
              const active = filters.domain === domain.id;
              return (
                <button
                  key={domain.id}
                  type="button"
                  role="tab"
                  aria-selected={active}
                  title={domain.description}
                  onClick={() => updateFilters({ domain: domain.id, provider: "all" })}
                  className={`-mb-px border-b-2 px-3 py-2 text-[13px] font-medium ${active ? "border-[color:var(--primary)] text-[var(--primary)]" : "border-transparent text-[var(--text-muted)] hover:text-[var(--text-primary)]"}`}
                >
                  {domain.label} <span className="ml-1 text-[11px] tabular-nums opacity-70">{count.toLocaleString()}</span>
                </button>
              );
            })}
          </div>

          <div className="grid gap-4 lg:grid-cols-[minmax(0,5fr)_minmax(0,6fr)]">
            <div className="surface-panel flex min-h-[32rem] flex-col p-4">
              <div className="grid gap-2 sm:grid-cols-2">
                <input
                  aria-label="Search rules"
                  value={filters.query}
                  onChange={(event) => updateFilters({ query: event.target.value })}
                  placeholder="Search by name, id, resource, framework, or technique"
                  className={`${inputClass} sm:col-span-2`}
                />
                <select aria-label="Severity" value={filters.severity} onChange={(event) => updateFilters({ severity: event.target.value })} className={inputClass}>
                  <option value="all">All severities</option>
                  {ruleSeverities.map((severity) => <option key={severity} value={severity}>{severity[0].toUpperCase() + severity.slice(1)}</option>)}
                </select>
                <select aria-label="Source" value={filters.origin} onChange={(event) => updateFilters({ origin: event.target.value })} className={inputClass}>
                  <option value="all">All sources</option>
                  {Object.entries(ruleOriginLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                </select>
                <select aria-label="Provider" value={filters.provider} onChange={(event) => updateFilters({ provider: event.target.value })} className={inputClass}>
                  <option value="all">All providers</option>
                  {summary.providers.map(({ provider, count }) => <option key={provider} value={provider}>{provider} ({count})</option>)}
                </select>
              </div>

              <div className="mt-3 text-[12px] text-[var(--text-muted)]">
                {visible.length.toLocaleString()} {visible.length === 1 ? "rule" : "rules"}
              </div>

              {visible.length === 0 ? (
                <div className="mt-3"><EmptyBlock label="No rule matches these filters." /></div>
              ) : (
                <ul className="mt-2 max-h-[70vh] flex-1 divide-y divide-[color:var(--border)] overflow-y-auto" aria-label="Rules">
                  {visible.slice(0, limit).map((rule) => {
                    const active = rule.id === selectedID;
                    return (
                      <li key={`${rule.origin}:${rule.id}`}>
                        <button
                          type="button"
                          aria-current={active ? "true" : undefined}
                          onClick={() => {
                            setSelectedID(rule.id);
                            setEditor({ kind: "view" });
                          }}
                          className={`flex w-full items-start gap-2.5 px-2 py-2.5 text-left ${active ? "bg-[var(--primary-soft)]" : "hover:bg-[var(--surface-hover)]"}`}
                        >
                          <span className="mt-1.5"><SeverityDot severity={rule.severity} /></span>
                          <span className="min-w-0 flex-1">
                            <span className="block truncate text-[13px] font-medium text-[var(--text-primary)]">{rule.name || rule.id}</span>
                            <span className="mt-0.5 block truncate font-mono text-[11px] text-[var(--text-muted)]">{rule.id}</span>
                            <span className="mt-1 flex flex-wrap gap-1">
                              <RuleChip>{rulePostureLabels[rule.posture] ?? rule.posture}</RuleChip>
                              {rule.provider && <RuleChip>{rule.provider}</RuleChip>}
                              {rule.origin === "custom" && <RuleChip tone="primary">Custom</RuleChip>}
                            </span>
                          </span>
                        </button>
                      </li>
                    );
                  })}
                  {visible.length > limit && (
                    <li className="py-3 text-center">
                      <button type="button" onClick={() => setLimit((current) => current + PAGE_SIZE)} className="secondary-button px-3 py-1.5 text-[12px]">
                        Show {Math.min(PAGE_SIZE, visible.length - limit)} more
                      </button>
                    </li>
                  )}
                </ul>
              )}
            </div>

            <div className="surface-panel p-5">
              {editor.kind === "create" && (
                <RuleEditor
                  key="create"
                  mode="create"
                  initialContent={editor.content}
                  initialSample={editor.sample}
                  tenantID={tenantID}
                  onCancel={() => setEditor({ kind: "view" })}
                  onSaved={afterSave}
                />
              )}
              {editor.kind === "edit" && (
                <RuleEditor
                  key={`edit:${selectedID}`}
                  mode="edit"
                  initialContent={editor.content}
                  tenantID={tenantID}
                  onCancel={() => setEditor({ kind: "view" })}
                  onSaved={afterSave}
                  onDeleted={() => {
                    setEditor({ kind: "view" });
                    setSelectedID(null);
                    void catalogQuery.reload();
                  }}
                />
              )}
              {editor.kind === "view" && (
                <RuleDetailView
                  rule={detail}
                  loading={Boolean(selectedID) && detailQuery.loading}
                  error={selectedID ? detailQuery.error : null}
                  onRetry={() => void detailQuery.reload()}
                  onEdit={detail?.editable && detail.document && customReady ? () => setEditor({ kind: "edit", content: detail.document ?? "" }) : undefined}
                  onDuplicate={detail && !detail.editable && detail.document && customReady ? () => {
                    const copy = duplicateRuleDocument(detail.document ?? "", detail.id);
                    if (copy) startCreate(copy, {});
                  } : undefined}
                />
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
