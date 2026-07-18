"use client";

import Link from "next/link";
import { useCallback, useMemo, useState } from "react";

import AskAboutLink from "@/components/ask/AskAboutLink";
import { Badge, RiskBadge, SeverityDot } from "@/components/grc/Primitives";
import { useSecurityProducerCatalog } from "@/components/SecurityProducerCatalogProvider";
import { securityProducerContextForFinding } from "@/lib/security-producer-response";
import { displayDate, GRCFinding, shortEntity } from "@/lib/grc";

type SortKey = "risk_score" | "severity" | "last_observed_at" | "title";
type SortDir = "asc" | "desc";

const sevOrd: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

function compareFn(a: GRCFinding, b: GRCFinding, key: SortKey): number {
  switch (key) {
    case "risk_score":
      return (a.risk_score ?? 0) - (b.risk_score ?? 0);
    case "severity":
      return (sevOrd[a.severity?.toUpperCase()] ?? 0) - (sevOrd[b.severity?.toUpperCase()] ?? 0);
    case "last_observed_at":
      return (a.last_observed_at ?? "").localeCompare(b.last_observed_at ?? "");
    case "title":
      return (a.title ?? "").localeCompare(b.title ?? "");
    default:
      return 0;
  }
}

function SortIcon({ active, dir }: { active: boolean; dir: SortDir }) {
  if (!active) {
    return (
      <svg className="ml-1 inline h-3 w-3 text-[var(--text-muted)] opacity-50" viewBox="0 0 16 16" fill="currentColor">
        <path d="M8 4l3 4H5l3-4zm0 8l-3-4h6l-3 4z" />
      </svg>
    );
  }
  return (
    <svg className="ml-1 inline h-3 w-3 text-[var(--primary)]" viewBox="0 0 16 16" fill="currentColor">
      {dir === "asc" ? <path d="M8 4l4 5H4l4-5z" /> : <path d="M8 12l-4-5h8l-4 5z" />}
    </svg>
  );
}

export default function FindingTable({
  findings,
  empty = "No findings match this view.",
  initialRows = 100,
  selectable = false,
  selectedIds,
  onToggleSelect,
  onToggleSelectAll,
  onPreviewFinding,
}: {
  findings: GRCFinding[];
  empty?: string;
  initialRows?: number;
  selectable?: boolean;
  selectedIds?: Set<string>;
  onToggleSelect?: (id: string) => void;
  onToggleSelectAll?: (ids: string[], selected: boolean) => void;
  onPreviewFinding?: (finding: GRCFinding) => void;
}) {
  const [showAll, setShowAll] = useState(false);
  const [sortKey, setSortKey] = useState<SortKey>("risk_score");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const { catalog } = useSecurityProducerCatalog();
  const securityProducers = catalog.state === "ready" ? catalog.producers : [];

  const toggleSort = useCallback((key: SortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("desc");
    }
  }, [sortKey]);

  const sorted = useMemo(() => {
    const copy = [...findings];
    copy.sort((a, b) => {
      const cmp = compareFn(a, b, sortKey);
      return sortDir === "desc" ? -cmp : cmp;
    });
    return copy;
  }, [findings, sortKey, sortDir]);

  const visible = useMemo(
    () => (showAll ? sorted : sorted.slice(0, initialRows)),
    [sorted, initialRows, showAll],
  );
  const hiddenCount = sorted.length - visible.length;
  const selected = selectedIds ?? new Set<string>();
  const visibleIds = useMemo(() => visible.map((finding) => finding.id), [visible]);
  const allVisibleSelected = selectable && visibleIds.length > 0 && visibleIds.every((id) => selected.has(id));

  if (findings.length === 0) {
    return (
      <div className="flex items-center justify-center rounded-lg border border-dashed border-[color:var(--border-strong)] p-8 text-[13px] text-[var(--text-muted)]">
        {empty}
      </div>
    );
  }

  const thClass = "select-none";
  const sortable = (key: SortKey, label: string) => (
    <button type="button" onClick={() => toggleSort(key)} className="inline-flex items-center hover:text-[var(--text-primary)]">
      {label}
      <SortIcon active={sortKey === key} dir={sortDir} />
    </button>
  );

  return (
    <div className="surface-panel overflow-x-auto">
      <table className="data-table">
        <thead>
          <tr>
            {selectable && (
              <th className={thClass}>
                <input
                  type="checkbox"
                  aria-label="Select all findings"
                  checked={allVisibleSelected}
                  onChange={(e) => onToggleSelectAll?.(visibleIds, e.target.checked)}
                  className="h-3.5 w-3.5 cursor-pointer rounded border-slate-300 text-indigo-600 focus:ring-indigo-400"
                />
              </th>
            )}
            <th className={thClass}>{sortable("title", "Finding")}</th>
            <th className={thClass}>{sortable("risk_score", "Risk")}</th>
            <th className={thClass}>{sortable("severity", "Severity")}</th>
            {selectable && <th className={thClass}>Disposition</th>}
            <th className={thClass}>Entity</th>
            <th className={thClass}>Owner</th>
            <th className={thClass}>SLA</th>
            <th className={thClass}>Evidence</th>
            <th className={thClass}>{sortable("last_observed_at", "Last Seen")}</th>
            <th className={thClass}></th>
          </tr>
        </thead>
        <tbody>
          {visible.map((finding) => (
            <tr key={finding.id} className={selectable && selected.has(finding.id) ? "bg-indigo-50/50" : undefined}>
              {selectable && (
                <td>
                  <input
                    type="checkbox"
                    aria-label={`Select ${finding.title}`}
                    checked={selected.has(finding.id)}
                    onChange={() => onToggleSelect?.(finding.id)}
                    className="h-3.5 w-3.5 cursor-pointer rounded border-slate-300 text-indigo-600 focus:ring-indigo-400"
                  />
                </td>
              )}
              <td className="max-w-xs">
                <Link href={`/findings/${encodeURIComponent(finding.id)}`} className="font-medium text-[var(--text-primary)] hover:text-[var(--primary)]">
                  {finding.title}
                </Link>
                <div className="mt-0.5 truncate text-[12px] text-[var(--text-muted)]">
                  {finding.summary || finding.rule_id}
                </div>
              </td>
              <td>
                <RiskBadge score={finding.risk_score} />
              </td>
              <td>
                <div className="flex items-center gap-1.5">
                  <SeverityDot severity={finding.severity} />
                  <Badge value={finding.severity} tone="severity" />
                </div>
              </td>
              {selectable && (
                <td>
                  {finding.disposition ? <Badge value={finding.disposition} /> : <span className="text-[var(--text-muted)]">--</span>}
                </td>
              )}
              <td>
                <span className="font-mono text-[12px] text-[var(--text-secondary)]">{shortEntity(finding.entity)}</span>
              </td>
              <td>{finding.owner || <span className="text-[var(--text-muted)]">--</span>}</td>
              <td><Badge value={finding.sla_status} /></td>
              <td className="text-center tabular-nums">{finding.evidence_count}</td>
              <td className="text-[var(--text-muted)]">{displayDate(finding.last_observed_at)}</td>
              <td>
                <div className="flex items-center justify-end gap-2">
                  {onPreviewFinding && (
                    <button
                      type="button"
                      onClick={() => onPreviewFinding(finding)}
                      className="rounded-md border border-[color:var(--border)] px-2 py-1 text-[12px] font-medium text-[var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[var(--text-primary)]"
                    >
                      Review
                    </button>
                  )}
                  <AskAboutLink
                    question={`Why is ${finding.title} risky and which entities are affected?`}
                    scopeUrn={finding.entity}
                    title="Ask about this finding"
                    context={{
                      route: "/risk-inbox",
                      routeLabel: "Risks",
                      title: finding.title,
                      findingId: finding.id,
                      rule_id: finding.rule_id,
                      runtime_id: finding.runtime_id,
                      source_id: finding.source_id,
                      severity: finding.severity,
                      status: finding.status,
                      oauth_app_id: finding.attributes?.oauthAppId ?? finding.attributes?.oauth_app_id,
                      oauth_grant_id: finding.attributes?.oauthGrantId ?? finding.attributes?.oauth_grant_id,
                      ...securityProducerContextForFinding(finding, securityProducers),
                      chips: [
                        { label: "Finding", value: finding.id },
                        finding.rule_id ? { label: "Rule", value: finding.rule_id } : null,
                        finding.source_id ? { label: "Source", value: finding.source_id } : null,
                      ].filter(Boolean) as { label: string; value: string }[],
                    }}
                  >
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="h-4 w-4 text-[var(--text-muted)] transition hover:text-[var(--primary)]">
                      <path strokeLinecap="round" strokeLinejoin="round" d="m21 21-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z" />
                    </svg>
                  </AskAboutLink>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {hiddenCount > 0 && (
        <div className="border-t border-[color:var(--border)] px-4 py-3">
          <button
            type="button"
            onClick={() => setShowAll(true)}
            className="text-[13px] font-medium text-[var(--primary)] transition hover:text-[var(--primary-hover)]"
          >
            Show {hiddenCount} more findings
          </button>
        </div>
      )}
    </div>
  );
}
