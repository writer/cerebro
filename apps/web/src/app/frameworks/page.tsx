"use client";

import Link from "next/link";
import { useMemo, useState } from "react";

import { Badge, ErrorBlock, LoadingBlock, MetricCard, PageHeader, Panel } from "@/components/grc/Primitives";
import type { GRCFramework, GRCFrameworksResponse } from "@/lib/grc";
import { humanize } from "@/lib/grc";
import { grcPath, useGRCQuery } from "@/lib/grc-client";
import { frameworkRouteSegment, staticGRCFrameworkCatalog } from "@/lib/grc-frameworks";

const inputClass = "control-input px-3 py-1.5 text-[13px]";

const maturityScore = (framework: GRCFramework) =>
  framework.lifecycle === "upcoming" ? null : framework.maturity?.score ?? null;

const maturityLabel = (framework: GRCFramework) =>
  framework.lifecycle === "upcoming" ? "Planning" : humanize(framework.maturity?.status || "not configured");

const maturityDetail = (framework: GRCFramework) => {
  if (framework.lifecycle === "upcoming") return "Not measured yet";
  const coverage = framework.coverage;
  if (!coverage || coverage.selected_controls === 0) return "No measured controls";
  return `${coverage.mapped_controls}/${coverage.selected_controls} controls mapped`;
};

function FrameworkCard({ framework }: { framework: GRCFramework }) {
  const score = maturityScore(framework);
  const gapActions = framework.gap_actions ?? [];
  return (
    <Link href={`/frameworks/${frameworkRouteSegment(framework)}`} className="surface-panel block p-4 transition hover:border-[color:var(--ring)]">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-[15px] font-semibold text-[var(--text-primary)]">{framework.name}</h2>
            <Badge value={framework.lifecycle} />
          </div>
          <p className="mt-2 line-clamp-2 text-[13px] leading-5 text-[var(--text-muted)]">{framework.description || "Framework tracking and audit readiness workspace."}</p>
        </div>
        <div className="shrink-0 text-right">
          <div className="text-2xl font-semibold text-[var(--text-primary)]">{score === null ? "N/A" : `${score}%`}</div>
          <div className="mt-1 text-[11px] uppercase tracking-wider text-[var(--text-muted)]">Maturity</div>
        </div>
      </div>
      <div className="mt-4 grid gap-3 text-[12px] text-[var(--text-muted)] sm:grid-cols-3">
        <div>
          <div className="font-medium text-[var(--text-primary)]">{maturityLabel(framework)}</div>
          <div>{maturityDetail(framework)}</div>
        </div>
        <div>
          <div className="font-medium text-[var(--text-primary)]">{framework.family_count}</div>
          <div>{framework.family_count === 1 ? "Family" : "Families"}</div>
        </div>
        <div>
          <div className="font-medium text-[var(--text-primary)]">{framework.control_count}</div>
          <div>{framework.control_count === 1 ? "Catalog control" : "Catalog controls"}</div>
        </div>
      </div>
      {gapActions.length > 0 && (
        <div className="mt-4 rounded-lg bg-[var(--surface-muted)] px-3 py-2 text-[12px] text-[var(--text-secondary)]">
          Next: {gapActions[0].label}
        </div>
      )}
    </Link>
  );
}

export default function FrameworksPage() {
  const [query, setQuery] = useState("");
  const [lifecycle, setLifecycle] = useState<"all" | "active" | "upcoming">("all");
  const { data, error, loading, reload } = useGRCQuery<GRCFrameworksResponse>(grcPath("/grc/frameworks"));
  const frameworks = useMemo(() => data?.frameworks?.length ? data.frameworks : staticGRCFrameworkCatalog, [data?.frameworks]);
  const filteredFrameworks = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return frameworks.filter((framework) => {
      if (lifecycle !== "all" && framework.lifecycle !== lifecycle) return false;
      if (!normalizedQuery) return true;
      return [framework.name, framework.id, framework.description, ...(framework.tags ?? [])]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(normalizedQuery);
    });
  }, [frameworks, lifecycle, query]);
  const activeCount = frameworks.filter((framework) => framework.lifecycle !== "upcoming").length;
  const upcomingCount = frameworks.filter((framework) => framework.lifecycle === "upcoming").length;
  const measured = frameworks.filter((framework) => framework.lifecycle !== "upcoming" && typeof framework.maturity?.score === "number");
  const averageMaturity = measured.length === 0 ? 0 : Math.round(measured.reduce((sum, framework) => sum + (framework.maturity?.score ?? 0), 0) / measured.length);
  const needsAction = frameworks.filter((framework) => (framework.gap_actions ?? []).some((action) => action.code !== "export_audit_packet")).length;
  const soc2 = frameworks.find((framework) => framework.name === "SOC 2");

  return (
    <div className="space-y-6">
      <PageHeader
        contractId="frameworks"
        title="Frameworks"
        description="Track framework status, controls, gaps, planning, and reports."
        action={soc2 ? (
          <Link href={`/frameworks/${frameworkRouteSegment(soc2)}`} className="rounded-md bg-[var(--primary)] px-3 py-1.5 text-[12px] font-medium text-white transition hover:bg-[var(--primary-hover)]">
            Open SOC 2
          </Link>
        ) : null}
      />

      <div className="grid gap-4 md:grid-cols-4">
        <MetricCard label="Frameworks" value={frameworks.length} detail={`${activeCount} active`} state={loading && !data ? "loading" : "ready"} />
        <MetricCard label="Average maturity" value={`${averageMaturity}%`} detail={`${measured.length} measured frameworks`} state={loading && !data ? "loading" : "ready"} />
        <MetricCard label="Needs action" value={needsAction} detail="Frameworks with open gap actions" intent={needsAction > 0 ? "warning" : "success"} state={loading && !data ? "loading" : "ready"} />
        <MetricCard label="Upcoming" value={upcomingCount} detail="Planning mode, not measured" state={loading && !data ? "loading" : "ready"} />
      </div>

      <Panel
        title="Compliance catalog"
        action={
          <div className="flex flex-wrap items-center gap-2">
            <select value={lifecycle} onChange={(event) => setLifecycle(event.target.value as typeof lifecycle)} className={inputClass}>
              <option value="all">All lifecycles</option>
              <option value="active">Active</option>
              <option value="upcoming">Upcoming</option>
            </select>
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search frameworks" className={inputClass} />
          </div>
        }
      >
        {error && data?.frameworks?.length ? <ErrorBlock error={error} onRetry={reload} /> : null}
        {error && !data?.frameworks?.length ? (
          <div className="mb-4 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-[13px] text-amber-900">
            Live framework metadata is unavailable, showing the local catalog.
            <button type="button" onClick={reload} className="ml-2 font-medium text-amber-950 underline">Retry</button>
          </div>
        ) : null}
        {loading && !data && <LoadingBlock label="Loading live framework metadata..." />}
        {!loading && !error && filteredFrameworks.length === 0 && (
          <div className="rounded-lg border border-dashed border-[color:var(--border-strong)] p-8 text-center text-[13px] text-[var(--text-muted)]">No frameworks match the current filters.</div>
        )}
        <div className="grid gap-4 lg:grid-cols-2">
          {filteredFrameworks.map((framework) => <FrameworkCard key={framework.id || framework.name} framework={framework} />)}
        </div>
      </Panel>
    </div>
  );
}
