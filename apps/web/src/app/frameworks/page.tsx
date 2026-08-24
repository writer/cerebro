"use client";

import Link from "next/link";
import { useMemo, useState } from "react";

import { Badge, ErrorBlock, LoadingBlock, MetricCard, PageHeader, Panel } from "@/components/grc/Primitives";
import type { GRCFramework, GRCFrameworksResponse } from "@/lib/grc";
import { grcPath, useGRCQuery } from "@/lib/grc-client";
import { frameworkRouteSegment, staticGRCFrameworkCatalog } from "@/lib/grc-frameworks";

const inputClass = "control-input px-3 py-1.5 text-[13px]";

const FRAMEWORK_PREVIEW_LIMIT = 6;

const setupControlCount = (framework: GRCFramework) =>
  (framework.readiness?.needs_enrichment_controls ?? 0) + (framework.readiness?.placeholder_controls ?? 0);

export const frameworkNeedsWork = (framework: GRCFramework) =>
  framework.lifecycle === "upcoming" ||
  (framework.gap_actions ?? []).some((action) => action.code !== "export_audit_packet") ||
  setupControlCount(framework) > 0;

export const frameworkPreview = (frameworks: GRCFramework[], expanded: boolean, filtering: boolean) =>
  expanded || filtering ? frameworks : frameworks.slice(0, FRAMEWORK_PREVIEW_LIMIT);

function FrameworkCard({ framework }: { framework: GRCFramework }) {
  const gapActions = framework.gap_actions ?? [];
  const selectedControls = framework.coverage?.selected_controls ?? framework.control_count;
  const mappedControls = framework.coverage?.mapped_controls ?? 0;
  const needsSetup = setupControlCount(framework);
  const stateLabel = framework.lifecycle === "upcoming" ? "Planning" : frameworkNeedsWork(framework) ? "Needs setup" : "Setup complete";
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
        <Badge value={stateLabel} />
      </div>
      <div className="mt-4 grid gap-3 text-[12px] text-[var(--text-muted)] sm:grid-cols-3">
        <div>
          <div className="font-medium text-[var(--text-primary)]">{mappedControls}/{selectedControls}</div>
          <div>Controls mapped</div>
        </div>
        <div>
          <div className="font-medium text-[var(--text-primary)]">{needsSetup}</div>
          <div>{needsSetup === 1 ? "Control needs setup" : "Controls need setup"}</div>
        </div>
        <div>
          <div className="font-medium text-[var(--text-primary)]">{framework.coverage?.mapped_rules ?? 0}</div>
          <div>Automated checks</div>
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
  const [showAll, setShowAll] = useState(false);
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
  const filtering = Boolean(query.trim()) || lifecycle !== "all";
  const visibleFrameworks = frameworkPreview(filteredFrameworks, showAll, filtering);
  const activeCount = frameworks.filter((framework) => framework.lifecycle !== "upcoming").length;
  const upcomingCount = frameworks.filter((framework) => framework.lifecycle === "upcoming").length;
  const needsAction = frameworks.filter((framework) => framework.lifecycle !== "upcoming" && frameworkNeedsWork(framework)).length;
  const setupComplete = frameworks.filter((framework) => framework.lifecycle !== "upcoming" && !frameworkNeedsWork(framework)).length;
  const soc2 = frameworks.find((framework) => framework.name === "SOC 2");

  return (
    <div className="space-y-6">
      <PageHeader
        contractId="frameworks"
        title="Frameworks"
        description="Open the programs your team is working on, resolve control gaps, and prepare audit packets."
        action={soc2 ? (
          <Link href={`/frameworks/${frameworkRouteSegment(soc2)}`} className="rounded-md bg-[var(--primary)] px-3 py-1.5 text-[12px] font-medium text-white transition hover:bg-[var(--primary-hover)]">
            Open SOC 2
          </Link>
        ) : null}
      />

      <div className="grid gap-4 md:grid-cols-4">
        <MetricCard label="Active programs" value={activeCount} detail="Available for control work" state={loading && !data ? "loading" : "ready"} />
        <MetricCard label="Needs work" value={needsAction} detail="Programs with setup or evidence gaps" intent={needsAction > 0 ? "warning" : "success"} state={loading && !data ? "loading" : "ready"} />
        <MetricCard label="Setup complete" value={setupComplete} detail="No catalog setup gaps" intent={setupComplete > 0 ? "success" : "neutral"} state={loading && !data ? "loading" : "ready"} />
        <MetricCard label="Planned" value={upcomingCount} detail="Not included in readiness" state={loading && !data ? "loading" : "ready"} />
      </div>

      <Panel
        title="Compliance programs"
        action={
          <div className="flex flex-wrap items-center gap-2">
            <select value={lifecycle} onChange={(event) => setLifecycle(event.target.value as typeof lifecycle)} className={inputClass}>
              <option value="all">All programs</option>
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
          {visibleFrameworks.map((framework) => <FrameworkCard key={framework.id || framework.name} framework={framework} />)}
        </div>
        {!filtering && filteredFrameworks.length > FRAMEWORK_PREVIEW_LIMIT && (
          <div className="mt-4 flex items-center justify-between border-t border-[color:var(--border)] pt-4">
            <span className="text-[12px] text-[var(--text-muted)]">Showing {visibleFrameworks.length} of {filteredFrameworks.length} programs</span>
            <button type="button" onClick={() => setShowAll((current) => !current)} className="secondary-button px-3 py-1.5 text-[12px]">
              {showAll ? "Show priority programs" : "Browse all programs"}
            </button>
          </div>
        )}
      </Panel>
    </div>
  );
}
