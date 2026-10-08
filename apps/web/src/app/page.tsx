"use client";

import Link from "next/link";

import AskAboutLink from "@/components/ask/AskAboutLink";
import { useMemo } from "react";

import { useUserPreferences } from "@/components/providers";
import { DataStateBanner, PageHeader } from "@/components/grc/Primitives";
import { countLabel } from "@/lib/format";
import {
  GRCDashboard,
  GRCInventoryAssetsResponse,
  GRCInventorySummary,
  GRCSourceCoverageRecord,
  GRCSummary,
  GRCTrends,
} from "@/lib/grc";
import { DASHBOARD_FINDING_LIMIT, grcDashboardPath, grcPath, useGRCQuery } from "@/lib/grc-client";
import { grcScopeQuery, type GRCScope, useGRCScopeQueryState } from "@/lib/grc-scope";

const HOME_TREND_DAYS = 30;

export const homeGRCPaths = (scope: GRCScope) => {
  const query = grcScopeQuery(scope);
  if (query.workspace_id && !query.tenant_id) {
    return { coverage: null, dashboard: null, inventory: null, trends: null };
  }
  return {
    coverage: grcPath("/connectors/coverage", {
      coverage_scope: "configured",
      coverage_view: "page",
      blind_spots_only: "true",
      page_size: 3,
      ...query,
    }),
    dashboard: grcDashboardPath({
      limit: DASHBOARD_FINDING_LIMIT,
      enrichments: "deferred",
      ...query,
    }),
    // Only the summary is rendered here, so ask for the smallest asset page.
    inventory: grcPath("/grc/inventory/assets", { surface: "asset", page_size: 1, ...query }),
    trends: grcPath("/grc/trends", { interval: "day", days: HOME_TREND_DAYS, ...query }),
  };
};

type CoverageTone = "danger" | "warning" | "success" | "neutral";

const toneDot: Record<CoverageTone, string> = {
  danger: "bg-red-500",
  warning: "bg-amber-500",
  success: "bg-emerald-500",
  neutral: "bg-slate-300",
};

const toneText: Record<CoverageTone, string> = {
  danger: "text-red-600",
  warning: "text-amber-600",
  success: "text-emerald-600",
  neutral: "text-[var(--text-primary)]",
};

function OverviewTile({
  detail,
  href,
  label,
  tone,
  value,
}: {
  detail: string;
  href: string;
  label: string;
  tone: CoverageTone;
  value: string | number;
}) {
  return (
    <Link href={href} className="surface-panel block px-4 py-3 transition hover:border-[color:var(--border-strong)]">
      <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">{label}</div>
      <div className={`mt-1 text-2xl font-semibold tabular-nums ${toneText[tone]}`}>{value}</div>
      <div className="mt-0.5 truncate text-[12px] text-[var(--text-muted)]">{detail}</div>
    </Link>
  );
}

const HOME_ASK_PROMPTS = [
  "Which assets have no owner?",
  "What changed this week?",
  "Which identities have admin access?",
];

function CoverageRow({
  detail,
  href,
  label,
  tone,
  value,
}: {
  detail: string;
  href: string;
  label: string;
  tone: CoverageTone;
  value: string | number;
}) {
  return (
    <Link href={href} className="grid grid-cols-[minmax(0,1fr)_auto] gap-3 rounded-md px-2 py-2.5 transition hover:bg-[var(--surface-muted)]">
      <div className="min-w-0">
        <div className="text-[12px] font-medium text-[var(--text-primary)]">{label}</div>
        <div className="mt-0.5 truncate text-[12px] text-[var(--text-muted)]">{detail}</div>
      </div>
      <div className="flex items-center gap-2">
        <span className="text-[16px] font-semibold tabular-nums text-[var(--text-primary)]">{value}</span>
        <span className={`h-2 w-2 rounded-full ${toneDot[tone]}`} />
      </div>
    </Link>
  );
}

// Opened above the baseline, closed below it, so a window where the backlog
// grew is visible without reading any number.
export function ChangeStrip({ trends }: { trends?: GRCTrends }) {
  const points = trends?.points ?? [];
  const peak = Math.max(1, ...points.map((point) => Math.max(point.opened, point.closed)));
  const summary = trends?.summary;
  const net = summary?.net ?? 0;
  return (
    <section className="surface-panel px-5 py-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-[15px] font-semibold text-[var(--text-primary)]">What Changed</h2>
          <p className="mt-1 text-[13px] text-[var(--text-muted)]">
            Findings opened against findings closed, last {HOME_TREND_DAYS} days.
          </p>
        </div>
        <div className="flex items-center gap-4 text-right">
          <div>
            <div className="text-[11px] uppercase tracking-wide text-[var(--text-muted)]">Opened</div>
            <div className="text-[18px] font-semibold tabular-nums text-amber-600">{summary?.total_opened ?? 0}</div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wide text-[var(--text-muted)]">Closed</div>
            <div className="text-[18px] font-semibold tabular-nums text-emerald-600">{summary?.total_closed ?? 0}</div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wide text-[var(--text-muted)]">Net</div>
            <div className={`text-[18px] font-semibold tabular-nums ${net > 0 ? "text-red-600" : "text-emerald-600"}`}>
              {net > 0 ? `+${net}` : net}
            </div>
          </div>
          <Link href="/trends" className="secondary-button px-3 py-1.5 text-[12px]">Open Trends</Link>
        </div>
      </div>
      {points.length === 0 ? (
        <div className="mt-4 text-[13px] text-[var(--text-muted)]">No finding activity recorded in this window.</div>
      ) : (
        <div className="mt-4 flex items-end gap-[3px]" aria-hidden="true">
          {points.map((point) => (
            <div key={point.date} className="flex min-w-0 flex-1 flex-col items-center gap-[2px]">
              <div className="w-full rounded-sm bg-amber-400/80" style={{ height: `${(point.opened / peak) * 28}px` }} />
              <div className="w-full rounded-sm bg-emerald-400/80" style={{ height: `${(point.closed / peak) * 28}px` }} />
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

export function AssetCoveragePanel({ assets, pending }: { assets?: GRCInventorySummary; pending: boolean }) {
  const placeholder = pending ? "Loading asset inventory." : "No asset inventory reported.";
  return (
    <section className="surface-panel p-5">
      <div>
        <h2 className="text-[15px] font-semibold text-[var(--text-primary)]">Asset Coverage</h2>
        <p className="mt-1 text-[13px] text-[var(--text-muted)]">What Cerebro is tracking, and what is unaccounted for.</p>
      </div>
      {assets ? (
        <div className="mt-4 divide-y divide-[color:var(--border)]">
          <CoverageRow
            href="/inventory"
            label="Unowned Assets"
            value={assets.unassigned_assets}
            detail={`${assets.accountable_assets ?? 0} of ${assets.total_assets} have an accountable owner`}
            tone={assets.unassigned_assets > 0 ? "warning" : "success"}
          />
          <CoverageRow
            href="/inventory"
            label="Publicly Reachable"
            value={assets.public_assets}
            detail="Exposed outside the organization boundary."
            tone={assets.public_assets > 0 ? "danger" : "success"}
          />
          <CoverageRow
            href="/inventory"
            label="High Risk Assets"
            value={assets.high_risk_assets}
            detail="Carrying the heaviest composed risk."
            tone={assets.high_risk_assets > 0 ? "danger" : "success"}
          />
          <CoverageRow
            href="/inventory"
            label="Needs Review"
            value={assets.needs_review_assets ?? 0}
            detail={`${assets.out_of_scope_assets} currently out of scope`}
            tone={(assets.needs_review_assets ?? 0) > 0 ? "warning" : "success"}
          />
        </div>
      ) : (
        <div className="mt-4 text-[13px] text-[var(--text-muted)]">{placeholder}</div>
      )}
    </section>
  );
}

export function SignalCoveragePanel({
  coverageBlindSpotCount,
  coveragePending,
  coverageSourceCount,
  summary,
}: {
  coverageBlindSpotCount: number;
  coveragePending: boolean;
  coverageSourceCount: number;
  summary: GRCSummary;
}) {
  const healthySources = Math.max(0, summary.connectors - summary.stale_connectors);
  return (
    <section className="surface-panel p-5">
      <div>
        <h2 className="text-[15px] font-semibold text-[var(--text-primary)]">Signal Coverage</h2>
        <p className="mt-1 text-[13px] text-[var(--text-muted)]">Where the data comes from, and whether it is current.</p>
      </div>
      <div className="mt-4 divide-y divide-[color:var(--border)]">
        <CoverageRow
          href="/connectors"
          label="Sources Reporting"
          value={`${healthySources}/${summary.connectors}`}
          detail={countLabel(summary.stale_connectors, "stale source")}
          tone={summary.stale_connectors > 0 ? "warning" : "success"}
        />
        <CoverageRow
          href="/connectors"
          label="Collection Gaps"
          value={coveragePending ? "—" : coverageBlindSpotCount}
          detail={coveragePending
            ? "Loading source coverage."
            : `${countLabel(coverageBlindSpotCount, "coverage gap")} across ${countLabel(coverageSourceCount, "source")}`}
          tone={coveragePending ? "neutral" : coverageBlindSpotCount > 0 ? "warning" : "success"}
        />
        <CoverageRow
          href="/rules"
          label="Detection Coverage"
          value="Review"
          detail="Which rules can fire on the events being collected."
          tone="neutral"
        />
      </div>
      <div className="mt-5 border-t border-[color:var(--border)] pt-4">
        <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Ask Cerebro</div>
        <div className="mt-2 space-y-1.5">
          {HOME_ASK_PROMPTS.map((question) => (
            <AskAboutLink
              key={question}
              question={question}
              className="block truncate text-left text-[12px] text-[var(--primary)] hover:underline"
            >
              {question}
            </AskAboutLink>
          ))}
        </div>
      </div>
    </section>
  );
}

export default function Home() {
  const { preferences } = useUserPreferences();
  const { tenantID, workspaceID } = useGRCScopeQueryState();
  const visibleSections = preferences.homepage.sections;
  const compactHome = preferences.display.density === "compact";
  const paths = homeGRCPaths({ tenantID, workspaceID });
  const invalidWorkspaceScope = Boolean(workspaceID.trim() && !tenantID.trim());
  const dashboard = useGRCQuery<GRCDashboard>(paths.dashboard);
  const coverageQuery = useGRCQuery<{ blind_spots?: GRCSourceCoverageRecord[]; records?: GRCSourceCoverageRecord[] }>(
    paths.coverage,
  );
  const inventoryQuery = useGRCQuery<GRCInventoryAssetsResponse>(paths.inventory);
  const trendsQuery = useGRCQuery<GRCTrends>(paths.trends);

  const data = dashboard.data;
  const summary = data?.summary;
  const assets = inventoryQuery.data?.summary;
  const coverageSummaries = useMemo(() => data?.coverage_summaries ?? [], [data?.coverage_summaries]);
  const coverageBlindSpots = useMemo(
    () => coverageQuery.data?.blind_spots ?? coverageQuery.data?.records ?? data?.coverage_blind_spots ?? [],
    [coverageQuery.data?.blind_spots, coverageQuery.data?.records, data?.coverage_blind_spots],
  );
  const coverageBlindSpotCount = coverageSummaries.length > 0
    ? coverageSummaries.reduce((total, source) => total + source.blind_spots, 0)
    : coverageBlindSpots.length;
  const coverageSourceCount = coverageSummaries.filter((source) => source.blind_spots > 0).length;
  const coveragePending = coverageSummaries.length === 0 && !coverageQuery.data && coverageQuery.loading;
  const criticalAndHigh = (summary?.critical_findings ?? 0) + (summary?.high_findings ?? 0);

  const reload = () => {
    if (invalidWorkspaceScope) return;
    void dashboard.reload();
    void coverageQuery.reload();
    void inventoryQuery.reload();
    void trendsQuery.reload();
  };

  return (
    <div className={compactHome ? "space-y-4" : "space-y-5"}>
      <PageHeader
        contractId="overview"
        title="Security Overview"
        description="Findings, assets, and source health across every connected cloud and SaaS account."
        action={
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" onClick={reload} className="secondary-button px-3 py-2 text-[13px]">Refresh Data</button>
            <Link href="/connectors" className="secondary-button px-3 py-2 text-[13px]">Connect Source</Link>
            <Link href="/risks" className="primary-button px-3 py-2 text-[13px]">Open Risks</Link>
          </div>
        }
      />

      <DataStateBanner
        state={invalidWorkspaceScope ? "permission-denied" : dashboard.state}
        subject="Graph data"
        error={dashboard.error}
        lastSuccessfulAt={dashboard.lastSuccessfulAt}
        onRetry={invalidWorkspaceScope ? undefined : () => void dashboard.reload()}
        detail={invalidWorkspaceScope
          ? "Select a tenant before loading a workspace."
          : dashboard.state === "loading" ? "Loading findings, assets, and source health." : undefined}
      />

      {data && summary && (
        <>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <OverviewTile
              href="/risks"
              label="Open Findings"
              value={summary.open_findings}
              detail={`${summary.critical_findings} critical, ${summary.high_findings} high`}
              tone={criticalAndHigh > 0 ? "danger" : summary.open_findings > 0 ? "warning" : "success"}
            />
            <OverviewTile
              href="/inventory"
              label="Assets Tracked"
              value={assets ? assets.total_assets : "—"}
              detail={assets ? `${countLabel(assets.org_groups, "org group")} in scope` : "Loading asset inventory."}
              tone="neutral"
            />
            <OverviewTile
              href="/connectors"
              label="Sources Connected"
              value={summary.connectors}
              detail={countLabel(summary.stale_connectors, "stale source")}
              tone={summary.stale_connectors > 0 ? "warning" : "success"}
            />
            <OverviewTile
              href="/inventory"
              label="Owner Coverage"
              value={assets ? `${assets.assigned_coverage_pct}%` : "—"}
              detail={assets ? countLabel(assets.unassigned_assets, "asset") + " unowned" : "Loading asset inventory."}
              tone={!assets ? "neutral" : assets.assigned_coverage_pct >= 90 ? "success" : assets.assigned_coverage_pct >= 70 ? "warning" : "danger"}
            />
          </div>

          <ChangeStrip trends={trendsQuery.data ?? undefined} />

          {(visibleSections.assetCoverage || visibleSections.signalCoverage) && (
            <div className={`grid gap-4 ${visibleSections.assetCoverage && visibleSections.signalCoverage ? "lg:grid-cols-2" : ""}`}>
              {visibleSections.assetCoverage && (
                <AssetCoveragePanel assets={assets} pending={inventoryQuery.loading} />
              )}
              {visibleSections.signalCoverage && (
                <SignalCoveragePanel
                  coverageBlindSpotCount={coverageBlindSpotCount}
                  coveragePending={coveragePending}
                  coverageSourceCount={coverageSourceCount}
                  summary={summary}
                />
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}
