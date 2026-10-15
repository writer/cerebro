"use client";

import Link from "next/link";
import {
  ArrowUpRight,
  Boxes,
  ChevronRight,
  ClipboardCheck,
  Globe,
  Flame,
  type LucideIcon,
  MessageSquareText,
  PlugZap,
  Radar,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  TrendingUp,
  UserCheck,
  UserX,
} from "lucide-react";

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

const toneLabel: Record<CoverageTone, string> = {
  danger: "Act now",
  warning: "Review",
  success: "Healthy",
  neutral: "Info",
};

function OverviewTile({
  detail,
  hint,
  href,
  icon: Icon,
  label,
  tone,
  value,
}: {
  detail: string;
  hint: string;
  href: string;
  icon: LucideIcon;
  label: string;
  tone: CoverageTone;
  value: string | number;
}) {
  return (
    <Link href={href} className={`surface-panel metric-tile tone-${tone} group flex flex-col p-5`}>
      <div className="relative flex items-start justify-between gap-3">
        <span className="icon-bubble h-10 w-10" aria-hidden="true">
          <Icon className="h-5 w-5" strokeWidth={2} />
        </span>
        <span className="tone-pill">{toneLabel[tone]}</span>
      </div>
      <div className="relative mt-4 eyebrow">{label}</div>
      <div className="metric-value relative mt-1.5">{value}</div>
      <div className="relative mt-1.5 truncate text-[13px] font-medium text-[var(--text-secondary)]">{detail}</div>
      <p className="relative mt-3 border-t border-[color:var(--border)] pt-3 text-[12px] leading-5 text-[var(--text-muted)]">
        {hint}
      </p>
      <ArrowUpRight
        aria-hidden="true"
        className="absolute right-4 bottom-4 h-4 w-4 text-[var(--text-muted)] opacity-0 transition group-hover:opacity-100"
      />
    </Link>
  );
}

const HOME_ASK_PROMPTS = [
  "What can reach production from the internet?",
  "Which identities can escalate to admin?",
  "Which exposed assets have no owner?",
];

function CoverageRow({
  detail,
  href,
  icon: Icon,
  label,
  tone,
  value,
}: {
  detail: string;
  href: string;
  icon: LucideIcon;
  label: string;
  tone: CoverageTone;
  value: string | number;
}) {
  return (
    <Link
      href={href}
      className={`tone-${tone} group grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-3.5 rounded-xl px-3 py-3 transition hover:bg-[var(--surface-hover)]`}
    >
      <span className="icon-bubble" aria-hidden="true">
        <Icon className="h-[18px] w-[18px]" strokeWidth={2} />
      </span>
      <div className="min-w-0">
        <div className="text-[13px] font-semibold text-[var(--text-primary)]">{label}</div>
        <div className="mt-0.5 truncate text-[12px] leading-5 text-[var(--text-muted)]">{detail}</div>
      </div>
      <div className="flex items-center gap-2">
        <span className="tone-pill px-2.5 py-1 text-[13px]">{value}</span>
        <ChevronRight aria-hidden="true" className="h-4 w-4 text-[var(--text-muted)] transition group-hover:translate-x-0.5" />
      </div>
    </Link>
  );
}

function SectionHeader({ description, icon: Icon, title }: { description: string; icon: LucideIcon; title: string }) {
  return (
    <div className="flex items-start gap-3">
      <span className="icon-bubble tone-neutral" aria-hidden="true">
        <Icon className="h-[18px] w-[18px]" strokeWidth={2} />
      </span>
      <div className="min-w-0">
        <h2 className="text-[16px] font-semibold tracking-[-0.01em] text-[var(--text-primary)]">{title}</h2>
        <p className="mt-0.5 text-[13px] leading-5 text-[var(--text-muted)]">{description}</p>
      </div>
    </div>
  );
}

// Opened above the baseline, closed below it, so a window where the backlog
// grew is visible without reading any number.
export function ChangeStrip({ trends }: { trends?: GRCTrends }) {
  const points = trends?.points ?? [];
  const peak = Math.max(1, ...points.map((point) => point.opened + point.closed));
  const summary = trends?.summary;
  const net = summary?.net ?? 0;
  const stats = [
    { label: "New", value: summary?.total_opened ?? 0, tone: "warning" as const, hint: "Risky states detected" },
    { label: "Resolved", value: summary?.total_closed ?? 0, tone: "success" as const, hint: "Fixed or no longer present" },
    {
      label: "Net change",
      value: net > 0 ? `+${net}` : net,
      tone: net > 0 ? ("danger" as const) : ("success" as const),
      hint: net > 0 ? "Risk is outpacing fixes" : net < 0 ? "Fixes are outpacing risk" : "Holding steady",
    },
  ];
  return (
    <section className="surface-panel p-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <SectionHeader
          icon={TrendingUp}
          title="Risk Trend"
          description={`Are fixes keeping pace with new risk? Daily, last ${HOME_TREND_DAYS} days.`}
        />
        <div className="flex flex-wrap items-center gap-3">
          {stats.map((stat) => (
            <div key={stat.label} className={`tone-${stat.tone} rounded-xl border border-[color:var(--border)] bg-[var(--surface-muted)] px-3.5 py-2`}>
              <div className="eyebrow text-[10px]">{stat.label}</div>
              <div className="mt-0.5 text-[20px] font-semibold tabular-nums" style={{ color: "var(--bubble-fg)" }}>{stat.value}</div>
              <div className="text-[11px] text-[var(--text-muted)]">{stat.hint}</div>
            </div>
          ))}
          <Link href="/trends" className="secondary-button px-3.5 py-2 text-[12px]">
            View Trends
            <ArrowUpRight aria-hidden="true" className="h-3.5 w-3.5" />
          </Link>
        </div>
      </div>
      {points.length === 0 ? (
        <div className="mt-5 rounded-xl border border-dashed border-[color:var(--border-strong)] px-4 py-6 text-center text-[13px] text-[var(--text-muted)]">
          No new or resolved findings in this window.
        </div>
      ) : (
        <>
          <div className="mt-6 flex h-24 items-end gap-1" aria-hidden="true">
            {points.map((point) => (
              <div key={point.date} className="flex h-full min-w-0 flex-1 flex-col justify-end gap-[3px]">
                <div
                  className="w-full rounded-md bg-gradient-to-t from-amber-400 to-amber-300 dark:from-amber-500/80 dark:to-amber-400/70"
                  style={{ height: `${Math.max(point.opened > 0 ? 4 : 0, (point.opened / peak) * 88)}px` }}
                />
                <div
                  className="w-full rounded-md bg-gradient-to-t from-emerald-500 to-emerald-300 dark:from-emerald-500/80 dark:to-emerald-400/70"
                  style={{ height: `${Math.max(point.closed > 0 ? 4 : 0, (point.closed / peak) * 88)}px` }}
                />
              </div>
            ))}
          </div>
          <div className="mt-3 flex items-center gap-4 text-[12px] text-[var(--text-muted)]">
            <span className="inline-flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm bg-amber-400" />New findings</span>
            <span className="inline-flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm bg-emerald-400" />Resolved</span>
          </div>
        </>
      )}
    </section>
  );
}

export function AssetCoveragePanel({ assets, pending }: { assets?: GRCInventorySummary; pending: boolean }) {
  const placeholder = pending ? "Loading asset inventory." : "No asset inventory reported.";
  return (
    <section className="surface-panel p-6">
      <SectionHeader
        icon={Boxes}
        title="Asset Coverage"
        description="How much of your attack surface is mapped, owned, and exposed."
      />
      {assets ? (
        <div className="mt-4 space-y-1">
          <CoverageRow
            href="/inventory"
            icon={UserX}
            label="Unowned Assets"
            value={assets.unassigned_assets}
            detail={`${assets.accountable_assets ?? 0} of ${assets.total_assets} have an accountable owner`}
            tone={assets.unassigned_assets > 0 ? "warning" : "success"}
          />
          <CoverageRow
            href="/inventory"
            icon={Globe}
            label="Publicly Reachable"
            value={assets.public_assets}
            detail="Reachable from the internet. Attack paths start here."
            tone={assets.public_assets > 0 ? "danger" : "success"}
          />
          <CoverageRow
            href="/inventory"
            icon={Flame}
            label="High Risk Assets"
            value={assets.high_risk_assets}
            detail="Highest composed risk across their findings and graph context."
            tone={assets.high_risk_assets > 0 ? "danger" : "success"}
          />
          <CoverageRow
            href="/inventory"
            icon={ClipboardCheck}
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
    <section className="surface-panel p-6">
      <SectionHeader
        icon={Radar}
        title="Source Health"
        description="Posture is only as current as the evidence behind it."
      />
      <div className="mt-4 space-y-1">
        <CoverageRow
          href="/connectors"
          icon={PlugZap}
          label="Sources Reporting"
          value={`${healthySources}/${summary.connectors}`}
          detail={countLabel(summary.stale_connectors, "stale source")}
          tone={summary.stale_connectors > 0 ? "warning" : "success"}
        />
        <CoverageRow
          href="/connectors"
          icon={ScanSearch}
          label="Blind Spots"
          value={coveragePending ? "—" : coverageBlindSpotCount}
          detail={coveragePending
            ? "Loading source coverage."
            : `${countLabel(coverageBlindSpotCount, "coverage gap")} across ${countLabel(coverageSourceCount, "source")}`}
          tone={coveragePending ? "neutral" : coverageBlindSpotCount > 0 ? "warning" : "success"}
        />
        <CoverageRow
          href="/rules"
          icon={ShieldCheck}
          label="Rule Coverage"
          value="Review"
          detail="Which posture rules can evaluate the data you collect."
          tone="neutral"
        />
      </div>
      <div className="mt-5 border-t border-[color:var(--border)] pt-4">
        <div className="eyebrow flex items-center gap-1.5">
          <MessageSquareText aria-hidden="true" className="h-3.5 w-3.5" />
          Ask Cerebro
        </div>
        <div className="mt-2.5 flex flex-wrap gap-2">
          {HOME_ASK_PROMPTS.map((question) => (
            <AskAboutLink
              key={question}
              question={question}
              className="max-w-full truncate rounded-full border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-1.5 text-left text-[12px] font-medium text-[var(--primary)] transition hover:border-[color:var(--primary)] hover:bg-[var(--primary-soft)]"
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
        title="Security Posture"
        description="What can reach your production systems, through which path, and who owns the fix."
        action={
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" onClick={reload} className="secondary-button px-3 py-2 text-[13px]">Refresh</button>
            <Link href="/connectors" className="secondary-button px-3 py-2 text-[13px]">Add Source</Link>
            <Link href="/risks" className="primary-button px-3 py-2 text-[13px]">Review Findings</Link>
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
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <OverviewTile
              href="/risks"
              icon={ShieldAlert}
              hint="Current risky states, each tied to an affected asset and a fix."
              label="Open Findings"
              value={summary.open_findings}
              detail={`${summary.critical_findings} critical, ${summary.high_findings} high`}
              tone={criticalAndHigh > 0 ? "danger" : summary.open_findings > 0 ? "warning" : "success"}
            />
            <OverviewTile
              href="/inventory"
              icon={Boxes}
              hint="Cloud, SaaS, identity, and code assets mapped into one graph."
              label="Assets Tracked"
              value={assets ? assets.total_assets : "—"}
              detail={assets ? `${countLabel(assets.org_groups, "org group")} in scope` : "Loading asset inventory."}
              tone="neutral"
            />
            <OverviewTile
              href="/connectors"
              icon={PlugZap}
              hint="Clouds, SaaS, and scanners feeding evidence. Stale data, stale posture."
              label="Sources Connected"
              value={summary.connectors}
              detail={countLabel(summary.stale_connectors, "stale source")}
              tone={summary.stale_connectors > 0 ? "warning" : "success"}
            />
            <OverviewTile
              href="/inventory"
              icon={UserCheck}
              hint="Fixes route to owners, and unowned assets are where they stall. Target 90%+."
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
