"use client";

import Link from "next/link";
import { useMemo } from "react";

import { useUserPreferences } from "@/components/providers";
import { AttentionBanner, DataStateBanner, PageHeader } from "@/components/grc/Primitives";
import { countLabel } from "@/lib/format";
import { isControlAuditReady } from "@/lib/framework-readiness";
import {
  displayDate,
  displayDurationSeconds,
  GRCDashboard,
  GRCConnector,
  GRCControl,
  GRCFinding,
  GRCProgramReadiness,
  GRCProgramWorkItem,
  GRCSourceCoverageRecord,
  GRCSummary,
  humanize,
  riskSort,
  shortEntity,
} from "@/lib/grc";
import { DASHBOARD_FINDING_LIMIT, grcDashboardPath, grcPath, grcProgramReadinessPath, useGRCQuery } from "@/lib/grc-client";
import { normalizeLegacyControlHref } from "@/lib/navigation";

const HOME_DASHBOARD_FINDING_LIMIT = DASHBOARD_FINDING_LIMIT;

type WorkChipTone = "danger" | "warning" | "success" | "neutral";

const workChipClass: Record<WorkChipTone, string> = {
  danger: "border-red-200 bg-red-50 text-red-700",
  warning: "border-amber-200 bg-amber-50 text-amber-700",
  success: "border-emerald-200 bg-emerald-50 text-emerald-700",
  neutral: "border-slate-200 bg-slate-50 text-slate-600",
};

function WorkChip({ children, tone = "neutral" }: { children: string | number; tone?: WorkChipTone }) {
  return (
    <span className={`inline-flex rounded-md border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${workChipClass[tone]}`}>
      {children}
    </span>
  );
}

type HomeMetrics = {
  auditReadinessScore: number;
  controlTotal: number;
  coverageBlindSpotCount: number;
  criticalOrHighFindings: number;
  evidenceIssues: number;
  missingEvidenceItems: number;
  passingControls: number;
  staleEvidenceItems: number;
  summary: GRCSummary;
};

type HomeQueueItem = {
  dedupeKey: string;
  detail: string;
  href: string;
  id: string;
  due: string;
  framework: string;
  owner: string;
  rank: number;
  title: string;
  tone: WorkChipTone;
  type: string;
  status: string;
};

const ownerMissing = (finding: GRCFinding) => !finding.owner || finding.owner === "Unassigned";

const findingSlaLabel = (finding: GRCFinding) => {
  if (finding.due_at) return `${humanize(finding.sla_status)} - ${displayDate(finding.due_at)}`;
  return humanize(finding.sla_status || "no_due_date");
};

const findingReviewItem = (finding: GRCFinding): HomeQueueItem => {
  const riskScore = finding.risk_score ?? 0;
  return {
    dedupeKey: `finding:${finding.id}`,
    detail: `${finding.owner || "Unassigned"} - ${findingSlaLabel(finding)}`,
    href: `/findings/${encodeURIComponent(finding.id)}`,
    id: `finding:${finding.id}`,
    due: finding.due_at ? displayDate(finding.due_at) : "Not set",
    framework: finding.controls?.[0]?.framework_name || "Risk",
    owner: finding.owner || "Unassigned",
    rank: riskScore >= 85 ? 0 : finding.severity === "CRITICAL" || finding.severity === "HIGH" ? 5 : ownerMissing(finding) ? 20 : 60,
    title: finding.title,
    tone: riskScore >= 85 || finding.severity === "CRITICAL" ? "danger" : "warning",
    type: "Risk",
    status: humanize(finding.sla_status || finding.status),
  };
};

const findingKeyFromHref = (href: string) => {
  const match = href.match(/^\/findings\/([^/?#]+)/);
  if (!match) return "";
  try {
    return `finding:${decodeURIComponent(match[1])}`;
  } catch {
    return `finding:${match[1]}`;
  }
};

const workItemReviewItem = (item: GRCProgramWorkItem): HomeQueueItem => {
  const href = normalizeLegacyControlHref(item.href || (item.framework_name && item.control_id ? `/controls?framework=${encodeURIComponent(item.framework_name)}&control=${encodeURIComponent(item.control_id)}` : "/controls"));
  const evidenceIssue = (item.missing_evidence_items ?? 0) + (item.stale_evidence_items ?? 0);
  const pointsAtRisk = href.startsWith("/findings/");
  return {
    dedupeKey: findingKeyFromHref(href) || `work:${href}`,
    detail: item.reasons?.[0] || countLabel(item.open_findings ?? 0, "mapped finding"),
    href,
    id: `work:${item.id}`,
    due: item.due_at ? displayDate(item.due_at) : "Not set",
    framework: item.framework_name || (pointsAtRisk ? "Risk" : "Control"),
    owner: item.assignee || item.owner_domain || "Unassigned",
    rank: pointsAtRisk ? 45 : item.status === "failing" ? 12 : evidenceIssue > 0 ? 18 : 35,
    title: item.title,
    tone: item.status === "failing" ? "danger" : "warning",
    type: pointsAtRisk ? "Risk" : "Control",
    status: humanize(item.status || "needs review"),
  };
};

const controlKey = (control: GRCControl) => `${control.framework_name}-${control.control_id}`;

const controlOwner = (control: GRCControl) =>
  control.owner_domain || control.findings?.find((finding) => finding.owner && finding.owner !== "Unassigned")?.owner || "Unassigned";

const earliestDueAt = (findings: GRCFinding[] | undefined) => {
  const timestamps = (findings ?? [])
    .map((finding) => finding.due_at ? Date.parse(finding.due_at) : Number.NaN)
    .filter((value) => Number.isFinite(value));
  if (timestamps.length === 0) return undefined;
  return new Date(Math.min(...timestamps)).toISOString();
};

const controlRecommendation = (control: GRCControl) => {
  if (control.status === "failing" && control.open_findings > 0) return "Mapped findings open";
  if ((control.missing_evidence_items ?? 0) > 0) return "Missing evidence";
  if ((control.stale_evidence_items ?? 0) > 0) return "Stale proof";
  if (control.status === "manual_review") return "Manual assessment";
  return "Audit-ready";
};

const controlWorkQueueRank = (control: GRCControl) => {
  const statusWeight: Record<string, number> = {
    failing: 0,
    missing_evidence: 1,
    stale_evidence: 2,
    manual_review: 3,
    exception: 4,
    passing: 8,
  };
  return [
    statusWeight[control.status] ?? 5,
    -(control.critical_findings * 100 + control.open_findings * 10 + (control.missing_evidence_items ?? 0) + (control.stale_evidence_items ?? 0)),
    Date.parse(earliestDueAt(control.findings) ?? "9999-12-31"),
  ] as const;
};

const controlHref = (control: GRCControl) =>
  `/controls?framework=${encodeURIComponent(control.framework_name)}&control=${encodeURIComponent(control.control_id)}`;

const controlReviewItem = (control: GRCControl): HomeQueueItem => {
  const missingEvidence = control.missing_evidence_items ?? 0;
  const staleEvidence = control.stale_evidence_items ?? 0;
  const dueAt = earliestDueAt(control.findings);
  return {
    dedupeKey: `control:${control.framework_name}:${control.control_id}`,
    detail: controlRecommendation(control),
    href: controlHref(control),
    id: `control:${controlKey(control)}`,
    due: dueAt ? displayDate(dueAt) : "Not set",
    framework: control.framework_name,
    owner: controlOwner(control),
    rank: control.status === "failing" ? 15 : missingEvidence + staleEvidence > 0 ? 25 : 70,
    title: `${control.framework_name} ${control.control_id}`,
    tone: control.status === "failing" ? "danger" : missingEvidence + staleEvidence > 0 ? "warning" : "success",
    type: "Control",
    status: humanize(control.status),
  };
};

const connectorNeedsAttention = (connector: GRCConnector) =>
  connector.status !== "healthy" ||
  connector.freshness !== "fresh" ||
  (typeof connector.sync_lag_seconds === "number" && connector.sync_lag_seconds > 60 * 60) ||
  (typeof connector.watermark_lag_seconds === "number" && connector.watermark_lag_seconds > 60 * 60);

const connectorReviewItem = (connector: GRCConnector): HomeQueueItem => {
  const source = connector.source_id || shortEntity(connector.runtime_id);
  const sourceFilter = connector.source_id || connector.runtime_id;
  const syncLag = displayDurationSeconds(connector.sync_lag_seconds);
  const dataLag = displayDurationSeconds(connector.watermark_lag_seconds);
  const syncDetail = syncLag === "\u2014" ? "not observed" : `${syncLag} ago`;
  const dataDetail = dataLag === "\u2014" ? "not observed" : `${dataLag} ago`;
  const status = connector.status === "healthy" && connector.freshness !== "fresh" ? connector.freshness : connector.status;
  return {
    dedupeKey: `source:${sourceFilter}`,
    detail: `Sync ${syncDetail} - data ${dataDetail}`,
    href: `/connectors?source_id=${encodeURIComponent(sourceFilter)}`,
    id: `connector:${connector.runtime_id}`,
    due: "Review now",
    framework: "Integration",
    owner: "Unassigned",
    rank: connector.status === "failed" ? 30 : 50,
    title: source,
    tone: connector.status === "healthy" ? "warning" : "danger",
    type: "Source",
    status: humanize(status || "needs review"),
  };
};

const coverageReviewItem = (record: GRCSourceCoverageRecord): HomeQueueItem => ({
  dedupeKey: `coverage:${record.source_id}:${record.dimension_id}`,
  detail: record.warning || record.notes?.[0] || `${record.dimension_type} coverage is incomplete.`,
  href: `/connectors/${encodeURIComponent(record.source_id)}?tab=scope`,
  id: `coverage:${record.source_id}:${record.dimension_id}`,
  due: "Review now",
  framework: "Integration",
  owner: "Unassigned",
  rank: record.high_value ? 35 : 55,
  title: record.title || humanize(record.dimension_id),
  tone: record.high_value ? "danger" : "warning",
  type: "Coverage",
  status: humanize(record.state || record.support_level || "coverage gap"),
});

const dedupeQueueItems = (items: HomeQueueItem[]) => {
  const seen = new Set<string>();
  return items.filter((item) => {
    if (seen.has(item.dedupeKey)) return false;
    seen.add(item.dedupeKey);
    return true;
  });
};

export function buildHomeQueue({
  connectors,
  controls,
  coverageBlindSpots,
  findings,
  readinessData,
}: {
  connectors: GRCConnector[];
  controls: GRCControl[];
  coverageBlindSpots: GRCSourceCoverageRecord[];
  findings: GRCFinding[];
  readinessData?: GRCProgramReadiness;
}) {
  const highRiskFindings = findings
    .filter((finding) => (finding.risk_score ?? 0) >= 70 || finding.severity === "CRITICAL" || finding.severity === "HIGH" || ownerMissing(finding))
    .slice(0, 5)
    .map(findingReviewItem);
  const readinessItems = (readinessData?.work_items ?? [])
    .filter((item) => !findingKeyFromHref(item.href || ""))
    .slice(0, 2)
    .map(workItemReviewItem);
  const controlItems = controls
    .filter((control) => control.status !== "passing" || (control.missing_evidence_items ?? 0) > 0 || (control.stale_evidence_items ?? 0) > 0)
    .slice()
    .sort((left, right) => {
      const leftRank = controlWorkQueueRank(left);
      const rightRank = controlWorkQueueRank(right);
      for (let index = 0; index < leftRank.length; index += 1) {
        const diff = leftRank[index] - rightRank[index];
        if (diff !== 0) return diff;
      }
      return controlKey(left).localeCompare(controlKey(right));
    })
    .slice(0, 3)
    .map(controlReviewItem);
  const sourceItems = connectors.filter(connectorNeedsAttention).slice(0, 3).map(connectorReviewItem);
  const coverageItems = coverageBlindSpots
    .slice()
    .sort((left, right) => Number(Boolean(right.high_value)) - Number(Boolean(left.high_value)) || (left.title || left.dimension_id).localeCompare(right.title || right.dimension_id))
    .slice(0, 3)
    .map(coverageReviewItem);

  return dedupeQueueItems([...readinessItems, ...highRiskFindings, ...controlItems, ...sourceItems, ...coverageItems])
    .sort((left, right) => left.rank - right.rank || left.title.localeCompare(right.title))
    .slice(0, 5);
}

export function ReviewNowPanel({ items }: { items: HomeQueueItem[] }) {
  return (
    <section className="surface-panel min-w-0 overflow-hidden">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-[color:var(--border)] px-5 py-4">
        <div>
          <h2 className="text-[15px] font-semibold text-[var(--text-primary)]">Open work queue</h2>
          <p className="mt-1 text-[13px] text-[var(--text-muted)]">Items blocking readiness or waiting for an owner.</p>
        </div>
        <Link href="/risk-inbox" className="secondary-button px-3 py-1.5 text-[12px]">Open queue</Link>
      </div>
      <div className="hidden grid-cols-[minmax(220px,1fr)_120px_140px_100px_120px] gap-3 border-b border-[color:var(--border)] bg-[var(--surface-muted)] px-5 py-2 text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)] lg:grid">
        <span>Work</span>
        <span>Framework</span>
        <span>Owner</span>
        <span>Due</span>
        <span>Status</span>
      </div>
      <div className="divide-y divide-[color:var(--border)]">
        {items.map((item) => (
          <Link
            key={item.id}
            href={normalizeLegacyControlHref(item.href)}
            className="grid gap-3 px-5 py-4 transition hover:bg-[var(--surface-muted)] lg:grid-cols-[minmax(220px,1fr)_120px_140px_100px_120px] lg:items-center"
          >
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <WorkChip tone={item.tone}>{item.type}</WorkChip>
                <div className="truncate text-[13px] font-semibold text-[var(--text-primary)]">{item.title}</div>
              </div>
              <div className="mt-1 truncate text-[12px] leading-5 text-[var(--text-muted)]">{item.detail}</div>
            </div>
            <div className="truncate text-[12px] text-[var(--text-secondary)]"><span className="mr-2 text-[var(--text-muted)] lg:hidden">Framework</span>{item.framework}</div>
            <div className="truncate text-[12px] text-[var(--text-secondary)]"><span className="mr-2 text-[var(--text-muted)] lg:hidden">Owner</span>{item.owner}</div>
            <div className="text-[12px] text-[var(--text-secondary)]"><span className="mr-2 text-[var(--text-muted)] lg:hidden">Due</span>{item.due}</div>
            <div className="flex items-center justify-between gap-2">
              <WorkChip tone={item.tone}>{item.status}</WorkChip>
              <span className="text-[16px] leading-none text-[var(--text-muted)]" aria-hidden="true">›</span>
            </div>
          </Link>
        ))}
        {items.length === 0 && (
          <div className="px-5 py-8 text-center text-[13px] text-[var(--text-muted)]">No urgent review items.</div>
        )}
      </div>
    </section>
  );
}

function ReadinessBand({ framework, metrics }: { framework: string; metrics: HomeMetrics }) {
  const score = Math.max(0, Math.min(100, metrics.auditReadinessScore));
  return (
    <Link href="/frameworks" className="surface-panel block px-5 py-4 transition hover:border-[color:var(--border-strong)]">
      <div className="grid items-center gap-4 md:grid-cols-[180px_minmax(0,1fr)_80px_190px]">
        <div>
          <div className="text-[12px] font-semibold text-[var(--text-primary)]">{framework} readiness</div>
          <div className="mt-1 text-[12px] text-[var(--text-muted)]">Open framework details</div>
        </div>
        <div className="h-2 overflow-hidden rounded-full bg-[var(--surface-muted)]">
          <div className="h-full rounded-full bg-[var(--primary)]" style={{ width: `${score}%` }} />
        </div>
        <div className="text-2xl font-semibold tabular-nums text-[var(--text-primary)]">{Math.round(score)}%</div>
        <div className="text-[12px] text-[var(--text-muted)]">{metrics.passingControls} of {metrics.controlTotal} controls ready</div>
      </div>
    </Link>
  );
}

function HealthRow({
  detail,
  href,
  label,
  tone,
  value,
}: {
  detail: string;
  href: string;
  label: string;
  tone: WorkChipTone;
  value: string | number;
}) {
  return (
    <Link href={href} className="grid grid-cols-[minmax(0,1fr)_auto] gap-3 rounded-md px-2 py-2.5 transition hover:bg-[var(--surface-muted)]">
      <div className="min-w-0">
        <div className="text-[12px] font-medium text-[var(--text-primary)]">{label}</div>
        <div className="mt-0.5 truncate text-[12px] text-[var(--text-muted)]">{detail}</div>
      </div>
      <div className="flex items-center gap-2">
        <span className="text-[16px] font-semibold text-[var(--text-primary)]">{value}</span>
        <span className={`h-2 w-2 rounded-full ${tone === "danger" ? "bg-red-500" : tone === "warning" ? "bg-amber-500" : tone === "success" ? "bg-emerald-500" : "bg-slate-300"}`} />
      </div>
    </Link>
  );
}

function ProgramHealthPanel({
  coveragePending,
  coverageSourceCount,
  metrics,
  readinessLabel,
}: {
  coveragePending: boolean;
  coverageSourceCount: number;
  metrics: HomeMetrics;
  readinessLabel: string;
}) {
  const sourceIssues = metrics.summary.stale_connectors + metrics.coverageBlindSpotCount;
  const sourceDetail = coveragePending
    ? "Loading source coverage."
    : `${countLabel(metrics.summary.stale_connectors, "stale source")}, ${countLabel(metrics.coverageBlindSpotCount, "coverage gap")} across ${countLabel(coverageSourceCount, "source")}`;
  return (
    <aside className="surface-panel p-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-[15px] font-semibold text-[var(--text-primary)]">Program health</h2>
          <p className="mt-1 text-[13px] text-[var(--text-muted)]">Current program blockers.</p>
        </div>
        <div className="text-right">
          <div className="text-2xl font-semibold text-[var(--text-primary)]">{Math.round(metrics.auditReadinessScore)}%</div>
          <div className="mt-0.5 text-[11px] uppercase tracking-wide text-[var(--text-muted)]">{readinessLabel}</div>
        </div>
      </div>
      <div className="mt-4 divide-y divide-[color:var(--border)]">
        <HealthRow
          href="/controls"
          label="Controls"
          value={Math.max(0, metrics.controlTotal - metrics.passingControls)}
          detail={`${metrics.passingControls} of ${metrics.controlTotal} ready`}
          tone={metrics.passingControls < metrics.controlTotal ? "warning" : "success"}
        />
        <HealthRow
          href="/evidence"
          label="Evidence"
          value={metrics.evidenceIssues}
          detail={`${metrics.missingEvidenceItems} missing, ${metrics.staleEvidenceItems} stale`}
          tone={metrics.evidenceIssues > 0 ? "warning" : "success"}
        />
        <HealthRow
          href="/connectors"
          label="Sources"
          value={coveragePending ? "—" : sourceIssues}
          detail={sourceDetail}
          tone={coveragePending ? "neutral" : sourceIssues > 0 ? "warning" : "success"}
        />
      </div>
      <div className="mt-5 border-t border-[color:var(--border)] pt-4">
        <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Next audit</div>
        <div className="mt-2 text-[13px] font-semibold text-[var(--text-primary)]">Review the current evidence packet</div>
        <p className="mt-1 text-[12px] leading-5 text-[var(--text-muted)]">Resolve packet blockers before sharing a snapshot.</p>
        <Link href="/reports/audit-packages" className="secondary-button mt-3 inline-flex px-3 py-1.5 text-[12px]">Open audit packet</Link>
      </div>
    </aside>
  );
}

export default function Home() {
  const { preferences } = useUserPreferences();
  const visibleSections = preferences.homepage.sections;
  const compactHome = preferences.display.density === "compact";
  const dashboard = useGRCQuery<GRCDashboard>(grcDashboardPath({ limit: HOME_DASHBOARD_FINDING_LIMIT, enrichments: "deferred" }));
  const data = dashboard.data;
  const readinessQuery = useGRCQuery<GRCProgramReadiness>(data ? grcProgramReadinessPath() : null);
  const coverageQuery = useGRCQuery<{ blind_spots?: GRCSourceCoverageRecord[]; records?: GRCSourceCoverageRecord[] }>(
    data
      ? grcPath("/connectors/coverage", { coverage_scope: "configured", coverage_view: "page", blind_spots_only: "true", page_size: 3 })
      : null,
  );
  const readiness = readinessQuery.data?.summary;
  const priorityFindings = useMemo(() => (data?.findings ?? []).slice().sort(riskSort), [data?.findings]);

  const summary = data?.summary;
  const coverageBlindSpots = useMemo(
    () => coverageQuery.data?.blind_spots ?? coverageQuery.data?.records ?? readinessQuery.data?.coverage_blind_spots ?? data?.coverage_blind_spots ?? [],
    [coverageQuery.data?.blind_spots, coverageQuery.data?.records, data?.coverage_blind_spots, readinessQuery.data?.coverage_blind_spots],
  );
  const coverageSummaries = useMemo(
    () => readinessQuery.data?.coverage_summaries ?? data?.coverage_summaries ?? [],
    [data?.coverage_summaries, readinessQuery.data?.coverage_summaries],
  );
  const coverageBlindSpotCount = readiness?.coverage_blind_spots ?? coverageSummaries.reduce((total, source) => total + source.blind_spots, 0);
  const coverageSourceCount = coverageSummaries.filter((source) => source.blind_spots > 0).length;
  const coveragePending = !readinessQuery.data && !coverageQuery.data && (readinessQuery.loading || coverageQuery.loading);
  const missingEvidenceItems = readiness?.missing_evidence_items
    ?? (data?.controls ?? []).reduce((total, control) => total + (control.missing_evidence_items ?? 0), 0);
  const staleEvidenceItems = readiness?.stale_evidence_items
    ?? (data?.controls ?? []).reduce((total, control) => total + (control.stale_evidence_items ?? 0), 0);
  const primaryFrameworkRecord = readinessQuery.data?.frameworks?.[0];
  const primaryFramework = primaryFrameworkRecord?.framework_name || "Program";
  const scopedDashboardControls = (data?.controls ?? []).filter((control) =>
    !primaryFrameworkRecord || control.framework_name === primaryFrameworkRecord.framework_name,
  );
  const controlTotal = primaryFrameworkRecord?.controls ?? scopedDashboardControls.length;
  const passingControls = primaryFrameworkRecord
    ? Math.max(0, Math.min(primaryFrameworkRecord.passing_controls, controlTotal))
    : scopedDashboardControls.filter(isControlAuditReady).length;
  const controlProgress = controlTotal === 0 ? 0 : (passingControls / controlTotal) * 100;
  const criticalOrHighFindings = (summary?.critical_findings ?? 0) + (summary?.high_findings ?? 0);
  const evidenceIssues = missingEvidenceItems + staleEvidenceItems;
  const homeMetrics: HomeMetrics | null = summary ? {
    auditReadinessScore: controlProgress,
    controlTotal,
    coverageBlindSpotCount,
    criticalOrHighFindings,
    evidenceIssues,
    missingEvidenceItems,
    passingControls,
    staleEvidenceItems,
    summary,
  } : null;
  const queueItems = useMemo(() => buildHomeQueue({
    connectors: data?.connectors ?? [],
    controls: data?.controls ?? [],
    coverageBlindSpots,
    findings: priorityFindings,
    readinessData: readinessQuery.data ?? undefined,
  }), [coverageBlindSpots, data?.connectors, data?.controls, priorityFindings, readinessQuery.data]);
  const readinessLabel = "Control readiness";

  const reload = () => {
    void dashboard.reload();
    void readinessQuery.reload();
    void coverageQuery.reload();
  };

  return (
    <div className={compactHome ? "space-y-4" : "space-y-5"}>
      <PageHeader
        contractId="overview"
        title="Compliance overview"
        description="Review open work, evidence gaps, and audit readiness."
        action={
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" onClick={reload} className="secondary-button px-3 py-2 text-[13px]">Refresh data</button>
            <Link href="/connectors" className="secondary-button px-3 py-2 text-[13px]">Connect source</Link>
            <Link href="/reports/audit-packages" className="primary-button px-3 py-2 text-[13px]">Export audit packet</Link>
          </div>
        }
      />

      <DataStateBanner
        state={dashboard.state}
        subject="Graph data"
        error={dashboard.error}
        lastSuccessfulAt={dashboard.lastSuccessfulAt}
        onRetry={() => void dashboard.reload()}
        detail={dashboard.state === "loading" ? "Loading risks, controls, evidence, and sources." : undefined}
      />

      {data && summary && homeMetrics && (
        <>
          <ReadinessBand framework={primaryFramework} metrics={homeMetrics} />
          {(visibleSections.reviewNow || visibleSections.programHealth) && (
            <div className={`grid gap-4 ${visibleSections.reviewNow && visibleSections.programHealth ? "xl:grid-cols-[minmax(0,1fr)_340px]" : ""}`}>
              {visibleSections.reviewNow && <ReviewNowPanel items={queueItems} />}
              {visibleSections.programHealth && (
                <ProgramHealthPanel
                  coveragePending={coveragePending}
                  coverageSourceCount={coverageSourceCount}
                  metrics={homeMetrics}
                  readinessLabel={readinessLabel}
                />
              )}
            </div>
          )}

          {readinessQuery.error && (
            <AttentionBanner
              action={
                <button
                  type="button"
                  onClick={() => void readinessQuery.reload()}
                  className="rounded-md border border-amber-300 bg-white px-3 py-1 text-[12px] font-medium text-amber-900 hover:bg-amber-50"
                >
                  Retry
                </button>
              }
            >
              Program readiness is unavailable; showing current risks, controls, evidence, and source health.
            </AttentionBanner>
          )}

        </>
      )}
    </div>
  );
}
