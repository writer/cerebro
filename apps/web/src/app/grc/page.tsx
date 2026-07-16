"use client";

import Link from "next/link";
import { useMemo } from "react";

import { AttentionBanner, Badge, DataStateBanner, MetricCard, PageHeader, Panel } from "@/components/grc/Primitives";
import { countLabel } from "@/lib/format";
import {
  displayDate,
  GRCDashboard,
  GRCControl,
  GRCProgramFramework,
  GRCProgramProofBundle,
  GRCProgramReadiness,
  GRCProgramReadinessSummary,
  GRCProgramWorkItem,
  humanize,
} from "@/lib/grc";
import { DASHBOARD_FINDING_LIMIT, grcDashboardPath, grcProgramReadinessPath, useGRCQuery } from "@/lib/grc-client";
import { frameworkRouteSegment } from "@/lib/grc-frameworks";
import type { RuntimeState } from "@/lib/runtime-state";

type IssueQueueItem = {
  action: string;
  assignee: string;
  dueLabel: string;
  detail: string;
  href: string;
  id: string;
  owner: string;
  severity?: string;
  slaStatus: string;
  source: string;
  status: string;
  title: string;
  type: string;
};

type ReadinessCheck = {
  action: string;
  detail: string;
  href: string;
  label: string;
  status: string;
  tone: "danger" | "warning" | "success" | "neutral";
  value: string;
};

const controlHref = (control: GRCControl) =>
  `/controls?framework=${encodeURIComponent(control.framework_name)}&control=${encodeURIComponent(control.control_id)}`;

const workItemHref = (item: GRCProgramWorkItem) => {
  if (item.href) return item.href;
  if (item.framework_name && item.control_id) {
    return `/controls?framework=${encodeURIComponent(item.framework_name)}&control=${encodeURIComponent(item.control_id)}`;
  }
  return "/controls";
};

const workItemDetail = (item: GRCProgramWorkItem) => {
  if (item.reasons?.[0]) return item.reasons[0];
  const parts = [
    item.open_findings ? countLabel(item.open_findings, "open finding") : "",
    item.missing_evidence_items ? countLabel(item.missing_evidence_items, "missing evidence item") : "",
    item.stale_evidence_items ? countLabel(item.stale_evidence_items, "stale evidence item") : "",
  ].filter(Boolean);
  return parts.join(", ") || item.action || "Review required";
};

const compactDate = (value?: string) => {
  if (!value) return "No due date";
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return value;
  return new Intl.DateTimeFormat("en", { month: "short", day: "numeric" }).format(new Date(timestamp));
};

const dueCopy = (dueLabel: string) => dueLabel === "No due date" ? dueLabel : `Due ${dueLabel}`;

const workItemType = (item: GRCProgramWorkItem) => {
  if (item.kind === "finding") return "Issue";
  if (item.kind === "control") return "Control";
  return humanize(item.kind || "work item");
};

const fallbackQueueItem = (control: GRCControl): IssueQueueItem => ({
  action: control.status === "failing" ? "Open control" : "Review evidence",
  assignee: "Unassigned",
  dueLabel: "No due date",
  detail: [
    control.open_findings ? countLabel(control.open_findings, "open finding") : "",
    control.missing_evidence_items ? countLabel(control.missing_evidence_items, "missing evidence item") : "",
    control.stale_evidence_items ? countLabel(control.stale_evidence_items, "stale evidence item") : "",
  ].filter(Boolean).join(", ") || control.audit_summary || "Control needs review",
  href: controlHref(control),
  id: `${control.framework_name}:${control.control_id}`,
  owner: control.owner_domain || "Unassigned",
  slaStatus: "not_set",
  source: control.framework_name,
  status: control.status,
  title: `${control.framework_name} ${control.control_id}`,
  type: "Control",
});

const fallbackControlRank = (control: GRCControl) => {
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
    `${control.framework_name}:${control.control_id}`,
  ] as const;
};

export const buildIssueQueue = (readinessData: GRCProgramReadiness | null | undefined, controls: GRCControl[]) => {
  const readinessItems = readinessData?.work_items ?? [];
  if (readinessItems.length > 0) {
    return readinessItems.slice(0, 10).map((item): IssueQueueItem => ({
      action: item.action || "Open item",
      assignee: item.assignee || "Unassigned",
      dueLabel: compactDate(item.due_at),
      detail: workItemDetail(item),
      href: workItemHref(item),
      id: item.id,
      owner: item.owner_domain || "Unassigned",
      severity: item.severity,
      slaStatus: item.sla_status || "not_set",
      source: item.source_id || item.framework_name || "No source",
      status: item.status,
      title: item.title,
      type: workItemType(item),
    }));
  }

  return controls
    .filter((control) => control.status !== "passing" || (control.missing_evidence_items ?? 0) > 0 || (control.stale_evidence_items ?? 0) > 0)
    .slice()
    .sort((left, right) => {
      const leftRank = fallbackControlRank(left);
      const rightRank = fallbackControlRank(right);
      for (let index = 0; index < leftRank.length; index += 1) {
        const diff = typeof leftRank[index] === "number"
          ? Number(leftRank[index]) - Number(rightRank[index])
          : String(leftRank[index]).localeCompare(String(rightRank[index]));
        if (diff !== 0) return diff;
      }
      return 0;
    })
    .slice(0, 10)
    .map(fallbackQueueItem);
};

const controlSummaryFromDashboard = (controls: GRCControl[]): GRCProgramReadinessSummary => {
  const summary = controls.reduce((acc, control) => {
    acc.controls += 1;
    if (control.status === "passing") acc.passing_controls += 1;
    if (control.status === "failing") acc.failing_controls += 1;
    if ((control.missing_evidence_items ?? 0) > 0) acc.missing_evidence_controls += 1;
    if ((control.stale_evidence_items ?? 0) > 0) acc.stale_evidence_controls += 1;
    if (control.status === "manual_review") acc.manual_review_controls += 1;
    acc.evidence_items += control.evidence_items;
    acc.missing_evidence_items += control.missing_evidence_items ?? 0;
    acc.stale_evidence_items += control.stale_evidence_items ?? 0;
    acc.open_findings += control.open_findings;
    acc.critical_findings += control.critical_findings;
    acc.high_findings += control.high_findings;
    return acc;
  }, {
    connectors: 0,
    controls: 0,
    coverage_blind_spots: 0,
    critical_findings: 0,
    evidence_items: 0,
    failing_controls: 0,
    high_findings: 0,
    manual_review_controls: 0,
    missing_evidence_controls: 0,
    missing_evidence_items: 0,
    open_findings: 0,
    passing_controls: 0,
    score: 0,
    stale_connectors: 0,
    stale_evidence_controls: 0,
    stale_evidence_items: 0,
    status: "current_counts",
  });
  summary.score = summary.controls === 0 ? 100 : Math.round((summary.passing_controls / summary.controls) * 100);
  return summary;
};

const appRouteOrFallback = (href: string | undefined, fallback: string) => {
  if (!href || href.startsWith("/grc/")) return fallback;
  return href;
};

const stepToneClass: Record<ReadinessCheck["tone"], string> = {
  danger: "bg-red-500",
  warning: "bg-amber-500",
  success: "bg-emerald-500",
  neutral: "bg-[var(--border-strong)]",
};

const metricIntent = (count: number) => count > 0 ? "warning" : "success";

export const buildReadinessChecks = ({
  summary,
}: {
  summary: GRCProgramReadinessSummary;
}): ReadinessCheck[] => {
  const evidenceIssues = summary.missing_evidence_items + summary.stale_evidence_items;
  const sourceIssues = summary.stale_connectors + summary.coverage_blind_spots;
  const checks: ReadinessCheck[] = [];

  if (sourceIssues > 0) {
    checks.push({
      action: "Refresh sources",
      detail: `${countLabel(summary.coverage_blind_spots, "coverage gap")}, ${countLabel(summary.stale_connectors, "stale source")}`,
      href: "/reports/audit-packages#source-freshness",
      label: "Source gaps",
      status: "needs_attention",
      tone: "warning",
      value: sourceIssues.toLocaleString(),
    });
  }

  if (summary.failing_controls > 0 || summary.manual_review_controls > 0) {
    checks.push({
      action: "Resolve controls",
      detail: `${countLabel(summary.failing_controls, "failing control")}, ${countLabel(summary.manual_review_controls, "manual review")}`,
      href: "/reports/audit-packages#control-owner-queue",
      label: "Failing controls",
      status: "needs_attention",
      tone: "warning",
      value: summary.failing_controls.toLocaleString(),
    });
  }

  if (evidenceIssues > 0) {
    checks.push({
      action: "Collect evidence",
      detail: `${summary.missing_evidence_items.toLocaleString()} missing, ${summary.stale_evidence_items.toLocaleString()} stale`,
      href: "/reports/audit-packages#evidence-review",
      label: "Evidence gaps",
      status: "needs_attention",
      tone: "warning",
      value: evidenceIssues.toLocaleString(),
    });
  }

  if (checks.length === 0) {
    checks.push({
      action: "Open packet",
      detail: "No failing controls, missing evidence, stale evidence, or source gaps.",
      href: "/reports/audit-packages",
      label: "Packet ready",
      status: "ready",
      tone: "success",
      value: "Clear",
    });
  }

  return checks;
};

function ReadinessChecksPanel({ checks }: { checks: ReadinessCheck[] }) {
  return (
    <Panel title="Packet blockers">
      <div className="divide-y divide-[color:var(--border)]">
        {checks.map((step) => (
          <Link key={step.label} href={step.href} className="grid gap-3 py-3 transition hover:bg-[var(--surface-muted)] sm:grid-cols-[minmax(0,1fr)_92px_132px]">
            <div className="flex min-w-0 gap-3">
              <span className={`mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full ${stepToneClass[step.tone]}`} aria-hidden="true" />
              <div className="min-w-0">
                <div className="text-[13px] font-semibold text-[var(--text-primary)]">{step.label}</div>
                <div className="mt-1 line-clamp-2 text-[12px] leading-5 text-[var(--text-muted)]">{step.detail}</div>
              </div>
            </div>
            <div className="text-[13px] font-semibold text-[var(--text-primary)]">{step.value}</div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[12px] font-medium text-[var(--primary)]">{step.action}</span>
              <Badge value={step.status} />
            </div>
          </Link>
        ))}
      </div>
    </Panel>
  );
}

function IssueQueuePanel({ items }: { items: IssueQueueItem[] }) {
  return (
    <Panel title="Open control issues" action={<Link href="/risk-inbox" className="secondary-button px-3 py-1.5 text-[12px]">View issue queue</Link>}>
      {items.length === 0 ? (
        <div className="rounded-lg border border-dashed border-[color:var(--border-strong)] px-4 py-8 text-center text-[13px] text-[var(--text-muted)]">
          No control, evidence, or source issues are blocking the packet.
        </div>
      ) : (
        <div className="divide-y divide-[color:var(--border)]">
          {items.map((item) => (
            <Link key={item.id} href={item.href} className="grid gap-3 py-3 transition hover:bg-[var(--surface-muted)] md:grid-cols-[minmax(0,1fr)_150px_132px_80px]">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge value={item.type} />
                  {item.severity && <Badge value={item.severity} tone="severity" />}
                  <div className="text-[13px] font-semibold text-[var(--text-primary)]">{item.title}</div>
                </div>
                <div className="mt-1 line-clamp-2 text-[12px] leading-5 text-[var(--text-muted)]">
                  {item.detail}
                </div>
              </div>
              <div className="min-w-0 text-[12px]">
                <div className="truncate font-medium text-[var(--text-primary)]">{item.owner}</div>
                <div className="mt-1 truncate text-[var(--text-muted)]">Assignee: {item.assignee}</div>
              </div>
              <div className="min-w-0 text-[12px]">
                <div className="font-medium text-[var(--text-primary)]">{dueCopy(item.dueLabel)}</div>
                <div className="mt-1 flex flex-wrap gap-1.5">
                  <Badge value={item.slaStatus} />
                  <span className="truncate text-[var(--text-muted)]">{item.source}</span>
                </div>
              </div>
              <div className="flex items-center justify-between gap-2 text-[12px] font-medium text-[var(--primary)] md:justify-end">
                <span className="sr-only">{item.action}</span>
                <span aria-hidden="true">Open</span>
              </div>
            </Link>
          ))}
        </div>
      )}
    </Panel>
  );
}

function AuditPacketPanel({
  proofBundle,
  summary,
}: {
  proofBundle?: GRCProgramProofBundle;
  summary: GRCProgramReadinessSummary;
}) {
  const blockers = proofBundle?.readiness.blockers ?? summary.readiness_blockers ?? [];

  return (
    <Panel title="Control evidence packet">
      {proofBundle ? (
        <div className="space-y-4">
          <div>
            <div className="flex items-start justify-between gap-3">
              <h2 className="text-[15px] font-semibold text-[var(--text-primary)]">{proofBundle.title}</h2>
              <Badge value={proofBundle.status} />
            </div>
            <p className="mt-2 text-[13px] leading-5 text-[var(--text-muted)]">
              {proofBundle.description || `${countLabel(summary.missing_evidence_items, "missing evidence item")}, ${countLabel(summary.stale_evidence_items, "stale evidence item")}.`}
            </p>
          </div>
          <div className="grid gap-3 text-[12px] sm:grid-cols-2">
            <div>
              <div className="text-[11px] uppercase tracking-wide text-[var(--text-muted)]">Packet status</div>
              <div className="mt-1 text-xl font-semibold text-[var(--text-primary)]">{proofBundle.score}/100</div>
            </div>
            <div>
              <div className="text-[11px] uppercase tracking-wide text-[var(--text-muted)]">Generated</div>
              <div className="mt-1 font-medium text-[var(--text-primary)]">{displayDate(proofBundle.generated_at)}</div>
            </div>
          </div>
          {blockers.length > 0 && (
            <div className="rounded-lg border border-[color:var(--border)] px-3 py-2">
              <div className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">Packet blockers</div>
              <div className="mt-2 flex flex-wrap gap-2">
                {blockers.slice(0, 4).map((blocker) => (
                  <span key={`${blocker.code}:${blocker.label}`} className="rounded-md bg-[var(--surface-muted)] px-2 py-1 text-[12px] text-[var(--text-secondary)]">
                    {blocker.count ? `${blocker.count} ` : ""}{blocker.label}
                  </span>
                ))}
              </div>
            </div>
          )}
          <div className="flex flex-wrap gap-2">
            <Link href={appRouteOrFallback(proofBundle.export_path, "/reports")} className="primary-button px-3 py-1.5 text-[12px]">Export packet</Link>
            <Link href={appRouteOrFallback(proofBundle.reports_path, "/reports")} className="secondary-button px-3 py-1.5 text-[12px]">Open packet</Link>
          </div>
        </div>
      ) : (
        <div className="text-[13px] leading-5 text-[var(--text-muted)]">
          Loading packet status.
        </div>
      )}
    </Panel>
  );
}

function FrameworkPosturePanel({ frameworks }: { frameworks: GRCProgramFramework[] }) {
  const sorted = frameworks
    .slice()
    .filter((framework) => framework.status !== "ready" || framework.failing_controls > 0 || framework.missing_evidence_controls > 0 || framework.stale_evidence_controls > 0)
    .sort((left, right) => left.score - right.score || right.failing_controls - left.failing_controls)
    .slice(0, 6);

  if (sorted.length === 0) return null;

  return (
    <Panel title="Frameworks needing attention" action={<Link href="/frameworks" className="secondary-button px-3 py-1.5 text-[12px]">Open frameworks</Link>}>
      <div className="divide-y divide-[color:var(--border)]">
        {sorted.map((framework) => (
          <Link
            key={`${framework.framework_name}:${framework.framework_id ?? ""}`}
            href={`/frameworks/${frameworkRouteSegment({ id: framework.framework_id, name: framework.framework_name })}`}
            className="grid gap-3 py-3 transition hover:bg-[var(--surface-muted)] sm:grid-cols-[minmax(0,1fr)_92px_160px]"
          >
            <div className="min-w-0">
              <div className="truncate text-[13px] font-semibold text-[var(--text-primary)]">{framework.framework_name}</div>
              <div className="mt-1 text-[12px] text-[var(--text-muted)]">
                {framework.passing_controls.toLocaleString()} of {framework.controls.toLocaleString()} controls passing
              </div>
            </div>
            <div className="text-[13px] font-semibold text-[var(--text-primary)]">{Math.round(framework.score)}%</div>
            <div className="flex flex-wrap items-center gap-2">
              <Badge value={framework.status} />
              {framework.failing_controls > 0 && (
                <span className="text-[12px] text-[var(--text-muted)]">{framework.failing_controls} failing</span>
              )}
            </div>
          </Link>
        ))}
      </div>
    </Panel>
  );
}

export default function GRCPage() {
  const dashboard = useGRCQuery<GRCDashboard>(grcDashboardPath({ limit: DASHBOARD_FINDING_LIMIT }));
  const readinessQuery = useGRCQuery<GRCProgramReadiness>(dashboard.data ? grcProgramReadinessPath() : null);
  const dashboardControls = useMemo(() => dashboard.data?.controls ?? [], [dashboard.data?.controls]);
  const fallbackSummary = useMemo(() => controlSummaryFromDashboard(dashboardControls), [dashboardControls]);
  const summary = readinessQuery.data?.summary ?? fallbackSummary;
  const frameworks = useMemo(() => readinessQuery.data?.frameworks ?? [], [readinessQuery.data?.frameworks]);
  const issueItems = useMemo(() => buildIssueQueue(readinessQuery.data, dashboardControls), [dashboardControls, readinessQuery.data]);
  const readinessChecks = useMemo(() => buildReadinessChecks({ summary }), [summary]);
  const metricState: RuntimeState = dashboard.state === "stale" || dashboard.state === "empty" ? "ready" : dashboard.state;
  const evidenceIssues = summary.missing_evidence_items + summary.stale_evidence_items;
  const sourceIssues = summary.stale_connectors + summary.coverage_blind_spots;
  const packetBlockers = summary.readiness_blockers?.reduce((total, blocker) => total + (blocker.count ?? 1), 0) ?? issueItems.length;
  const packetBlockerVerb = packetBlockers === 1 ? "affects" : "affect";
  const readinessSource = readinessQuery.data ? humanize(summary.status) : "current counts";
  const pageDescription = dashboard.data
    ? `${countLabel(packetBlockers, "blocker")} ${packetBlockerVerb} packet export. ${countLabel(summary.failing_controls, "failing control")}, ${countLabel(evidenceIssues, "evidence issue")}, ${countLabel(sourceIssues, "source issue")}.`
    : "Open control issues, packet status, evidence gaps, and source freshness.";

  const reload = () => {
    void dashboard.reload();
    void readinessQuery.reload();
  };

  return (
    <div className="space-y-6">
      <PageHeader
        contractId="grc"
        title="Compliance"
        description={pageDescription}
        action={
          <div className="flex items-center gap-2">
            <button type="button" onClick={reload} className="secondary-button px-3 py-1.5 text-[13px]">Refresh</button>
          </div>
        }
      />

      <DataStateBanner
        state={dashboard.state}
        subject="Compliance data"
        error={dashboard.error}
        lastSuccessfulAt={dashboard.lastSuccessfulAt}
        onRetry={() => void dashboard.reload()}
        detail={dashboard.state === "loading" ? "Loading controls, findings, evidence, and sources." : undefined}
      />

      {readinessQuery.error && dashboard.data && (
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
          Packet status is unavailable; showing current control counts.
        </AttentionBanner>
      )}

      {dashboard.data && (
        <>
          <div className="grid gap-4 md:grid-cols-4">
            <MetricCard label="Packet score" value={`${Math.round(summary.score)}%`} detail={readinessSource} intent={summary.score >= 80 ? "success" : summary.score >= 50 ? "warning" : "danger"} state={metricState} />
            <MetricCard label="Open issues" value={issueItems.length} detail={`${summary.critical_findings} critical, ${summary.high_findings} high`} intent={issueItems.length > 0 ? "warning" : "success"} state={metricState} />
            <MetricCard label="Evidence issues" value={evidenceIssues} detail={`${summary.missing_evidence_items} missing, ${summary.stale_evidence_items} stale`} intent={metricIntent(evidenceIssues)} state={metricState} />
            <MetricCard label="Source issues" value={sourceIssues} detail={`${summary.stale_connectors} stale, ${summary.coverage_blind_spots} coverage gaps`} intent={metricIntent(sourceIssues)} state={metricState} />
          </div>

          <IssueQueuePanel items={issueItems} />

          <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_360px]">
            <ReadinessChecksPanel checks={readinessChecks} />
            <AuditPacketPanel proofBundle={readinessQuery.data?.proof_bundle} summary={summary} />
          </div>

          <FrameworkPosturePanel frameworks={frameworks} />
        </>
      )}
    </div>
  );
}
