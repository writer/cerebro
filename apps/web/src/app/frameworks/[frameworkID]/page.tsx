"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useMemo, useState } from "react";

import FindingTable from "@/components/grc/FindingTable";
import { Badge, ErrorBlock, LoadingBlock, MetricCard, PageHeader, Panel, ResultLimitNotice } from "@/components/grc/Primitives";
import TrendsChart from "@/components/grc/LazyTrendsChart";
import { useApiKey } from "@/components/providers";
import type { GRCControl, GRCControlEvidencePacketResponse, GRCFinding, GRCFramework, GRCFrameworksResponse, GRCListMeta, GRCTrends } from "@/lib/grc";
import { displayDate, humanize, riskSort } from "@/lib/grc";
import { downloadGRCExport, grcPath, useGRCQuery } from "@/lib/grc-client";
import { frameworkMatchesRouteSegment, frameworkRouteSegment, isUpcomingGRCFramework, staticGRCFrameworkCatalog } from "@/lib/grc-frameworks";
import { GRC_DETAIL_LIMIT, GRC_WORKLIST_LIMIT, grcBoundedRows } from "@/lib/grc-list";
import { hasTrendActivity } from "@/lib/trends";

type FindingsResponse = { findings: GRCFinding[]; meta?: GRCListMeta; generated_at: string };

const FRAMEWORK_CONTROL_LIMIT = GRC_WORKLIST_LIMIT;
const FRAMEWORK_FINDING_LIMIT = GRC_DETAIL_LIMIT;

const readinessTotal = (framework?: GRCFramework) =>
  (framework?.readiness?.auditor_ready_controls ?? 0) +
  (framework?.readiness?.needs_enrichment_controls ?? 0) +
  (framework?.readiness?.placeholder_controls ?? 0);

const countLabel = (count: number, singular: string, plural = `${singular}s`) =>
  `${count.toLocaleString()} ${count === 1 ? singular : plural}`;

const frameworkNameFromSegment = (segment: string) =>
  decodeURIComponent(segment).replace(/-/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());

const actionHref = (framework: GRCFramework, code: string) => {
  const frameworkParam = encodeURIComponent(framework.name);
  if (code === "plan_framework_scope") return `/controls/builder?framework_name=${frameworkParam}`;
  if (code === "export_audit_packet") return "";
  return `/controls?framework=${frameworkParam}`;
};

function GapActions({ framework, onExport, exportState }: { framework: GRCFramework; onExport: () => void; exportState: string }) {
  const actions = framework.gap_actions ?? [];
  return (
    <div className="space-y-3">
      {actions.map((action) => {
        const href = actionHref(framework, action.code);
        return (
          <div key={action.code} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-[color:var(--border)] p-3">
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <Badge value={action.code} />
                <span className="text-[12px] text-[var(--text-muted)]">Priority {action.priority}</span>
                {action.count ? <span className="text-[12px] text-[var(--text-muted)]">{countLabel(action.count, "control")}</span> : null}
              </div>
              <div className="mt-2 text-[13px] text-[var(--text-primary)]">{action.label}</div>
            </div>
            {href ? (
              <Link href={href} className="rounded-md border border-[color:var(--border)] px-3 py-1.5 text-[12px] font-medium text-[var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[var(--text-primary)]">
                Open
              </Link>
            ) : (
              <button type="button" onClick={onExport} disabled={exportState === "working"} className="rounded-md border border-[color:var(--border)] px-3 py-1.5 text-[12px] font-medium text-[var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[var(--text-primary)] disabled:opacity-60">
                {exportState === "working" ? "Exporting..." : "Export"}
              </button>
            )}
          </div>
        );
      })}
    </div>
  );
}

function ControlRows({ controls, framework }: { controls: GRCControl[]; framework: string }) {
  if (controls.length === 0) {
    return <div className="rounded-lg border border-dashed border-[color:var(--border-strong)] p-8 text-center text-[13px] text-[var(--text-muted)]">No measured controls are available for this framework yet.</div>;
  }
  return (
    <div className="overflow-hidden rounded-lg border border-[color:var(--border)]">
      <table className="min-w-full divide-y divide-[color:var(--border)] text-[13px]">
        <thead className="bg-[var(--surface-muted)] text-left text-[11px] uppercase tracking-wider text-[var(--text-muted)]">
          <tr>
            <th className="px-3 py-2">Control</th>
            <th className="px-3 py-2">Status</th>
            <th className="px-3 py-2">Findings</th>
            <th className="px-3 py-2">Evidence</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[color:var(--border)]">
          {controls.slice(0, 12).map((control) => (
            <tr key={`${control.framework_name}-${control.control_id}`}>
              <td className="px-3 py-3">
                <Link href={`/controls/detail?framework=${encodeURIComponent(framework)}&control=${encodeURIComponent(control.control_id)}`} className="font-medium text-[var(--text-primary)] hover:text-[var(--primary)]">
                  {control.control_id}
                </Link>
                <div className="mt-0.5 text-[12px] text-[var(--text-muted)]">{control.title || control.family_name}</div>
              </td>
              <td className="px-3 py-3"><Badge value={control.status} /></td>
              <td className="px-3 py-3 text-[var(--text-secondary)]">{control.open_findings}</td>
              <td className="px-3 py-3 text-[var(--text-secondary)]">{control.evidence_items}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {controls.length > 12 && (
        <div className="border-t border-[color:var(--border)] px-3 py-2 text-[12px] text-[var(--text-muted)]">
          Showing 12 of {controls.length}. <Link href={`/controls?framework=${encodeURIComponent(framework)}`} className="font-medium text-[var(--primary)]">Open all controls</Link>
        </div>
      )}
    </div>
  );
}

function PlanningMode({ framework }: { framework: GRCFramework }) {
  const checklist = [
    "Confirm applicability and in-scope business units.",
    "Assign framework owner, control owners, and evidence reviewers.",
    "Define initial control families and expected evidence sources.",
    "Create a draft custom control pack before measurement starts.",
  ];
  return (
    <Panel title="Upcoming planning mode">
      <div className="grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
        <div>
          <p className="text-[13px] leading-5 text-[var(--text-muted)]">
            {framework.name} is available for planning without affecting posture, risk metrics, or audit readiness percentages.
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            <Link href={`/controls/builder?framework_name=${encodeURIComponent(framework.name)}`} className="rounded-md bg-[var(--primary)] px-3 py-1.5 text-[12px] font-medium text-white transition hover:bg-[var(--primary-hover)]">
              Start control pack
            </Link>
            <Link href={`/inventory?framework=${encodeURIComponent(framework.name)}`} className="rounded-md border border-[color:var(--border)] px-3 py-1.5 text-[12px] font-medium text-[var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[var(--text-primary)]">
              Scope inventory
            </Link>
          </div>
        </div>
        <ul className="space-y-2 text-[13px] text-[var(--text-secondary)]">
          {checklist.map((item) => (
            <li key={item} className="flex gap-2">
              <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--primary)]" />
              <span>{item}</span>
            </li>
          ))}
        </ul>
      </div>
    </Panel>
  );
}

export default function FrameworkDetailPage() {
  const params = useParams<{ frameworkID?: string }>();
  const routeSegment = String(params.frameworkID ?? "");
  const frameworksQuery = useGRCQuery<GRCFrameworksResponse>(grcPath("/grc/frameworks"));
  const frameworks = useMemo(
    () => frameworksQuery.data?.frameworks?.length ? frameworksQuery.data.frameworks : staticGRCFrameworkCatalog,
    [frameworksQuery.data?.frameworks],
  );
  const framework = useMemo(
    () => frameworks.find((item) => frameworkMatchesRouteSegment(item, routeSegment)),
    [frameworks, routeSegment],
  );
  const displayName = framework?.name || frameworkNameFromSegment(routeSegment);
  const isUpcoming = framework?.lifecycle === "upcoming" || isUpcomingGRCFramework(displayName);
  const packetQuery = useGRCQuery<GRCControlEvidencePacketResponse>(framework && !isUpcoming ? grcPath("/grc/control-packets", { framework: framework.name, limit: FRAMEWORK_CONTROL_LIMIT }) : null);
  const findingsQuery = useGRCQuery<FindingsResponse>(framework && !isUpcoming ? grcPath("/grc/findings", { framework: framework.name, status: "open", limit: FRAMEWORK_FINDING_LIMIT }) : null);
  const trendsQuery = useGRCQuery<GRCTrends>(framework && !isUpcoming ? grcPath("/grc/trends", { framework: framework.name, interval: "week", days: 90 }) : null);
  const { apiKey } = useApiKey();
  const [exportState, setExportState] = useState<"idle" | "working" | "failed">("idle");
  const exportPacket = useCallback(async () => {
    if (!framework || isUpcoming) return;
    setExportState("working");
    const result = await downloadGRCExport(
      grcPath("/grc/control-packets/export", { framework: framework.name, format: "markdown" }),
      apiKey,
      `cerebro-${frameworkRouteSegment(framework)}-audit-packet-${new Date().toISOString().slice(0, 10)}.md`,
    );
    setExportState(result.ok ? "idle" : "failed");
  }, [apiKey, framework, isUpcoming]);
  const boundedControlRows = useMemo(
    () => grcBoundedRows({ rows: packetQuery.data?.controls, limit: FRAMEWORK_CONTROL_LIMIT, total: packetQuery.data?.packet?.summary?.total }),
    [packetQuery.data?.controls, packetQuery.data?.packet?.summary?.total],
  );
  const controls = boundedControlRows.rows;
  const controlListMeta = packetQuery.data ? boundedControlRows.meta : undefined;
  const boundedFindingRows = useMemo(
    () => grcBoundedRows({ rows: findingsQuery.data?.findings, limit: FRAMEWORK_FINDING_LIMIT, meta: findingsQuery.data?.meta }),
    [findingsQuery.data?.findings, findingsQuery.data?.meta],
  );
  const loadedFindings = boundedFindingRows.rows;
  const findingListMeta = findingsQuery.data ? boundedFindingRows.meta : undefined;
  const findings = useMemo(() => loadedFindings.slice().sort(riskSort), [loadedFindings]);
  const readinessCount = readinessTotal(framework);
  const maturityScore = framework?.maturity?.score ?? 0;
  const evidenceGapCount = (framework?.readiness?.needs_enrichment_controls ?? 0) + (framework?.readiness?.placeholder_controls ?? 0);
  const packetControlTotal = controlListMeta?.total ?? packetQuery.data?.packet?.summary?.total ?? controls.length;
  const measuredControlCount = packetQuery.data ? packetControlTotal : framework?.coverage?.selected_controls ?? 0;
  const measuredControlDetail = packetQuery.data
    ? countLabel(controls.length, "loaded control")
    : countLabel(framework?.control_count ?? 0, "catalog control");
  const readinessDetail = countLabel(readinessCount, "readiness-scored control");
  const isLoadingFramework = frameworksQuery.loading && !frameworksQuery.data && !framework;

  if (!isLoadingFramework && !framework) {
    return (
      <div className="space-y-6">
        <PageHeader contractId="framework-detail" title="Framework not found" description={`No framework matched "${routeSegment}".`} />
        <Link href="/frameworks" className="text-[13px] font-medium text-[var(--primary)]">Back to frameworks</Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        contractId="framework-detail"
        title={displayName}
        description={framework?.description || "Framework posture, maturity, gaps, findings, controls, and audit packet exports."}
        action={
          <div className="flex flex-wrap items-center gap-2">
            {framework && <Badge value={framework.lifecycle} />}
            <Link href="/frameworks" className="rounded-md border border-[color:var(--border)] px-3 py-1.5 text-[12px] font-medium text-[var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[var(--text-primary)]">All frameworks</Link>
            {!isUpcoming && framework && (
              <button type="button" onClick={exportPacket} disabled={exportState === "working"} className="rounded-md bg-[var(--primary)] px-3 py-1.5 text-[12px] font-medium text-white transition hover:bg-[var(--primary-hover)] disabled:opacity-60">
                {exportState === "working" ? "Exporting..." : "Export packet"}
              </button>
            )}
          </div>
        }
      />

      {frameworksQuery.error && frameworksQuery.data?.frameworks?.length ? <ErrorBlock error={frameworksQuery.error} onRetry={frameworksQuery.reload} /> : null}
      {isLoadingFramework && <LoadingBlock label="Loading framework..." />}

      {framework && (
        <>
          <div className="grid gap-4 md:grid-cols-4">
            <MetricCard label="Maturity" value={isUpcoming ? "N/A" : `${maturityScore}%`} detail={framework.maturity?.summary || "Not measured"} state={isLoadingFramework ? "loading" : "ready"} />
            <MetricCard label="Measured controls" value={isUpcoming ? "N/A" : measuredControlCount} detail={measuredControlDetail} state={isLoadingFramework ? "loading" : "ready"} />
            <MetricCard label="Audit-ready" value={isUpcoming ? "N/A" : framework.readiness?.auditor_ready_controls ?? 0} detail={readinessDetail} state={isLoadingFramework ? "loading" : "ready"} />
            <MetricCard label="Evidence gaps" value={isUpcoming ? "N/A" : evidenceGapCount} detail={isUpcoming ? "Planning only" : "Controls needing enrichment"} intent={evidenceGapCount > 0 ? "warning" : "success"} state={isLoadingFramework ? "loading" : "ready"} />
          </div>

          {isUpcoming ? <PlanningMode framework={framework} /> : null}

          <Panel title="Gap-to-action workflow">
            <GapActions framework={framework} onExport={exportPacket} exportState={exportState} />
            {exportState === "failed" && <div className="mt-3 text-[12px] text-red-600">Export failed. Check API connectivity and try again.</div>}
          </Panel>

          {!isUpcoming && (
            <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
              <Panel title={`${displayName} tracking snapshot`}>
                <div className="grid gap-3 sm:grid-cols-3">
                  <div className="rounded-lg bg-[var(--surface-muted)] p-3">
                    <div className="text-xl font-semibold text-[var(--text-primary)]">{humanize(framework.maturity?.status || "not configured")}</div>
                    <div className="mt-1 text-[12px] text-[var(--text-muted)]">Maturity stage</div>
                  </div>
                  <div className="rounded-lg bg-[var(--surface-muted)] p-3">
                    <div className="text-xl font-semibold text-[var(--text-primary)]">{framework.coverage?.mapped_rules ?? 0}</div>
                    <div className="mt-1 text-[12px] text-[var(--text-muted)]">Mapped rules</div>
                  </div>
                  <div className="rounded-lg bg-[var(--surface-muted)] p-3">
                    <div className="text-xl font-semibold text-[var(--text-primary)]">{findings.length}</div>
                    <div className="mt-1 text-[12px] text-[var(--text-muted)]">Open findings</div>
                  </div>
                </div>
                <div className="mt-4 text-[12px] text-[var(--text-muted)]">Last packet generated {displayDate(packetQuery.data?.generated_at)}</div>
              </Panel>

              <Panel title="Finding trend">
                {trendsQuery.loading && !trendsQuery.data ? <LoadingBlock label="Loading trends..." /> : null}
                {trendsQuery.error ? <ErrorBlock error={trendsQuery.error} onRetry={trendsQuery.reload} /> : null}
                {trendsQuery.data && hasTrendActivity(trendsQuery.data) ? <TrendsChart points={trendsQuery.data.points} height={220} targets={trendsQuery.data.targets} /> : null}
                {trendsQuery.data && !hasTrendActivity(trendsQuery.data) ? <div className="rounded-lg border border-dashed border-[color:var(--border-strong)] p-8 text-center text-[13px] text-[var(--text-muted)]">No framework trend activity in this window.</div> : null}
              </Panel>
            </div>
          )}

          {!isUpcoming && (
            <Panel title="Controls and readiness">
              {packetQuery.error && <ErrorBlock error={packetQuery.error} onRetry={packetQuery.reload} />}
              {packetQuery.loading && !packetQuery.data && <LoadingBlock label="Loading controls..." />}
              {!packetQuery.error && packetQuery.data && (
                <ResultLimitNotice
                  loaded={controls.length}
                  limit={FRAMEWORK_CONTROL_LIMIT}
                  meta={controlListMeta}
                  noun="controls"
                  className="mb-3"
                />
              )}
              {!packetQuery.error && <ControlRows controls={controls} framework={framework.name} />}
            </Panel>
          )}

          {!isUpcoming && (
            <Panel title="Open framework findings">
              {findingsQuery.error && <ErrorBlock error={findingsQuery.error} onRetry={findingsQuery.reload} />}
              {findingsQuery.loading && !findingsQuery.data && <LoadingBlock label="Loading findings..." />}
              {!findingsQuery.error && findingsQuery.data && (
                <ResultLimitNotice
                  loaded={findings.length}
                  limit={FRAMEWORK_FINDING_LIMIT}
                  meta={findingListMeta}
                  noun="findings"
                  className="mb-3"
                />
              )}
              {!findingsQuery.error && findings.length === 0 && <div className="rounded-lg border border-dashed border-[color:var(--border-strong)] p-8 text-center text-[13px] text-[var(--text-muted)]">No open findings are currently mapped to this framework.</div>}
              {findings.length > 0 && <FindingTable findings={findings} />}
            </Panel>
          )}
        </>
      )}
    </div>
  );
}
