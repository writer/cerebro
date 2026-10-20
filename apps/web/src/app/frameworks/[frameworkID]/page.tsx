"use client";

import Link from "next/link";
import { useParams, useSearchParams } from "next/navigation";
import { useMemo, useState } from "react";

import FindingTable from "@/components/grc/FindingTable";
import { Badge, EmptyBlock, ErrorBlock, LoadingBlock, MetricCard, PageHeader, Panel, ResultLimitNotice } from "@/components/grc/Primitives";
import {
  type ControlViolation,
  controlViolations,
  FRAMEWORK_FINDING_LIMIT,
  frameworkFindingsPath,
  FRAMEWORK_SETTINGS_PATH,
  type FrameworkSettingsResponse,
  frameworkViolationSummary,
} from "@/lib/compliance-frameworks";
import { countLabel } from "@/lib/format";
import type { GRCFinding, GRCFrameworksResponse, GRCListMeta } from "@/lib/grc";
import { grcPath, useGRCQuery } from "@/lib/grc-client";
import { frameworkMatchesRouteSegment, staticGRCFrameworkCatalog } from "@/lib/grc-frameworks";

type FindingsResponse = { findings: GRCFinding[]; meta?: GRCListMeta };

const matchesControlFilter = (violation: ControlViolation, query: string) => {
  if (!query) return true;
  return violation.controlID.toLowerCase().includes(query)
    || violation.rules.some((rule) => rule.ruleID.toLowerCase().includes(query))
    || violation.findings.some((finding) => finding.title.toLowerCase().includes(query));
};

function ControlViolationRow({ violation, defaultOpen }: { violation: ControlViolation; defaultOpen: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="rounded-lg border border-[color:var(--border)]" data-control-violation={violation.controlID}>
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        className="flex w-full flex-wrap items-center justify-between gap-3 px-4 py-3 text-left"
      >
        <div className="min-w-0">
          <div className="font-mono text-[13px] font-semibold text-[var(--text-primary)]">{violation.controlID}</div>
          <div className="mt-1 flex flex-wrap gap-1.5">
            {violation.rules.slice(0, 4).map((rule) => (
              <span key={rule.ruleID} className="rounded bg-[var(--surface-muted)] px-1.5 py-0.5 font-mono text-[11px] text-[var(--text-secondary)]">
                {rule.ruleID}
              </span>
            ))}
            {violation.rules.length > 4 && <span className="text-[11px] text-[var(--text-muted)]">+{violation.rules.length - 4} more rules</span>}
          </div>
        </div>
        <div className="flex items-center gap-3 text-[12px] text-[var(--text-muted)]">
          {violation.critical > 0 && <Badge value="CRITICAL" tone="severity" />}
          {violation.critical === 0 && violation.high > 0 && <Badge value="HIGH" tone="severity" />}
          <span>{countLabel(violation.findings.length, "open finding")}</span>
          <span aria-hidden>{open ? "−" : "+"}</span>
        </div>
      </button>
      {open && (
        <div className="border-t border-[color:var(--border)] p-3">
          <FindingTable findings={violation.findings} />
        </div>
      )}
    </div>
  );
}

export default function FrameworkDetailPage() {
  const params = useParams<{ frameworkID?: string }>();
  const searchParams = useSearchParams();
  const routeSegment = String(params.frameworkID ?? "");
  const tenantID = (searchParams.get("tenant_id") ?? "").trim();
  const focusedControl = (searchParams.get("control") ?? "").trim();
  const [filter, setFilter] = useState(focusedControl);
  const catalogQuery = useGRCQuery<GRCFrameworksResponse>(grcPath("/grc/frameworks"));
  const settingsQuery = useGRCQuery<FrameworkSettingsResponse>(grcPath(FRAMEWORK_SETTINGS_PATH, { tenant_id: tenantID }));
  const catalog = catalogQuery.data?.frameworks?.length ? catalogQuery.data.frameworks : staticGRCFrameworkCatalog;
  const framework = useMemo(() => catalog.find((item) => frameworkMatchesRouteSegment(item, routeSegment)), [catalog, routeSegment]);
  const isUpcoming = framework?.lifecycle === "upcoming";
  const findingsQuery = useGRCQuery<FindingsResponse>(framework && !isUpcoming ? frameworkFindingsPath(framework, tenantID) : null);
  const violations = useMemo(
    () => (framework ? controlViolations(findingsQuery.data?.findings ?? [], framework) : []),
    [findingsQuery.data?.findings, framework],
  );
  const summary = frameworkViolationSummary(violations);
  const query = filter.trim().toLowerCase();
  const visible = violations.filter((violation) => matchesControlFilter(violation, query));
  const enabled = settingsQuery.data?.settings.enabled_frameworks.some((name) => name.toLowerCase() === framework?.name.toLowerCase());
  const backHref = tenantID ? `/grc?tenant_id=${encodeURIComponent(tenantID)}` : "/grc";
  const findingsState = findingsQuery.loading && !findingsQuery.data ? "loading" : findingsQuery.data ? "ready" : "unavailable";

  if (catalogQuery.loading && !catalogQuery.data && !framework) {
    return <LoadingBlock label="Loading framework..." />;
  }

  if (!framework) {
    return (
      <div className="space-y-6">
        <PageHeader contractId="framework-detail" title="Framework Not Found" description={`No framework matched "${decodeURIComponent(routeSegment)}".`} />
        <Link href={backHref} className="text-[13px] font-medium text-[var(--primary)]">Back to compliance</Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        contractId="framework-detail"
        title={framework.name}
        description={framework.description || "Open findings mapped to this framework's controls."}
        action={
          <div className="flex flex-wrap items-center gap-2">
            {settingsQuery.data && <Badge value={enabled ? "enabled" : "not_enabled"} />}
            <Link href={backHref} className="secondary-button px-3 py-1.5 text-[12px]">All frameworks</Link>
          </div>
        }
      />

      {isUpcoming ? (
        <Panel title="Not Measured Yet">
          <EmptyBlock label={`No rules map to ${framework.name} yet, so its controls cannot show violations.`} />
        </Panel>
      ) : (
        <>
          <div className="grid gap-4 md:grid-cols-4">
            <MetricCard label="Controls violated" value={summary.controls} detail={`of ${countLabel(framework.control_count, "control")} in the catalog`} intent={summary.controls > 0 ? "danger" : "success"} state={findingsState} />
            <MetricCard label="Open findings" value={summary.findings} detail="Mapped to these controls" intent={summary.findings > 0 ? "warning" : "success"} state={findingsState} />
            <MetricCard label="Failing rules" value={summary.rules} detail={`${countLabel(framework.coverage?.mapped_rules ?? 0, "rule")} map to this framework`} intent={summary.rules > 0 ? "warning" : "success"} state={findingsState} />
            <MetricCard label="Critical findings" value={summary.critical} detail="Across violated controls" intent={summary.critical > 0 ? "danger" : "success"} state={findingsState} />
          </div>

          <Panel title="Violations by Control">
            {findingsQuery.loading && !findingsQuery.data && <LoadingBlock label="Loading violations..." />}
            {findingsQuery.error && <ErrorBlock error={findingsQuery.error} onRetry={findingsQuery.reload} />}
            {findingsQuery.data && (
              <>
                <ResultLimitNotice
                  loaded={findingsQuery.data.findings.length}
                  limit={FRAMEWORK_FINDING_LIMIT}
                  meta={findingsQuery.data.meta}
                  noun="open findings"
                  className="mb-3"
                />
                {violations.length > 0 && (
                  <input
                    type="search"
                    value={filter}
                    onChange={(event) => setFilter(event.target.value)}
                    placeholder="Filter by control, rule, or finding"
                    aria-label="Filter controls"
                    className="mb-3 w-full max-w-sm rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-3 py-1.5 text-[13px]"
                  />
                )}
                {violations.length === 0 && <EmptyBlock label={`No open findings map to ${framework.name} controls.`} />}
                {violations.length > 0 && visible.length === 0 && <EmptyBlock label="No violated controls match that filter." />}
                <div className="space-y-2">
                  {visible.map((violation) => (
                    <ControlViolationRow
                      key={violation.controlID}
                      violation={violation}
                      defaultOpen={violation.controlID.toLowerCase() === focusedControl.toLowerCase() || visible.length === 1}
                    />
                  ))}
                </div>
              </>
            )}
          </Panel>
        </>
      )}
    </div>
  );
}
