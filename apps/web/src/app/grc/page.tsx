"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useMemo, useState } from "react";

import { Badge, DataStateBanner, EmptyBlock, ErrorBlock, LoadingBlock, PageHeader, Panel } from "@/components/grc/Primitives";
import {
  controlViolations,
  enabledFrameworks,
  frameworkDetailHref,
  frameworkFindingsPath,
  FRAMEWORK_SETTINGS_PATH,
  type FrameworkSettingsResponse,
  frameworkViolationSummary,
  selectableFrameworks,
  toggleFrameworkName,
} from "@/lib/compliance-frameworks";
import { countLabel } from "@/lib/format";
import type { GRCFinding, GRCFramework, GRCFrameworksResponse, GRCListMeta } from "@/lib/grc";
import { grcPath, useGRCMutation, useGRCQuery } from "@/lib/grc-client";

type FindingsResponse = { findings: GRCFinding[]; meta?: GRCListMeta };

function FrameworkCard({ framework, tenantID }: { framework: GRCFramework; tenantID: string }) {
  const findingsQuery = useGRCQuery<FindingsResponse>(frameworkFindingsPath(framework, tenantID));
  const violations = useMemo(
    () => controlViolations(findingsQuery.data?.findings ?? [], framework),
    [findingsQuery.data?.findings, framework],
  );
  const summary = frameworkViolationSummary(violations);
  const truncated = Boolean(findingsQuery.data?.meta?.truncated);
  const href = frameworkDetailHref(framework, tenantID);

  return (
    <div className="surface-panel flex flex-col gap-4 p-5" data-compliance-framework={framework.name}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <Link href={href} className="text-[16px] font-semibold text-[var(--text-primary)] hover:text-[var(--primary)]">
            {framework.name}
          </Link>
          <div className="mt-1 text-[12px] text-[var(--text-muted)]">
            {countLabel(framework.control_count, "control")}
            {framework.coverage?.mapped_rules ? ` · ${countLabel(framework.coverage.mapped_rules, "mapped rule")}` : ""}
          </div>
        </div>
        {findingsQuery.data && (
          <Badge value={summary.controls > 0 ? "failing" : "passing"} />
        )}
      </div>

      {findingsQuery.loading && !findingsQuery.data && <LoadingBlock label="Loading violations..." />}
      {findingsQuery.error && !findingsQuery.data && <ErrorBlock error={findingsQuery.error} onRetry={findingsQuery.reload} />}

      {findingsQuery.data && (
        <>
          <div className="grid grid-cols-3 gap-2">
            {[
              { label: "Controls violated", value: summary.controls },
              { label: "Open findings", value: summary.findings },
              { label: "Failing rules", value: summary.rules },
            ].map((metric) => (
              <div key={metric.label} className="rounded-lg bg-[var(--surface-muted)] p-3">
                <div className="text-xl font-semibold text-[var(--text-primary)]">
                  {metric.value.toLocaleString()}{truncated ? "+" : ""}
                </div>
                <div className="mt-1 text-[11px] text-[var(--text-muted)]">{metric.label}</div>
              </div>
            ))}
          </div>

          {violations.length > 0 ? (
            <ul className="space-y-1.5 text-[13px]">
              {violations.slice(0, 3).map((violation) => (
                <li key={violation.controlID} className="flex items-center justify-between gap-3">
                  <Link
                    href={frameworkDetailHref(framework, tenantID, violation.controlID)}
                    className="font-mono text-[12px] font-medium text-[var(--text-primary)] hover:text-[var(--primary)]"
                  >
                    {violation.controlID}
                  </Link>
                  <span className="text-[12px] text-[var(--text-muted)]">
                    {countLabel(violation.findings.length, "finding")}
                    {violation.critical > 0 ? ` · ${violation.critical} critical` : ""}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <div className="text-[13px] text-[var(--text-muted)]">No open findings map to this framework&apos;s controls.</div>
          )}

          <Link href={href} className="mt-auto text-[13px] font-medium text-[var(--primary)]">
            View controls
          </Link>
        </>
      )}
    </div>
  );
}

function FrameworkPicker({
  catalog,
  enabledNames,
  onCancel,
  onSaved,
  tenantID,
}: {
  catalog: GRCFramework[];
  enabledNames: string[];
  onCancel: () => void;
  onSaved: () => void;
  tenantID: string;
}) {
  const [selected, setSelected] = useState(enabledNames);
  const [filter, setFilter] = useState("");
  const { mutate, saving, error } = useGRCMutation<FrameworkSettingsResponse>();
  const options = useMemo(() => {
    const query = filter.trim().toLowerCase();
    return selectableFrameworks(catalog).filter((framework) => !query || framework.name.toLowerCase().includes(query));
  }, [catalog, filter]);
  const isSelected = (name: string) => selected.some((value) => value.toLowerCase() === name.toLowerCase());

  const save = async () => {
    try {
      await mutate(FRAMEWORK_SETTINGS_PATH, { ...(tenantID ? { tenant_id: tenantID } : {}), enabled_frameworks: selected }, "PUT");
      onSaved();
    } catch {
      // useGRCMutation surfaces the message through `error`.
    }
  };

  return (
    <Panel title="Enabled Frameworks">
      <p className="mb-3 text-[13px] text-[var(--text-muted)]">
        Pick the frameworks to measure. Findings from CSPM and SSPM rules are mapped to each enabled framework&apos;s controls. This applies to everyone in the tenant.
      </p>
      <input
        type="search"
        value={filter}
        onChange={(event) => setFilter(event.target.value)}
        placeholder="Filter frameworks"
        aria-label="Filter frameworks"
        className="mb-3 w-full max-w-sm rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-3 py-1.5 text-[13px]"
      />
      <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
        {options.map((framework) => (
          <label
            key={framework.name}
            className={`flex cursor-pointer items-start gap-3 rounded-lg border p-3 text-[13px] transition ${isSelected(framework.name) ? "border-[color:var(--primary)] bg-[var(--surface-muted)]" : "border-[color:var(--border)]"}`}
          >
            <input
              type="checkbox"
              checked={isSelected(framework.name)}
              onChange={() => setSelected((current) => toggleFrameworkName(current, framework.name))}
              className="mt-0.5"
            />
            <span className="min-w-0">
              <span className="block font-medium text-[var(--text-primary)]">{framework.name}</span>
              <span className="block text-[12px] text-[var(--text-muted)]">
                {countLabel(framework.control_count, "control")} · {countLabel(framework.coverage?.mapped_rules ?? 0, "mapped rule")}
              </span>
            </span>
          </label>
        ))}
      </div>
      {options.length === 0 && <div className="text-[13px] text-[var(--text-muted)]">No frameworks match that filter.</div>}
      {error && <div className="mt-3 text-[12px] text-red-600">{error}</div>}
      <div className="mt-4 flex items-center gap-2">
        <button
          type="button"
          onClick={() => void save()}
          disabled={saving}
          className="rounded-md bg-[var(--primary)] px-3 py-1.5 text-[13px] font-medium text-white transition hover:bg-[var(--primary-hover)] disabled:opacity-60"
        >
          {saving ? "Saving..." : `Save ${countLabel(selected.length, "framework")}`}
        </button>
        <button type="button" onClick={onCancel} disabled={saving} className="secondary-button px-3 py-1.5 text-[13px]">
          Cancel
        </button>
      </div>
    </Panel>
  );
}

export default function CompliancePage() {
  const searchParams = useSearchParams();
  const tenantID = (searchParams.get("tenant_id") ?? "").trim();
  const [managing, setManaging] = useState(false);
  const settingsQuery = useGRCQuery<FrameworkSettingsResponse>(grcPath(FRAMEWORK_SETTINGS_PATH, { tenant_id: tenantID }));
  const catalogQuery = useGRCQuery<GRCFrameworksResponse>(grcPath("/grc/frameworks"));
  const catalog = useMemo(() => catalogQuery.data?.frameworks ?? [], [catalogQuery.data?.frameworks]);
  const enabledNames = useMemo(() => settingsQuery.data?.settings.enabled_frameworks ?? [], [settingsQuery.data?.settings.enabled_frameworks]);
  const enabled = useMemo(() => enabledFrameworks(catalog, enabledNames), [catalog, enabledNames]);
  const loading = (settingsQuery.loading && !settingsQuery.data) || (catalogQuery.loading && !catalogQuery.data);
  const error = settingsQuery.error ?? catalogQuery.error;
  const ready = Boolean(settingsQuery.data && catalogQuery.data);

  return (
    <div className="space-y-6">
      <PageHeader
        contractId="grc"
        title="Compliance"
        description="Open CSPM and SSPM findings mapped to the controls of each framework you enable."
        action={ready && !managing ? (
          <button type="button" onClick={() => setManaging(true)} className="secondary-button px-3 py-1.5 text-[13px]">
            Manage frameworks
          </button>
        ) : undefined}
      />

      <DataStateBanner
        state={error ? "error" : loading ? "loading" : "ready"}
        subject="Compliance frameworks"
        error={error}
        onRetry={() => {
          void settingsQuery.reload();
          void catalogQuery.reload();
        }}
      />

      {ready && managing && (
        <FrameworkPicker
          catalog={catalog}
          enabledNames={enabled.map((framework) => framework.name)}
          tenantID={tenantID}
          onCancel={() => setManaging(false)}
          onSaved={() => {
            setManaging(false);
            void settingsQuery.reload();
          }}
        />
      )}

      {ready && !managing && enabled.length === 0 && (
        <Panel title="No Frameworks Enabled">
          <EmptyBlock label="Enable a framework such as SOC 2, ISO 27001, or the CIS AWS Foundations Benchmark to see which controls your open findings violate." />
          <button type="button" onClick={() => setManaging(true)} className="mt-3 rounded-md bg-[var(--primary)] px-3 py-1.5 text-[13px] font-medium text-white">
            Enable frameworks
          </button>
        </Panel>
      )}

      {ready && enabled.length > 0 && (
        <>
          {!settingsQuery.data?.persisted && (
            <div className="text-[12px] text-[var(--text-muted)]">
              Showing the default frameworks. Use Manage frameworks to choose your own.
            </div>
          )}
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {enabled.map((framework) => (
              <FrameworkCard key={framework.name} framework={framework} tenantID={tenantID} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}
