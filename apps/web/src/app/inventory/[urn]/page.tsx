"use client";

import Link from "next/link";
import { useParams, useSearchParams } from "next/navigation";
import { useMemo, useState } from "react";

import { useApiKey, useCurrentUser } from "@/components/providers";
import { fetchCerebro } from "@/lib/cerebro-client";
import AssetReportModal from "@/components/grc/AssetReportModal";
import GraphViewer from "@/components/grc/LazyGraphViewer";
import { Badge, EmptyBlock, ErrorBlock, LoadingBlock, MetricCard, PageHeader, Panel, RiskBadge, SeverityDot } from "@/components/grc/Primitives";
import {
  displayDate,
  GRCInventoryAction,
  GRCInventoryAsset,
  GRCInventoryAssetDetail,
  GRCInventoryAssetReport,
  GRCInventoryTest,
  GRCInventoryTimelineEvent,
  GRCInventoryVulnerability,
  humanize,
  shortEntity,
} from "@/lib/grc";
import { grcPath, useGRCQuery } from "@/lib/grc-client";
import { controlMatchesFrameworkSegment, frameworkOptionLabel, supportedGRCFrameworkNames } from "@/lib/grc-frameworks";
import { inventoryAccountability, inventoryReviewDetail, inventoryReviewLabel, inventoryReviewState } from "@/lib/inventory-review";
import { inventoryAssetSurface } from "@/lib/inventory-surface";

type Tab = "overview" | "vulnerabilities" | "tests" | "framework" | "reports" | "timeline";

const inputClass = "control-input px-3 py-1.5 text-[13px]";

const attr = (asset?: GRCInventoryAsset, ...keys: string[]) => {
  for (const key of keys) {
    const value = asset?.attributes?.[key];
    if (value) return value;
  }
  return "";
};

function TabButton({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`border-b-2 px-4 py-2 text-[13px] font-medium transition ${
        active ? "border-[var(--primary)] text-[var(--primary)]" : "border-transparent text-[var(--text-muted)] hover:border-[color:var(--border-strong)] hover:text-[var(--text-primary)]"
      }`}
    >
      {label}
    </button>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid grid-cols-[120px_minmax(0,1fr)] gap-3 py-2 text-[13px]">
      <dt className="text-[var(--text-muted)]">{label}</dt>
      <dd className="break-words text-[var(--text-primary)]">{value || "Not set"}</dd>
    </div>
  );
}

const failingTests = (tests: GRCInventoryTest[]) =>
  tests.filter((test) => ["failing", "overdue", "open"].includes(test.status?.toLowerCase())).length;

const criticalHighVulnerabilities = (items: GRCInventoryVulnerability[]) =>
  items.filter((item) => ["CRITICAL", "HIGH"].includes(item.severity?.toUpperCase())).length;

const scopeState = (asset: GRCInventoryAsset) => asset.scope_state || "in_scope";

const scopeCopy = (state: string) => state === "out_of_scope" ? "Scoped out" : "In scope";

const surfaceLabel = (asset?: GRCInventoryAsset) => {
  switch (inventoryAssetSurface(asset)) {
    case "component":
      return "Component";
    case "signal":
      return "Signal";
    case "alias":
      return "Alias";
    case "raw_record":
      return "Raw record";
    default:
      return "Asset";
  }
};

const recordNoun = (asset?: GRCInventoryAsset) => inventoryAssetSurface(asset) === "asset" ? "asset" : "record";

const isReviewableAsset = (asset?: GRCInventoryAsset) => inventoryAssetSurface(asset) === "asset";

const reportStatuses = ["submitted", "in_triage", "accepted", "rejected", "resolved"];

function OverviewPane({ data, setTab }: { data: GRCInventoryAssetDetail; setTab: (tab: Tab) => void }) {
  const failing = failingTests(data.tests);
  const criticalHigh = criticalHighVulnerabilities(data.vulnerabilities);
  const publicState = attr(data.asset, "public", "publicly_accessible", "internet_exposed") === "true";
  const actions = data.actions ?? [];
  const reportCount = data.asset_reports?.length ?? 0;
  const noun = recordNoun(data.asset);
  const summary = [
    publicState ? "is publicly accessible" : "is not publicly accessible",
    criticalHigh === 0 ? "has no critical or high vulnerabilities" : `has ${criticalHigh} critical or high vulnerabilities`,
    failing === 0 ? "has no failing tests" : `has ${failing} failing tests`,
    reportCount === 0 ? "has no curation reports" : `has ${reportCount} curation report${reportCount === 1 ? "" : "s"}`,
    scopeState(data.asset) === "out_of_scope" ? "is scoped out of compliance review" : "is in scope",
  ].join(", ");
  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_320px]">
      <div className="space-y-6">
        <section className="surface-panel overflow-hidden">
          <div className="p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h2 className="text-lg font-semibold text-[var(--text-primary)]">Summary</h2>
              <RiskBadge score={data.asset.risk_score} level={data.asset.risk_level} />
            </div>
            <p className="mt-6 text-[15px] leading-6 text-[var(--text-secondary)]">This {noun} {summary}.</p>
            {data.asset.risk_reasons && data.asset.risk_reasons.length > 0 && (
              <div className="mt-4 flex flex-wrap gap-1.5">
                {data.asset.risk_reasons.slice(0, 8).map((reason) => <span key={reason} className="rounded-md bg-[var(--surface-muted)] px-2 py-0.5 text-[11px] text-[var(--text-secondary)]">{humanize(reason)}</span>)}
              </div>
            )}
            <div className="mt-6 text-[11px] font-medium uppercase tracking-wider text-[var(--text-muted)]">Recommendation</div>
            <p className="mt-2 text-[14px] leading-6 text-[var(--text-secondary)]">
              {isReviewableAsset(data.asset)
                ? "Review accountability, framework coverage, failing tests, vulnerability posture, and adjacent graph relationships before changing scope or remediation priority."
                : "Review graph relationships and source attributes before changing the related asset review state."}
            </p>
          </div>
          <div className="border-t border-[color:var(--border)] bg-[var(--surface-muted)] px-5 py-3 text-[12px] font-medium text-[var(--text-secondary)]">
            <span className="mr-2 text-[var(--primary)]">✦</span>Generated summary
          </div>
        </section>

        <section className="surface-panel overflow-hidden">
          <button type="button" onClick={() => setTab("vulnerabilities")} className="flex w-full items-center justify-between border-b border-[color:var(--border)] px-5 py-3 text-left hover:bg-[var(--surface-hover)]">
            <span className="text-[13px] font-medium text-[var(--text-primary)]">{criticalHigh === 0 ? "No critical or high vulnerabilities found" : `${criticalHigh} critical or high vulnerabilities found`}</span>
            <Badge value={criticalHigh === 0 ? "ok" : "open"} />
          </button>
          <button type="button" onClick={() => setTab("tests")} className="flex w-full items-center justify-between border-b border-[color:var(--border)] px-5 py-3 text-left hover:bg-[var(--surface-hover)]">
            <div>
              <div className="text-[13px] font-medium text-[var(--text-primary)]">{failing === 0 ? "No failing tests" : `${failing} failing compliance tests`}</div>
              <div className="mt-0.5 text-[12px] text-[var(--text-muted)]">Review these tests to ensure this asset is compliant</div>
            </div>
            <Badge value={failing === 0 ? "ok" : "overdue"} />
          </button>
          <div className="flex items-center justify-between px-5 py-3">
            <span className="text-[13px] font-medium text-[var(--text-primary)]">{publicState ? "Public exposure detected" : "Not publicly accessible"}</span>
            <Badge value={publicState ? "open" : "ok"} />
          </div>
          <div className="flex items-center justify-between border-t border-[color:var(--border)] px-5 py-3">
            <span className="text-[13px] font-medium text-[var(--text-primary)]">{scopeCopy(scopeState(data.asset))}</span>
            <Badge value={scopeState(data.asset)} />
          </div>
          <button type="button" onClick={() => setTab("reports")} className="flex w-full items-center justify-between border-t border-[color:var(--border)] px-5 py-3 text-left hover:bg-[var(--surface-hover)]">
            <span className="text-[13px] font-medium text-[var(--text-primary)]">{reportCount === 0 ? "No curation reports" : `${reportCount} curation report${reportCount === 1 ? "" : "s"}`}</span>
            <Badge value={reportCount === 0 ? "ok" : data.asset_reports?.[0]?.triage_status || "submitted"} />
          </button>
        </section>

        <Panel title="Next best actions">
          <div className="space-y-3">
            {actions.map((action: GRCInventoryAction) => (
              <div key={`${action.priority}-${action.title}`} className="rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] p-3">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="text-[13px] font-semibold text-[var(--text-primary)]">{action.title}</div>
                    <div className="mt-1 text-[12px] leading-5 text-[var(--text-secondary)]">{action.description}</div>
                  </div>
                  <Badge value={action.priority} />
                </div>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Relationships" action={<Link href={`/explore?root_urn=${encodeURIComponent(data.asset.urn)}`} className="text-[12px] font-medium text-indigo-600 hover:text-indigo-800">Open graph</Link>}>
          <GraphViewer graph={data.graph} />
        </Panel>
      </div>
      <aside>
        <h2 className="mb-3 text-[16px] font-semibold text-[var(--text-primary)]">Details</h2>
        <div className="mb-4 grid gap-3">
          <MetricCard label="Review" value={inventoryReviewLabel(inventoryReviewState(data.asset))} detail={inventoryReviewDetail(data.asset) || "current review state"} intent={inventoryReviewState(data.asset) === "needs_review" || inventoryReviewState(data.asset) === "reported_issue" ? "warning" : "neutral"} />
          <MetricCard label="Accountability" value={inventoryAccountability(data.asset).label} detail={inventoryAccountability(data.asset).principal || (isReviewableAsset(data.asset) ? "derived from inventory evidence" : "owner review not required")} intent={inventoryAccountability(data.asset).state === "required_missing" ? "warning" : "neutral"} />
          <MetricCard label="Risk score" value={data.asset.risk_score ?? 0} detail={humanize(data.asset.risk_level)} intent={(data.asset.risk_score ?? 0) >= 70 ? "danger" : "neutral"} />
          <MetricCard label="Scope" value={scopeState(data.asset) === "out_of_scope" ? "Scoped out" : "In"} detail={data.asset.scope_reason || "active inventory state"} intent={scopeState(data.asset) === "out_of_scope" ? "warning" : "success"} />
        </div>
        <dl className="divide-y divide-[color:var(--border)]">
          <DetailRow label="Surface" value={surfaceLabel(data.asset)} />
          <DetailRow label="Last updated" value={displayDate(attr(data.asset, "updated_at", "last_seen_at", "last_synced_at"))} />
          <DetailRow label="First seen" value={displayDate(attr(data.asset, "created_at", "first_seen_at"))} />
          <DetailRow label="Account" value={attr(data.asset, "account_id", "project_id", "org", "owner_login")} />
          <DetailRow label="Region" value={attr(data.asset, "region", "zone", "location")} />
          <DetailRow label="Runtime" value={shortEntity(data.asset.runtime_id)} />
          <DetailRow label="Source" value={data.asset.source_id || "Not set"} />
        </dl>
      </aside>
    </div>
  );
}

function VulnerabilitiesPane({ vulnerabilities }: { vulnerabilities: GRCInventoryVulnerability[] }) {
  const [query, setQuery] = useState("");
  const filtered = vulnerabilities.filter((item) => [item.title, item.id, item.severity, item.status].join(" ").toLowerCase().includes(query.toLowerCase()));
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-4">
        <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search" className={inputClass} />
        <button type="button" className="text-[13px] font-medium text-[var(--text-secondary)]">Source</button>
        <button type="button" className="text-[13px] font-medium text-[var(--text-secondary)]">Severity</button>
      </div>
      {filtered.length === 0 ? (
        <div className="surface-panel p-8 text-center">
          <div className="text-[14px] font-semibold text-[var(--text-primary)]">Get started with managing vulnerabilities</div>
          <div className="mt-2 text-[13px] text-[var(--text-muted)]">Connect and sync vulnerability sources to monitor detected security issues for this asset.</div>
        </div>
      ) : (
        <div className="surface-panel overflow-x-auto">
          <table className="data-table">
            <thead><tr><th>Vulnerability</th><th>Severity</th><th>Status</th><th>Source</th></tr></thead>
            <tbody>
              {filtered.map((item) => (
                <tr key={`${item.id}-${item.finding_id}`}>
                  <td>{item.finding_id ? <Link href={`/findings/${encodeURIComponent(item.finding_id)}`} className="font-medium text-[var(--primary)] hover:text-[var(--primary-hover)]">{item.title}</Link> : item.title}</td>
                  <td><span className="inline-flex items-center gap-2"><SeverityDot severity={item.severity} />{item.severity}</span></td>
                  <td><Badge value={item.status} /></td>
                  <td className="text-[var(--text-muted)]">{item.source_id || "Not set"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function TestsPane({ tests }: { tests: GRCInventoryTest[] }) {
  const [query, setQuery] = useState("");
  const [framework, setFramework] = useState("");
  const filtered = tests.filter((test) => {
    if (!controlMatchesFrameworkSegment(test, framework)) return false;
    return [test.name, test.owner, test.status, test.framework, test.control_id].join(" ").toLowerCase().includes(query.toLowerCase());
  });
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-4">
        <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search" className={inputClass} />
        <input value={framework} onChange={(e) => setFramework(e.target.value)} placeholder="Framework" list="asset-test-framework-options" className={inputClass} />
        <datalist id="asset-test-framework-options">
          {supportedGRCFrameworkNames.map((name) => <option key={name} value={name} label={frameworkOptionLabel(name)} />)}
        </datalist>
        <button type="button" className="text-[13px] font-medium text-[var(--text-secondary)]">Status</button>
        <button type="button" className="text-[13px] font-medium text-[var(--text-secondary)]">Due date</button>
      </div>
      <div className="surface-panel overflow-x-auto">
        <table className="data-table">
          <thead>
            <tr>
              <th>Test name</th>
              <th>Owner</th>
              <th>Status</th>
              <th>Due date</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((test) => (
              <tr key={`${test.name}-${test.finding_id}-${test.control_id}`}>
                <td className="font-medium text-[var(--text-primary)]">{test.finding_id ? <Link href={`/findings/${encodeURIComponent(test.finding_id)}`} className="hover:text-[var(--primary)]">{test.name}</Link> : test.name}</td>
                <td>{test.owner}</td>
                <td><Badge value={test.status} /></td>
                <td className="text-[var(--text-muted)]">{displayDate(test.due_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && <div className="p-8"><EmptyBlock label="No tests match this asset." /></div>}
      </div>
    </div>
  );
}

function FrameworkPane({ data }: { data: GRCInventoryAssetDetail }) {
  const [framework, setFramework] = useState("");
  const controls = data.controls.filter((control) => controlMatchesFrameworkSegment(control, framework));
  return (
    <div className="surface-panel overflow-hidden">
      <div className="border-b border-[color:var(--border)] px-4 py-3">
        <label className="block max-w-sm text-[11px] font-semibold text-[var(--text-muted)]">
          Framework
          <input value={framework} onChange={(e) => setFramework(e.target.value)} placeholder="All frameworks" list="asset-framework-options" className={`${inputClass} mt-1 w-full`} />
          <datalist id="asset-framework-options">
            {supportedGRCFrameworkNames.map((name) => <option key={name} value={name} label={frameworkOptionLabel(name)} />)}
          </datalist>
        </label>
      </div>
      <div className="overflow-x-auto">
      <table className="data-table">
        <thead><tr><th>Framework</th><th>Control</th><th>Status</th><th>Findings</th><th>Evidence</th></tr></thead>
        <tbody>
          {controls.map((control) => (
            <tr key={`${control.framework_name}-${control.control_id}`}>
              <td className="font-medium text-[var(--text-primary)]">{control.framework_name}</td>
              <td>{control.control_id}</td>
              <td><Badge value={control.status} /></td>
              <td className="tabular-nums">{control.open_findings}</td>
              <td className="tabular-nums">{control.evidence_items}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {controls.length === 0 && <div className="p-8"><EmptyBlock label="No framework scope is mapped to this asset." /></div>}
      </div>
    </div>
  );
}

function ReportsPane({
  error,
  onTriage,
  reports,
  savingID,
}: {
  error?: string | null;
  onTriage: (report: GRCInventoryAssetReport, status: string) => void;
  reports: GRCInventoryAssetReport[];
  savingID?: string | null;
}) {
  if (reports.length === 0) {
    return <EmptyBlock label="No data quality or curation reports have been submitted for this asset." />;
  }
  return (
    <div className="space-y-3">
      {error && <ErrorBlock error={error} />}
      {reports.map((report) => (
        <div key={report.id} className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <div className="text-[13px] font-semibold text-[var(--text-primary)]">{report.reason}</div>
              <div className="mt-1 text-[12px] text-[var(--text-muted)]">
                Reported {displayDate(report.created_at)}{report.reporter ? ` by ${report.reporter}` : ""}
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Badge value={report.triage_status} />
              <select
                value={report.triage_status}
                onChange={(event) => onTriage(report, event.target.value)}
                disabled={savingID === report.id}
                className="control-input px-2 py-1 text-[12px] disabled:opacity-50"
              >
                {reportStatuses.map((status) => <option key={status} value={status}>{humanize(status)}</option>)}
              </select>
            </div>
          </div>
          {(report.triage_reason || report.triaged_by || report.triaged_at) && (
            <div className="mt-3 rounded-md bg-[var(--surface-muted)] px-3 py-2 text-[12px] text-[var(--text-secondary)]">
              {report.triage_reason || "Triaged"}{report.triaged_by ? ` by ${report.triaged_by}` : ""}{report.triaged_at ? ` on ${displayDate(report.triaged_at)}` : ""}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function TimelinePane({ events }: { events: GRCInventoryTimelineEvent[] }) {
  const sorted = events.slice().sort((left, right) => (right.at ?? "").localeCompare(left.at ?? ""));
  if (sorted.length === 0) {
    return <EmptyBlock label="No inventory timeline events are available for this asset." />;
  }
  return (
    <div className="surface-panel">
      <div className="divide-y divide-[color:var(--border)]">
        {sorted.map((event, index) => (
          <div key={`${event.kind}-${event.title}-${event.at ?? index}`} className="grid gap-3 px-5 py-4 md:grid-cols-[160px_minmax(0,1fr)_120px]">
            <div className="text-[12px] text-[var(--text-muted)]">{displayDate(event.at)}</div>
            <div>
              <div className="text-[13px] font-semibold text-[var(--text-primary)]">{event.title}</div>
              {event.description && <div className="mt-1 text-[12px] text-[var(--text-muted)]">{event.description}</div>}
            </div>
            <div className="flex justify-start md:justify-end"><Badge value={event.status || event.kind} /></div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function InventoryAssetPage() {
  const params = useParams<{ urn: string }>();
  const searchParams = useSearchParams();
  const { apiKey } = useApiKey();
  const { actor } = useCurrentUser();
  const urn = useMemo(() => decodeURIComponent(params.urn ?? ""), [params.urn]);
  const initialTab = (searchParams.get("tab") as Tab | null) ?? "overview";
  const [tab, setTab] = useState<Tab>(["overview", "vulnerabilities", "tests", "framework", "reports", "timeline"].includes(initialTab) ? initialTab : "overview");
  const [scopeSaving, setScopeSaving] = useState(false);
  const [scopeError, setScopeError] = useState<string | null>(null);
  const [reportOpen, setReportOpen] = useState(false);
  const [reportSaving, setReportSaving] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);
  const [triageSavingID, setTriageSavingID] = useState<string | null>(null);
  const [triageError, setTriageError] = useState<string | null>(null);
  const { data, error, loading, reload } = useGRCQuery<GRCInventoryAssetDetail>(
    urn ? grcPath("/grc/inventory/assets/detail", { urn, limit: 100 }) : null,
  );
  const asset = data?.asset;
  const externalURL = attr(asset, "html_url", "url", "web_url", "console_url");
  const updateScope = async () => {
    if (!asset) return;
    setScopeSaving(true);
    setScopeError(null);
    const nextState = scopeState(asset) === "out_of_scope" ? "in_scope" : "out_of_scope";
    const response = await fetchCerebro("/grc/inventory/resource-scope", apiKey, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        asset_urn: asset.urn,
        source_id: asset.source_id,
        runtime_id: asset.runtime_id,
        scope_state: nextState,
        reason: nextState === "out_of_scope" ? "Scoped out from inventory review" : "Scoped into inventory review",
      }),
    });
    setScopeSaving(false);
    if (!response.ok) {
      setScopeError(typeof response.data === "string" ? response.data : `Scope update failed (${response.status})`);
      return;
    }
    void reload();
  };
  const submitAssetReport = async (reason: string) => {
    if (!asset) return;
    setReportSaving(true);
    setReportError(null);
    const response = await fetchCerebro<{ report: GRCInventoryAssetReport }>("/grc/inventory/asset-reports", apiKey, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        asset_urn: asset.urn,
        source_id: asset.source_id,
        reason,
        reporter: actor || undefined,
        attributes: {
          label: asset.label,
          entity_type: asset.entity_type,
        },
      }),
    });
    setReportSaving(false);
    if (!response.ok) {
      setReportError(typeof response.data === "string" ? response.data : `Report failed (${response.status})`);
      return;
    }
    setReportOpen(false);
    setTab("reports");
    void reload();
  };
  const updateReportTriage = async (report: GRCInventoryAssetReport, status: string) => {
    setTriageSavingID(report.id);
    setTriageError(null);
    const response = await fetchCerebro<{ report: GRCInventoryAssetReport }>(`/grc/inventory/asset-reports/${encodeURIComponent(report.id)}/triage`, apiKey, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        triage_status: status,
        triage_reason: `Marked ${humanize(status)} from inventory detail`,
        triaged_by: actor || undefined,
      }),
    });
    setTriageSavingID(null);
    if (!response.ok) {
      setTriageError(typeof response.data === "string" ? response.data : `Triage update failed (${response.status})`);
      return;
    }
    void reload();
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title={asset?.label || shortEntity(urn)}
        description={`${surfaceLabel(asset)} / ${humanize(asset?.entity_type)}${urn ? ` • ${urn}` : ""}`}
        action={
          <div className="flex items-center gap-2">
            {externalURL && <a href={externalURL} target="_blank" rel="noreferrer" className="secondary-button px-3 py-1.5 text-[13px]">Open source</a>}
            {asset && <button type="button" onClick={() => { setReportOpen(true); setReportError(null); }} className="secondary-button px-3 py-1.5 text-[13px]">Report issue</button>}
            {asset && isReviewableAsset(asset) && <button type="button" onClick={() => void updateScope()} disabled={scopeSaving} className="secondary-button px-3 py-1.5 text-[13px] disabled:opacity-50">{scopeSaving ? "Saving" : scopeState(asset) === "out_of_scope" ? "Scope in" : "Scope out"}</button>}
            <button type="button" onClick={() => void reload()} className="primary-button px-3 py-1.5 text-[13px]">Refresh</button>
          </div>
        }
      />

      {loading && <LoadingBlock label="Loading record..." />}
      {error && <ErrorBlock error={error} onRetry={() => void reload()} recoveryDetail="Record details will appear when the API is reachable." />}
      {scopeError && <ErrorBlock error={scopeError} onRetry={() => void reload()} recoveryDetail="Scope updates can resume when the API is reachable." />}

      {data && (
        <>
          <div className="mb-2 flex flex-wrap items-center gap-4 text-[12px] text-[var(--text-muted)]">
            <span className="rounded-full bg-[var(--surface-muted)] px-2 py-1 font-medium text-[var(--text-secondary)]">{inventoryAccountability(data.asset).principal || (isReviewableAsset(data.asset) ? attr(data.asset, "owner", "owner_email") || "Unassigned" : "Owner not required")}</span>
            <span>Last refreshed: {displayDate(attr(asset, "updated_at", "last_seen_at", "last_synced_at"))}</span>
            <span>{scopeCopy(scopeState(data.asset))}</span>
          </div>
          <div className="flex items-center gap-4 border-b border-[color:var(--border)]">
            <TabButton label="Overview" active={tab === "overview"} onClick={() => setTab("overview")} />
            <TabButton label="Vulnerabilities" active={tab === "vulnerabilities"} onClick={() => setTab("vulnerabilities")} />
            <TabButton label={`Tests (${data.tests.length})`} active={tab === "tests"} onClick={() => setTab("tests")} />
            <TabButton label="Framework scope" active={tab === "framework"} onClick={() => setTab("framework")} />
            <TabButton label={`Reports (${data.asset_reports?.length ?? 0})`} active={tab === "reports"} onClick={() => setTab("reports")} />
            <TabButton label={`Timeline (${data.timeline?.length ?? 0})`} active={tab === "timeline"} onClick={() => setTab("timeline")} />
          </div>
          {tab === "overview" && <OverviewPane data={data} setTab={setTab} />}
          {tab === "vulnerabilities" && <VulnerabilitiesPane vulnerabilities={data.vulnerabilities} />}
          {tab === "tests" && <TestsPane tests={data.tests} />}
          {tab === "framework" && <FrameworkPane data={data} />}
          {tab === "reports" && <ReportsPane reports={data.asset_reports ?? []} onTriage={(report, status) => void updateReportTriage(report, status)} savingID={triageSavingID} error={triageError} />}
          {tab === "timeline" && <TimelinePane events={data.timeline ?? []} />}
        </>
      )}
      {asset && reportOpen && (
        <AssetReportModal
          asset={asset}
          error={reportError}
          onClose={() => setReportOpen(false)}
          onSubmit={(reason) => void submitAssetReport(reason)}
          saving={reportSaving}
        />
      )}
    </div>
  );
}
