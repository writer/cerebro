"use client";

import Link from "next/link";
import { useCallback, useMemo, useState } from "react";

import { useApiKey, useCurrentUser } from "@/components/providers";
import { fetchCerebro } from "@/lib/cerebro-client";
import { countLabel } from "@/lib/format";
import AssetReportModal from "@/components/grc/AssetReportModal";
import { AppliedFilterChips, Badge, ErrorBlock, LoadingBlock, MetricCard, PageHeader, ProgressCard, ResultLimitNotice, RiskBadge } from "@/components/grc/Primitives";
import {
  GRCInventoryAsset,
  GRCInventoryAssetReport,
  GRCInventoryAccountabilityUpdateResponse,
  GRCInventoryAssetsResponse,
  GRCInventoryCategoriesResponse,
  GRCInventoryCategory,
  GRCInventorySurface,
  GRCResourceScopeResponse,
  humanize,
  shortEntity,
} from "@/lib/grc";
import { grcPath, useDebouncedValue, useGRCQuery } from "@/lib/grc-client";
import { frameworkOptionLabel, inventoryAssetMatchesFrameworkSegment, supportedGRCFrameworkNames } from "@/lib/grc-frameworks";
import { GRC_WORKLIST_LIMIT, grcBoundedRows } from "@/lib/grc-list";
import {
  inventoryAccountability,
  inventoryAttr,
  inventoryIsPublicAsset,
  inventoryMatchesAccountabilityFilter,
  inventoryMatchesOwnerFilter,
  inventoryMatchesReviewFilter,
  inventoryNeedsReview,
  inventoryOwnerLabel,
  inventoryReviewDetail,
  inventoryReviewLabel,
  inventoryReviewSort,
  inventoryReviewState,
  inventoryScopeCopy,
  inventoryScopeState,
  type InventoryAccountabilityFilter,
  type InventoryReviewFilter,
  type InventoryReviewState,
} from "@/lib/inventory-review";
import { inventoryAssetSurface, inventoryRequestSurface } from "@/lib/inventory-surface";
import { useQueryParamState } from "@/lib/query-params";
import { metricDetailForState, metricValueForState, runtimeStateForError, type RuntimeState } from "@/lib/runtime-state";

const inputClass = "control-input mt-1 w-full px-3 py-1.5 text-[13px]";
const labelClass = "text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]";
const INVENTORY_TABLE_PAGE_SIZE = 50;

const reviewFilters: Array<{ value: InventoryReviewFilter; label: string }> = [
  { value: "all", label: "All review states" },
  { value: "needs_review", label: "Needs review" },
  { value: "reported_issue", label: "Reported issue" },
  { value: "baseline", label: "Baseline" },
  { value: "out_of_scope", label: "Scoped out" },
];

const accountabilityFilters: Array<{ value: InventoryAccountabilityFilter; label: string }> = [
  { value: "all", label: "All accountability" },
  { value: "required_missing", label: "Owner required" },
  { value: "known", label: "Owner known" },
  { value: "not_required", label: "Owner not required" },
  { value: "candidate", label: "Owner candidate" },
  { value: "disputed", label: "Disputed" },
];

const surfaceFilters: Array<{ value: "" | GRCInventorySurface; label: string }> = [
  { value: "", label: "Assets" },
  { value: "component", label: "Components" },
  { value: "signal", label: "Signals" },
  { value: "alias", label: "Aliases" },
  { value: "raw_record", label: "Raw records" },
  { value: "all", label: "All records" },
];

const reviewBadgeClasses: Record<InventoryReviewState, string> = {
  needs_review: "bg-amber-50 text-amber-800 ring-1 ring-inset ring-amber-200 dark:bg-amber-500/15 dark:text-amber-100 dark:ring-amber-500/25",
  reported_issue: "bg-blue-50 text-blue-700 ring-1 ring-inset ring-blue-200 dark:bg-blue-500/15 dark:text-blue-200 dark:ring-blue-500/25",
  baseline: "bg-stone-100 text-stone-700 ring-1 ring-inset ring-stone-200 dark:bg-stone-500/15 dark:text-stone-100 dark:ring-stone-500/25",
  out_of_scope: "bg-stone-100 text-stone-600 ring-1 ring-inset ring-stone-200 dark:bg-stone-500/15 dark:text-stone-200 dark:ring-stone-500/25",
};

const providerLabel = (asset: GRCInventoryAsset) =>
  inventoryAttr(asset, "provider", "source_system") || asset.source_id || asset.entity_type.split(".")[0] || "source";

const ownerDisplay = (asset: GRCInventoryAsset) => {
  const accountability = inventoryAccountability(asset);
  if (accountability.principal) return accountability.principal;
  if (accountability.state === "required_missing") return "Owner required";
  if (accountability.state === "candidate") return "Owner candidate";
  if (accountability.state === "disputed") return "Disputed owner";
  return "Owner not required";
};

const regionLabel = (asset: GRCInventoryAsset) => {
  const account = inventoryAttr(asset, "account_id", "project_id", "org", "owner_login");
  const region = inventoryAttr(asset, "region", "zone", "location");
  if (account && region) return `${account} / ${region}`;
  return account || region || "Not set";
};

const descriptionLabel = (asset: GRCInventoryAsset) =>
  humanize(inventoryAttr(asset, "resource_type", "asset_type") || asset.entity_type);

const orgLabel = (asset: GRCInventoryAsset) =>
  inventoryAttr(asset, "org", "owner_login", "account_id", "project_id") || providerLabel(asset);

const reportStatusCopy = (status?: string) => status ? `Report ${humanize(status)}` : "";

const isReviewableAsset = (asset: GRCInventoryAsset) => inventoryAssetSurface(asset) === "asset";

const surfaceFilterLabel = (value: string) =>
  surfaceFilters.find((item) => item.value === value)?.label ?? humanize(value);

const csvEscape = (value: unknown) => {
  const text = String(value ?? "");
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, "\"\"")}"` : text;
};

function ReviewBadge({ asset }: { asset: GRCInventoryAsset }) {
  const status = inventoryReviewState(asset) as InventoryReviewState;
  return (
    <span className={`inline-flex rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${reviewBadgeClasses[status] ?? reviewBadgeClasses.baseline}`}>
      {inventoryReviewLabel(status)}
    </span>
  );
}

function SourceMark({ asset }: { asset: GRCInventoryAsset }) {
  const label = providerLabel(asset).slice(0, 3).toUpperCase();
  return (
    <span className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-[var(--surface-muted)] text-[10px] font-semibold text-[var(--text-secondary)]">
      {label}
    </span>
  );
}

function ScopeToggle({
  checked,
  disabled,
  onClick,
}: {
  checked: boolean;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={onClick}
      className={`relative h-5 w-9 rounded-full transition disabled:opacity-50 ${checked ? "bg-[var(--primary)]" : "bg-[var(--surface-muted)] ring-1 ring-inset ring-[color:var(--border)]"}`}
    >
      <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white shadow transition ${checked ? "left-[18px]" : "left-0.5"}`} />
    </button>
  );
}

function AssetClassRail({
  categories,
  heading,
  selectedID,
  total,
  currentCount,
  onSelect,
}: {
  categories: GRCInventoryCategory[];
  heading: string;
  selectedID: string;
  total: number;
  currentCount: number;
  onSelect: (id: string) => void;
}) {
  const [classQuery, setClassQuery] = useState("");
  const visibleCategories = useMemo(() => {
    const normalized = classQuery.trim().toLowerCase();
    if (!normalized) return categories;
    return categories.filter((category) =>
      [category.label, category.id, ...(category.entity_types ?? [])].join(" ").toLowerCase().includes(normalized),
    );
  }, [categories, classQuery]);

  return (
    <aside className="surface-panel overflow-hidden xl:sticky xl:top-4 xl:max-h-[calc(100vh-2rem)]">
      <div className="border-b border-[color:var(--border)] px-4 py-3">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-[13px] font-semibold text-[var(--text-primary)]">{heading}</h2>
          <span className="text-[12px] text-[var(--text-muted)]">{total.toLocaleString()}</span>
        </div>
        <input
          value={classQuery}
          onChange={(event) => setClassQuery(event.target.value)}
          placeholder="Find a class"
          className="control-input mt-3 w-full px-3 py-1.5 text-[13px]"
        />
      </div>
      <div className="max-h-[28rem] overflow-y-auto p-2 xl:max-h-[calc(100vh-12rem)]">
        <button
          type="button"
          onClick={() => onSelect("")}
          className={`flex w-full items-center justify-between gap-3 rounded-md px-3 py-2 text-left text-[13px] transition ${!selectedID ? "bg-[var(--nav-active)] font-semibold text-[var(--primary)]" : "text-[var(--text-secondary)] hover:bg-[var(--surface-hover)]"}`}
        >
          <span className="truncate">All classes</span>
          <span className="shrink-0 text-[11px] text-[var(--text-muted)]">{currentCount.toLocaleString()}</span>
        </button>
        {visibleCategories.map((category) => (
          <button
            key={category.id}
            type="button"
            onClick={() => onSelect(category.id)}
            className={`mt-1 flex w-full items-center justify-between gap-3 rounded-md px-3 py-2 text-left text-[13px] transition ${selectedID === category.id ? "bg-[var(--nav-active)] font-semibold text-[var(--primary)]" : "text-[var(--text-secondary)] hover:bg-[var(--surface-hover)]"}`}
          >
            <span className="min-w-0 truncate">{category.label}</span>
            <span className="shrink-0 text-[11px] text-[var(--text-muted)]">{category.count.toLocaleString()}</span>
          </button>
        ))}
        {visibleCategories.length === 0 && (
          <div className="px-3 py-8 text-center text-[13px] text-[var(--text-muted)]">No classes match.</div>
        )}
      </div>
      <div className="border-t border-[color:var(--border)] px-4 py-3 text-[12px] text-[var(--text-muted)]">
        Showing {visibleCategories.length.toLocaleString()} of {categories.length.toLocaleString()} classes.
      </div>
    </aside>
  );
}

function ScopeModal({
  onClose,
  onScopeChange,
  framework,
  response,
  savingURN,
}: {
  onClose: () => void;
  onScopeChange: (asset: GRCInventoryAsset, state: "in_scope" | "out_of_scope") => void;
  framework: string;
  response: GRCResourceScopeResponse | null;
  savingURN: string | null;
}) {
  const runtimes = useMemo(() => response?.runtimes ?? [], [response?.runtimes]);
  const resources = useMemo(() => response?.resources ?? [], [response?.resources]);
  const summary = response?.summary;
  const [query, setQuery] = useState("");
  const [frameworkQuery, setFrameworkQuery] = useState(framework);
  const [scopeView, setScopeView] = useState("all");
  const filteredResources = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return resources.filter((asset) => {
      const state = inventoryScopeState(asset);
      const matchesScope = scopeView === "all" || state === scopeView;
      const matchesFramework = inventoryAssetMatchesFrameworkSegment(asset, frameworkQuery);
      const matchesQuery = !normalizedQuery || [asset.label, asset.entity_type, asset.urn, asset.source_id]
        .join(" ")
        .toLowerCase()
        .includes(normalizedQuery);
      return matchesScope && matchesFramework && matchesQuery;
    });
  }, [frameworkQuery, query, resources, scopeView]);

  return (
    <div className="fixed inset-0 z-50 bg-stone-950/45 px-4 py-12 backdrop-blur-sm" onClick={onClose}>
      <div className="surface-raised mx-auto max-h-[calc(100vh-6rem)] max-w-4xl overflow-hidden" onClick={(event) => event.stopPropagation()}>
        <div className="flex items-start justify-between gap-4 border-b border-[color:var(--border)] px-7 py-6">
          <div>
            <h2 className="text-xl font-semibold tracking-tight text-[var(--text-primary)]">Configure scope</h2>
            <p className="mt-1 text-[13px] text-[var(--text-muted)]">Review source runtimes, projected resources, and items included or excluded from compliance review.</p>
          </div>
          <button type="button" onClick={onClose} className="rounded-md px-2 py-1 text-[13px] text-[var(--text-muted)] hover:bg-[var(--surface-hover)]">Close</button>
        </div>
        <div className="max-h-[calc(100vh-13rem)] overflow-y-auto p-7">
          <div className="mb-4 grid gap-3 md:grid-cols-[1fr_1fr_1fr]">
            <label className={labelClass}>
              Framework
              <input value={frameworkQuery} onChange={(event) => setFrameworkQuery(event.target.value)} list="scope-framework-options" placeholder="All frameworks" className={inputClass} />
              <datalist id="scope-framework-options">
                {supportedGRCFrameworkNames.map((name) => <option key={name} value={name} label={frameworkOptionLabel(name)} />)}
              </datalist>
            </label>
            <label className={labelClass}>
              Resource types
              <select className={inputClass} defaultValue="all">
                <option value="all">All resource types</option>
              </select>
            </label>
            <label className={labelClass}>
              Resource state
              <select value={scopeView} onChange={(event) => setScopeView(event.target.value)} className={inputClass}>
                <option value="all">All resources</option>
                <option value="in_scope">In scope</option>
                <option value="out_of_scope">Scoped out</option>
              </select>
            </label>
          </div>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search resources"
            className="control-input mb-5 w-full px-3 py-2 text-[13px]"
          />
          {summary && (
            <div className="mb-4 grid gap-3 md:grid-cols-3">
              <MetricCard label="Scoped" value={summary.in_scope_assets} detail={`${summary.scoped_coverage_pct}% coverage`} intent="success" />
              <MetricCard label="Scoped out" value={summary.out_of_scope_assets} detail="explicit scope decisions" intent={summary.out_of_scope_assets > 0 ? "warning" : "neutral"} />
              <MetricCard label="High risk" value={summary.high_risk_assets} detail="needs review" intent={summary.high_risk_assets > 0 ? "danger" : "success"} />
            </div>
          )}
          <div className="space-y-5">
            <section className="surface-panel overflow-hidden">
              <div className="flex items-center justify-between border-b border-[color:var(--border)] px-4 py-3">
                <div className="text-[13px] font-semibold text-[var(--text-primary)]">Accounts in scope</div>
                <div className="text-[12px] text-[var(--text-muted)]">{runtimes.length} accounts</div>
              </div>
              <div className="max-h-72 overflow-y-auto divide-y divide-[color:var(--border)]">
                {runtimes.map((runtime) => (
                  <div key={runtime.runtime_id} className="flex items-center justify-between gap-3 px-4 py-3">
                    <div className="min-w-0">
                      <div className="truncate text-[13px] font-medium text-[var(--text-primary)]">{runtime.owner || runtime.runtime_id}</div>
                      <div className="truncate font-mono text-[11px] text-[var(--text-muted)]">{runtime.runtime_id}</div>
                    </div>
                    <Badge value={runtime.status || "configured"} />
                  </div>
                ))}
                {runtimes.length === 0 && <div className="px-4 py-6 text-center text-[13px] text-[var(--text-muted)]">No source runtimes match this scope.</div>}
              </div>
            </section>
            <section className="surface-panel overflow-hidden">
              <div className="flex items-center justify-between border-b border-[color:var(--border)] px-4 py-3">
                <div className="text-[13px] font-semibold text-[var(--text-primary)]">Resources in scope</div>
                <div className="text-[12px] text-[var(--text-muted)]">{filteredResources.length} of {resources.length}</div>
              </div>
              <div className="max-h-[24rem] overflow-y-auto divide-y divide-[color:var(--border)]">
                {filteredResources.slice(0, 75).map((asset) => (
                  <div key={asset.urn} className="flex items-center justify-between gap-3 px-4 py-3">
                    <div className="min-w-0">
                      <div className="truncate text-[13px] font-medium text-[var(--text-primary)]">{asset.label}</div>
                      <div className="truncate font-mono text-[11px] text-[var(--text-muted)]">{asset.entity_type}</div>
                      <div className="mt-1"><Badge value={inventoryScopeCopy(inventoryScopeState(asset))} /></div>
                    </div>
                    <ScopeToggle
                      checked={inventoryScopeState(asset) !== "out_of_scope"}
                      disabled={savingURN === asset.urn}
                      onClick={() => onScopeChange(asset, inventoryScopeState(asset) === "out_of_scope" ? "in_scope" : "out_of_scope")}
                    />
                  </div>
                ))}
                {filteredResources.length === 0 && <div className="px-4 py-6 text-center text-[13px] text-[var(--text-muted)]">No resources match this scope.</div>}
              </div>
            </section>
          </div>
        </div>
      </div>
    </div>
  );
}

type AccountabilityUpdateState = "known" | "not_required" | "clear";

function AccountabilityModal({
  assets,
  defaultState,
  error,
  saving,
  onClose,
  onSubmit,
}: {
  assets: GRCInventoryAsset[];
  defaultState: AccountabilityUpdateState;
  error: string | null;
  saving: boolean;
  onClose: () => void;
  onSubmit: (update: { state: AccountabilityUpdateState; owner?: string; reason?: string }) => void;
}) {
  const firstOwner = assets.length === 1 && inventoryOwnerLabel(assets[0]) !== "Unassigned" ? inventoryOwnerLabel(assets[0]) : "";
  const [state, setState] = useState<AccountabilityUpdateState>(defaultState);
  const [owner, setOwner] = useState(firstOwner);
  const [reason, setReason] = useState(defaultState === "not_required" ? "Owner is not required for GRC review" : "");
  const canSubmit = state !== "known" || owner.trim().length > 0;

  return (
    <div className="fixed inset-0 z-50 bg-stone-950/45 px-4 py-12 backdrop-blur-sm" onClick={onClose}>
      <div className="surface-raised mx-auto max-w-2xl overflow-hidden" onClick={(event) => event.stopPropagation()}>
        <div className="flex items-start justify-between gap-4 border-b border-[color:var(--border)] px-7 py-6">
          <div>
            <h2 className="text-xl font-semibold tracking-tight text-[var(--text-primary)]">{assets.length === 1 ? "Update owner decision" : "Update selected assets"}</h2>
            <p className="mt-1 text-[13px] text-[var(--text-muted)]">{assets.length} asset{assets.length === 1 ? "" : "s"} will be updated in inventory accountability.</p>
          </div>
          <button type="button" onClick={onClose} className="rounded-md px-2 py-1 text-[13px] text-[var(--text-muted)] hover:bg-[var(--surface-hover)]">Close</button>
        </div>
        <div className="space-y-5 p-7">
          <div className="max-h-36 overflow-y-auto rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2">
            {assets.slice(0, 8).map((asset) => (
              <div key={asset.urn} className="flex items-center justify-between gap-3 py-1 text-[12px]">
                <span className="min-w-0 truncate font-medium text-[var(--text-primary)]">{asset.label || shortEntity(asset.urn)}</span>
                <span className="shrink-0 text-[var(--text-muted)]">{descriptionLabel(asset)}</span>
              </div>
            ))}
            {assets.length > 8 && <div className="py-1 text-[12px] text-[var(--text-muted)]">+ {assets.length - 8} more</div>}
          </div>

          <div className="grid gap-2 sm:grid-cols-3">
            {[
              { value: "known" as const, label: "Set owner" },
              { value: "not_required" as const, label: "Not required" },
              { value: "clear" as const, label: "Clear decision" },
            ].map((item) => (
              <button
                key={item.value}
                type="button"
                onClick={() => setState(item.value)}
                className={`rounded-md border px-3 py-2 text-left text-[13px] font-semibold transition ${state === item.value ? "border-[color:var(--ring)] bg-[var(--nav-active)] text-[var(--primary)]" : "border-[color:var(--border)] text-[var(--text-secondary)] hover:bg-[var(--surface-hover)]"}`}
              >
                {item.label}
              </button>
            ))}
          </div>

          {state === "known" && (
            <label className={labelClass}>
              Owner
              <input value={owner} onChange={(event) => setOwner(event.target.value)} placeholder="team@example.com or owner group" className={inputClass} />
            </label>
          )}
          {state !== "clear" && (
            <label className={labelClass}>
              Reason
              <textarea value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Why this owner decision is correct" className={`${inputClass} min-h-24 resize-y`} />
            </label>
          )}
          {error && <ErrorBlock error={error} recoveryDetail="The owner decision was not saved." />}
          <div className="flex flex-wrap items-center justify-end gap-2">
            <button type="button" onClick={onClose} className="secondary-button px-3 py-1.5 text-[13px]">Cancel</button>
            <button
              type="button"
              disabled={!canSubmit || saving}
              onClick={() => onSubmit({ state, owner: owner.trim(), reason: reason.trim() })}
              className="primary-button px-3 py-1.5 text-[13px] disabled:cursor-not-allowed disabled:opacity-50"
            >
              {saving ? "Saving" : "Save decision"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function ReviewQueuePanel({
  assets,
  onReport,
  onScopeChange,
  reportSavingURN,
  scopeSavingURN,
}: {
  assets: GRCInventoryAsset[];
  onReport: (asset: GRCInventoryAsset) => void;
  onScopeChange: (asset: GRCInventoryAsset, state: "in_scope" | "out_of_scope") => void;
  reportSavingURN: string | null;
  scopeSavingURN: string | null;
}) {
  const reviewQueue = assets
    .filter(inventoryNeedsReview)
    .slice()
    .sort(inventoryReviewSort)
    .slice(0, 6);

  return (
    <section className="surface-panel overflow-hidden">
      <div className="flex items-start justify-between gap-3 border-b border-[color:var(--border)] px-4 py-3">
        <div>
          <h2 className="text-[13px] font-semibold text-[var(--text-primary)]">Needs review</h2>
          <p className="mt-1 text-[12px] text-[var(--text-muted)]">Reported issues and assets where GRC accountability is required.</p>
        </div>
        <Badge value={`${reviewQueue.length} open`} />
      </div>
      <div className="divide-y divide-[color:var(--border)]">
        {reviewQueue.map((asset) => (
          <div key={asset.urn} className="px-4 py-3">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <Link href={`/inventory/${encodeURIComponent(asset.urn)}`} className="block truncate text-[13px] font-semibold text-[var(--text-primary)] hover:text-[var(--primary)]">
                  {asset.label || shortEntity(asset.urn)}
                </Link>
                <div className="mt-1 line-clamp-2 text-[12px] leading-5 text-[var(--text-muted)]">{inventoryReviewDetail(asset)}</div>
              </div>
              <RiskBadge score={asset.risk_score} level={asset.risk_level} />
            </div>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => onReport(asset)}
                disabled={reportSavingURN === asset.urn}
                className="secondary-button px-2.5 py-1 text-[12px] disabled:opacity-50"
              >
                {reportSavingURN === asset.urn ? "Reporting" : "Report"}
              </button>
              <button
                type="button"
                onClick={() => onScopeChange(asset, inventoryScopeState(asset) === "out_of_scope" ? "in_scope" : "out_of_scope")}
                disabled={scopeSavingURN === asset.urn}
                className="secondary-button px-2.5 py-1 text-[12px] disabled:opacity-50"
              >
                {scopeSavingURN === asset.urn ? "Saving" : inventoryScopeState(asset) === "out_of_scope" ? "Scope in" : "Scope out"}
              </button>
              <Link href={`/inventory/${encodeURIComponent(asset.urn)}`} className="px-2.5 py-1 text-[12px] font-semibold text-[var(--primary)] hover:text-[var(--primary-hover)]">Open</Link>
            </div>
          </div>
        ))}
        {reviewQueue.length === 0 && <div className="px-4 py-8 text-center text-[13px] text-[var(--text-muted)]">No assets need review in this view.</div>}
      </div>
    </section>
  );
}

export default function InventoryPage() {
  const { apiKey } = useApiKey();
  const { actor } = useCurrentUser();
  const [tenantID, setTenantID] = useQueryParamState("tenant_id");
  const [categoryID, setCategoryID] = useQueryParamState("category_id");
  const [query, setQuery] = useQueryParamState("q");
  const [sourceID, setSourceID] = useQueryParamState("source_id");
  const [framework, setFramework] = useQueryParamState("framework");
  const [surfaceFilter, setSurfaceFilter] = useQueryParamState("surface");
  const [scopeFilter, setScopeFilter] = useQueryParamState("scope_state");
  const [ownerFilter, setOwnerFilter] = useQueryParamState("owner");
  const [reviewFilter, setReviewFilter] = useQueryParamState("review_state");
  const [accountabilityFilter, setAccountabilityFilter] = useQueryParamState("accountability_state");
  const [scopeOpen, setScopeOpen] = useState(false);
  const [scopeSavingURN, setScopeSavingURN] = useState<string | null>(null);
  const [scopeError, setScopeError] = useState<string | null>(null);
  const [reportAsset, setReportAsset] = useState<GRCInventoryAsset | null>(null);
  const [reportSavingURN, setReportSavingURN] = useState<string | null>(null);
  const [reportError, setReportError] = useState<string | null>(null);
  const [selectedAssetURNs, setSelectedAssetURNs] = useState<string[]>([]);
  const [assetPage, setAssetPage] = useState(1);
  const [accountabilityAssets, setAccountabilityAssets] = useState<GRCInventoryAsset[] | null>(null);
  const [accountabilityDefaultState, setAccountabilityDefaultState] = useState<AccountabilityUpdateState>("known");
  const [accountabilitySaving, setAccountabilitySaving] = useState(false);
  const [accountabilityError, setAccountabilityError] = useState<string | null>(null);
  const debouncedTenantID = useDebouncedValue(tenantID.trim());
  const debouncedCategoryID = useDebouncedValue(categoryID.trim());
  const debouncedQuery = useDebouncedValue(query.trim());
  const debouncedSourceID = useDebouncedValue(sourceID.trim());
  const debouncedFramework = useDebouncedValue(framework.trim());
  const debouncedSurfaceFilter = useDebouncedValue(surfaceFilter.trim());
  const debouncedScopeFilter = useDebouncedValue(scopeFilter.trim());
  const debouncedOwnerFilter = useDebouncedValue(ownerFilter.trim());
  const debouncedReviewFilter = useDebouncedValue(reviewFilter.trim());
  const debouncedAccountabilityFilter = useDebouncedValue(accountabilityFilter.trim());
  const selectedSurface = inventoryRequestSurface(debouncedSurfaceFilter);

  const categoriesQuery = useGRCQuery<GRCInventoryCategoriesResponse>(
    grcPath("/grc/inventory/categories", { tenant_id: debouncedTenantID, source_id: debouncedSourceID, surface: selectedSurface, limit: GRC_WORKLIST_LIMIT }),
  );
  const assetsQuery = useGRCQuery<GRCInventoryAssetsResponse>(
    grcPath("/grc/inventory/assets", {
      tenant_id: debouncedTenantID,
      source_id: debouncedSourceID,
      surface: selectedSurface,
      category_id: debouncedCategoryID,
      q: debouncedQuery,
      scope_state: debouncedScopeFilter,
      review_state: debouncedReviewFilter,
      accountability_state: debouncedAccountabilityFilter,
      limit: GRC_WORKLIST_LIMIT,
    }),
  );
  const scopeQuery = useGRCQuery<GRCResourceScopeResponse>(
    scopeOpen ? grcPath("/grc/inventory/resource-scope", { tenant_id: debouncedTenantID, source_id: debouncedSourceID || "github", surface: selectedSurface, category_id: debouncedCategoryID, q: debouncedQuery, limit: GRC_WORKLIST_LIMIT }) : null,
  );

  const surfaceIsAssets = selectedSurface === "asset";
  const recordNoun = surfaceIsAssets ? "assets" : "records";
  const recordNounTitle = surfaceIsAssets ? "Assets" : "Records";
  const categories = useMemo(() => categoriesQuery.data?.categories ?? [], [categoriesQuery.data?.categories]);
  const boundedAssetRows = useMemo(
    () => grcBoundedRows({ rows: assetsQuery.data?.assets, limit: GRC_WORKLIST_LIMIT, total: assetsQuery.data?.summary?.total_assets }),
    [assetsQuery.data?.assets, assetsQuery.data?.summary?.total_assets],
  );
  const loadedAssets = boundedAssetRows.rows;
  const assetListMeta = assetsQuery.data ? boundedAssetRows.meta : undefined;
  const rawAssets = useMemo(() => (
    loadedAssets
  ).slice().sort((left, right) => (
    inventoryReviewSort(left, right) || left.label.localeCompare(right.label)
  )), [loadedAssets]);
  const frameworkAssets = useMemo(() => rawAssets.filter((asset) => inventoryAssetMatchesFrameworkSegment(asset, debouncedFramework)), [debouncedFramework, rawAssets]);
  const assets = useMemo(() => frameworkAssets.filter((asset) =>
    inventoryMatchesOwnerFilter(asset, debouncedOwnerFilter) &&
    inventoryMatchesReviewFilter(asset, debouncedReviewFilter || "all") &&
    inventoryMatchesAccountabilityFilter(asset, debouncedAccountabilityFilter || "all"),
  ), [debouncedAccountabilityFilter, debouncedOwnerFilter, debouncedReviewFilter, frameworkAssets]);
  const totalAssetPages = Math.max(1, Math.ceil(assets.length / INVENTORY_TABLE_PAGE_SIZE));
  const currentAssetPage = Math.min(assetPage, totalAssetPages);
  const assetPageStart = (currentAssetPage - 1) * INVENTORY_TABLE_PAGE_SIZE;
  const visibleAssets = useMemo(() => assets.slice(assetPageStart, assetPageStart + INVENTORY_TABLE_PAGE_SIZE), [assetPageStart, assets]);
  const selectedAssetURNSet = useMemo(() => new Set(selectedAssetURNs), [selectedAssetURNs]);
  const selectableAssets = useMemo(() => assets.filter(isReviewableAsset), [assets]);
  const selectedAssets = useMemo(() => selectableAssets.filter((asset) => selectedAssetURNSet.has(asset.urn)), [selectableAssets, selectedAssetURNSet]);
  const selectableVisibleAssets = useMemo(() => visibleAssets.filter(isReviewableAsset), [visibleAssets]);
  const selectedVisibleAssets = useMemo(() => selectableVisibleAssets.filter((asset) => selectedAssetURNSet.has(asset.urn)), [selectableVisibleAssets, selectedAssetURNSet]);
  const allVisibleSelected = selectableVisibleAssets.length > 0 && selectedVisibleAssets.length === selectableVisibleAssets.length;
  const summary = assetsQuery.data?.summary;
  const hasFrameworkFilter = debouncedFramework.length > 0;
  const selectedCategory = categories.find((category) => category.id === categoryID);
  const ownerGroupCount = useMemo(() => new Set(assets.map(inventoryOwnerLabel).filter((owner) => owner !== "Unassigned")).size, [assets]);
  const providerCount = useMemo(() => new Set(assets.map((asset) => providerLabel(asset))).size, [assets]);
  const hasClientFilters = hasFrameworkFilter || debouncedOwnerFilter.length > 0;
  const outOfScopeCount = hasClientFilters
    ? assets.filter((asset) => inventoryScopeState(asset) === "out_of_scope").length
    : summary?.out_of_scope_assets ?? assets.filter((asset) => inventoryScopeState(asset) === "out_of_scope").length;
  const publicAssetCount = hasClientFilters
    ? assets.filter(inventoryIsPublicAsset).length
    : summary?.public_assets ?? assets.filter(inventoryIsPublicAsset).length;
  const needsReviewCount = hasClientFilters
    ? assets.filter(inventoryNeedsReview).length
    : (summary ? (summary.needs_review_assets ?? 0) + (summary.reported_issue_assets ?? 0) : assets.filter(inventoryNeedsReview).length);
  const baselineCount = hasClientFilters
    ? assets.filter((asset) => inventoryReviewState(asset) === "baseline").length
    : summary?.baseline_assets ?? assets.filter((asset) => inventoryReviewState(asset) === "baseline").length;
  const ownerRequiredCount = hasClientFilters
    ? assets.filter((asset) => inventoryAccountability(asset).state === "required_missing").length
    : summary?.owner_required_assets ?? assets.filter((asset) => inventoryAccountability(asset).state === "required_missing").length;
  const accountableCount = hasClientFilters
    ? assets.filter((asset) => inventoryAccountability(asset).state === "known").length
    : summary?.accountable_assets ?? assets.filter((asset) => inventoryAccountability(asset).state === "known").length;
  const inventoryError = categoriesQuery.error || assetsQuery.error;
  const runtimeState = runtimeStateForError(inventoryError);
  const inventoryLoading = categoriesQuery.loading || assetsQuery.loading;
  const hasInventoryData = Boolean(assetsQuery.data);
  const metricState: RuntimeState = inventoryError ? runtimeState : inventoryLoading && !assetsQuery.data ? "loading" : "ready";
  const hasAssetData = assets.length > 0;
  const scopedCoverage = hasAssetData ? `${hasClientFilters ? Math.round(((assets.length - outOfScopeCount) / assets.length) * 100) : summary?.scoped_coverage_pct ?? 100}%` : "No data";
  const ownerOptions = useMemo(() => (
    [...new Set(frameworkAssets.map(inventoryOwnerLabel))]
      .sort((left, right) => left.localeCompare(right))
  ), [frameworkAssets]);
  const filteredCategories = useMemo(() => {
    if (categories.some((category) => category.id === categoryID) || !categoryID) return categories;
    return [{ id: categoryID, label: humanize(categoryID), entity_types: [], count: assets.length }, ...categories];
  }, [assets.length, categories, categoryID]);
  const orgGroups = useMemo(() => {
    const groups = new Map<string, { total: number; accountable: number; needsReview: number; publicAssets: number }>();
    for (const asset of assets) {
      const label = orgLabel(asset);
      const group = groups.get(label) ?? { total: 0, accountable: 0, needsReview: 0, publicAssets: 0 };
      group.total += 1;
      if (inventoryAccountability(asset).state === "known") group.accountable += 1;
      if (inventoryNeedsReview(asset)) group.needsReview += 1;
      if (inventoryIsPublicAsset(asset)) group.publicAssets += 1;
      groups.set(label, group);
    }
    return [...groups.entries()].sort(([, left], [, right]) => right.needsReview - left.needsReview || right.total - left.total).slice(0, 6);
  }, [assets]);
  const filterChips = [
    { label: "Records", value: surfaceFilter ? surfaceFilterLabel(surfaceFilter) : "", onClear: () => { setSurfaceFilter(""); setCategoryID(""); setSelectedAssetURNs([]); } },
    { label: "Class", value: selectedCategory?.label || categoryID, onClear: () => setCategoryID("") },
    { label: "Search", value: query, onClear: () => setQuery("") },
    { label: "Framework", value: framework, onClear: () => setFramework("") },
    { label: "Owner", value: ownerFilter, onClear: () => setOwnerFilter("") },
    { label: "Review", value: reviewFilters.find((item) => item.value === reviewFilter)?.label ?? reviewFilter, onClear: () => setReviewFilter("") },
    { label: "Accountability", value: accountabilityFilters.find((item) => item.value === accountabilityFilter)?.label ?? accountabilityFilter, onClear: () => setAccountabilityFilter("") },
    { label: "Source", value: sourceID, onClear: () => setSourceID("") },
    { label: "Scope", value: scopeFilter ? inventoryScopeCopy(scopeFilter) : "", onClear: () => setScopeFilter("") },
    { label: "Tenant", value: tenantID, onClear: () => setTenantID("") },
  ];
  const clearFilters = () => {
    setCategoryID("");
    setQuery("");
    setFramework("");
    setSurfaceFilter("");
    setOwnerFilter("");
    setReviewFilter("");
    setAccountabilityFilter("");
    setSourceID("");
    setScopeFilter("");
    setTenantID("");
    setSelectedAssetURNs([]);
  };
  const toggleAssetSelection = useCallback((asset: GRCInventoryAsset) => {
    if (!isReviewableAsset(asset)) return;
    setSelectedAssetURNs((current) => current.includes(asset.urn)
      ? current.filter((urn) => urn !== asset.urn)
      : [...current, asset.urn]);
  }, []);
  const toggleAllVisible = useCallback(() => {
    const visibleURNs = new Set(selectableVisibleAssets.map((asset) => asset.urn));
    setSelectedAssetURNs((current) => allVisibleSelected
      ? current.filter((urn) => !visibleURNs.has(urn))
      : Array.from(new Set([...current, ...visibleURNs])));
  }, [allVisibleSelected, selectableVisibleAssets]);
  const openAccountabilityModal = useCallback((targetAssets: GRCInventoryAsset[], defaultState: AccountabilityUpdateState = "known") => {
    if (targetAssets.length === 0) return;
    setAccountabilityAssets(targetAssets);
    setAccountabilityDefaultState(defaultState);
    setAccountabilityError(null);
  }, []);
  const updateScope = useCallback(async (asset: GRCInventoryAsset, state: "in_scope" | "out_of_scope", reload = true) => {
    setScopeSavingURN(asset.urn);
    setScopeError(null);
    const response = await fetchCerebro("/grc/inventory/resource-scope", apiKey, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        tenant_id: debouncedTenantID || undefined,
        asset_urn: asset.urn,
        source_id: asset.source_id || debouncedSourceID || undefined,
        runtime_id: asset.runtime_id || undefined,
        scope_state: state,
        reason: state === "out_of_scope" ? "Scoped out from inventory review" : "Scoped into inventory review",
      }),
    });
    setScopeSavingURN(null);
    if (!response.ok) {
      setScopeError(typeof response.data === "string" ? response.data : `Scope update failed (${response.status})`);
      return false;
    }
    if (reload) {
      void assetsQuery.reload();
      void scopeQuery.reload();
    }
    return true;
  }, [apiKey, assetsQuery, debouncedSourceID, debouncedTenantID, scopeQuery]);
  const updateScopeForAssets = useCallback(async (targetAssets: GRCInventoryAsset[], state: "in_scope" | "out_of_scope") => {
    if (targetAssets.length === 0) return;
    for (const asset of targetAssets) {
      const ok = await updateScope(asset, state, false);
      if (!ok) return;
    }
    setSelectedAssetURNs([]);
    void assetsQuery.reload();
    void scopeQuery.reload();
  }, [assetsQuery, scopeQuery, updateScope]);
  const submitAccountabilityUpdate = useCallback(async (targetAssets: GRCInventoryAsset[], update: { state: AccountabilityUpdateState; owner?: string; reason?: string }) => {
    if (targetAssets.length === 0) return;
    setAccountabilitySaving(true);
    setAccountabilityError(null);
    for (const asset of targetAssets) {
      const response = await fetchCerebro<GRCInventoryAccountabilityUpdateResponse>("/grc/inventory/accountability", apiKey, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenant_id: debouncedTenantID || undefined,
          asset_urn: asset.urn,
          source_id: asset.source_id || debouncedSourceID || undefined,
          runtime_id: asset.runtime_id || undefined,
          state: update.state,
          owner: update.state === "known" ? update.owner : undefined,
          reason: update.reason || undefined,
        }),
      });
      if (!response.ok) {
        setAccountabilitySaving(false);
        setAccountabilityError(typeof response.data === "string" ? response.data : `Owner decision failed (${response.status})`);
        return;
      }
    }
    setAccountabilitySaving(false);
    setAccountabilityAssets(null);
    setSelectedAssetURNs([]);
    void assetsQuery.reload();
    void scopeQuery.reload();
  }, [apiKey, assetsQuery, debouncedSourceID, debouncedTenantID, scopeQuery]);
  const submitAssetReport = useCallback(async (asset: GRCInventoryAsset, reason: string) => {
    setReportSavingURN(asset.urn);
    setReportError(null);
    const response = await fetchCerebro<{ report: GRCInventoryAssetReport }>("/grc/inventory/asset-reports", apiKey, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        tenant_id: debouncedTenantID || undefined,
        asset_urn: asset.urn,
        source_id: asset.source_id || debouncedSourceID || undefined,
        reason,
        reporter: actor || undefined,
        attributes: {
          label: asset.label,
          entity_type: asset.entity_type,
          owner: inventoryOwnerLabel(asset),
        },
      }),
    });
    setReportSavingURN(null);
    if (!response.ok) {
      setReportError(typeof response.data === "string" ? response.data : `Report failed (${response.status})`);
      return;
    }
    setReportAsset(null);
    void assetsQuery.reload();
  }, [actor, apiKey, assetsQuery, debouncedSourceID, debouncedTenantID]);
  const exportAssets = useCallback(() => {
    const headers = ["Record", "Surface", "Class", "Review state", "Accountability", "Risk score", "Owner", "Scope", "Source", "Account / region", "URN"];
    const rows = assets.map((asset) => [
      asset.label || shortEntity(asset.urn),
      surfaceFilterLabel(inventoryAssetSurface(asset)),
      descriptionLabel(asset),
      inventoryReviewLabel(inventoryReviewState(asset)),
      inventoryAccountability(asset).label,
      asset.risk_score ?? "",
      ownerDisplay(asset),
      inventoryScopeCopy(inventoryScopeState(asset)),
      providerLabel(asset),
      regionLabel(asset),
      asset.urn,
    ]);
    const csv = [headers, ...rows].map((row) => row.map(csvEscape).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = window.URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `cerebro-inventory-${new Date().toISOString().slice(0, 10)}.csv`;
    anchor.click();
    window.URL.revokeObjectURL(url);
  }, [assets]);

  return (
    <div className="space-y-6">
      <PageHeader
        title={selectedCategory?.label || "Inventory"}
        description="Review assets, owners, scope, and supporting records collected from sources."
        action={
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" onClick={exportAssets} className="secondary-button px-3 py-1.5 text-[13px]">
              Export loaded CSV
            </button>
            {surfaceIsAssets && (
              <button type="button" onClick={() => setScopeOpen(true)} className="secondary-button px-3 py-1.5 text-[13px]">
                Configure scope
              </button>
            )}
            <button type="button" onClick={() => { void categoriesQuery.reload(); void assetsQuery.reload(); }} className="primary-button px-3 py-1.5 text-[13px]">
              Refresh
            </button>
          </div>
        }
      />

      {inventoryError && (
        <ErrorBlock
          error={inventoryError || "Unable to load inventory."}
          onRetry={() => { void categoriesQuery.reload(); void assetsQuery.reload(); }}
          recoveryDetail="Inventory data will appear when the API is reachable."
        />
      )}

      <div className="grid gap-6 xl:grid-cols-[260px_minmax(0,1fr)]">
        <AssetClassRail
          categories={filteredCategories}
          heading={surfaceIsAssets ? "Asset classes" : "Record classes"}
          selectedID={categoryID}
          total={categories.reduce((sum, item) => sum + item.count, 0)}
          currentCount={assets.length}
          onSelect={(id) => { setCategoryID(id); setSelectedAssetURNs([]); }}
        />

        <div className="min-w-0 space-y-6">
          <div className="surface-panel grid gap-0 divide-y divide-[color:var(--border)] overflow-hidden md:grid-cols-5 md:divide-x md:divide-y-0">
            {[
              { label: recordNounTitle, value: String(assets.length), detail: "matching filters" },
              { label: "Needs review", value: String(needsReviewCount), detail: surfaceIsAssets ? `${ownerRequiredCount} owner required` : `${needsReviewCount} reported` },
              { label: "Baseline", value: String(baselineCount), detail: "no immediate action" },
              { label: "Accountable", value: String(accountableCount), detail: surfaceIsAssets ? `${ownerGroupCount} owner groups` : "owner review not required" },
              { label: "Scope", value: scopedCoverage, detail: `${outOfScopeCount} scoped out` },
            ].map((item) => (
              <div key={item.label} className="px-4 py-3">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">{item.label}</div>
                <div className="mt-1 text-xl font-semibold text-[var(--text-primary)]">{metricValueForState({ state: metricState, value: item.value })}</div>
                <div className="mt-0.5 text-[12px] text-[var(--text-muted)]">{metricDetailForState({ state: metricState, detail: item.detail })}</div>
              </div>
            ))}
          </div>

          <div className="surface-panel px-5 py-4">
            <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4 2xl:grid-cols-[minmax(0,1fr)_140px_150px_150px_150px_150px_150px_130px]">
              <label className={labelClass}>Search<input value={query} onChange={(event) => { setQuery(event.target.value); setSelectedAssetURNs([]); }} placeholder="Search..." className={inputClass} /></label>
              <label className={labelClass}>
                Records
                <select value={surfaceFilter} onChange={(event) => { setSurfaceFilter(event.target.value); setCategoryID(""); setSelectedAssetURNs([]); }} className={inputClass}>
                  {surfaceFilters.map((item) => <option key={item.value || "asset"} value={item.value}>{item.label}</option>)}
                </select>
              </label>
              <label className={labelClass}>
                Framework
                <input value={framework} onChange={(event) => { setFramework(event.target.value); setSelectedAssetURNs([]); }} placeholder="FedRAMP Rev. 5" list="inventory-framework-options" className={inputClass} />
                <datalist id="inventory-framework-options">
                  {supportedGRCFrameworkNames.map((name) => <option key={name} value={name} label={frameworkOptionLabel(name)} />)}
                </datalist>
              </label>
              <label className={labelClass}>
                Owner
                <input value={ownerFilter} onChange={(event) => { setOwnerFilter(event.target.value); setSelectedAssetURNs([]); }} placeholder="Any owner" list="inventory-owner-options" className={inputClass} />
                <datalist id="inventory-owner-options">
                  {ownerOptions.map((owner) => <option key={owner} value={owner} />)}
                </datalist>
              </label>
              <label className={labelClass}>
                Review
                <select value={reviewFilter} onChange={(event) => { setReviewFilter(event.target.value); setSelectedAssetURNs([]); }} className={inputClass}>
                  {reviewFilters.map((item) => <option key={item.value} value={item.value === "all" ? "" : item.value}>{item.label}</option>)}
                </select>
              </label>
              <label className={labelClass}>
                Accountability
                <select value={accountabilityFilter} onChange={(event) => { setAccountabilityFilter(event.target.value); setSelectedAssetURNs([]); }} className={inputClass}>
                  {accountabilityFilters.map((item) => <option key={item.value} value={item.value === "all" ? "" : item.value}>{item.label}</option>)}
                </select>
              </label>
              <label className={labelClass}>Source<input value={sourceID} onChange={(event) => { setSourceID(event.target.value); setSelectedAssetURNs([]); }} placeholder="All" className={inputClass} /></label>
              <label className={labelClass}>Scope
                <select value={scopeFilter} onChange={(event) => { setScopeFilter(event.target.value); setSelectedAssetURNs([]); }} className={inputClass}>
                  <option value="">All</option>
                  <option value="in_scope">In scope</option>
                  <option value="out_of_scope">Scoped out</option>
                </select>
              </label>
            </div>
            <div className="mt-3 max-w-xs">
              <label className={labelClass}>Tenant<input value={tenantID} onChange={(event) => { setTenantID(event.target.value); setSelectedAssetURNs([]); }} placeholder="All" className={inputClass} /></label>
            </div>
            <AppliedFilterChips filters={filterChips} onClearAll={clearFilters} />
          </div>

          {inventoryLoading && <LoadingBlock label="Loading inventory..." />}

          {!inventoryError && hasInventoryData && (
            <ResultLimitNotice
              loaded={rawAssets.length}
              limit={GRC_WORKLIST_LIMIT}
              meta={assetListMeta}
              noun={recordNoun}
            />
          )}
          {!inventoryError && hasInventoryData && hasClientFilters && (
            <div className="rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2 text-[12px] text-[var(--text-muted)]">
              Framework and owner filters apply to loaded {recordNoun}.
            </div>
          )}

          {!inventoryError && selectedAssets.length > 0 && (
            <div className="surface-panel flex flex-wrap items-center justify-between gap-3 px-4 py-3">
              <div className="text-[13px] font-semibold text-[var(--text-primary)]">{selectedAssets.length} selected</div>
              <div className="flex flex-wrap items-center gap-2">
                <button type="button" onClick={() => openAccountabilityModal(selectedAssets, "known")} className="secondary-button px-3 py-1.5 text-[12px]">Set owner</button>
                <button type="button" onClick={() => openAccountabilityModal(selectedAssets, "not_required")} className="secondary-button px-3 py-1.5 text-[12px]">Owner not required</button>
                <button type="button" onClick={() => void updateScopeForAssets(selectedAssets, "out_of_scope")} className="secondary-button px-3 py-1.5 text-[12px]">Scope out</button>
                <button type="button" onClick={() => void updateScopeForAssets(selectedAssets, "in_scope")} className="secondary-button px-3 py-1.5 text-[12px]">Scope in</button>
                <button type="button" onClick={() => setSelectedAssetURNs([])} className="rounded-md px-3 py-1.5 text-[12px] font-semibold text-[var(--text-muted)] hover:bg-[var(--surface-hover)]">Clear</button>
              </div>
            </div>
          )}

          {!inventoryError && (
            <div className="grid gap-6 min-[1800px]:grid-cols-[minmax(0,1fr)_340px]">
              <main className="space-y-4">
                {!assetsQuery.loading && !assetsQuery.error && (
                  <div className="surface-panel overflow-x-auto">
                    <table className="data-table min-w-[1180px]">
                      <thead>
                        <tr>
                          <th className="w-10">
                            <input
                              type="checkbox"
                              aria-label="Select current page assets"
                              checked={allVisibleSelected}
                              disabled={selectableVisibleAssets.length === 0}
                              onChange={toggleAllVisible}
                              className="h-4 w-4 rounded border-[color:var(--border)]"
                            />
                          </th>
                          <th>{surfaceIsAssets ? "Asset / Details" : "Record / Details"}</th>
                          <th>Review</th>
                          <th>Risk</th>
                          <th>Accountability</th>
                          <th>Framework Scope</th>
                          <th>Account / Region</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {visibleAssets.map((asset) => (
                          <tr key={asset.urn} className={selectedAssetURNSet.has(asset.urn) ? "bg-[var(--surface-hover)]" : ""}>
                            <td>
                              <input
                                type="checkbox"
                                aria-label={`Select ${asset.label || shortEntity(asset.urn)}`}
                                checked={selectedAssetURNSet.has(asset.urn)}
                                disabled={!isReviewableAsset(asset)}
                                onChange={() => toggleAssetSelection(asset)}
                                className="h-4 w-4 rounded border-[color:var(--border)]"
                              />
                            </td>
                            <td>
                              <div className="flex items-center gap-3">
                                <SourceMark asset={asset} />
                                <div className="min-w-0">
                                  <Link href={`/inventory/${encodeURIComponent(asset.urn)}`} className="block max-w-[26rem] truncate font-medium text-[var(--text-primary)] hover:text-[var(--primary)]">{asset.label || shortEntity(asset.urn)}</Link>
                                  <div className="truncate font-mono text-[11px] text-[var(--text-muted)]">{shortEntity(inventoryAttr(asset, "resource_id", "id") || asset.urn)}</div>
                                  <div className="mt-1 text-[11px] text-[var(--text-muted)]">{surfaceFilterLabel(inventoryAssetSurface(asset))} / {descriptionLabel(asset)}</div>
                                </div>
                              </div>
                            </td>
                            <td>
                              <div className="space-y-1">
                                <ReviewBadge asset={asset} />
                                <div className="max-w-[190px] text-[11px] leading-4 text-[var(--text-muted)]">{inventoryReviewDetail(asset)}</div>
                              </div>
                            </td>
                            <td>
                              <RiskBadge score={asset.risk_score} level={asset.risk_level} />
                              {asset.risk_reasons && asset.risk_reasons.length > 0 && <div className="mt-1 max-w-[180px] text-[11px] leading-4 text-[var(--text-muted)]">{asset.risk_reasons.slice(0, 2).map(humanize).join(", ")}</div>}
                            </td>
                            <td>
                              <div className="max-w-[170px] truncate font-medium text-[var(--text-primary)]">{ownerDisplay(asset)}</div>
                              {isReviewableAsset(asset) && inventoryOwnerLabel(asset) === "Unassigned" && (
                                <div className="mt-1 text-[11px] text-[var(--text-muted)]">
                                  {inventoryAccountability(asset).state === "required_missing" ? "Required for review" : "Default inventory state"}
                                </div>
                              )}
                              {isReviewableAsset(asset) && (
                                <button type="button" onClick={() => openAccountabilityModal([asset], "known")} className="mt-1 text-[11px] font-semibold text-[var(--primary)] hover:text-[var(--primary-hover)]">Edit owner</button>
                              )}
                            </td>
                            <td>
                              <div className="space-y-1">
                                <Badge value={inventoryScopeCopy(inventoryScopeState(asset))} />
                                {asset.scope_reason && <div className="max-w-[170px] truncate text-[11px] text-[var(--text-muted)]">{asset.scope_reason}</div>}
                                {asset.asset_report_count ? (
                                  <div className="space-y-1">
                                    <Badge value={reportStatusCopy(asset.latest_asset_report_status)} />
                                    <div className="max-w-[170px] truncate text-[11px] text-[var(--text-muted)]">{asset.latest_asset_report_reason}</div>
                                  </div>
                                ) : null}
                              </div>
                            </td>
                            <td>{regionLabel(asset)}</td>
                            <td>
                              <div className="flex flex-wrap items-center gap-2">
                                {isReviewableAsset(asset) && (
                                  <button type="button" onClick={() => void updateScope(asset, inventoryScopeState(asset) === "out_of_scope" ? "in_scope" : "out_of_scope")} disabled={scopeSavingURN === asset.urn} className="secondary-button px-2.5 py-1 text-[12px] disabled:opacity-50">
                                    {scopeSavingURN === asset.urn ? "Saving" : inventoryScopeState(asset) === "out_of_scope" ? "Scope in" : "Scope out"}
                                  </button>
                                )}
                                <button type="button" onClick={() => { setReportAsset(asset); setReportError(null); }} disabled={reportSavingURN === asset.urn} className="secondary-button px-2.5 py-1 text-[12px] disabled:opacity-50">
                                  {reportSavingURN === asset.urn ? "Reporting" : "Report"}
                                </button>
                                <Link href={`/inventory/${encodeURIComponent(asset.urn)}`} className="px-2.5 py-1 text-[12px] font-semibold text-[var(--primary)] hover:text-[var(--primary-hover)]">Open</Link>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {assets.length === 0 && <div className="flex items-center justify-center p-8 text-[13px] text-[var(--text-muted)]">No {recordNoun} match this view.</div>}
                    {assets.length > 0 && totalAssetPages > 1 && (
                      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[color:var(--border)] px-4 py-3 text-[12px] text-[var(--text-muted)]">
                        <span>
                          Rows {assetPageStart + 1}-{Math.min(assetPageStart + INVENTORY_TABLE_PAGE_SIZE, assets.length)} of {assets.length.toLocaleString()} loaded {recordNoun}.
                        </span>
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => setAssetPage((page) => Math.max(1, page - 1))}
                            disabled={currentAssetPage === 1}
                            className="secondary-button px-2.5 py-1 text-[12px] disabled:cursor-not-allowed disabled:opacity-50"
                          >
                            Previous
                          </button>
                          <span>Page {currentAssetPage} of {totalAssetPages}</span>
                          <button
                            type="button"
                            onClick={() => setAssetPage((page) => Math.min(totalAssetPages, page + 1))}
                            disabled={currentAssetPage === totalAssetPages}
                            className="secondary-button px-2.5 py-1 text-[12px] disabled:cursor-not-allowed disabled:opacity-50"
                          >
                            Next
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </main>
              <aside className="grid gap-4 lg:grid-cols-2 min-[1800px]:block min-[1800px]:space-y-4">
                {surfaceIsAssets && (
                  <ReviewQueuePanel
                    assets={assets}
                    onReport={(asset) => { setReportAsset(asset); setReportError(null); }}
                    onScopeChange={(asset, state) => void updateScope(asset, state)}
                    reportSavingURN={reportSavingURN}
                    scopeSavingURN={scopeSavingURN}
                  />
                )}
                <section className="surface-panel p-4">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <h2 className="text-[13px] font-semibold text-[var(--text-primary)]">Review posture</h2>
                      <p className="mt-1 text-[12px] text-[var(--text-muted)]">{surfaceIsAssets ? "Accountability coverage for assets in this view." : "Supporting records stay linked to assets without owner review."}</p>
                    </div>
                    <Badge value={countLabel(providerCount, "source")} />
                  </div>
                  <div className="mt-4 grid gap-3">
                    <ProgressCard title="Scoped coverage" percent={hasAssetData ? summary?.scoped_coverage_pct ?? Math.round(((assets.length - outOfScopeCount) / assets.length) * 100) : 0} detail={hasAssetData ? "assets in review" : "no data"} total={summary?.in_scope_assets ?? assets.length} />
                    <ProgressCard title="Accountable assets" percent={assets.length ? Math.round((accountableCount / assets.length) * 100) : 0} detail="known owner group" total={accountableCount} />
                    <ProgressCard title="Private posture" percent={assets.length ? Math.round(((assets.length - publicAssetCount) / assets.length) * 100) : 0} detail="not public" total={`${publicAssetCount} public`} />
                  </div>
                  {scopeError && (
                    <div className="mt-4">
                      <ErrorBlock
                        error={scopeError}
                        onRetry={() => { void assetsQuery.reload(); void scopeQuery.reload(); }}
                        recoveryDetail="Scope updates can resume when the API is reachable."
                      />
                    </div>
                  )}
                </section>
              </aside>
            </div>
          )}

          {!inventoryError && (
            <section className="surface-panel p-4">
              <h2 className="text-[13px] font-semibold text-[var(--text-primary)]">Org parity</h2>
              <p className="mt-1 text-[12px] text-[var(--text-muted)]">Compare review pressure, accountability coverage, and exposure by organization, account, project, or owner scope.</p>
              <div className="mt-4 grid gap-2 md:grid-cols-2 xl:grid-cols-3">
                {orgGroups.map(([label, group]) => (
                  <div key={label} className="rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2">
                    <div className="flex items-center justify-between gap-3 text-[13px]">
                      <span className="truncate font-medium text-[var(--text-primary)]">{label}</span>
                      <span className="text-[var(--text-muted)]">{group.accountable}/{group.total} accountable</span>
                    </div>
                    <div className="mt-1 text-[12px] text-[var(--text-muted)]">{group.needsReview} need review, {group.publicAssets} public</div>
                  </div>
                ))}
                {orgGroups.length === 0 && <div className="text-[13px] text-[var(--text-muted)]">No org groups found.</div>}
              </div>
            </section>
          )}
        </div>
      </div>

      {scopeOpen && <ScopeModal onClose={() => setScopeOpen(false)} onScopeChange={(asset, state) => void updateScope(asset, state)} framework={framework} response={scopeQuery.data} savingURN={scopeSavingURN} />}
      {scopeOpen && scopeQuery.loading && <div className="fixed bottom-5 right-5 z-[60]"><LoadingBlock label="Loading scope..." /></div>}
      {accountabilityAssets && (
        <AccountabilityModal
          assets={accountabilityAssets}
          defaultState={accountabilityDefaultState}
          error={accountabilityError}
          saving={accountabilitySaving}
          onClose={() => setAccountabilityAssets(null)}
          onSubmit={(update) => void submitAccountabilityUpdate(accountabilityAssets, update)}
        />
      )}
      {reportAsset && (
        <AssetReportModal
          asset={reportAsset}
          error={reportError}
          onClose={() => setReportAsset(null)}
          onSubmit={(reason) => void submitAssetReport(reportAsset, reason)}
          saving={reportSavingURN === reportAsset.urn}
        />
      )}
    </div>
  );
}
