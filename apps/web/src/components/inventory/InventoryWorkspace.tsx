"use client";

import Link from "next/link";
import { useMemo, useState } from "react";

import { AppliedFilterChips, Badge, ErrorBlock, LoadingBlock, PageHeader, ResultLimitNotice, RiskBadge } from "@/components/grc/Primitives";
import {
  GRCInventoryAsset,
  GRCInventoryAssetsResponse,
  GRCInventoryCategoriesResponse,
  GRCInventoryCategory,
  GRCInventorySurface,
  humanize,
  shortEntity,
} from "@/lib/grc";
import { grcPath, useDebouncedValue, useGRCQuery } from "@/lib/grc-client";
import { grcScopeQuery, useDebouncedGRCScope, useGRCScopeQueryState, withGRCScope } from "@/lib/grc-scope";
import { GRC_WORKLIST_LIMIT } from "@/lib/grc-list";
import { inventoryGroupFor, type InventoryGroupID } from "@/lib/inventory-groups";
import { inventoryAttr } from "@/lib/inventory-review";
import { inventoryMetadataMatch, inventorySourceOptions, inventoryTypeOptions } from "@/lib/inventory-search";
import { inventoryAssetSurface, inventoryNarrowingFilterCount, inventoryRequestSurface } from "@/lib/inventory-surface";
import { useQueryParamState } from "@/lib/query-params";
import { metricDetailForState, metricValueForState, runtimeStateForError, type RuntimeState } from "@/lib/runtime-state";

const inputClass = "control-input mt-1 w-full px-3 py-1.5 text-[13px]";
const labelClass = "text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]";
const INVENTORY_TABLE_PAGE_SIZE = 50;

const surfaceFilters: Array<{ value: "" | GRCInventorySurface; label: string }> = [
  { value: "", label: "Assets" },
  { value: "component", label: "Components" },
  { value: "signal", label: "Signals" },
  { value: "alias", label: "Aliases" },
  { value: "raw_record", label: "Raw records" },
  { value: "all", label: "All records" },
];

const providerLabel = (asset: GRCInventoryAsset) =>
  inventoryAttr(asset, "provider", "source_system") || asset.source_id || asset.entity_type.split(".")[0] || "source";

const regionLabel = (asset: GRCInventoryAsset) => {
  const account = inventoryAttr(asset, "account_id", "project_id", "org", "owner_login");
  const region = inventoryAttr(asset, "region", "zone", "location");
  if (account && region) return `${account} / ${region}`;
  return account || region || "Not set";
};

const descriptionLabel = (asset: GRCInventoryAsset) =>
  humanize(inventoryAttr(asset, "resource_type", "asset_type") || asset.entity_type);

const secondaryAssetID = (asset: GRCInventoryAsset) => {
  const value = shortEntity(inventoryAttr(asset, "resource_id", "id") || asset.urn);
  return value === (asset.label || shortEntity(asset.urn)) ? "" : value;
};

const surfaceFilterLabel = (value: string) =>
  surfaceFilters.find((item) => item.value === value)?.label ?? humanize(value);

const csvEscape = (value: unknown) => {
  const text = String(value ?? "");
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
};

function SourceMark({ asset }: { asset: GRCInventoryAsset }) {
  const provider = providerLabel(asset);
  return (
    <span
      title={provider}
      className="grid h-7 w-7 shrink-0 place-items-center rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] text-[10px] font-semibold uppercase text-[var(--text-secondary)]"
    >
      {provider.slice(0, 2)}
    </span>
  );
}

function AssetClassRail({
  categories,
  currentCount,
  heading,
  onSelect,
  selectedID,
  total,
}: {
  categories: GRCInventoryCategory[];
  currentCount: number;
  heading: string;
  onSelect: (id: string) => void;
  selectedID: string;
  total: number;
}) {
  return (
    <aside className="surface-panel overflow-hidden xl:sticky xl:top-4 xl:max-h-[calc(100vh-2rem)]">
      <div className="border-b border-[color:var(--border)] px-4 py-3">
        <div className="flex items-baseline justify-between">
          <h2 className="text-[13px] font-semibold text-[var(--text-primary)]">{heading}</h2>
          <span className="text-[11px] text-[var(--text-muted)]">{total.toLocaleString()}</span>
        </div>
        {/* Class counts come from a catalog aggregate over the tenant, so a search does not narrow them. */}
        <p className="mt-1 text-[11px] text-[var(--text-muted)]">Totals cover the tenant, not the current search.</p>
      </div>
      <div className="max-h-[60vh] overflow-y-auto xl:max-h-[calc(100vh-7rem)]">
        <button
          type="button"
          onClick={() => onSelect("")}
          aria-pressed={selectedID === ""}
          className={`flex w-full items-center justify-between px-4 py-2 text-left text-[13px] transition hover:bg-[var(--surface-hover)] ${selectedID === "" ? "bg-[var(--surface-hover)] font-semibold text-[var(--text-primary)]" : "text-[var(--text-secondary)]"}`}
        >
          <span>All classes</span>
          <span className="text-[11px] text-[var(--text-muted)]">{selectedID === "" ? currentCount.toLocaleString() : total.toLocaleString()}</span>
        </button>
        {categories.map((category) => (
          <button
            key={category.id}
            type="button"
            onClick={() => onSelect(category.id)}
            aria-pressed={selectedID === category.id}
            className={`flex w-full items-center justify-between gap-2 px-4 py-2 text-left text-[13px] transition hover:bg-[var(--surface-hover)] ${selectedID === category.id ? "bg-[var(--surface-hover)] font-semibold text-[var(--text-primary)]" : "text-[var(--text-secondary)]"}`}
          >
            <span className="min-w-0 truncate">{category.label}</span>
            <span className="text-[11px] text-[var(--text-muted)]">{category.count.toLocaleString()}</span>
          </button>
        ))}
      </div>
    </aside>
  );
}

export function InventoryWorkspace({ group }: { group?: InventoryGroupID } = {}) {
  const groupDefinition = inventoryGroupFor(group);
  const { tenantID, workspaceID, setTenantID, setWorkspaceID } = useGRCScopeQueryState();
  const [categoryID, setCategoryID] = useQueryParamState("category_id");
  const [query, setQuery] = useQueryParamState("q");
  const [sourceID, setSourceID] = useQueryParamState("source_id");
  const [entityType, setEntityType] = useQueryParamState("entity_type");
  const [surfaceFilter, setSurfaceFilter] = useQueryParamState("surface");
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [assetPage, setAssetPage] = useState(1);

  const debouncedScope = useDebouncedGRCScope({ tenantID, workspaceID });
  const debouncedCategoryID = useDebouncedValue(categoryID.trim());
  const debouncedQuery = useDebouncedValue(query.trim());
  const debouncedSourceID = useDebouncedValue(sourceID.trim());
  const debouncedEntityType = useDebouncedValue(entityType.trim());
  const debouncedSurfaceFilter = useDebouncedValue(surfaceFilter.trim());
  const selectedSurface = inventoryRequestSurface(debouncedSurfaceFilter);
  // The route pins the group; choosing a class in the rail narrows within it.
  const requestCategoryID = debouncedCategoryID || group || "";

  const categoriesQuery = useGRCQuery<GRCInventoryCategoriesResponse>(
    grcPath("/grc/inventory/categories", { ...grcScopeQuery(debouncedScope), source_id: debouncedSourceID, surface: selectedSurface, limit: GRC_WORKLIST_LIMIT }),
  );
  const assetsQuery = useGRCQuery<GRCInventoryAssetsResponse>(
    grcPath("/grc/inventory/assets", {
      ...grcScopeQuery(debouncedScope),
      source_id: debouncedSourceID,
      surface: selectedSurface,
      category_id: requestCategoryID,
      entity_type: debouncedEntityType,
      q: debouncedQuery,
      limit: GRC_WORKLIST_LIMIT,
    }),
  );

  const surfaceIsAssets = selectedSurface === "asset";
  const recordNoun = surfaceIsAssets ? "assets" : "records";
  const recordNounTitle = surfaceIsAssets ? "Assets" : "Records";
  const allCategories = useMemo(() => categoriesQuery.data?.categories ?? [], [categoriesQuery.data?.categories]);
  // A preset route shows only the classes the service placed in its group.
  const categories = useMemo(
    () => (group ? allCategories.filter((category) => category.group === group) : allCategories),
    [allCategories, group],
  );
  // The catalog reports no match total, so the row count is never presented as one.
  const assets = useMemo(
    () => (assetsQuery.data?.assets ?? [])
      .slice(0, GRC_WORKLIST_LIMIT)
      .sort((left, right) => left.label.localeCompare(right.label)),
    [assetsQuery.data?.assets],
  );

  const totalAssetPages = Math.max(1, Math.ceil(assets.length / INVENTORY_TABLE_PAGE_SIZE));
  const currentAssetPage = Math.min(assetPage, totalAssetPages);
  const assetPageStart = (currentAssetPage - 1) * INVENTORY_TABLE_PAGE_SIZE;
  const visibleAssets = useMemo(() => assets.slice(assetPageStart, assetPageStart + INVENTORY_TABLE_PAGE_SIZE), [assetPageStart, assets]);

  const typeOptions = useMemo(() => inventoryTypeOptions(categories), [categories]);
  const sourceOptions = useMemo(() => inventorySourceOptions(assets), [assets]);
  const classCount = categories.length;
  const sourceCount = sourceOptions.length;
  const selectedCategory = categories.find((category) => category.id === categoryID);

  const inventoryError = categoriesQuery.error || assetsQuery.error;
  const runtimeState = runtimeStateForError(inventoryError);
  const inventoryLoading = categoriesQuery.loading || assetsQuery.loading;
  const hasInventoryData = Boolean(assetsQuery.data);
  const metricState: RuntimeState = inventoryError ? runtimeState : inventoryLoading && !assetsQuery.data ? "loading" : "ready";

  const filteredCategories = useMemo(() => {
    if (categories.some((category) => category.id === categoryID) || !categoryID) return categories;
    return [{ id: categoryID, label: humanize(categoryID), entity_types: [], count: assets.length }, ...categories];
  }, [assets.length, categories, categoryID]);

  const filterChips = [
    { label: "Records", value: surfaceFilter ? surfaceFilterLabel(surfaceFilter) : "", onClear: () => { setSurfaceFilter(""); setCategoryID(""); } },
    { label: "Class", value: selectedCategory?.label || categoryID, onClear: () => setCategoryID("") },
    { label: "Search", value: query, onClear: () => setQuery("") },
    { label: "Type", value: entityType, onClear: () => setEntityType("") },
    { label: "Source", value: sourceID, onClear: () => setSourceID("") },
    { label: "Tenant", value: tenantID, onClear: () => setTenantID("") },
    { label: "Workspace", value: workspaceID, onClear: () => setWorkspaceID("") },
  ];
  const activeFilterCount = inventoryNarrowingFilterCount({
    surface: surfaceFilter,
    tenant: tenantID,
    category: categoryID,
    query,
    entityType,
    source: sourceID,
  }) + Number(Boolean(workspaceID.trim()));

  const clearFilters = () => {
    setCategoryID("");
    setQuery("");
    setSourceID("");
    setEntityType("");
    setSurfaceFilter("");
    setTenantID("");
    setWorkspaceID("");
  };

  const exportAssets = () => {
    const header = ["urn", "label", "entity_type", "surface", "source_id", "account_region", "risk_score", "risk_level"];
    const rows = assets.map((asset) => [
      asset.urn,
      asset.label,
      asset.entity_type,
      inventoryAssetSurface(asset),
      asset.source_id ?? "",
      regionLabel(asset),
      asset.risk_score ?? "",
      asset.risk_level ?? "",
    ]);
    const csv = [header, ...rows].map((row) => row.map(csvEscape).join(",")).join("\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8;" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `cerebro-inventory-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-5">
      <PageHeader
        title={selectedCategory?.label || groupDefinition?.label || "Inventory"}
        description={groupDefinition?.description ?? "Search every asset, resource, and record Cerebro has collected, by name, identifier, or metadata."}
        action={<button type="button" onClick={() => { void categoriesQuery.reload(); void assetsQuery.reload(); }} className="primary-button px-3 py-1.5 text-[13px]">Refresh</button>}
      />

      {inventoryError && (
        <ErrorBlock
          error={inventoryError || "Unable to load inventory."}
          onRetry={() => { void categoriesQuery.reload(); void assetsQuery.reload(); }}
          recoveryDetail="Inventory data will appear when the API is reachable."
        />
      )}

      <div className="grid gap-6 xl:grid-cols-[260px_minmax(0,1fr)]">
        <div className="hidden xl:block">
          <AssetClassRail
            categories={filteredCategories}
            heading={surfaceIsAssets ? "Asset classes" : "Record classes"}
            selectedID={categoryID}
            total={categories.reduce((sum, item) => sum + item.count, 0)}
            currentCount={assets.length}
            onSelect={(id) => { setCategoryID(id); setAssetPage(1); }}
          />
        </div>

        <div className="min-w-0 space-y-5">
          <div className="surface-panel px-5 py-4">
            <label className="block">
              <span className={labelClass}>Search inventory</span>
              <input
                value={query}
                onChange={(event) => { setQuery(event.target.value); setAssetPage(1); }}
                placeholder="Name, URN, account, region, tag, or any metadata value"
                className="control-input mt-1 w-full px-3 py-2.5 text-[15px]"
              />
            </label>
            <p className="mt-2 text-[12px] text-[var(--text-muted)]">
              Matches the asset name, its URN, and every attribute collected from the source.
            </p>

            <div className="mt-4 flex flex-wrap items-end gap-3">
              <label className={`${labelClass} min-w-[150px] flex-1`}>
                Records
                <select value={surfaceFilter} onChange={(event) => { setSurfaceFilter(event.target.value); setCategoryID(""); setAssetPage(1); }} className={inputClass}>
                  {surfaceFilters.map((item) => <option key={item.value || "asset"} value={item.value}>{item.label}</option>)}
                </select>
              </label>
              <label className={`${labelClass} min-w-[170px] flex-1`}>
                Type
                <input value={entityType} onChange={(event) => { setEntityType(event.target.value); setAssetPage(1); }} placeholder="Any type" list="inventory-type-options" className={inputClass} />
                <datalist id="inventory-type-options">
                  {typeOptions.map((option) => <option key={option} value={option} />)}
                </datalist>
              </label>
              <label className={`${labelClass} min-w-[150px] flex-1`}>
                Source
                <input value={sourceID} onChange={(event) => { setSourceID(event.target.value); setAssetPage(1); }} placeholder="Any source" list="inventory-source-options" className={inputClass} />
                <datalist id="inventory-source-options">
                  {sourceOptions.map((option) => <option key={option} value={option} />)}
                </datalist>
              </label>
              <button
                type="button"
                aria-expanded={filtersOpen}
                onClick={() => setFiltersOpen((open) => !open)}
                className="secondary-button px-3 py-1.5 text-[13px]"
              >
                Scope{activeFilterCount > 0 ? ` (${activeFilterCount})` : ""}
              </button>
              <button type="button" onClick={exportAssets} className="secondary-button px-3 py-1.5 text-[13px]">Export CSV</button>
            </div>

            <div className={`${filtersOpen ? "grid" : "hidden"} mt-3 max-w-2xl gap-3 border-t border-[color:var(--border)] pt-3 sm:grid-cols-2`}>
              <label className={labelClass}>Tenant ID<input value={tenantID} onChange={(event) => setTenantID(event.target.value)} placeholder="All authorized tenants" className={inputClass} /></label>
              <label className={labelClass}>Workspace ID<input value={workspaceID} onChange={(event) => setWorkspaceID(event.target.value)} placeholder="All authorized workspaces" className={inputClass} /></label>
            </div>

            <AppliedFilterChips filters={filterChips} onClearAll={clearFilters} />
          </div>

          <div className="surface-panel hidden gap-0 divide-y divide-[color:var(--border)] overflow-hidden md:grid md:grid-cols-3 md:divide-x md:divide-y-0">
            {[
              { label: recordNounTitle, value: assets.length.toLocaleString(), detail: debouncedQuery ? `matching "${debouncedQuery}"` : "on this page" },
              { label: surfaceIsAssets ? "Asset Classes" : "Record Classes", value: String(classCount), detail: "in this view" },
              { label: "Sources", value: String(sourceCount), detail: "represented on this page" },
            ].map((item) => (
              <div key={item.label} className="px-4 py-3">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">{item.label}</div>
                <div className="mt-1 text-xl font-semibold text-[var(--text-primary)]">{metricValueForState({ state: metricState, value: item.value })}</div>
                <div className="mt-0.5 text-[12px] text-[var(--text-muted)]">{metricDetailForState({ state: metricState, detail: item.detail })}</div>
              </div>
            ))}
          </div>

          {inventoryLoading && <LoadingBlock label="Searching inventory..." />}

          {!inventoryError && hasInventoryData && (
            <ResultLimitNotice
              loaded={assets.length}
              limit={GRC_WORKLIST_LIMIT}
              noun={recordNoun}
            />
          )}

          {!inventoryError && !assetsQuery.loading && (
            <main className="surface-panel overflow-hidden">
              <div className="overflow-x-auto">
                <table className="data-table inventory-results min-w-0 md:min-w-[940px]" data-testid="inventory-results">
                  <thead>
                    <tr>
                      <th>{surfaceIsAssets ? "Asset" : "Record"}</th>
                      <th>Type</th>
                      <th>Source</th>
                      <th>Account / Region</th>
                      <th>Risk</th>
                    </tr>
                  </thead>
                  <tbody>
                    {visibleAssets.map((asset) => {
                      const metadataHit = inventoryMetadataMatch(asset, debouncedQuery);
                      return (
                        <tr key={asset.urn}>
                          <td className="inventory-record-cell">
                            <div className="flex items-center gap-3">
                              <SourceMark asset={asset} />
                              <div className="min-w-0">
                                <Link href={withGRCScope(`/inventory/${encodeURIComponent(asset.urn)}`, { tenantID, workspaceID })} className="block max-w-[26rem] truncate font-medium text-[var(--text-primary)] hover:text-[var(--primary)]">{asset.label || shortEntity(asset.urn)}</Link>
                                {secondaryAssetID(asset) && <div className="truncate font-mono text-[11px] text-[var(--text-muted)]">{secondaryAssetID(asset)}</div>}
                                {metadataHit && (
                                  <div className="mt-1 truncate text-[11px] text-[var(--text-secondary)]" title={`${metadataHit.key}: ${metadataHit.value}`}>
                                    Matched {humanize(metadataHit.key)}: {metadataHit.value}
                                  </div>
                                )}
                              </div>
                            </div>
                          </td>
                          <td data-label="Type">
                            <div className="text-[13px] text-[var(--text-primary)]">{descriptionLabel(asset)}</div>
                            <div className="mt-0.5 font-mono text-[11px] text-[var(--text-muted)]">{asset.entity_type}</div>
                          </td>
                          <td data-label="Source">
                            <div className="text-[13px] text-[var(--text-primary)]">{providerLabel(asset)}</div>
                            <Badge value={surfaceFilterLabel(inventoryAssetSurface(asset))} />
                          </td>
                          <td data-label="Account / region">{regionLabel(asset)}</td>
                          <td data-label="Risk">
                            <RiskBadge score={asset.risk_score} level={asset.risk_level} />
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              {assets.length === 0 && (
                <div className="flex items-center justify-center p-8 text-center text-[13px] text-[var(--text-muted)]">
                  {debouncedQuery ? `Nothing in inventory matches "${debouncedQuery}".` : `No ${recordNoun} have been collected for this view yet.`}
                </div>
              )}
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
            </main>
          )}
        </div>
      </div>
    </div>
  );
}
