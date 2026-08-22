"use client";

import { useMemo, useState } from "react";
import { ListChecks, Plus, RotateCcw, Search, X } from "lucide-react";

import { Badge } from "@/components/grc/Primitives";
import type { ConnectorCatalogEntry, ConnectorScopeOption, ConnectorScopeResource } from "@/lib/connectors";
import { connectorScopeOptionFamilies } from "@/lib/connectors";
import {
  connectorScopeOptionMatchesFrameworkSegment,
  frameworkOptionLabel,
  supportedGRCFrameworkNames,
} from "@/lib/grc-frameworks";

export const splitScopeValues = (value: string) => value.split(/[,\n]/).map((item) => item.trim()).filter(Boolean);

type ResourceTypeFilter = "all" | "enabled" | "disabled" | "high_value" | "framework";

function scopeOptionSearchText(option: ConnectorScopeOption, families: string[]) {
  return [option.label, option.id, option.type, option.support, ...families].filter(Boolean).join(" ").toLowerCase();
}
export default function ScopePolicyBuilder({
  connector,
  selectedFamilies,
  protectedFamilies,
  initialFramework,
  onDisableFamilies,
  onEnableFamilies,
  resourceURNs,
  onResourceURNsChange,
  resources,
  onResourcesChange,
}: {
  connector: ConnectorCatalogEntry;
  selectedFamilies: Set<string>;
  protectedFamilies: Set<string>;
  initialFramework?: string;
  onDisableFamilies: (families: string[]) => void;
  onEnableFamilies: (families: string[]) => void;
  resourceURNs: string;
  onResourceURNsChange: (value: string) => void;
  resources: ConnectorScopeResource[];
  onResourcesChange: (resources: ConnectorScopeResource[]) => void;
}) {
  const [query, setQuery] = useState("");
  const initialFrameworkQuery = (initialFramework ?? "").trim();
  const [framework, setFramework] = useState(initialFramework ?? "");
  const [filter, setFilter] = useState<ResourceTypeFilter>(initialFrameworkQuery ? "framework" : "all");
  const [resourceType, setResourceType] = useState("");
  const [resourceID, setResourceID] = useState("");
  const [resourceReason, setResourceReason] = useState("");
  const options = useMemo(() => connector.scope_options ?? [], [connector.scope_options]);
  const rows = useMemo(() => options.map((option) => {
    const families = connectorScopeOptionFamilies(option);
    const protectedRow = families.length > 0 && families.every((family) => protectedFamilies.has(family));
    const disabled = !protectedRow && families.some((family) => selectedFamilies.has(family));
    return {
      option,
      families,
      disabled,
      protectedRow,
      search: scopeOptionSearchText(option, families),
    };
  }), [options, protectedFamilies, selectedFamilies]);
  const disabledRows = rows.filter((row) => row.disabled);
  const frameworkQueryActive = framework.trim().length > 0;
  const frameworkRows = frameworkQueryActive
    ? rows.filter((row) => connectorScopeOptionMatchesFrameworkSegment(row.option, framework, connector.source_id))
    : [];
  const enabledCount = Math.max(rows.length - disabledRows.length, 0);
  const selectedURNs = splitScopeValues(resourceURNs);
  const exactCount = selectedURNs.length + resources.length;
  const queryText = query.trim().toLowerCase();
  const visibleRows = rows.filter((row) => {
    const matchesQuery = queryText === "" || row.search.includes(queryText);
    const matchesFilter =
      filter === "all" ||
      (filter === "enabled" && !row.disabled) ||
      (filter === "disabled" && row.disabled) ||
      (filter === "high_value" && row.option.high_value) ||
      (filter === "framework" && frameworkRows.some((frameworkRow) => frameworkRow.option.id === row.option.id));
    return matchesQuery && matchesFilter;
  });
  const shownRows = visibleRows.slice(0, 80);
  const mutableShownRows = shownRows.filter((row) => !row.protectedRow);
  const allVisibleDisabled = mutableShownRows.length > 0 && mutableShownRows.every((row) => row.disabled);
  const visibleFamilies = mutableShownRows.flatMap((row) => row.families).filter((family) => !protectedFamilies.has(family));
  const frameworkFamilies = frameworkRows
    .filter((row) => !row.protectedRow)
    .flatMap((row) => row.families)
    .filter((family) => !protectedFamilies.has(family));
  const outsideFrameworkFamilies = rows
    .filter((row) => frameworkQueryActive && !row.protectedRow && !frameworkRows.some((frameworkRow) => frameworkRow.option.id === row.option.id))
    .flatMap((row) => row.families)
    .filter((family) => !protectedFamilies.has(family));
  const exampleFamily = rows[0]?.families[0] ?? `${connector.source_id}.resource`;
  const exampleResourceType = exampleFamily.includes(".") || exampleFamily.startsWith(`${connector.source_id}_`)
    ? exampleFamily.replace(`${connector.source_id}_`, `${connector.source_id}.`)
    : `${connector.source_id}.${exampleFamily}`;
  const exampleResourceURN = `urn:cerebro:tenant:${exampleResourceType.replaceAll(".", "_")}:example`;
  const addResource = () => {
    const type = resourceType.trim();
    const id = resourceID.trim();
    if (!type || !id) return;
    onResourcesChange([...resources, { type, id, reason: resourceReason.trim() || undefined }]);
    setResourceType("");
    setResourceID("");
    setResourceReason("");
  };
  const filters: Array<{ id: ResourceTypeFilter; label: string; count: number }> = [
    { id: "all", label: "All", count: rows.length },
    { id: "enabled", label: "Collecting", count: enabledCount },
    { id: "disabled", label: "Skipped", count: disabledRows.length },
    { id: "high_value", label: "High value", count: rows.filter((row) => row.option.high_value).length },
    ...(frameworkQueryActive ? [{ id: "framework" as const, label: "Framework", count: frameworkRows.length }] : []),
  ];
  const applyFrameworkFilter = () => {
    if (!frameworkQueryActive) return;
    onEnableFamilies(frameworkFamilies);
    onDisableFamilies(outsideFrameworkFamilies);
    setFilter("framework");
  };

  return (
    <div className="space-y-4">
      <div className="overflow-hidden rounded-lg border border-[color:var(--border)] bg-[var(--surface)]">
        <div className="grid gap-3 border-b border-[color:var(--border)] bg-[var(--surface-muted)] px-4 py-3 xl:grid-cols-[minmax(0,1fr)_auto]">
          <div>
            <div className="text-[13px] font-semibold text-[var(--text-primary)]">Resource collection</div>
            <div className="mt-1 text-[12px] leading-5 text-[var(--text-muted)]">
              Resource types are collected by default. Switch a type off to skip that resource type before collection; exact assets can be added separately.
            </div>
          </div>
          <div className="grid grid-cols-3 overflow-hidden rounded-md border border-[color:var(--border)] bg-[var(--surface)] text-center text-[11px]">
            <div className="px-3 py-2">
              <div className="text-[15px] font-semibold text-[var(--text-primary)]">{rows.length}</div>
              <div className="text-[var(--text-muted)]">Available</div>
            </div>
            <div className="border-l border-[color:var(--border)] px-3 py-2">
              <div className="text-[15px] font-semibold text-emerald-600">{enabledCount}</div>
              <div className="text-[var(--text-muted)]">On</div>
            </div>
            <div className="border-l border-[color:var(--border)] px-3 py-2">
              <div className="text-[15px] font-semibold text-amber-600">{disabledRows.length}</div>
              <div className="text-[var(--text-muted)]">Off</div>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 border-b border-[color:var(--border)] px-4 py-3">
          <label className="min-w-[220px] flex-1">
            <span className="sr-only">Framework filter</span>
            <input
              value={framework}
              onChange={(event) => {
                setFramework(event.target.value);
                setFilter(event.target.value.trim() ? "framework" : "all");
              }}
              placeholder="Framework filter"
              list="connector-framework-options"
              className="control-input w-full px-3 py-2 text-[13px]"
            />
            <datalist id="connector-framework-options">
              {supportedGRCFrameworkNames.map((name) => <option key={name} value={name} label={frameworkOptionLabel(name)} />)}
            </datalist>
          </label>
          <label className="relative min-w-[240px] flex-1">
            <span className="sr-only">Search resource types</span>
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--text-muted)]" />
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search resource types..." className="control-input w-full px-9 py-2 text-[13px]" />
          </label>
          <div className="flex flex-wrap gap-1 rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] p-1">
            {filters.map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => setFilter(item.id)}
                className={`rounded px-2.5 py-1.5 text-[12px] font-semibold transition ${
                  filter === item.id
                    ? "bg-[var(--surface)] text-[var(--text-primary)] shadow-[var(--shadow-sm)]"
                    : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                }`}
              >
                {item.label} <span className="font-mono text-[11px] opacity-70">{item.count}</span>
              </button>
            ))}
          </div>
          <button
            type="button"
            onClick={() => (allVisibleDisabled ? onEnableFamilies(visibleFamilies) : onDisableFamilies(visibleFamilies))}
            disabled={shownRows.length === 0 || visibleFamilies.length === 0}
            className="secondary-button inline-flex items-center gap-2 px-3 py-2 text-[12px] disabled:cursor-not-allowed disabled:opacity-50"
          >
            <RotateCcw className="h-3.5 w-3.5" />
            {allVisibleDisabled ? "Enable visible" : "Disable visible"}
          </button>
          {frameworkQueryActive && (
            <button
              type="button"
              onClick={applyFrameworkFilter}
              disabled={frameworkRows.length === 0}
              className="secondary-button inline-flex items-center gap-2 px-3 py-2 text-[12px] disabled:cursor-not-allowed disabled:opacity-50"
            >
              <ListChecks className="h-3.5 w-3.5" />
              Collect framework only
            </button>
          )}
        </div>

        <div className="max-h-[430px] overflow-y-auto">
          {shownRows.map(({ option, families, disabled, protectedRow }) => (
            <div
              key={`${option.id}:${families.join(",")}`}
              className={`grid gap-3 border-b border-[color:var(--border)] px-4 py-3 last:border-b-0 md:grid-cols-[minmax(0,1fr)_auto] ${
                disabled ? "bg-amber-50/60 dark:bg-amber-500/10" : "bg-[var(--surface)]"
              }`}
            >
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <div className="text-[13px] font-semibold text-[var(--text-primary)]">{option.label || option.id}</div>
                  {option.high_value && <Badge value="high value" />}
                  {option.support && <Badge value={option.support} />}
                </div>
                <div className="mt-1 flex flex-wrap gap-1.5">
                  {families.map((family) => (
                    <span key={family} className="rounded bg-[var(--surface-muted)] px-1.5 py-0.5 font-mono text-[11px] text-[var(--text-muted)]">
                      {family}
                    </span>
                  ))}
                </div>
              </div>
              <div className="flex items-center justify-between gap-3 md:justify-end">
                <span className={`text-[12px] font-semibold ${disabled ? "text-amber-700 dark:text-amber-300" : "text-emerald-700 dark:text-emerald-300"}`}>
                  {disabled ? "Skipped" : "Collecting"}
                </span>
                <button
                  type="button"
                  role="switch"
                  aria-checked={!disabled}
                  aria-label={protectedRow ? `${option.label || option.id} is required` : `${disabled ? "Enable" : "Disable"} ${option.label || option.id}`}
                  disabled={protectedRow}
                  onClick={() => (disabled ? onEnableFamilies(families) : onDisableFamilies(families))}
                  className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full border transition disabled:cursor-not-allowed disabled:opacity-55 ${
                    disabled
                      ? "border-amber-300 bg-amber-100 dark:border-amber-500/40 dark:bg-amber-500/20"
                      : "border-emerald-300 bg-emerald-100 dark:border-emerald-500/40 dark:bg-emerald-500/20"
                  }`}
                >
                  <span
                    className={`h-5 w-5 rounded-full bg-white shadow-sm transition dark:bg-zinc-100 ${
                      disabled ? "translate-x-0.5" : "translate-x-5"
                    }`}
                  />
                </button>
              </div>
            </div>
          ))}
          {shownRows.length === 0 && (
            <div className="p-6 text-center text-[13px] text-[var(--text-muted)]">
              {rows.length === 0 ? "This connector has not advertised resource types yet." : "No resource types match the current search and filter."}
            </div>
          )}
        </div>
        {visibleRows.length > shownRows.length && (
          <div className="border-t border-[color:var(--border)] bg-[var(--surface-muted)] px-4 py-2 text-[12px] text-[var(--text-muted)]">
            Showing {shownRows.length} of {visibleRows.length} matching resource types. Narrow the search to edit the rest.
          </div>
        )}
      </div>

      <details className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-4" open={exactCount > 0}>
        <summary className="cursor-pointer list-none">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="text-[13px] font-semibold text-[var(--text-primary)]">Specific asset exclusions</div>
              <div className="mt-0.5 text-[12px] text-[var(--text-muted)]">
                Use only when a single known asset should be skipped while its resource type stays enabled.
              </div>
            </div>
            <Badge value={exactCount > 0 ? `${exactCount} exact` : "optional"} />
          </div>
        </summary>

        <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(260px,0.75fr)]">
          <label className="text-[11px] font-semibold text-[var(--text-muted)]">
            Exact resource URNs
            <textarea
              value={resourceURNs}
              onChange={(event) => onResourceURNsChange(event.target.value)}
              placeholder={exampleResourceURN}
              className="control-input mt-1 min-h-[112px] w-full px-3 py-2 font-mono text-[12px]"
            />
            <span className="mt-1 block text-[11px] font-normal leading-4 text-[var(--text-muted)]">One URN per line or comma-separated.</span>
          </label>
          <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] p-3">
            <div className="text-[13px] font-semibold text-[var(--text-primary)]">Typed resource ID</div>
            <div className="mt-3 grid gap-2">
              <input value={resourceType} onChange={(event) => setResourceType(event.target.value)} placeholder={exampleResourceType} className="control-input px-3 py-2 text-[13px]" />
              <input value={resourceID} onChange={(event) => setResourceID(event.target.value)} placeholder="resource-id" className="control-input px-3 py-2 text-[13px]" />
              <input value={resourceReason} onChange={(event) => setResourceReason(event.target.value)} placeholder="Reason, optional" className="control-input px-3 py-2 text-[13px]" />
              <button type="button" onClick={addResource} disabled={!resourceType.trim() || !resourceID.trim()} className="secondary-button inline-flex items-center justify-center gap-2 px-3 py-2 text-[13px] disabled:cursor-not-allowed disabled:opacity-50">
                <Plus className="h-4 w-4" />
                Add resource
              </button>
            </div>
          </div>
        </div>

        {exactCount > 0 && (
          <div className="mt-4 flex flex-wrap gap-2">
            {selectedURNs.slice(0, 8).map((urn) => (
              <span key={urn} className="inline-flex max-w-full items-center gap-2 rounded-md bg-[var(--surface-muted)] px-2 py-1 font-mono text-[11px] text-[var(--text-secondary)]">
                <span className="truncate">{urn}</span>
                <button
                  type="button"
                  onClick={() => onResourceURNsChange(selectedURNs.filter((item) => item !== urn).join("\n"))}
                  className="shrink-0 text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                  aria-label={`Remove ${urn}`}
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </span>
            ))}
            {selectedURNs.length > 8 && (
              <span className="rounded-md bg-[var(--surface-muted)] px-2 py-1 text-[12px] font-semibold text-[var(--text-muted)]">
                +{selectedURNs.length - 8} URNs
              </span>
            )}
            {resources.map((resource, index) => (
              <span key={`${resource.type}:${resource.id}:${index}`} className="inline-flex items-center gap-2 rounded-md bg-[var(--surface-muted)] px-2 py-1 text-[12px] font-semibold text-[var(--text-secondary)]">
                {resource.type}:{resource.id}
                <button type="button" onClick={() => onResourcesChange(resources.filter((_, itemIndex) => itemIndex !== index))} className="text-[var(--text-muted)] hover:text-[var(--text-primary)]" aria-label={`Remove ${resource.type}:${resource.id}`}>
                  <X className="h-3.5 w-3.5" />
                </button>
              </span>
            ))}
          </div>
        )}
      </details>
    </div>
  );
}
