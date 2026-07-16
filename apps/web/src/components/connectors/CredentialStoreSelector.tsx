"use client";

import type { ConnectorCredentialStoreID, NormalizedCredentialStore } from "@/lib/connectors";

export default function CredentialStoreSelector({
  stores,
  selectedID,
  onSelect,
  compact = false,
  showUnavailable = true,
}: {
  stores: NormalizedCredentialStore[];
  selectedID: ConnectorCredentialStoreID;
  onSelect: (id: ConnectorCredentialStoreID) => void;
  compact?: boolean;
  showUnavailable?: boolean;
}) {
  const visibleStores = showUnavailable ? stores : stores.filter((store) => store.available);
  const readyStores = visibleStores.filter((store) => store.available);
  const unavailableStores = visibleStores.filter((store) => !store.available);
  const primaryStores = compact && readyStores.length > 0 ? readyStores : visibleStores;

  const renderStore = (store: NormalizedCredentialStore) => {
    const selected = selectedID === store.id && store.available;
    const statusLabel = store.available ? (store.nativeResolutionAvailable ? "Native" : "Ready") : "Setup";
    const resolverLabel = store.mode === "encrypted_submission"
      ? "sealed vault"
      : store.nativeResolutionAvailable
        ? "backend resolver"
        : store.mode === "environment_managed"
          ? "runtime env"
          : "env projection";
    const tone = selected
      ? "border-[var(--primary)] border-l-[var(--primary)] bg-[var(--primary-soft)] shadow-[var(--shadow-sm)]"
      : store.available
        ? "border-[color:var(--border)] border-l-emerald-500 bg-[var(--surface-raised)] hover:border-[color:var(--border-strong)] hover:bg-[var(--surface-hover)]"
        : "border-[color:var(--border)] border-l-amber-500 bg-[var(--surface-muted)]";

    return (
      <button
        key={store.id}
        type="button"
        disabled={!store.available}
        aria-pressed={selected}
        onClick={() => onSelect(store.id)}
        className={`${compact ? "min-h-[108px]" : "min-h-[148px]"} group rounded-lg border border-l-4 p-3 text-left transition ${tone} ${store.available ? "" : "cursor-not-allowed opacity-60"}`}
      >
        <div className="flex items-start justify-between gap-3">
          <div className={`${compact ? "h-8 min-w-12 px-2" : "h-9 min-w-9 px-2"} flex items-center justify-center rounded-md border border-[color:var(--border)] bg-[var(--surface)] text-[11px] font-semibold text-[var(--text-secondary)] group-hover:text-[var(--text-primary)]`}>
            {store.shortLabel}
          </div>
          <span className={`rounded-md px-1.5 py-0.5 text-[10px] font-semibold ${
            store.available
              ? store.nativeResolutionAvailable
                ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-100"
                : "bg-blue-100 text-blue-700 dark:bg-blue-500/15 dark:text-blue-100"
              : "bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-100"
          }`}>
            {statusLabel}
          </span>
        </div>
        <div className="mt-3 flex items-start justify-between gap-2">
          <div className="min-w-0">
            <div className="truncate text-[13px] font-semibold text-[var(--text-primary)]">{store.label}</div>
            <div className="mt-1 flex flex-wrap gap-1.5 text-[11px] text-[var(--text-muted)]">
              <span>{store.provider}</span>
              <span aria-hidden="true">·</span>
              <span>{resolverLabel}</span>
            </div>
          </div>
          {selected && <span className="shrink-0 rounded-full bg-[var(--surface)] px-2 py-1 text-[10px] font-semibold text-[var(--primary)]">Selected</span>}
        </div>
        <div className={`${compact ? "mt-2" : "mt-3"} text-[11px] leading-4 text-[var(--text-muted)]`}>
          {store.available ? store.detail : store.disabledReason}
        </div>
        {store.referencePrefixes.length > 0 && (
          <div className="mt-3 flex flex-wrap gap-1">
            {store.referencePrefixes.slice(0, compact ? 2 : 3).map((prefix) => (
              <span key={prefix} className="rounded bg-[var(--surface-muted)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--text-muted)]">
                {prefix}
              </span>
            ))}
          </div>
        )}
      </button>
    );
  };

  return (
    <div className="space-y-2">
      <div className={`grid gap-2 ${compact ? "sm:grid-cols-2" : "sm:grid-cols-2 xl:grid-cols-5"}`}>
        {primaryStores.map((store) => renderStore(store))}
      </div>
      {compact && readyStores.length > 0 && unavailableStores.length > 0 && (
        <details className="rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2">
          <summary className="cursor-pointer text-[12px] font-semibold text-[var(--text-secondary)]">
            {unavailableStores.length} store{unavailableStores.length === 1 ? "" : "s"} need backend setup
          </summary>
          <div className="mt-3 grid gap-2 sm:grid-cols-2">
            {unavailableStores.map((store) => renderStore(store))}
          </div>
        </details>
      )}
    </div>
  );
}
