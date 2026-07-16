"use client";

import Link from "next/link";
import { useMemo } from "react";
import { CheckCircle2, RefreshCw, Search } from "lucide-react";

import { AppliedFilterChips, Badge, EmptyBlock, ErrorBlock, LoadingBlock, MetricCard, PageHeader, Panel, ResultLimitNotice } from "@/components/grc/Primitives";
import { withQuery } from "@/lib/cerebro-data";
import {
  credentialStoreActionLabel,
  credentialStoreIssueMatchesQuery,
  credentialStoreMatchesQuery,
  credentialStoreModeLabel,
  credentialStoreResolverLabel,
  credentialStoreUsageTotals,
  type CredentialStoreBinding,
  type CredentialStoreIssue,
  type CredentialStoreListResponse,
  type CredentialStoreOperational,
} from "@/lib/credential-stores";
import { useDebouncedValue, useGRCQuery } from "@/lib/grc-client";
import { GRC_DETAIL_LIMIT, grcBoundedRows } from "@/lib/grc-list";
import { useQueryParamState } from "@/lib/query-params";
import { runtimeStateForError, type RuntimeState } from "@/lib/runtime-state";

const inputClass = "control-input mt-1 w-full px-3 py-2 text-[13px]";
const labelClass = "text-[11px] font-semibold text-[var(--text-muted)]";

function formatDate(value?: string) {
  if (!value) return "Not recorded";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(date);
}

function compactList(values?: string[], fallback = "No values") {
  const visible = (values ?? []).filter(Boolean);
  if (visible.length === 0) return fallback;
  if (visible.length <= 3) return visible.join(", ");
  return `${visible.slice(0, 3).join(", ")} +${visible.length - 3}`;
}

function storePrimaryAction(store: CredentialStoreOperational) {
  const issueAction = store.issues?.find((issue) => issue.next_action)?.next_action;
  return credentialStoreActionLabel(issueAction || store.health.next_action);
}

function flattenBindings(stores: CredentialStoreOperational[]) {
  return stores.flatMap((store) => (store.bindings ?? []).map((binding) => ({
    ...binding,
    credential_store_label: store.store.label,
  })));
}

function StoreTable({ stores }: { stores: CredentialStoreOperational[] }) {
  if (stores.length === 0) return <EmptyBlock label="No credential stores match these filters." />;

  return (
    <div className="overflow-auto">
      <table className="w-full min-w-[980px] text-left text-[12px]">
        <thead className="border-b border-[color:var(--border)] bg-[var(--surface-muted)] text-[11px] uppercase tracking-wider text-[var(--text-muted)]">
          <tr>
            <th className="px-3 py-2 font-semibold">Store</th>
            <th className="px-3 py-2 font-semibold">Status</th>
            <th className="px-3 py-2 font-semibold">Use</th>
            <th className="px-3 py-2 font-semibold">Reference contract</th>
            <th className="px-3 py-2 font-semibold">Backend config</th>
            <th className="px-3 py-2 font-semibold">Action</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[color:var(--border)]">
          {stores.map((item) => {
            const requiredConfig = item.store.required_config ?? [];
            const prefixes = item.store.reference_prefixes ?? [];
            return (
              <tr key={item.store.id} className="align-top">
                <td className="px-3 py-3">
                  <div className="font-semibold text-[var(--text-primary)]">{item.store.label}</div>
                  <div className="mt-1 text-[11px] text-[var(--text-muted)]">{item.store.provider} / {credentialStoreModeLabel(item.store.mode)}</div>
                  <div className="mt-1 max-w-[22rem] text-[11px] leading-4 text-[var(--text-secondary)]">{item.store.description}</div>
                </td>
                <td className="px-3 py-3">
                  <Badge value={item.health.status} />
                  <div className="mt-1 max-w-[14rem] text-[11px] leading-4 text-[var(--text-muted)]">{item.health.detail || item.store.detail || "No status detail"}</div>
                </td>
                <td className="px-3 py-3 text-[var(--text-secondary)]">
                  <div>{item.usage.connections} connections</div>
                  <div>{item.usage.credentials} credentials</div>
                  <div>{item.usage.field_references} field references</div>
                  {item.usage.issues > 0 && <div className="mt-1 font-semibold text-amber-700 dark:text-amber-200">{item.usage.issues} issues</div>}
                </td>
                <td className="px-3 py-3">
                  <div className="flex flex-wrap gap-1">
                    {prefixes.length > 0 ? prefixes.map((prefix) => (
                      <code key={prefix} className="rounded bg-[var(--surface-muted)] px-1.5 py-0.5 text-[11px] text-[var(--text-secondary)]">{prefix}</code>
                    )) : <span className="text-[11px] text-[var(--text-muted)]">Direct submission</span>}
                  </div>
                  <div className="mt-2 max-w-[18rem] break-all font-mono text-[11px] text-[var(--text-muted)]">
                    {item.store.reference_field_template || item.store.reference_placeholder || "No reference required"}
                  </div>
                </td>
                <td className="px-3 py-3">
                  {requiredConfig.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {requiredConfig.slice(0, 4).map((field) => (
                        <code key={field.env || field.label} className="rounded bg-[var(--surface-muted)] px-1.5 py-0.5 text-[11px] text-[var(--text-secondary)]">
                          {field.env || field.label}
                        </code>
                      ))}
                      {requiredConfig.length > 4 && <span className="text-[11px] text-[var(--text-muted)]">+{requiredConfig.length - 4}</span>}
                    </div>
                  ) : (
                    <span className="text-[11px] text-[var(--text-muted)]">No required backend config</span>
                  )}
                </td>
                <td className="px-3 py-3 text-[var(--text-secondary)]">{storePrimaryAction(item)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function IssueTable({ issues }: { issues: CredentialStoreIssue[] }) {
  if (issues.length === 0) return <EmptyBlock label="No credential store issues for these filters." />;

  return (
    <div className="overflow-auto">
      <table className="w-full min-w-[860px] text-left text-[12px]">
        <thead className="border-b border-[color:var(--border)] bg-[var(--surface-muted)] text-[11px] uppercase tracking-wider text-[var(--text-muted)]">
          <tr>
            <th className="px-3 py-2 font-semibold">Issue</th>
            <th className="px-3 py-2 font-semibold">Store</th>
            <th className="px-3 py-2 font-semibold">Runtime</th>
            <th className="px-3 py-2 font-semibold">Credential</th>
            <th className="px-3 py-2 font-semibold">Action</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[color:var(--border)]">
          {issues.map((issue) => (
            <tr key={issue.id} className="align-top">
              <td className="px-3 py-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge value={issue.status} tone={issue.severity === "error" ? "severity" : "status"} />
                  {issue.field && <code className="rounded bg-[var(--surface-muted)] px-1.5 py-0.5 text-[11px] text-[var(--text-secondary)]">{issue.field}</code>}
                </div>
                <div className="mt-1 max-w-[28rem] text-[12px] leading-5 text-[var(--text-secondary)]">{issue.detail}</div>
              </td>
              <td className="px-3 py-3 text-[var(--text-secondary)]">{issue.credential_store_id || "Unassigned"}</td>
              <td className="px-3 py-3">
                <div className="font-mono text-[11px] text-[var(--text-secondary)]">{issue.runtime_id || "No runtime"}</div>
                {issue.source_id && <div className="mt-1 text-[11px] text-[var(--text-muted)]">{issue.source_id}</div>}
              </td>
              <td className="px-3 py-3 font-mono text-[11px] text-[var(--text-secondary)]">{issue.credential_id || "No credential"}</td>
              <td className="px-3 py-3 text-[var(--text-secondary)]">{credentialStoreActionLabel(issue.next_action)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function BindingTable({ bindings }: { bindings: Array<CredentialStoreBinding & { credential_store_label?: string }> }) {
  if (bindings.length === 0) return <EmptyBlock label="No runtime bindings for these filters." />;

  return (
    <div className="overflow-auto">
      <table className="w-full min-w-[980px] text-left text-[12px]">
        <thead className="border-b border-[color:var(--border)] bg-[var(--surface-muted)] text-[11px] uppercase tracking-wider text-[var(--text-muted)]">
          <tr>
            <th className="px-3 py-2 font-semibold">Source runtime</th>
            <th className="px-3 py-2 font-semibold">Store</th>
            <th className="px-3 py-2 font-semibold">Fields</th>
            <th className="px-3 py-2 font-semibold">Resolver</th>
            <th className="px-3 py-2 font-semibold">Credential</th>
            <th className="px-3 py-2 font-semibold">Validation</th>
            <th className="px-3 py-2 font-semibold">Action</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[color:var(--border)]">
          {bindings.map((binding) => (
            <tr key={binding.id} className="align-top">
              <td className="px-3 py-3">
                <div className="font-semibold text-[var(--text-primary)]">{binding.source_name || binding.source_id || "Unknown source"}</div>
                <div className="mt-1 font-mono text-[11px] text-[var(--text-muted)]">{binding.runtime_id || "No runtime"}</div>
                {binding.tenant_id && <div className="mt-1 text-[11px] text-[var(--text-muted)]">{binding.tenant_id}</div>}
              </td>
              <td className="px-3 py-3">
                <div className="text-[var(--text-secondary)]">{binding.credential_store_label || binding.credential_store_id}</div>
                <div className="mt-1 text-[11px] text-[var(--text-muted)]">{binding.auth_method || "Unknown auth"}</div>
              </td>
              <td className="px-3 py-3">
                <div className="text-[var(--text-secondary)]">{compactList(binding.fields, "No fields")}</div>
                <div className="mt-1 text-[11px] text-[var(--text-muted)]">{compactList(binding.reference_prefixes, "No references")}</div>
              </td>
              <td className="px-3 py-3 text-[var(--text-secondary)]">{credentialStoreResolverLabel(binding.resolver)}</td>
              <td className="px-3 py-3">
                <div className="font-mono text-[11px] text-[var(--text-secondary)]">{binding.credential_id || "Reference only"}</div>
                {binding.credential_status && <div className="mt-1"><Badge value={binding.credential_status} /></div>}
              </td>
              <td className="px-3 py-3 text-[var(--text-secondary)]">
                <div>{formatDate(binding.last_validated_at)}</div>
                {binding.last_used_at && <div className="mt-1 text-[11px] text-[var(--text-muted)]">Used {formatDate(binding.last_used_at)}</div>}
              </td>
              <td className="px-3 py-3 text-[var(--text-secondary)]">{credentialStoreActionLabel(binding.next_action)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function CredentialStoresPage() {
  const [tenantID, setTenantID] = useQueryParamState("tenant_id");
  const [storeQuery, setStoreQuery] = useQueryParamState("q");
  const debouncedTenantID = useDebouncedValue(tenantID.trim());
  const debouncedStoreQuery = useDebouncedValue(storeQuery.trim());

  const path = withQuery("/credential-stores", { tenant_id: debouncedTenantID, limit: 1000 });
  const storesQuery = useGRCQuery<CredentialStoreListResponse>(path);
  const stores = useMemo(() => storesQuery.data?.stores ?? [], [storesQuery.data?.stores]);
  const allIssues = useMemo(() => storesQuery.data?.issues ?? [], [storesQuery.data?.issues]);
  const visibleStores = useMemo(
    () => stores.filter((store) => credentialStoreMatchesQuery(store, debouncedStoreQuery)),
    [debouncedStoreQuery, stores],
  );
  const visibleStoreIDs = useMemo(() => new Set(visibleStores.map((store) => store.store.id)), [visibleStores]);
  const issues = useMemo(
    () => allIssues.filter((issue) => {
      if (!credentialStoreIssueMatchesQuery(issue, debouncedStoreQuery)) return false;
      return !issue.credential_store_id || visibleStoreIDs.has(issue.credential_store_id);
    }),
    [allIssues, debouncedStoreQuery, visibleStoreIDs],
  );
  const allBindings = useMemo(() => flattenBindings(visibleStores), [visibleStores]);
  const boundedBindings = useMemo(() => grcBoundedRows({ rows: allBindings, limit: GRC_DETAIL_LIMIT }), [allBindings]);
  const bindings = boundedBindings.rows;
  const totals = useMemo(() => credentialStoreUsageTotals(stores), [stores]);
  const loading = storesQuery.loading && !storesQuery.data;
  const runtimeState = runtimeStateForError(storesQuery.error);
  const metricState: RuntimeState = storesQuery.error ? runtimeState : loading ? "loading" : "ready";
  const filterChips = [
    { label: "Tenant", value: tenantID, onClear: () => setTenantID("") },
    { label: "Search", value: storeQuery, onClear: () => setStoreQuery("") },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        contractId="credential-stores"
        title="Credential stores"
        description="Review store readiness, runtime bindings, credential records, and backend setup issues."
        action={
          <div className="flex flex-wrap gap-2">
            <Link href={`/connectors${debouncedTenantID ? `?tenant_id=${encodeURIComponent(debouncedTenantID)}&tab=available` : "?tab=available"}`} className="secondary-button inline-flex items-center gap-2 px-3 py-2 text-[13px]">
              <CheckCircle2 className="h-4 w-4" />
              Connect source
            </Link>
            <button type="button" onClick={() => void storesQuery.reload()} className="primary-button inline-flex items-center gap-2 px-3 py-2 text-[13px]">
              <RefreshCw className="h-4 w-4" />
              Refresh
            </button>
          </div>
        }
      />

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Stores in use" value={totals.storesInUse} detail={`${totals.readyStores} ready`} intent={totals.storesInUse > 0 ? "success" : "neutral"} state={metricState} />
        <MetricCard label="Runtime bindings" value={totals.bindings} detail={`${totals.fieldReferences} field references`} intent={totals.bindings > 0 ? "success" : "neutral"} state={metricState} />
        <MetricCard label="Credential records" value={totals.credentials} detail={storesQuery.data?.credential_store_status || "unknown"} state={metricState} />
        <MetricCard label="Open issues" value={totals.issues} detail={totals.issues === 1 ? "issue needs action" : "issues need action"} intent={totals.issues > 0 ? "warning" : "success"} state={metricState} />
      </div>

      <section className="surface-panel p-4">
        <div className="grid gap-3 md:grid-cols-[minmax(160px,0.75fr)_minmax(220px,1.25fr)]">
          <label className={labelClass}>Tenant<input value={tenantID} onChange={(event) => setTenantID(event.target.value)} placeholder="All tenants" className={inputClass} /></label>
          <label className={labelClass}>
            Search stores, runtimes, fields
            <div className="relative mt-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--text-muted)]" />
              <input
                value={storeQuery}
                onChange={(event) => setStoreQuery(event.target.value)}
                placeholder="Store, runtime, credential, field"
                className="control-input w-full px-9 py-2 text-[13px]"
              />
            </div>
          </label>
        </div>
        <AppliedFilterChips filters={filterChips} onClearAll={() => { setTenantID(""); setStoreQuery(""); }} />
      </section>

      {loading && <LoadingBlock label="Loading credential stores..." />}
      {storesQuery.error && <ErrorBlock error={storesQuery.error} onRetry={() => void storesQuery.reload()} recoveryDetail="Credential store data appears when /credential-stores is reachable." />}

      <Panel
        title="Store Health"
        action={<span className="text-[12px] text-[var(--text-muted)]">{visibleStores.length} stores</span>}
      >
        <StoreTable stores={visibleStores} />
      </Panel>

      <Panel
        title="Open Issues"
        action={<span className="text-[12px] text-[var(--text-muted)]">{issues.length} issues</span>}
      >
        <IssueTable issues={issues} />
      </Panel>

      <Panel
        title="Runtime Bindings"
        action={<span className="text-[12px] text-[var(--text-muted)]">{bindings.length} shown</span>}
      >
        <ResultLimitNotice className="mb-3" loaded={bindings.length} meta={boundedBindings.meta} limit={GRC_DETAIL_LIMIT} noun="runtime bindings" />
        <BindingTable bindings={bindings} />
      </Panel>

      {stores.some((store) => (store.store.setup_steps ?? []).length > 0) && (
        <Panel title="Backend Setup">
          <div className="grid gap-3 lg:grid-cols-2">
            {visibleStores.filter((store) => (store.store.setup_steps ?? []).length > 0 || (store.store.required_config ?? []).length > 0).map((item) => (
              <section key={item.store.id} className="rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h2 className="text-[13px] font-semibold text-[var(--text-primary)]">{item.store.label}</h2>
                  <Badge value={item.health.status} />
                </div>
                {(item.store.required_config ?? []).length > 0 && (
                  <div className="mt-3">
                    <div className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">Config</div>
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {(item.store.required_config ?? []).map((field) => (
                        <code key={field.env || field.label} className="rounded bg-[var(--surface)] px-1.5 py-0.5 text-[11px] text-[var(--text-secondary)]">
                          {field.env || field.label}
                        </code>
                      ))}
                    </div>
                  </div>
                )}
                {(item.store.setup_steps ?? []).length > 0 && (
                  <div className="mt-3 space-y-2">
                    <div className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">Steps</div>
                    {(item.store.setup_steps ?? []).slice(0, 3).map((step) => (
                      <div key={step.id || step.label} className="text-[12px] leading-5 text-[var(--text-secondary)]">
                        <span className="font-semibold text-[var(--text-primary)]">{step.label}</span>
                        {step.description && <span> / {step.description}</span>}
                        {step.command && <code className="mt-1 block overflow-x-auto rounded bg-[var(--surface)] px-2 py-1 text-[11px]">{step.command}</code>}
                      </div>
                    ))}
                  </div>
                )}
              </section>
            ))}
          </div>
        </Panel>
      )}
    </div>
  );
}
