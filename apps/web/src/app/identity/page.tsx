"use client";

import { useMemo, type ReactNode } from "react";
import { Building2, RefreshCw, Search, ShieldCheck, UsersRound } from "lucide-react";

import { AppliedFilterChips, Badge, EmptyBlock, ErrorBlock, LoadingBlock, MetricCard, PageHeader, Panel, ResultLimitNotice } from "@/components/grc/Primitives";
import { displayDate } from "@/lib/grc";
import { useDebouncedValue, useGRCQuery } from "@/lib/grc-client";
import { GRC_WORKLIST_LIMIT, grcBoundedRows } from "@/lib/grc-list";
import {
  identityOrganizationsPath,
  identityProviderLabel,
  identitySourceLabel,
  identityUsersPath,
  normalizeIdentityOrganizationSort,
  normalizeIdentityOrganizationsResponse,
  normalizeIdentityUserSort,
  normalizeIdentityUsersResponse,
  sortIdentityOrganizations,
  sortIdentityUsers,
  type IdentityOrganization,
  type IdentityOrganizationSort,
  type IdentityOrganizationListResponse,
  type IdentityUser,
  type IdentityUserSort,
  type IdentityUserListResponse,
} from "@/lib/identity-directory";
import { useQueryParamState } from "@/lib/query-params";
import { runtimeStateForError, type RuntimeState } from "@/lib/runtime-state";

type IdentityTab = "orgs" | "users";

const inputClass = "control-input mt-1 w-full px-3 py-2 text-[13px]";
const selectClass = "control-input mt-1 w-full px-3 py-2 text-[13px]";
const sortSelectClass = "control-input h-8 min-w-[9rem] px-2 text-[12px]";
const labelClass = "text-[11px] font-semibold text-[var(--text-muted)]";

const tabLabels: Record<IdentityTab, string> = {
  orgs: "Organizations",
  users: "Users",
};

const providerOptions = [
  { value: "", label: "All providers" },
  { value: "okta", label: "Okta" },
  { value: "oidc", label: "OIDC" },
];

const sourceOptions = [
  { value: "", label: "All sources" },
  { value: "mcp_oauth", label: "OAuth" },
  { value: "mcp_oauth_client", label: "OAuth client" },
  { value: "mcp_oauth_entitlement", label: "OAuth entitlement" },
  { value: "api_key", label: "API key" },
  { value: "api_credential", label: "API credential" },
  { value: "auth_config", label: "Auth config" },
  { value: "identity_directory", label: "Directory" },
];

const statusOptions = [
  { value: "", label: "All user statuses" },
  { value: "active", label: "Active" },
  { value: "inactive", label: "Inactive" },
  { value: "suspended", label: "Suspended" },
  { value: "disabled", label: "Disabled" },
];

const orgSortOptions: Array<{ value: IdentityOrganizationSort; label: string }> = [
  { value: "name", label: "Name" },
  { value: "users", label: "Most users" },
  { value: "last_synced", label: "Newest sync" },
  { value: "source", label: "Source" },
];

const userSortOptions: Array<{ value: IdentityUserSort; label: string }> = [
  { value: "last_seen", label: "Last seen" },
  { value: "name", label: "Name" },
  { value: "status", label: "Status" },
  { value: "source", label: "Source" },
];

const optionLabel = (options: Array<{ value: string; label: string }>, value: string) =>
  options.find((option) => option.value === value)?.label ?? value;

const identityMetaTotal = (meta: { configured: number; loaded: number; persisted: number }) =>
  Math.max(meta.loaded, meta.configured + meta.persisted);

function isOAuthRecord(item: { provider?: string; source?: string }) {
  const provider = item.provider?.trim().toLowerCase();
  const source = item.source?.trim();
  return provider === "okta" || provider === "oidc" || source === "mcp_oauth" || source === "mcp_oauth_entitlement" || source === "mcp_oauth_client";
}

function ProviderPill({ provider }: { provider?: string }) {
  if (!provider?.trim()) return <span className="text-[12px] text-[var(--text-muted)]">No provider</span>;
  return (
    <span className="inline-flex rounded-md bg-blue-50 px-2 py-0.5 text-[11px] font-semibold text-blue-800 dark:bg-blue-500/15 dark:text-blue-100">
      {identityProviderLabel(provider)}
    </span>
  );
}

function SourcePill({ source }: { source?: string }) {
  return (
    <span className="inline-flex rounded-md bg-[var(--surface-muted)] px-2 py-0.5 text-[11px] font-semibold text-[var(--text-secondary)]">
      {identitySourceLabel(source)}
    </span>
  );
}

function ChipList({ values, emptyLabel }: { values: string[]; emptyLabel: string }) {
  if (values.length === 0) {
    return <span className="text-[12px] text-[var(--text-muted)]">{emptyLabel}</span>;
  }
  return (
    <div className="flex max-w-md flex-wrap gap-1.5">
      {values.slice(0, 4).map((value) => (
        <span key={value} className="rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-2 py-0.5 text-[11px] font-medium text-[var(--text-secondary)]">
          {value}
        </span>
      ))}
      {values.length > 4 && (
        <span className="rounded-md bg-[var(--surface-muted)] px-2 py-0.5 text-[11px] font-medium text-[var(--text-muted)]">
          +{values.length - 4}
        </span>
      )}
    </div>
  );
}

function TabButton({
  active,
  children,
  count,
  icon,
  onClick,
}: {
  active: boolean;
  children: ReactNode;
  count: number;
  icon: ReactNode;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`inline-flex h-10 items-center gap-2 rounded-md border px-3 text-[13px] font-semibold transition ${
        active
          ? "border-[color:var(--border-strong)] bg-[var(--text-primary)] text-[var(--surface)]"
          : "border-[color:var(--border)] bg-[var(--surface)] text-[var(--text-secondary)] hover:border-[color:var(--border-strong)] hover:bg-[var(--surface-hover)]"
      }`}
    >
      {icon}
      <span>{children}</span>
      <span className={`rounded bg-current/10 px-1.5 py-0.5 text-[11px] ${active ? "text-[var(--surface)]" : "text-[var(--text-muted)]"}`}>{count}</span>
    </button>
  );
}

function SortControl<T extends string>({
  ariaLabel,
  onChange,
  options,
  value,
}: {
  ariaLabel: string;
  onChange: (value: T) => void;
  options: Array<{ value: T; label: string }>;
  value: T;
}) {
  return (
    <label className="flex items-center gap-2 text-[12px] font-medium text-[var(--text-muted)]">
      <span>Sort</span>
      <select aria-label={ariaLabel} value={value} onChange={(event) => onChange(event.target.value as T)} className={sortSelectClass}>
        {options.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
      </select>
    </label>
  );
}

function OrganizationsTable({
  onViewUsers,
  organizations,
}: {
  onViewUsers: (org: IdentityOrganization) => void;
  organizations: IdentityOrganization[];
}) {
  if (organizations.length === 0) {
    return <EmptyBlock label="No identity organizations match these filters." />;
  }

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-[color:var(--border)] text-left text-[13px]">
        <thead className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">
          <tr>
            <th className="py-2 pr-4">Organization</th>
            <th className="px-4 py-2">Tenant</th>
            <th className="px-4 py-2">Source</th>
            <th className="px-4 py-2 text-right">Users</th>
            <th className="px-4 py-2">Last synced</th>
            <th className="py-2 pl-4 text-right">Action</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[color:var(--border)]">
          {organizations.map((org) => (
            <tr key={`${org.tenant_id}:${org.org_id}`} className="align-top">
              <td className="py-3 pr-4">
                <div className="font-semibold text-[var(--text-primary)]">{org.name}</div>
                <div className="mt-1 max-w-sm truncate text-[12px] text-[var(--text-muted)]">
                  {org.domain || org.external_id || org.slug || "No external record"}
                </div>
              </td>
              <td className="px-4 py-3">
                <div className="font-mono text-[12px] text-[var(--text-secondary)]">{org.tenant_id}</div>
                {org.org_id !== org.tenant_id && <div className="mt-1 font-mono text-[11px] text-[var(--text-muted)]">{org.org_id}</div>}
              </td>
              <td className="px-4 py-3">
                <div className="flex flex-wrap gap-1.5">
                  <ProviderPill provider={org.provider} />
                  <SourcePill source={org.source} />
                </div>
              </td>
              <td className="px-4 py-3 text-right font-semibold text-[var(--text-primary)]">{org.user_count}</td>
              <td className="px-4 py-3 text-[12px] text-[var(--text-secondary)]">{displayDate(org.last_synced_at || org.updated_at || org.created_at)}</td>
              <td className="py-3 pl-4 text-right">
                <button type="button" onClick={() => onViewUsers(org)} className="secondary-button inline-flex items-center gap-1.5 px-2.5 py-1.5 text-[12px]">
                  <UsersRound className="h-3.5 w-3.5" />
                  View users
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function UsersTable({ users }: { users: IdentityUser[] }) {
  if (users.length === 0) {
    return <EmptyBlock label="No identity users match these filters." />;
  }

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-[color:var(--border)] text-left text-[13px]">
        <thead className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">
          <tr>
            <th className="py-2 pr-4">User</th>
            <th className="px-4 py-2">Organization</th>
            <th className="px-4 py-2">Status</th>
            <th className="px-4 py-2">Grants</th>
            <th className="px-4 py-2">Source</th>
            <th className="py-2 pl-4">Last seen</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[color:var(--border)]">
          {users.map((user) => (
            <tr key={`${user.tenant_id}:${user.user_id}`} className="align-top">
              <td className="py-3 pr-4">
                <div className="font-semibold text-[var(--text-primary)]">{user.display_name}</div>
                <div className="mt-1 max-w-xs truncate text-[12px] text-[var(--text-muted)]">
                  {user.email || user.subject || user.user_id}
                </div>
              </td>
              <td className="px-4 py-3">
                <div className="font-mono text-[12px] text-[var(--text-secondary)]">{user.org_id || user.tenant_id}</div>
                <div className="mt-1 font-mono text-[11px] text-[var(--text-muted)]">{user.tenant_id}</div>
              </td>
              <td className="px-4 py-3">
                <div className="flex flex-wrap gap-1.5">
                  <Badge value={user.status} />
                  <ProviderPill provider={user.provider} />
                </div>
              </td>
              <td className="px-4 py-3">
                <div className="space-y-2">
                  <ChipList values={user.roles} emptyLabel="No roles" />
                  <ChipList values={user.groups} emptyLabel="No groups" />
                </div>
              </td>
              <td className="px-4 py-3"><SourcePill source={user.source} /></td>
              <td className="py-3 pl-4 text-[12px] text-[var(--text-secondary)]">{displayDate(user.last_seen_at || user.last_synced_at || user.updated_at || user.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function IdentityPage() {
  const [tenantID, setTenantID] = useQueryParamState("tenant_id");
  const [orgID, setOrgID] = useQueryParamState("org_id");
  const [provider, setProvider] = useQueryParamState("provider");
  const [source, setSource] = useQueryParamState("source");
  const [status, setStatus] = useQueryParamState("status");
  const [query, setQuery] = useQueryParamState("q");
  const [view, setView] = useQueryParamState("view", "orgs");
  const [orgSortParam, setOrgSort] = useQueryParamState("org_sort", "name");
  const [userSortParam, setUserSort] = useQueryParamState("user_sort", "last_seen");
  const activeTab: IdentityTab = view === "users" ? "users" : "orgs";
  const orgSort = normalizeIdentityOrganizationSort(orgSortParam);
  const userSort = normalizeIdentityUserSort(userSortParam);
  const debouncedTenantID = useDebouncedValue(tenantID.trim());
  const debouncedOrgID = useDebouncedValue(orgID.trim());
  const debouncedProvider = useDebouncedValue(provider.trim());
  const debouncedSource = useDebouncedValue(source.trim());
  const debouncedStatus = useDebouncedValue(status.trim());
  const debouncedQuery = useDebouncedValue(query.trim());

  const orgsQuery = useGRCQuery<IdentityOrganizationListResponse>(identityOrganizationsPath({
    tenantID: debouncedTenantID,
    orgID: debouncedOrgID,
    provider: debouncedProvider,
    source: debouncedSource,
    query: debouncedQuery,
    limit: GRC_WORKLIST_LIMIT,
  }));
  const usersQuery = useGRCQuery<IdentityUserListResponse>(identityUsersPath({
    tenantID: debouncedTenantID,
    orgID: debouncedOrgID,
    provider: debouncedProvider,
    source: debouncedSource,
    status: debouncedStatus,
    query: debouncedQuery,
    limit: GRC_WORKLIST_LIMIT,
  }));

  const orgsResponse = useMemo(() => normalizeIdentityOrganizationsResponse(orgsQuery.data), [orgsQuery.data]);
  const usersResponse = useMemo(() => normalizeIdentityUsersResponse(usersQuery.data), [usersQuery.data]);
  const boundedOrganizationRows = useMemo(
    () => grcBoundedRows({ rows: orgsResponse.organizations, limit: GRC_WORKLIST_LIMIT, total: identityMetaTotal(orgsResponse.meta) }),
    [orgsResponse.meta, orgsResponse.organizations],
  );
  const boundedUserRows = useMemo(
    () => grcBoundedRows({ rows: usersResponse.users, limit: GRC_WORKLIST_LIMIT, total: identityMetaTotal(usersResponse.meta) }),
    [usersResponse.meta, usersResponse.users],
  );
  const organizations = boundedOrganizationRows.rows;
  const users = boundedUserRows.rows;
  const sortedOrganizations = useMemo(() => sortIdentityOrganizations(organizations, orgSort), [organizations, orgSort]);
  const sortedUsers = useMemo(() => sortIdentityUsers(users, userSort), [users, userSort]);
  const loading = (orgsQuery.loading && !orgsQuery.data) || (usersQuery.loading && !usersQuery.data);
  const error = orgsQuery.error || usersQuery.error;
  const runtimeState: RuntimeState = error ? runtimeStateForError(error) : loading ? "loading" : "ready";
  const oauthOrgCount = organizations.filter(isOAuthRecord).length;
  const oktaUserCount = users.filter((user) => user.provider?.trim().toLowerCase() === "okta").length;
  const storedUserCount = users.filter((user) => user.source === "mcp_oauth" || Boolean(user.last_seen_at)).length;
  const filterChips = [
    { label: "Tenant", value: tenantID, onClear: () => setTenantID("") },
    { label: "Organization", value: orgID, onClear: () => setOrgID("") },
    { label: "Provider", value: provider ? identityProviderLabel(provider) : "", onClear: () => setProvider("") },
    { label: "Source", value: source ? identitySourceLabel(source) : "", onClear: () => setSource("") },
    { label: "User status", value: status ? optionLabel(statusOptions, status) : "", onClear: () => setStatus("") },
    { label: "Search", value: query, onClear: () => setQuery("") },
  ];

  const reload = () => {
    void orgsQuery.reload();
    void usersQuery.reload();
  };

  const showOrgUsers = (org: IdentityOrganization) => {
    setTenantID(org.tenant_id);
    setOrgID(org.org_id);
    setView("users");
  };

  return (
    <div className="space-y-6">
      <PageHeader
        contractId="identity-directory"
        title="Members"
        description="Organizations and users from auth configuration and OAuth login history."
        action={
          <button type="button" onClick={reload} className="primary-button inline-flex items-center gap-2 px-3 py-2 text-[13px]">
            <RefreshCw className="h-4 w-4" />
            Refresh
          </button>
        }
      />

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Organizations" value={organizations.length} detail={`${orgsResponse.meta.configured} configured, ${orgsResponse.meta.persisted} stored`} intent={organizations.length > 0 ? "success" : "warning"} state={runtimeState} />
        <MetricCard label="Users" value={users.length} detail={`${usersResponse.meta.configured} configured, ${usersResponse.meta.persisted} stored`} intent={users.length > 0 ? "success" : "warning"} state={runtimeState} />
        <MetricCard label="OAuth orgs" value={oauthOrgCount} detail="provider-linked organizations" intent={oauthOrgCount > 0 ? "success" : "neutral"} state={runtimeState} />
        <MetricCard label="Okta users" value={oktaUserCount} detail={`${storedUserCount} stored login records`} intent={oktaUserCount > 0 ? "success" : "neutral"} state={runtimeState} />
      </div>

      <section className="surface-panel p-4">
        <div className="grid gap-3 lg:grid-cols-3 xl:grid-cols-[minmax(150px,0.75fr)_minmax(150px,0.75fr)_minmax(150px,0.75fr)_minmax(160px,0.8fr)_minmax(150px,0.75fr)_minmax(240px,1.5fr)]">
          <label className={labelClass}>Tenant<input value={tenantID} onChange={(event) => setTenantID(event.target.value)} placeholder="All tenants" className={inputClass} /></label>
          <label className={labelClass}>Organization<input value={orgID} onChange={(event) => setOrgID(event.target.value)} placeholder="All organizations" className={inputClass} /></label>
          <label className={labelClass}>
            Provider
            <select value={provider} onChange={(event) => setProvider(event.target.value)} className={selectClass}>
              {providerOptions.map((option) => <option key={option.value || "all"} value={option.value}>{option.label}</option>)}
            </select>
          </label>
          <label className={labelClass}>
            Source
            <select value={source} onChange={(event) => setSource(event.target.value)} className={selectClass}>
              {sourceOptions.map((option) => <option key={option.value || "all"} value={option.value}>{option.label}</option>)}
            </select>
          </label>
          <label className={labelClass}>
            User status
            <select value={status} onChange={(event) => setStatus(event.target.value)} className={selectClass}>
              {statusOptions.map((option) => <option key={option.value || "all"} value={option.value}>{option.label}</option>)}
            </select>
          </label>
          <label className={labelClass}>
            Search members
            <div className="relative mt-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--text-muted)]" />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="User, email, organization, provider"
                className="control-input w-full px-9 py-2 text-[13px]"
              />
            </div>
          </label>
        </div>
        <AppliedFilterChips filters={filterChips} onClearAll={() => { setTenantID(""); setOrgID(""); setProvider(""); setSource(""); setStatus(""); setQuery(""); }} />
      </section>

      <div className="flex flex-wrap gap-2">
        <TabButton active={activeTab === "orgs"} count={organizations.length} icon={<Building2 className="h-4 w-4" />} onClick={() => setView("orgs")}>
          {tabLabels.orgs}
        </TabButton>
        <TabButton active={activeTab === "users"} count={users.length} icon={<UsersRound className="h-4 w-4" />} onClick={() => setView("users")}>
          {tabLabels.users}
        </TabButton>
      </div>

      {loading && <LoadingBlock label="Loading member directory..." />}
      {error && <ErrorBlock error={error} onRetry={reload} recoveryDetail="Member data will appear when the Cerebro API can list organizations and users." />}

      <Panel
        title={tabLabels[activeTab]}
        action={
          <div className="flex flex-wrap items-center justify-end gap-3">
            {activeTab === "orgs" ? (
              <SortControl ariaLabel="Sort organizations" options={orgSortOptions} value={orgSort} onChange={(nextSort) => setOrgSort(nextSort)} />
            ) : (
              <SortControl ariaLabel="Sort users" options={userSortOptions} value={userSort} onChange={(nextSort) => setUserSort(nextSort)} />
            )}
            <span className="inline-flex items-center gap-1.5 text-[12px] text-[var(--text-muted)]">
              <ShieldCheck className="h-3.5 w-3.5" />
              {activeTab === "orgs" ? organizations.length : users.length} shown
            </span>
          </div>
        }
      >
        <ResultLimitNotice
          className="mb-3"
          loaded={activeTab === "orgs" ? organizations.length : users.length}
          meta={activeTab === "orgs" ? boundedOrganizationRows.meta : boundedUserRows.meta}
          limit={GRC_WORKLIST_LIMIT}
          noun={activeTab === "orgs" ? "organizations" : "users"}
        />
        {activeTab === "orgs" ? <OrganizationsTable organizations={sortedOrganizations} onViewUsers={showOrgUsers} /> : <UsersTable users={sortedUsers} />}
      </Panel>
    </div>
  );
}
