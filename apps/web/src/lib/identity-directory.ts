import { asRecord, withQuery } from "@/lib/cerebro-data";

export type IdentityListMeta = {
  limit: number;
  loaded: number;
  configured: number;
  persisted: number;
};

export type IdentityOrganization = {
  org_id: string;
  tenant_id: string;
  name: string;
  slug?: string;
  domain?: string;
  provider?: string;
  source: string;
  external_id?: string;
  user_count: number;
  last_synced_at?: string;
  created_at?: string;
  updated_at?: string;
};

export type IdentityUser = {
  user_id: string;
  tenant_id: string;
  org_id?: string;
  subject?: string;
  email?: string;
  display_name: string;
  status: string;
  provider?: string;
  source: string;
  roles: string[];
  groups: string[];
  last_seen_at?: string;
  last_synced_at?: string;
  created_at?: string;
  updated_at?: string;
};

export type IdentityOrganizationListResponse = {
  tenant_id?: string;
  organizations: IdentityOrganization[];
  meta: IdentityListMeta;
};

export type IdentityUserListResponse = {
  tenant_id?: string;
  org_id?: string;
  users: IdentityUser[];
  meta: IdentityListMeta;
};

export type IdentityDirectoryParams = {
  tenantID?: string;
  orgID?: string;
  provider?: string;
  source?: string;
  status?: string;
  query?: string;
  limit?: number;
};

export type IdentityOrganizationSort = "name" | "users" | "last_synced" | "source";
export type IdentityUserSort = "last_seen" | "name" | "status" | "source";

const defaultMeta: IdentityListMeta = {
  limit: 100,
  loaded: 0,
  configured: 0,
  persisted: 0,
};

const cleanString = (value: unknown) => (typeof value === "string" ? value.trim() : "");

const optionalString = (value: unknown) => {
  const cleaned = cleanString(value);
  return cleaned || undefined;
};

const cleanNumber = (value: unknown, fallback = 0) => {
  if (typeof value === "number" && Number.isFinite(value)) {
    return Math.max(0, Math.round(value));
  }
  if (typeof value === "string" && value.trim()) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) {
      return Math.max(0, Math.round(parsed));
    }
  }
  return fallback;
};

const cleanStringList = (value: unknown) => {
  if (!Array.isArray(value)) return [];
  return Array.from(new Set(value.map((item) => cleanString(item)).filter(Boolean)));
};

const textSortValue = (value?: string) => value?.trim().toLowerCase() ?? "";

const timestampSortValue = (value?: string) => {
  const parsed = Date.parse(value ?? "");
  return Number.isFinite(parsed) ? parsed : 0;
};

const compareText = (left?: string, right?: string) => {
  const normalizedLeft = textSortValue(left);
  const normalizedRight = textSortValue(right);
  if (normalizedLeft < normalizedRight) return -1;
  if (normalizedLeft > normalizedRight) return 1;
  return 0;
};

const compareRecent = (left?: string, right?: string) => timestampSortValue(right) - timestampSortValue(left);

const organizationSorts: IdentityOrganizationSort[] = ["name", "users", "last_synced", "source"];
const userSorts: IdentityUserSort[] = ["last_seen", "name", "status", "source"];

export const normalizeIdentityOrganizationSort = (value?: string): IdentityOrganizationSort => {
  const normalized = value?.trim() as IdentityOrganizationSort | undefined;
  return normalized && organizationSorts.includes(normalized) ? normalized : "name";
};

export const normalizeIdentityUserSort = (value?: string): IdentityUserSort => {
  const normalized = value?.trim() as IdentityUserSort | undefined;
  return normalized && userSorts.includes(normalized) ? normalized : "last_seen";
};

const normalizeMeta = (value: unknown): IdentityListMeta => {
  const record = asRecord(value);
  if (!record) return defaultMeta;
  return {
    limit: cleanNumber(record.limit, defaultMeta.limit),
    loaded: cleanNumber(record.loaded),
    configured: cleanNumber(record.configured),
    persisted: cleanNumber(record.persisted),
  };
};

const normalizeOrganization = (value: unknown): IdentityOrganization | null => {
  const record = asRecord(value);
  if (!record) return null;
  const orgID = cleanString(record.org_id);
  const tenantID = cleanString(record.tenant_id);
  const name = cleanString(record.name) || orgID || tenantID;
  if (!orgID || !tenantID || !name) return null;
  return {
    org_id: orgID,
    tenant_id: tenantID,
    name,
    slug: optionalString(record.slug),
    domain: optionalString(record.domain),
    provider: optionalString(record.provider),
    source: cleanString(record.source) || "identity_directory",
    external_id: optionalString(record.external_id),
    user_count: cleanNumber(record.user_count),
    last_synced_at: optionalString(record.last_synced_at),
    created_at: optionalString(record.created_at),
    updated_at: optionalString(record.updated_at),
  };
};

const normalizeUser = (value: unknown): IdentityUser | null => {
  const record = asRecord(value);
  if (!record) return null;
  const userID = cleanString(record.user_id);
  const tenantID = cleanString(record.tenant_id);
  const displayName = cleanString(record.display_name) || cleanString(record.email) || userID;
  if (!userID || !tenantID || !displayName) return null;
  return {
    user_id: userID,
    tenant_id: tenantID,
    org_id: optionalString(record.org_id),
    subject: optionalString(record.subject),
    email: optionalString(record.email),
    display_name: displayName,
    status: cleanString(record.status) || "active",
    provider: optionalString(record.provider),
    source: cleanString(record.source) || "identity_directory",
    roles: cleanStringList(record.roles),
    groups: cleanStringList(record.groups),
    last_seen_at: optionalString(record.last_seen_at),
    last_synced_at: optionalString(record.last_synced_at),
    created_at: optionalString(record.created_at),
    updated_at: optionalString(record.updated_at),
  };
};

export const normalizeIdentityOrganizationsResponse = (value: unknown): IdentityOrganizationListResponse => {
  const record = asRecord(value);
  const organizations = Array.isArray(record?.organizations)
    ? record.organizations.map(normalizeOrganization).filter((item): item is IdentityOrganization => Boolean(item))
    : [];
  return {
    tenant_id: optionalString(record?.tenant_id),
    organizations,
    meta: normalizeMeta(record?.meta),
  };
};

export const normalizeIdentityUsersResponse = (value: unknown): IdentityUserListResponse => {
  const record = asRecord(value);
  const users = Array.isArray(record?.users)
    ? record.users.map(normalizeUser).filter((item): item is IdentityUser => Boolean(item))
    : [];
  return {
    tenant_id: optionalString(record?.tenant_id),
    org_id: optionalString(record?.org_id),
    users,
    meta: normalizeMeta(record?.meta),
  };
};

const organizationTieBreak = (left: IdentityOrganization, right: IdentityOrganization) =>
  compareText(left.name, right.name) || compareText(left.org_id, right.org_id) || compareText(left.tenant_id, right.tenant_id);

const userTieBreak = (left: IdentityUser, right: IdentityUser) =>
  compareText(left.display_name, right.display_name) || compareText(left.email || left.subject || left.user_id, right.email || right.subject || right.user_id);

export const sortIdentityOrganizations = (organizations: IdentityOrganization[], sort?: string) => {
  const normalizedSort = normalizeIdentityOrganizationSort(sort);
  return [...organizations].sort((left, right) => {
    switch (normalizedSort) {
      case "users":
        return right.user_count - left.user_count || organizationTieBreak(left, right);
      case "last_synced":
        return compareRecent(left.last_synced_at || left.updated_at || left.created_at, right.last_synced_at || right.updated_at || right.created_at) || organizationTieBreak(left, right);
      case "source":
        return compareText(left.provider, right.provider) || compareText(left.source, right.source) || organizationTieBreak(left, right);
      case "name":
      default:
        return organizationTieBreak(left, right);
    }
  });
};

export const sortIdentityUsers = (users: IdentityUser[], sort?: string) => {
  const normalizedSort = normalizeIdentityUserSort(sort);
  return [...users].sort((left, right) => {
    switch (normalizedSort) {
      case "name":
        return userTieBreak(left, right);
      case "status":
        return compareText(left.status, right.status) || userTieBreak(left, right);
      case "source":
        return compareText(left.provider, right.provider) || compareText(left.source, right.source) || userTieBreak(left, right);
      case "last_seen":
      default:
        return compareRecent(left.last_seen_at || left.last_synced_at || left.updated_at || left.created_at, right.last_seen_at || right.last_synced_at || right.updated_at || right.created_at) || userTieBreak(left, right);
    }
  });
};

const pathParams = ({ tenantID, orgID, provider, source, status, query, limit }: IdentityDirectoryParams) => ({
  tenant_id: tenantID?.trim() ?? "",
  org_id: orgID?.trim() ?? "",
  provider: provider?.trim() ?? "",
  source: source?.trim() ?? "",
  status: status?.trim() ?? "",
  q: query?.trim() ?? "",
  limit: typeof limit === "number" && Number.isFinite(limit) ? Math.max(1, Math.round(limit)) : "",
});

export const identityOrganizationsPath = (params: IdentityDirectoryParams = {}) =>
  withQuery("/identity/orgs", { ...pathParams(params), status: "" });

export const identityUsersPath = (params: IdentityDirectoryParams = {}) =>
  withQuery("/identity/users", pathParams(params));

export const identitySourceLabel = (value?: string) => {
  switch (value?.trim()) {
    case "api_key":
      return "API key";
    case "api_credential":
      return "API credential";
    case "auth_config":
      return "Auth config";
    case "mcp_oauth":
      return "OAuth";
    case "mcp_oauth_client":
      return "OAuth client";
    case "mcp_oauth_entitlement":
      return "OAuth entitlement";
    case "identity_directory":
      return "Directory";
    default:
      return value?.trim() || "Unknown";
  }
};

export const identityProviderLabel = (value?: string) => {
  switch (value?.trim().toLowerCase()) {
    case "okta":
      return "Okta";
    case "oidc":
      return "OIDC";
    default:
      return value?.trim() || "Unknown";
  }
};
