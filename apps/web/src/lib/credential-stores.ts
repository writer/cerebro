import type {
  ConnectorCredentialStore,
  ConnectorCredentialStoreID,
  ConnectorCredentialStoreMode,
} from "@/lib/connectors";

export type CredentialStoreHealthStatus =
  | "ready"
  | "in_use"
  | "warning"
  | "needs_attention"
  | "needs_configuration"
  | "unavailable"
  | string;

export type CredentialStoreHealth = {
  status: CredentialStoreHealthStatus;
  severity?: "success" | "warning" | "error" | string;
  detail?: string;
  next_action?: string;
};

export type CredentialStoreUsage = {
  connections: number;
  credentials: number;
  bindings: number;
  field_references: number;
  issues: number;
  last_updated_at?: string;
};

export type CredentialStoreBinding = {
  id: string;
  credential_store_id: ConnectorCredentialStoreID | string;
  source_id?: string;
  source_name?: string;
  runtime_id?: string;
  tenant_id?: string;
  auth_method?: string;
  resolver?: string;
  credential_id?: string;
  credential_status?: string;
  connection_status?: string;
  next_action?: string;
  fields?: string[];
  field_count?: number;
  reference_prefixes?: string[];
  updated_at?: string;
  last_used_at?: string;
  last_validated_at?: string;
};

export type CredentialStoreIssue = {
  id: string;
  credential_store_id?: ConnectorCredentialStoreID | string;
  source_id?: string;
  runtime_id?: string;
  credential_id?: string;
  field?: string;
  status: "blocked" | "warning" | string;
  severity: "error" | "warning" | string;
  detail: string;
  next_action?: string;
};

export type CredentialStoreMetadata = ConnectorCredentialStore & {
  id: ConnectorCredentialStoreID | string;
  label: string;
  provider: string;
  available: boolean;
  mode: ConnectorCredentialStoreMode | string;
};

export type CredentialStoreOperational = {
  store: CredentialStoreMetadata;
  health: CredentialStoreHealth;
  usage: CredentialStoreUsage;
  bindings?: CredentialStoreBinding[];
  issues?: CredentialStoreIssue[];
};

export type CredentialStoreListResponse = {
  generated_at: string;
  tenant_id?: string;
  runtime_store_status: "ready" | "unavailable" | string;
  credential_store_status: "ready" | "unavailable" | string;
  stores: CredentialStoreOperational[];
  issues?: CredentialStoreIssue[];
};

export type CredentialStoreUsageTotals = {
  storesInUse: number;
  readyStores: number;
  credentials: number;
  bindings: number;
  fieldReferences: number;
  issues: number;
};

export function credentialStoreUsageTotals(stores: CredentialStoreOperational[]): CredentialStoreUsageTotals {
  return stores.reduce<CredentialStoreUsageTotals>((totals, item) => {
    totals.readyStores += item.store.available ? 1 : 0;
    totals.storesInUse += item.usage.connections > 0 || item.usage.credentials > 0 ? 1 : 0;
    totals.credentials += item.usage.credentials;
    totals.bindings += item.usage.bindings;
    totals.fieldReferences += item.usage.field_references;
    totals.issues += item.usage.issues;
    return totals;
  }, { storesInUse: 0, readyStores: 0, credentials: 0, bindings: 0, fieldReferences: 0, issues: 0 });
}

export function credentialStoreIntent(status?: string): "neutral" | "danger" | "warning" | "success" {
  switch ((status || "").toLowerCase()) {
    case "in_use":
    case "ready":
      return "success";
    case "needs_attention":
    case "blocked":
    case "unavailable":
      return "danger";
    case "warning":
    case "needs_configuration":
      return "warning";
    default:
      return "neutral";
  }
}

export function credentialStoreActionLabel(action?: string) {
  switch ((action || "").trim()) {
    case "configure_store":
      return "Configure store";
    case "connect_source":
      return "Connect source";
    case "fix_credential_reference":
      return "Fix reference";
    case "fix_credential_store_issues":
      return "Fix issues";
    case "monitor_rotation":
      return "Monitor rotation";
    case "replace_with_credential_reference":
      return "Replace value";
    case "review_credential_store_warnings":
      return "Review warnings";
    case "rotate_credential":
      return "Rotate credential";
    case "run_connector_preflight":
      return "Run preflight";
    case "run_source_check":
      return "Run check";
    default:
      return action ? action.replaceAll("_", " ") : "Review";
  }
}

export function credentialStoreModeLabel(mode?: string) {
  if (mode === "encrypted_submission") return "Encrypted submission";
  if (mode === "environment_managed") return "Environment managed";
  return "Reference";
}

export function credentialStoreResolverLabel(resolver?: string) {
  switch ((resolver || "").trim()) {
    case "cerebro_vault":
      return "Cerebro Vault";
    case "environment":
      return "Environment";
    case "environment_projection":
      return "Environment projection";
    case "native":
      return "Native resolver";
    case "native_reference":
      return "Native reference";
    default:
      return resolver ? resolver.replaceAll("_", " ") : "Not bound";
  }
}

export function credentialStoreMatchesQuery(item: CredentialStoreOperational, query: string) {
  const normalized = query.trim().toLowerCase();
  if (!normalized) return true;
  const values = [
    item.store.id,
    item.store.label,
    item.store.provider,
    item.store.mode,
    item.store.status,
    item.store.detail,
    item.health.status,
    item.health.detail,
    item.health.next_action,
    ...(item.store.reference_prefixes ?? []),
    ...(item.bindings ?? []).flatMap((binding) => [
      binding.source_id,
      binding.source_name,
      binding.runtime_id,
      binding.tenant_id,
      binding.auth_method,
      binding.resolver,
      binding.credential_id,
      binding.credential_status,
      ...(binding.fields ?? []),
      ...(binding.reference_prefixes ?? []),
    ]),
    ...(item.issues ?? []).flatMap((issue) => [
      issue.source_id,
      issue.runtime_id,
      issue.credential_id,
      issue.field,
      issue.detail,
      issue.next_action,
    ]),
  ];
  return values.filter(Boolean).some((value) => String(value).toLowerCase().includes(normalized));
}

export function credentialStoreIssueMatchesQuery(issue: CredentialStoreIssue, query: string) {
  const normalized = query.trim().toLowerCase();
  if (!normalized) return true;
  return [
    issue.credential_store_id,
    issue.source_id,
    issue.runtime_id,
    issue.credential_id,
    issue.field,
    issue.detail,
    issue.next_action,
    issue.status,
    issue.severity,
  ].filter(Boolean).some((value) => String(value).toLowerCase().includes(normalized));
}
