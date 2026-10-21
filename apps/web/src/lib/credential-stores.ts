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

export type SourceCredentialState = "failing" | "attention" | "ok";

export type SourceCredentialHealth = {
  state: SourceCredentialState;
  stores: string[];
  lastValidatedAt?: string;
  detail?: string;
  issues: number;
  // True when every binding points at a secret Cerebro does not hold, such as
  // an environment variable, so there is no stored credential to call valid.
  referenceOnly: boolean;
};

const failingCredentialStatuses = new Set(["invalid", "revoked"]);
const pendingCredentialStatuses = new Set(["pending", "rotating"]);
const credentialStateRank: Record<SourceCredentialState, number> = { ok: 0, attention: 1, failing: 2 };

// Only issues tied to a source count against it. Store-level issues, such as an
// optional resolver nobody has configured, are not a problem with any integration.
export function sourceCredentialHealth(response?: CredentialStoreListResponse | null): Map<string, SourceCredentialHealth> {
  const health = new Map<string, SourceCredentialHealth>();
  if (!response) return health;

  const entryFor = (sourceID: string) => {
    let entry = health.get(sourceID);
    if (!entry) {
      entry = { issues: 0, referenceOnly: true, state: "ok", stores: [] };
      health.set(sourceID, entry);
    }
    return entry;
  };
  const raise = (entry: SourceCredentialHealth, state: SourceCredentialState, detail?: string) => {
    if (credentialStateRank[state] > credentialStateRank[entry.state]) {
      entry.state = state;
      entry.detail = detail || entry.detail;
    } else if (state === entry.state && !entry.detail) {
      entry.detail = detail;
    }
  };

  for (const item of response.stores ?? []) {
    for (const binding of item.bindings ?? []) {
      if (!binding.source_id) continue;
      const entry = entryFor(binding.source_id);
      if (!entry.stores.includes(item.store.label)) entry.stores.push(item.store.label);
      if (binding.credential_id) entry.referenceOnly = false;
      if (binding.last_validated_at && (!entry.lastValidatedAt || binding.last_validated_at < entry.lastValidatedAt)) {
        entry.lastValidatedAt = binding.last_validated_at;
      }
      const status = (binding.credential_status || "").toLowerCase();
      if (failingCredentialStatuses.has(status)) raise(entry, "failing", `Credential is ${status}.`);
      else if (pendingCredentialStatuses.has(status)) raise(entry, "attention", `Credential is ${status}.`);
    }
  }

  const issues = [...(response.issues ?? []), ...(response.stores ?? []).flatMap((item) => item.issues ?? [])];
  const seen = new Set<string>();
  for (const issue of issues) {
    if (!issue.source_id || seen.has(issue.id)) continue;
    seen.add(issue.id);
    const entry = entryFor(issue.source_id);
    entry.issues += 1;
    raise(entry, issue.severity === "error" || issue.status === "blocked" ? "failing" : "attention", issue.detail);
  }

  return health;
}
