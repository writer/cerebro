"use client";

import { useCallback, useEffect, useState } from "react";
import { RefreshCw, RotateCcw, ShieldCheck, Trash2 } from "lucide-react";

import { Badge, ErrorBlock } from "@/components/grc/Primitives";
import { fetchCerebro } from "@/lib/cerebro-client";
import type {
  ConnectorCatalogEntry,
  ConnectorConnectionMethod,
  ConnectorCredential,
  ConnectorCredentialBrokerResponse,
  ConnectorCredentialKey,
  ConnectorCredentialListResponse,
  ConnectorField,
  NormalizedCredentialStore,
} from "@/lib/connectors";
import {
  connectorCredentialErrorMessage,
  connectorCredentialHealth,
  connectorCredentialRevokePath,
  connectorCredentialRotatePath,
  connectorCredentialsPath,
  connectorCredentialStatusLabel,
  encryptConnectorCredentials,
} from "@/lib/connectors";

const credentialActionID = () =>
  globalThis.crypto?.randomUUID?.() ?? `credential-${Date.now()}-${Math.random().toString(36).slice(2)}`;

const shortCredentialID = (id: string) => {
  if (id.length <= 16) return id;
  return `${id.slice(0, 10)}...${id.slice(-5)}`;
};

const credentialTimestamp = (value?: string) => {
  if (!value) return "Never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(date);
};

const credentialHealthClass: Record<string, string> = {
  healthy: "border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-500/25 dark:bg-emerald-500/10 dark:text-emerald-100",
  warning: "border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-500/25 dark:bg-amber-500/10 dark:text-amber-100",
  bad: "border-red-200 bg-red-50 text-red-800 dark:border-red-500/25 dark:bg-red-500/10 dark:text-red-100",
  unknown: "border-[color:var(--border)] bg-[var(--surface-muted)] text-[var(--text-secondary)]",
};

export default function CredentialBrokerPanel({
  connector,
  method,
  store,
  tenantID,
  runtimeID,
  apiKey,
}: {
  connector: ConnectorCatalogEntry;
  method?: ConnectorConnectionMethod;
  store?: NormalizedCredentialStore;
  tenantID: string;
  runtimeID: string;
  apiKey?: string;
}) {
  const credentialFields = method?.credential_fields ?? [];
  const [credentials, setCredentials] = useState<ConnectorCredential[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [action, setAction] = useState<"store" | "rotate" | "revoke" | null>(null);
  const [selectedCredentialID, setSelectedCredentialID] = useState("");
  const [credentialValues, setCredentialValues] = useState<Record<string, string>>({});
  const [references, setReferences] = useState<Record<string, string>>({});
  const enabled = Boolean(method?.id === "encrypted_submission" && store?.id === "cerebro_vault" && store.available && tenantID.trim() && runtimeID.trim());
  const selectedCredential = credentials.find((credential) => credential.id === selectedCredentialID) ?? credentials[0];
  const fields: ConnectorField[] = credentialFields.length > 0
    ? credentialFields
    : (selectedCredential?.fields ?? []).map((field) => ({ key: field, label: field, type: "password" as const, required: true, secret: true }));
  const activeCredentials = credentials.filter((credential) => credential.status !== "revoked");
  const fieldValuesReady = fields.length > 0 && fields.every((field) => !field.required || credentialValues[field.key]?.trim());

  const loadCredentials = useCallback(async () => {
    if (!enabled) {
      setCredentials([]);
      setSelectedCredentialID("");
      return;
    }
    setLoading(true);
    setError(null);
    const response = await fetchCerebro<ConnectorCredentialListResponse>(
      connectorCredentialsPath(connector.source_id, { tenantID, runtimeID }),
      apiKey,
    );
    setLoading(false);
    if (!response.ok) {
      setError(connectorCredentialErrorMessage(response.status));
      return;
    }
    const nextCredentials = response.data.credentials ?? [];
    setCredentials(nextCredentials);
    setSelectedCredentialID((current) => current || nextCredentials[0]?.id || "");
  }, [apiKey, connector.source_id, enabled, runtimeID, tenantID]);

  useEffect(() => {
    const timer = window.setTimeout(() => void loadCredentials(), 0);
    return () => window.clearTimeout(timer);
  }, [loadCredentials]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setCredentialValues({});
      setReferences({});
    }, 0);
    return () => window.clearTimeout(timer);
  }, [connector.source_id, runtimeID, tenantID]);

  if (method?.id !== "encrypted_submission") {
    return null;
  }

  const updateCredentialValue = (field: string, value: string) => {
    setCredentialValues((current) => ({ ...current, [field]: value }));
  };

  const clearCredentialValues = () => {
    setCredentialValues({});
  };

  const submitCredential = async (mode: "store" | "rotate") => {
    if (!enabled || !store || fields.length === 0) return;
    if (mode === "rotate" && !selectedCredential) return;
    setAction(mode);
    setError(null);
    setReferences({});
    try {
      const plainFields: Record<string, string> = {};
      fields.forEach((field) => {
        const value = credentialValues[field.key]?.trim();
        if (value) plainFields[field.key] = value;
      });
      const keyResponse = await fetchCerebro<ConnectorCredentialKey>("/connectors/credential-key", apiKey);
      if (!keyResponse.ok) throw new Error(connectorCredentialErrorMessage(keyResponse.status));
      const encrypted = await encryptConnectorCredentials(keyResponse.data, plainFields, {
        sourceID: connector.source_id,
        tenantID,
        runtimeID,
        credentialStoreID: store.id,
      });
      const path = mode === "rotate" && selectedCredential
        ? connectorCredentialRotatePath(connector.source_id, selectedCredential.id)
        : connectorCredentialsPath(connector.source_id);
      const response = await fetchCerebro<ConnectorCredentialBrokerResponse>(path, apiKey, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "Idempotency-Key": credentialActionID(),
        },
        body: JSON.stringify({
          tenant_id: tenantID,
          runtime_id: runtimeID,
          credential_store_id: store.id,
          revoke_previous: mode === "rotate",
          encrypted_credentials: encrypted,
        }),
      });
      if (!response.ok) throw new Error(connectorCredentialErrorMessage(response.status));
      setReferences(response.data.credential_references ?? {});
      clearCredentialValues();
      await loadCredentials();
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : connectorCredentialErrorMessage());
    } finally {
      setAction(null);
    }
  };

  const revokeCredential = async (credential: ConnectorCredential) => {
    setAction("revoke");
    setError(null);
    setReferences({});
    try {
      const response = await fetchCerebro(connectorCredentialRevokePath(connector.source_id, credential.id), apiKey, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ reason: "operator requested" }),
      });
      if (!response.ok) throw new Error(connectorCredentialErrorMessage(response.status));
      await loadCredentials();
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : connectorCredentialErrorMessage());
    } finally {
      setAction(null);
    }
  };

  return (
    <div className="mt-4 rounded-lg border border-[color:var(--border)] bg-[var(--surface)]">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-[color:var(--border)] bg-[var(--surface-muted)] px-4 py-3">
        <div>
          <div className="flex items-center gap-2 text-[13px] font-semibold text-[var(--text-primary)]">
            <ShieldCheck className="h-4 w-4 text-[var(--text-muted)]" />
            Credential broker
          </div>
          <div className="mt-1 text-[12px] text-[var(--text-muted)]">{runtimeID || "Connection ID required"}</div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Badge value={store?.available ? "broker ready" : "broker unavailable"} />
          <button type="button" onClick={() => void loadCredentials()} disabled={!enabled || loading} className="secondary-button inline-flex items-center gap-1.5 px-2.5 py-1.5 text-[12px] disabled:cursor-not-allowed disabled:opacity-50">
            <RefreshCw className="h-3.5 w-3.5" />
            Refresh
          </button>
        </div>
      </div>

      <div className="grid gap-4 p-4 xl:grid-cols-[minmax(0,1fr)_minmax(280px,0.62fr)]">
        <div className="min-w-0">
          {!enabled && (
            <div className="rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2 text-[12px] text-[var(--text-muted)]">
              Select a credential vault, tenant, and connection ID to manage stored credentials.
            </div>
          )}
          {error && <div className="mb-3"><ErrorBlock error={error} /></div>}
          {enabled && loading && <div className="rounded-md bg-[var(--surface-muted)] px-3 py-2 text-[12px] text-[var(--text-muted)]">Loading credentials...</div>}
          {enabled && !loading && credentials.length === 0 && (
            <div className="rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-3 text-[12px] text-[var(--text-muted)]">
              No stored credentials for this connection.
            </div>
          )}
          {credentials.length > 0 && (
            <div className="grid gap-2">
              {credentials.map((credential) => {
                const health = connectorCredentialHealth(credential);
                const selected = selectedCredential?.id === credential.id;
                return (
                  <button
                    key={credential.id}
                    type="button"
                    onClick={() => setSelectedCredentialID(credential.id)}
                    className={`w-full rounded-lg border p-3 text-left transition ${
                      selected
                        ? "border-[var(--primary)] bg-[var(--primary-soft)]"
                        : "border-[color:var(--border)] bg-[var(--surface-raised)] hover:border-[color:var(--border-strong)]"
                    }`}
                  >
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono text-[12px] font-semibold text-[var(--text-primary)]">{shortCredentialID(credential.id)}</span>
                          <span className={`rounded-md border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${credentialHealthClass[health]}`}>
                            {connectorCredentialStatusLabel(credential.status)}
                          </span>
                        </div>
                        <div className="mt-1 flex flex-wrap gap-1.5">
                          {credential.fields.map((field) => (
                            <span key={field} className="rounded bg-[var(--surface-muted)] px-1.5 py-0.5 text-[11px] text-[var(--text-secondary)]">{field}</span>
                          ))}
                        </div>
                      </div>
                      <div className="text-right text-[11px] leading-4 text-[var(--text-muted)]">
                        <div>Used {credentialTimestamp(credential.last_used_at)}</div>
                        <div>Updated {credentialTimestamp(credential.updated_at)}</div>
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] p-3">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="text-[13px] font-semibold text-[var(--text-primary)]">
                {activeCredentials.length > 0 ? "Replace credential" : "Store credential"}
              </div>
              <div className="mt-1 text-[12px] text-[var(--text-muted)]">{store?.label ?? "Managed credential vault"}</div>
            </div>
            {selectedCredential && <Badge value={connectorCredentialStatusLabel(selectedCredential.status)} />}
          </div>

          <div className="mt-3 grid gap-2">
            {fields.map((field) => (
              <label key={field.key} className="text-[11px] font-semibold text-[var(--text-muted)]">
                {field.label || field.key}
                <input
                  type={field.type === "password" || field.secret ? "password" : "text"}
                  value={credentialValues[field.key] ?? ""}
                  onChange={(event) => updateCredentialValue(field.key, event.target.value)}
                  required={field.required}
                  placeholder={field.placeholder || field.key}
                  className="control-input mt-1 w-full px-3 py-2 text-[13px]"
                />
              </label>
            ))}
          </div>

          <div className="mt-3 flex flex-wrap gap-2">
            <button
              type="button"
              disabled={!enabled || !fieldValuesReady || action !== null}
              onClick={() => void submitCredential(activeCredentials.length > 0 ? "rotate" : "store")}
              className="primary-button inline-flex items-center gap-2 px-3 py-2 text-[13px] disabled:cursor-not-allowed disabled:opacity-50"
            >
              <RotateCcw className="h-4 w-4" />
              {action === "store" || action === "rotate" ? "Saving..." : activeCredentials.length > 0 ? "Rotate" : "Store"}
            </button>
            {selectedCredential && selectedCredential.status !== "revoked" && (
              <button
                type="button"
                disabled={action !== null}
                onClick={() => void revokeCredential(selectedCredential)}
                className="secondary-button inline-flex items-center gap-2 px-3 py-2 text-[13px] disabled:cursor-not-allowed disabled:opacity-50"
              >
                <Trash2 className="h-4 w-4" />
                {action === "revoke" ? "Revoking..." : "Revoke"}
              </button>
            )}
          </div>

          {Object.keys(references).length > 0 && (
            <div className="mt-3 rounded-md border border-[color:var(--border)] bg-[var(--surface)] p-3">
              <div className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">References</div>
              <div className="mt-2 grid gap-1.5">
                {Object.entries(references).map(([field, reference]) => (
                  <div key={field} className="flex min-w-0 items-center gap-2 rounded bg-[var(--surface-muted)] px-2 py-1.5">
                    <span className="shrink-0 text-[11px] font-semibold text-[var(--text-muted)]">{field}</span>
                    <code className="min-w-0 flex-1 truncate font-mono text-[11px] text-[var(--text-secondary)]">{reference}</code>
                    <button type="button" onClick={() => void navigator.clipboard?.writeText(reference)} className="text-[11px] font-semibold text-[var(--primary)]">
                      Copy
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
