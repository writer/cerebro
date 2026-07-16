"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useMemo, useState } from "react";
import {
  ArrowLeft,
  ArrowRight,
  Bot,
  CheckCircle2,
  CircleAlert,
  DatabaseZap,
  FileJson2,
  KeyRound,
  Lock,
  Plus,
  Save,
  Search,
  ShieldCheck,
  Trash2,
} from "lucide-react";

import { useApiKey } from "@/components/providers";
import { AppliedFilterChips, Badge, EmptyBlock, ErrorBlock, LoadingBlock, MetricCard, PageHeader, Panel } from "@/components/grc/Primitives";
import { fetchCerebro } from "@/lib/cerebro-client";
import { withQuery } from "@/lib/cerebro-data";
import {
  ConnectorDefinition,
  ConnectorDefinitionListResponse,
  ConnectorDefinitionPreviewResponse,
  ConnectorDefinitionPromotionResponse,
  ConnectorDefinitionResponse,
  ConnectorDefinitionResourceFamily,
  ConnectorDefinitionTransport,
  ConnectorDefinitionValidationResponse,
  ConnectorLibraryResponse,
  connectorDefinitionBlockingChecks,
  connectorDefinitionNextStage,
  connectorDefinitionStageDescription,
  connectorDefinitionStageLabels,
  connectorDefinitionStages,
  connectorDefinitionStatus,
  connectorDefinitionValidationLabel,
  defaultConnectorDefinitionDraft,
  normalizeConnectorDefinitionID,
  normalizeCredentialStores,
  sourceActivationPlanPath,
} from "@/lib/connectors";
import { useGRCQuery } from "@/lib/grc-client";
import { displayDate } from "@/lib/grc";
import type { RuntimeState } from "@/lib/runtime-state";

const inputClass = "control-input mt-1 w-full px-3 py-2 text-[13px]";
const labelClass = "text-[11px] font-semibold text-[var(--text-muted)]";

const authModels = [
  { id: "bearer_token", label: "Bearer token" },
  { id: "api_key", label: "API key" },
  { id: "basic", label: "Basic auth" },
  { id: "oauth_client_credentials", label: "OAuth client credentials" },
  { id: "none", label: "No auth" },
];

function stageLabel(stage?: string) {
  return connectorDefinitionStageLabels[stage as keyof typeof connectorDefinitionStageLabels] ?? stage ?? "Draft";
}

function StageRail({ definition }: { definition: ConnectorDefinition }) {
  const currentIndex = Math.max(0, connectorDefinitionStages.indexOf(definition.stage as (typeof connectorDefinitionStages)[number]));
  return (
    <div className="grid gap-2 md:grid-cols-5">
      {connectorDefinitionStages.map((stage, index) => {
        const active = index === currentIndex;
        const complete = index < currentIndex;
        return (
          <div
            key={stage}
            className={`rounded-lg border p-3 ${
              active
                ? "border-[color:var(--ring)] bg-[var(--primary-soft)]"
                : complete
                  ? "border-emerald-200 bg-emerald-50 dark:border-emerald-500/25 dark:bg-emerald-500/10"
                  : "border-[color:var(--border)] bg-[var(--surface)]"
            }`}
          >
            <div className="flex items-center justify-between gap-2">
              <div className="text-[12px] font-semibold text-[var(--text-primary)]">{stageLabel(stage)}</div>
              {complete ? <CheckCircle2 className="h-4 w-4 text-emerald-600" /> : <span className="h-2 w-2 rounded-full bg-[var(--border-strong)]" />}
            </div>
            <p className="mt-2 text-[11px] leading-4 text-[var(--text-muted)]">{connectorDefinitionStageDescription[stage]}</p>
          </div>
        );
      })}
    </div>
  );
}

function DefinitionList({
  definitions,
  selectedID,
  onLoad,
}: {
  definitions: ConnectorDefinition[];
  selectedID?: string;
  onLoad: (definition: ConnectorDefinition) => void;
}) {
  return (
    <Panel title="Custom library" action={<span className="text-[12px] text-[var(--text-muted)]">{definitions.length} definitions</span>}>
      <div className="space-y-2">
        {definitions.map((definition) => (
          <button
            key={definition.id ?? definition.source_id}
            type="button"
            onClick={() => onLoad(definition)}
            className={`w-full rounded-lg border p-3 text-left transition ${
              selectedID && selectedID === definition.id
                ? "border-[color:var(--ring)] bg-[var(--surface-hover)]"
                : "border-[color:var(--border)] bg-[var(--surface)] hover:border-[color:var(--border-strong)]"
            }`}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="truncate text-[13px] font-semibold text-[var(--text-primary)]">{definition.display_name}</div>
                <div className="mt-1 text-[11px] text-[var(--text-muted)]">{definition.source_id} · v{definition.current_version ?? 0}</div>
              </div>
              <Badge value={definition.stage || "draft"} />
            </div>
            <div className="mt-3 flex items-center justify-between gap-3 text-[11px] text-[var(--text-muted)]">
              <span>{definition.resource_families?.length ?? 0} resource types</span>
              <span>{definition.updated_at ? displayDate(definition.updated_at) : "Not saved"}</span>
            </div>
          </button>
        ))}
        {definitions.length === 0 && <EmptyBlock label="No custom connector definitions for this tenant." />}
      </div>
    </Panel>
  );
}

function CheckList({ definition }: { definition: ConnectorDefinition }) {
  const checks = definition.validation?.checks ?? [];
  return (
    <Panel title="Validation gates" action={<Badge value={connectorDefinitionStatus(definition)} />}>
      <div className="space-y-2">
        {checks.map((check) => (
          <div key={check.id} className="flex items-start gap-3 rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-3">
            {check.blocking || check.status === "blocked"
              ? <CircleAlert className="mt-0.5 h-4 w-4 shrink-0 text-red-500" />
              : <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600" />}
            <div className="min-w-0">
              <div className="text-[13px] font-semibold text-[var(--text-primary)]">{check.label}</div>
              <div className="mt-1 text-[12px] leading-5 text-[var(--text-muted)]">{check.detail || check.next_action || connectorDefinitionValidationLabel(check.status)}</div>
            </div>
          </div>
        ))}
        {checks.length === 0 && <EmptyBlock label="Run validation to populate connector gates." />}
      </div>
    </Panel>
  );
}

function FamilyEditor({
  families,
  ingestMode,
  onChange,
}: {
  families: ConnectorDefinitionResourceFamily[];
  ingestMode?: string;
  onChange: (families: ConnectorDefinitionResourceFamily[]) => void;
}) {
  const depositMode = ingestMode === "deposit";
  const updateFamily = (index: number, patch: Partial<ConnectorDefinitionResourceFamily>) => {
    onChange(families.map((family, current) => current === index ? { ...family, ...patch } : family));
  };
  const updateFamilyEvent = (index: number, patch: NonNullable<ConnectorDefinitionResourceFamily["event"]>) => {
    const current = families[index]?.event ?? {};
    updateFamily(index, { event: { ...current, ...patch } });
  };
  const updateFamilyProjection = (index: number, patch: NonNullable<ConnectorDefinitionResourceFamily["projection"]>) => {
    const current = families[index]?.projection ?? {};
    updateFamily(index, { projection: { ...current, ...patch } });
  };
  const addFamily = () => {
    const nextIndex = families.length + 1;
    onChange([...families, {
      id: `resource_${nextIndex}`,
      label: `Resource ${nextIndex}`,
      path: depositMode ? "" : `/v1/resources/${nextIndex}`,
      method: "GET",
      list_key: "items",
      id_field: "id",
      name_field: "name",
      default_enabled: true,
    }]);
  };
  const removeFamily = (index: number) => {
    onChange(families.filter((_, current) => current !== index));
  };

  return (
    <Panel title="Resource types" action={<button type="button" onClick={addFamily} className="secondary-button inline-flex items-center gap-1.5 px-2.5 py-1.5 text-[12px]"><Plus className="h-3.5 w-3.5" />Add</button>}>
      <div className="space-y-3">
        {families.map((family, index) => (
          <div key={`${family.id}-${index}`} className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-3">
            <div className="grid gap-3 md:grid-cols-2">
              <label className={labelClass}>Resource type ID<input value={family.id} onChange={(event) => updateFamily(index, { id: normalizeConnectorDefinitionID(event.target.value) })} className={inputClass} /></label>
              <label className={labelClass}>Label<input value={family.label ?? ""} onChange={(event) => updateFamily(index, { label: event.target.value })} className={inputClass} /></label>
              <label className={labelClass}>{depositMode ? "Path (optional for deposit)" : "Path"}<input value={family.path ?? ""} onChange={(event) => updateFamily(index, { path: event.target.value })} className={inputClass} /></label>
              <label className={labelClass}>List key<input value={family.list_key ?? ""} onChange={(event) => updateFamily(index, { list_key: event.target.value })} className={inputClass} /></label>
              <label className={labelClass}>ID field<input value={family.id_field} onChange={(event) => updateFamily(index, { id_field: event.target.value })} className={inputClass} /></label>
              <label className={labelClass}>Name field<input value={family.name_field ?? ""} onChange={(event) => updateFamily(index, { name_field: event.target.value })} className={inputClass} /></label>
              <label className={labelClass}>Event kind<input value={family.event?.kind ?? ""} onChange={(event) => updateFamilyEvent(index, { kind: normalizeConnectorDefinitionID(event.target.value).replace(/-/g, "_") })} placeholder="custom_asset" className={inputClass} /></label>
              <label className={labelClass}>Schema ref<input value={family.event?.schema_ref ?? ""} onChange={(event) => updateFamilyEvent(index, { schema_ref: event.target.value })} placeholder="schemas/custom_asset.json" className={inputClass} /></label>
              <label className={labelClass}>Resource type mapping<input value={family.projection?.template ?? ""} onChange={(event) => updateFamilyProjection(index, { template: event.target.value })} placeholder="asset" className={inputClass} /></label>
            </div>
            <div className="mt-3 flex items-center justify-between gap-3 border-t border-[color:var(--border)] pt-3">
              <label className="inline-flex items-center gap-2 text-[12px] font-semibold text-[var(--text-secondary)]">
                <input
                  type="checkbox"
                  checked={Boolean(family.default_enabled)}
                  onChange={(event) => updateFamily(index, { default_enabled: event.target.checked })}
                />
                Enabled by default
              </label>
              <button type="button" onClick={() => removeFamily(index)} className="secondary-button inline-flex items-center gap-1.5 px-2.5 py-1.5 text-[12px]">
                <Trash2 className="h-3.5 w-3.5" />
                Remove
              </button>
            </div>
          </div>
        ))}
        {families.length === 0 && <EmptyBlock label="No resource types modeled." />}
      </div>
    </Panel>
  );
}

function ConnectorBuilderContent() {
  const searchParams = useSearchParams();
  const { apiKey } = useApiKey();
  const initialTenantID = searchParams.get("tenant_id") ?? "";
  const initialDefinitionID = searchParams.get("definition_id") ?? "";
  const defaultDraft = useMemo(() => defaultConnectorDefinitionDraft(initialTenantID), [initialTenantID]);
  const [draftOverride, setDraftOverride] = useState<ConnectorDefinition | null>(null);
  const [selectedDefinitionID, setSelectedDefinitionID] = useState(initialDefinitionID);
  const [message, setMessage] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [working, setWorking] = useState<"validate" | "preview" | "save" | "promote" | null>(null);
  const [previewConfig, setPreviewConfig] = useState("{}");
  const [preview, setPreview] = useState<ConnectorDefinitionPreviewResponse | null>(null);

  const detailQuery = useGRCQuery<ConnectorDefinitionResponse>(selectedDefinitionID ? `/connector-definitions/${encodeURIComponent(selectedDefinitionID)}` : null);
  const loadedDefinition = detailQuery.data?.definition;
  const draft = draftOverride ?? loadedDefinition ?? defaultDraft;
  const scopedTenantID = draft.tenant_id.trim();
  const definitionsQuery = useGRCQuery<ConnectorDefinitionListResponse>(scopedTenantID ? withQuery("/connector-definitions", { tenant_id: scopedTenantID }) : null);
  const libraryQuery = useGRCQuery<ConnectorLibraryResponse>(withQuery("/connectors", { tenant_id: scopedTenantID, view: "full", limit: 1 }));
  const definitions = useMemo(() => definitionsQuery.data?.definitions ?? [], [definitionsQuery.data?.definitions]);
  const credentialStores = normalizeCredentialStores(libraryQuery.data ?? undefined);
  const availableStores = credentialStores.filter((store) => store.available);
  const selectedStores = draft.auth.supported_store_ids ?? [];
  const selectedStoreRecords = credentialStores.filter((store) => selectedStores.includes(store.id));
  const selectedUnavailableStores = selectedStoreRecords.filter((store) => !store.available).length;
  const nextStage = connectorDefinitionNextStage(draft);
  const blockingChecks = connectorDefinitionBlockingChecks(draft);
  const tenantScoped = Boolean(scopedTenantID);
  const ingestMode = draft.ingest?.mode === "deposit" ? "deposit" : "pull";
  const runtimeState: RuntimeState = selectedDefinitionID && detailQuery.loading ? "loading" : "ready";

  const loadDefinition = (definition: ConnectorDefinition) => {
    setDraftOverride(definition);
    setSelectedDefinitionID(definition.id ?? "");
    setMessage(null);
    setSubmitError(null);
  };

  const updateDraft = (patch: Partial<ConnectorDefinition>) => {
    setDraftOverride((current) => ({ ...(current ?? draft), ...patch }));
  };

  const updateAuth = (patch: Partial<ConnectorDefinition["auth"]>) => {
    setDraftOverride((current) => {
      const base = current ?? draft;
      return { ...base, auth: { ...base.auth, ...patch } };
    });
  };

  const updateTransport = (patch: Partial<ConnectorDefinitionTransport>) => {
    setDraftOverride((current) => {
      const base = current ?? draft;
      return { ...base, transport: { ...(base.transport ?? {}), ...patch } };
    });
  };

  const updateVerification = (patch: NonNullable<ConnectorDefinitionTransport["verification"]>) => {
    setDraftOverride((current) => {
      const base = current ?? draft;
      const transport = base.transport ?? {};
      return { ...base, transport: { ...transport, verification: { ...(transport.verification ?? {}), ...patch } } };
    });
  };

  const updateIngestMode = (mode: "pull" | "deposit") => {
    setDraftOverride((current) => {
      const base = current ?? draft;
      return {
        ...base,
        ingest: {
          ...(base.ingest ?? {}),
          mode,
          deposit: mode === "deposit" ? { resource_families: base.resource_families?.map((family) => family.id) ?? [] } : undefined,
        },
      };
    });
  };

  const toggleStore = (storeID: string) => {
    const nextStores = selectedStores.includes(storeID)
      ? selectedStores.filter((id) => id !== storeID)
      : [...selectedStores, storeID];
    updateAuth({ supported_store_ids: nextStores });
  };

  const submitDefinition = async <T,>(path: string, method: string, body: unknown): Promise<T> => {
    const response = await fetchCerebro<T>(path, apiKey, {
      method,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      throw new Error(typeof response.data === "string" ? response.data : `Connector definition request failed (${response.status})`);
    }
    return response.data;
  };

  const validateDefinition = async () => {
    setWorking("validate");
    setSubmitError(null);
    try {
      const response = await submitDefinition<ConnectorDefinitionValidationResponse>("/connector-definitions/validate", "POST", draft);
      if (response.definition) {
        setDraftOverride(response.definition);
      }
      setMessage(response.validation?.summary ?? "Validation finished.");
    } catch (error) {
      setSubmitError(error instanceof Error ? error.message : "Validation failed.");
    } finally {
      setWorking(null);
    }
  };

  const previewDefinition = async () => {
    setWorking("preview");
    setSubmitError(null);
    try {
      let config: Record<string, string> = {};
      if (previewConfig.trim()) {
        const parsed = JSON.parse(previewConfig) as Record<string, unknown>;
        config = Object.fromEntries(Object.entries(parsed).map(([key, value]) => [key, String(value ?? "")]));
      }
      const response = await submitDefinition<ConnectorDefinitionPreviewResponse>("/connector-definitions/preview", "POST", {
        definition: draft,
        config,
        page_limit: 1,
      });
      if (response.definition) {
        setDraftOverride(response.definition);
      }
      setPreview(response);
      setMessage(response.status === "previewed" ? "Live preview returned sample events." : "Preview check passed.");
    } catch (error) {
      setSubmitError(error instanceof Error ? error.message : "Preview failed.");
    } finally {
      setWorking(null);
    }
  };

  const saveDefinition = async () => {
    setWorking("save");
    setSubmitError(null);
    try {
      const path = draft.id ? `/connector-definitions/${encodeURIComponent(draft.id)}` : "/connector-definitions";
      const method = draft.id ? "PUT" : "POST";
      const response = await submitDefinition<ConnectorDefinitionResponse>(path, method, draft);
      if (response.definition) {
        setDraftOverride(response.definition);
        setSelectedDefinitionID(response.definition.id ?? "");
      }
      setMessage("Connector definition saved.");
      void definitionsQuery.reload();
    } catch (error) {
      setSubmitError(error instanceof Error ? error.message : "Save failed.");
    } finally {
      setWorking(null);
    }
  };

  const promoteDefinition = async () => {
    if (!draft.id || !nextStage) return;
    setWorking("promote");
    setSubmitError(null);
    try {
      const response = await submitDefinition<ConnectorDefinitionPromotionResponse>(
        `/connector-definitions/${encodeURIComponent(draft.id)}/promote`,
        "POST",
        { target_stage: nextStage, reason: "builder promotion" },
      );
      if (response.result?.definition) {
        setDraftOverride(response.result.definition);
        setSelectedDefinitionID(response.result.definition.id ?? "");
      }
      setMessage(response.result?.next_action ?? `Promoted to ${stageLabel(nextStage)}.`);
      void definitionsQuery.reload();
    } catch (error) {
      setSubmitError(error instanceof Error ? error.message : "Promotion failed.");
    } finally {
      setWorking(null);
    }
  };

  const metricState = runtimeState;
  const validationStatus = connectorDefinitionStatus(draft);
  const resourceFamilies = draft.resource_families ?? [];
  const secretStoreDetail = selectedUnavailableStores > 0 ? `${selectedUnavailableStores} selected unavailable` : `${availableStores.length} available`;
  const secretStoreIntent = selectedStores.length > 0 && selectedUnavailableStores === 0 ? "success" : "warning";
  const filterChips = [
    { label: "Definition", value: selectedDefinitionID, onClear: () => setSelectedDefinitionID("") },
  ];

  const stageDetail = useMemo(() => {
    const stage = draft.stage as keyof typeof connectorDefinitionStageDescription;
    return connectorDefinitionStageDescription[stage] ?? "Dynamic connector definition";
  }, [draft.stage]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Connector Builder"
        description="Dynamic connector definitions, validation gates, credential-store boundaries, and staged promotion."
        action={
          <div className="flex flex-wrap gap-2">
            <Link href="/connectors" className="secondary-button inline-flex items-center gap-2 px-3 py-2 text-[13px]">
              <ArrowLeft className="h-4 w-4" />
              Library
            </Link>
            <button type="button" onClick={() => void definitionsQuery.reload()} className="secondary-button inline-flex items-center gap-2 px-3 py-2 text-[13px]">
              <Search className="h-4 w-4" />
              Refresh
            </button>
          </div>
        }
      />

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <MetricCard label="Stage" value={stageLabel(draft.stage)} detail={stageDetail} state={metricState} />
        <MetricCard label="Validation" value={connectorDefinitionValidationLabel(draft.validation?.status)} detail={`${blockingChecks} blocking gates`} intent={validationStatus === "blocked" ? "danger" : validationStatus === "warning" ? "warning" : "success"} state={metricState} />
        <MetricCard label="Resource Types" value={resourceFamilies.length} detail="custom resource types" state={metricState} />
        <MetricCard label="Credential stores" value={selectedStores.length} detail={secretStoreDetail} intent={secretStoreIntent} state={metricState} />
        <MetricCard label="Ingest" value={ingestMode === "deposit" ? "Deposit" : "Pull"} detail={ingestMode === "deposit" ? "customer-pushed records" : "scheduled runtime pull"} state={metricState} />
      </div>

      <StageRail definition={draft} />
      <AppliedFilterChips filters={filterChips} />

      {definitionsQuery.loading && !definitionsQuery.data && <LoadingBlock label="Loading connector definitions..." />}
      {definitionsQuery.error && <ErrorBlock error={definitionsQuery.error} onRetry={() => void definitionsQuery.reload()} recoveryDetail="Custom connector definitions need the dynamic connector backend." />}
      {submitError && <ErrorBlock error={submitError} recoveryDetail="Review the manifest fields and backend availability." />}
      {message && (
        <div className="rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-[13px] font-semibold text-emerald-800 dark:border-emerald-500/25 dark:bg-emerald-500/10 dark:text-emerald-100">
          {message}
        </div>
      )}

      <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,1.35fr)_minmax(340px,0.75fr)]">
        <div className="space-y-5">
          <Panel title="Definition">
            <div className="grid gap-3 md:grid-cols-2">
              <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-3 md:col-span-2">
                <div className="flex items-center justify-between gap-2">
                  <div className={labelClass}>Tenant boundary</div>
                  <Badge value={tenantScoped ? "ready" : "blocked"} />
                </div>
                <div className="mt-2 flex items-center gap-2">
                  <Lock className="h-4 w-4 shrink-0 text-[var(--primary)]" />
                  <input value={draft.tenant_id} onChange={(event) => updateDraft({ tenant_id: event.target.value, id: undefined })} placeholder="tenant-id" className={inputClass} />
                </div>
                <div className="mt-2 text-[12px] leading-5 text-[var(--text-muted)]">
                  {tenantScoped ? "Bound to this tenant and eligible to appear in that tenant's connector library." : "Enter a tenant ID before saving or connecting this custom source."}
                </div>
              </div>
              <label className={labelClass}>Source ID<input value={draft.source_id} onChange={(event) => updateDraft({ source_id: normalizeConnectorDefinitionID(event.target.value), id: undefined })} placeholder="custom_api" className={inputClass} /></label>
              <label className={labelClass}>Display name<input value={draft.display_name} onChange={(event) => updateDraft({ display_name: event.target.value })} placeholder="Custom API" className={inputClass} /></label>
              <label className={labelClass}>
                Auth model
                <select value={draft.auth.model} onChange={(event) => updateAuth({ model: event.target.value })} className={inputClass}>
                  {authModels.map((model) => <option key={model.id} value={model.id}>{model.label}</option>)}
                </select>
              </label>
              <label className={labelClass}>
                Ingest mode
                <select value={ingestMode} onChange={(event) => updateIngestMode(event.target.value === "deposit" ? "deposit" : "pull")} className={inputClass}>
                  <option value="pull">Pull from provider</option>
                  <option value="deposit">Deposit records</option>
                </select>
              </label>
              <label className={`${labelClass} md:col-span-2`}>Description<textarea value={draft.description ?? ""} onChange={(event) => updateDraft({ description: event.target.value })} rows={3} className={`${inputClass} min-h-20`} /></label>
            </div>
          </Panel>

          <Panel title={ingestMode === "deposit" ? "Deposit transport" : "Runtime transport"}>
            {ingestMode === "deposit" && (
              <div className="mb-3 rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] p-3 text-[12px] leading-5 text-[var(--text-muted)]">
                Deposit mode uses the same resource schema and resource type mapping, but records are posted into a connector-scoped inbox instead of pulled from an API. Path fields are optional for deposit-only resource types.
              </div>
            )}
            <div className="grid gap-3 md:grid-cols-2">
              <label className={`${labelClass} md:col-span-2`}>
                Base URL template
                <input value={draft.transport?.base_url ?? ""} onChange={(event) => updateTransport({ base_url: event.target.value })} placeholder="${config.base_url}" className={inputClass} />
              </label>
              <label className={labelClass}>
                Verification path
                <input value={draft.transport?.verification?.path ?? ""} onChange={(event) => updateVerification({ path: event.target.value })} placeholder="/health" className={inputClass} />
              </label>
              <label className={labelClass}>
                Expected status
                <input
                  key={(draft.transport?.verification?.expect_status ?? [200]).join(",")}
                  defaultValue={(draft.transport?.verification?.expect_status ?? [200]).join(", ")}
                  onBlur={(event) => { const parsed = event.target.value.split(",").map((value) => Number.parseInt(value.trim(), 10)).filter(Number.isFinite); updateVerification({ expect_status: parsed.length > 0 ? parsed : undefined }); }}
                  placeholder="200"
                  className={inputClass}
                />
              </label>
            </div>
          </Panel>

          <Panel title="Credential boundary">
            <div className="grid gap-3 md:grid-cols-2">
              {(credentialStores.length > 0 ? credentialStores : normalizeCredentialStores(undefined)).map((store) => {
                const checked = selectedStores.includes(store.id);
                return (
                  <button
                    key={store.id}
                    type="button"
                    onClick={() => toggleStore(store.id)}
                    className={`rounded-lg border p-3 text-left transition ${
                      checked ? "border-[color:var(--ring)] bg-[var(--primary-soft)]" : "border-[color:var(--border)] bg-[var(--surface)] hover:border-[color:var(--border-strong)]"
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="text-[13px] font-semibold text-[var(--text-primary)]">{store.label}</div>
                        <div className="mt-1 text-[11px] leading-4 text-[var(--text-muted)]">{store.detail || store.description}</div>
                      </div>
                      <Badge value={store.available ? "ready" : "not_configured"} />
                    </div>
                  </button>
                );
              })}
            </div>
          </Panel>

          <FamilyEditor families={resourceFamilies} ingestMode={ingestMode} onChange={(families) => updateDraft({ resource_families: families })} />
        </div>

        <div className="space-y-5">
          <DefinitionList definitions={definitions} selectedID={selectedDefinitionID || draft.id} onLoad={loadDefinition} />
          <CheckList definition={draft} />
          <Panel title="Live preview">
            <div className="space-y-3">
              <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-3">
                <div className="text-[12px] font-semibold text-[var(--text-primary)]">Runtime config JSON</div>
                <textarea
                  value={previewConfig}
                  onChange={(event) => setPreviewConfig(event.target.value)}
                  rows={4}
                  className={`${inputClass} font-mono`}
                  placeholder={'{"base_url":"https://api.example.com"}'}
                />
                <div className="mt-2 text-[11px] leading-4 text-[var(--text-muted)]">
                  Used only for this bounded check and sample read. Secrets should stay as credential references.
                </div>
              </div>
              <button type="button" onClick={previewDefinition} disabled={Boolean(working) || blockingChecks > 0} className="secondary-button inline-flex w-full items-center justify-center gap-2 px-3 py-2 text-[13px] disabled:cursor-not-allowed disabled:opacity-50">
                <DatabaseZap className="h-4 w-4" />
                {working === "preview" ? "Previewing..." : "Run live preview"}
              </button>
              {preview && (
                <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="text-[12px] font-semibold text-[var(--text-primary)]">Preview result</div>
                    <Badge value={preview.status ?? "checked"} />
                  </div>
                  <div className="mt-2 grid grid-cols-2 gap-2 text-[12px] text-[var(--text-muted)]">
                    <span>{preview.pages_read ?? 0} page read</span>
                    <span>{preview.events?.length ?? 0} sample events</span>
                  </div>
                  {(preview.events?.length ?? 0) > 0 && (
                    <pre className="mt-3 max-h-56 overflow-auto rounded-md bg-[var(--surface-muted)] p-3 text-[11px] leading-5 text-[var(--text-secondary)]">
                      {JSON.stringify(preview.events?.slice(0, 3), null, 2)}
                    </pre>
                  )}
                </div>
              )}
            </div>
          </Panel>
          <Panel title="Promotion">
            <div className="space-y-3">
              <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-3">
                <div className="flex items-center gap-2 text-[13px] font-semibold text-[var(--text-primary)]">
                  <ShieldCheck className="h-4 w-4 text-[var(--primary)]" />
                  {nextStage ? `Next: ${stageLabel(nextStage)}` : "Certification complete"}
                </div>
                <div className="mt-2 text-[12px] leading-5 text-[var(--text-muted)]">{draft.promotion?.next_action || "Save and validate the definition before promotion."}</div>
              </div>
              <div className="grid gap-2">
                <button type="button" onClick={validateDefinition} disabled={Boolean(working)} className="secondary-button inline-flex items-center justify-center gap-2 px-3 py-2 text-[13px] disabled:cursor-not-allowed disabled:opacity-50">
                  <FileJson2 className="h-4 w-4" />
                  {working === "validate" ? "Validating..." : "Validate"}
                </button>
                <button type="button" onClick={saveDefinition} disabled={Boolean(working) || !tenantScoped} className="primary-button inline-flex items-center justify-center gap-2 px-3 py-2 text-[13px] disabled:cursor-not-allowed disabled:opacity-50">
                  <Save className="h-4 w-4" />
                  {working === "save" ? "Saving..." : "Save definition"}
                </button>
                <button type="button" onClick={promoteDefinition} disabled={Boolean(working) || !tenantScoped || !draft.id || !nextStage || blockingChecks > 0} className="secondary-button inline-flex items-center justify-center gap-2 px-3 py-2 text-[13px] disabled:cursor-not-allowed disabled:opacity-50">
                  <ArrowRight className="h-4 w-4" />
                  {working === "promote" ? "Promoting..." : nextStage ? `Promote to ${stageLabel(nextStage)}` : "No promotion available"}
                </button>
                <Link href={sourceActivationPlanPath(draft.id, scopedTenantID)} className="secondary-button inline-flex items-center justify-center gap-2 px-3 py-2 text-[13px]">
                  <ShieldCheck className="h-4 w-4" />
                  Open activation view
                </Link>
              </div>
            </div>
          </Panel>
          <Panel title="Agent workspace">
            <div className="space-y-2 text-[12px] leading-5 text-[var(--text-muted)]">
              {[
                { icon: Bot, label: "Discovery", value: "Provider docs, API base, auth model, resources" },
                { icon: KeyRound, label: "Secrets", value: "Credential references and store policy only" },
                { icon: DatabaseZap, label: "Runtime", value: "JSON API executor with read-only resource types" },
              ].map((item) => {
                const Icon = item.icon;
                return (
                  <div key={item.label} className="flex gap-3 rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-3">
                    <Icon className="mt-0.5 h-4 w-4 shrink-0 text-[var(--primary)]" />
                    <div>
                      <div className="text-[13px] font-semibold text-[var(--text-primary)]">{item.label}</div>
                      <div>{item.value}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}

export default function ConnectorBuilderPage() {
  return (
    <Suspense fallback={<LoadingBlock label="Loading connector builder..." />}>
      <ConnectorBuilderContent />
    </Suspense>
  );
}
