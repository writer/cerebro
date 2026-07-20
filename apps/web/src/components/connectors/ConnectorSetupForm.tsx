"use client";

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { AlertCircle, ArrowRight, CheckCircle2, Circle, Clipboard, Code2, FileJson, Globe2, KeyRound, ListChecks, LockKeyhole, PackageCheck, Plus, RefreshCw, RotateCcw, Search, ShieldAlert, ShieldCheck, SlidersHorizontal, TerminalSquare, Trash2, X } from "lucide-react";

import CredentialStoreSelector from "@/components/connectors/CredentialStoreSelector";
import { Badge, ErrorBlock } from "@/components/grc/Primitives";
import { fetchCerebro } from "@/lib/cerebro-client";
import type {
  ConnectorCatalogEntry,
  ConnectorConnectedContext,
  ConnectorConnectionResponse,
  ConnectorConnectionMethod,
  ConnectorConnectionMethodID,
  ConnectorDeploymentGuide,
  ConnectorCredential,
  ConnectorCredentialBrokerResponse,
  ConnectorCredentialListResponse,
  ConnectorCredentialKey,
  ConnectorCredentialStoreID,
  ConnectorField,
  ConnectorPreflightCheck,
  ConnectorPreflightResponse,
  ConnectorProductGroup,
  ConnectorScopeOption,
  ConnectorScopeResource,
  NormalizedCredentialStore,
} from "@/lib/connectors";
import {
  connectionMethodsForConnector,
  connectorCredentialErrorMessage,
  connectorCredentialHealth,
  connectorCredentialRevokePath,
  connectorCredentialRotatePath,
  connectorCredentialsPath,
  connectorCredentialStatusLabel,
  connectorConnectedContextFromResponse,
  connectorScopeOptionFamilies,
  connectorSubmitErrorMessage,
  defaultCredentialStoreID,
  encryptConnectorCredentials,
  normalizeScopePolicy,
  scopePolicyExclusionCount,
} from "@/lib/connectors";
import {
  connectorScopeOptionMatchesFrameworkSegment,
  frameworkOptionLabel,
  supportedGRCFrameworkNames,
} from "@/lib/grc-frameworks";

const labelClass = "text-[11px] font-semibold text-[var(--text-muted)]";
const inputClass = "control-input mt-1 w-full px-3 py-2 text-[13px]";

const readField = (formData: FormData, key: string) => String(formData.get(key) ?? "").trim();
const credentialInputName = (key: string) => `credential:${key}`;
const splitScopeValues = (value: string) => value.split(/[,\n]/).map((item) => item.trim()).filter(Boolean);
const normalizeFamily = (family: string) => family.trim().toLowerCase();

function productGroupDefaultExcludedFamilies(method?: ConnectorConnectionMethod) {
  const families = new Set<string>();
  (method?.product_groups ?? []).forEach((group) => {
    if (group.required || group.default_enabled) return;
    (group.families ?? []).forEach((family) => {
      const normalized = normalizeFamily(family);
      if (normalized) families.add(normalized);
    });
  });
  return Array.from(families).sort();
}

function productGroupRequiredFamilies(method?: ConnectorConnectionMethod) {
  const families = new Set<string>();
  (method?.product_groups ?? []).forEach((group) => {
    if (!group.required) return;
    (group.families ?? []).forEach((family) => {
      const normalized = normalizeFamily(family);
      if (normalized) families.add(normalized);
    });
  });
  return families;
}

function clearCredentialInputs(form: HTMLFormElement, fields: ConnectorField[]) {
  fields.forEach((field) => {
    const element = form.elements.namedItem(credentialInputName(field.key));
    if (element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement) {
      element.value = "";
    }
  });
}

function storeMatchesMethod(store: NormalizedCredentialStore, method: ConnectorConnectionMethod) {
  if (method.credential_stores?.includes(store.id)) return true;
  if (method.id === "encrypted_submission") return store.mode === "encrypted_submission";
  if (method.id === "external_reference") return store.mode === "reference";
  return store.mode === "environment_managed";
}

function storesForMethod(method: ConnectorConnectionMethod | undefined, stores: NormalizedCredentialStore[]) {
  if (!method) return stores;
  return stores.filter((store) => storeMatchesMethod(store, method));
}

function defaultStoreForMethod(method: ConnectorConnectionMethod | undefined, stores: NormalizedCredentialStore[]) {
  const methodStores = storesForMethod(method, stores);
  return defaultCredentialStoreID(methodStores.length > 0 ? methodStores : stores);
}

function MethodTabs({
  methods,
  selectedID,
  onSelect,
}: {
  methods: ConnectorConnectionMethod[];
  selectedID: ConnectorConnectionMethodID;
  onSelect: (id: ConnectorConnectionMethodID) => void;
}) {
  const availableMethods = methods.filter((method) => method.status !== "unavailable" && method.saveable !== false);
  const unavailableMethods = methods.filter((method) => method.status === "unavailable" || method.saveable === false);
  return (
    <div className="space-y-3">
      <div className="grid min-w-0 gap-3 md:grid-cols-2 xl:grid-cols-4">
        {availableMethods.map((method) => {
          const active = method.id === selectedID;
          return (
            <button
              key={method.id}
              type="button"
              onClick={() => onSelect(method.id)}
              className={`group min-h-0 w-full min-w-0 rounded-lg border p-3 text-left transition md:min-h-[154px] md:p-4 ${
                active
                  ? "border-[var(--primary)] bg-[var(--primary-soft)] shadow-[var(--shadow-sm)]"
                  : "border-[color:var(--border)] bg-[var(--surface-raised)] hover:border-[color:var(--border-strong)] hover:bg-[var(--surface-hover)]"
              }`}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <div className="text-[14px] font-semibold text-[var(--text-primary)]">{method.label || method.shortLabel}</div>
                    {method.recommended && <span className="rounded bg-emerald-50 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-emerald-700 ring-1 ring-emerald-200 dark:bg-emerald-500/15 dark:text-emerald-100 dark:ring-emerald-500/25">Recommended</span>}
                  </div>
                  <div className="mt-1 text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">{method.category}</div>
                </div>
                {active ? <CheckCircle2 className="h-4 w-4 text-[var(--primary)]" /> : <Circle className="h-4 w-4 text-[var(--text-muted)] group-hover:text-[var(--text-secondary)]" />}
              </div>
              <div className="mt-2 max-h-[4.75rem] overflow-hidden break-words text-[12px] leading-5 text-[var(--text-muted)] sm:max-h-none md:mt-3">{method.description}</div>
              <div className="mt-3 flex flex-wrap gap-1.5 md:mt-4">
                <Badge value={method.id === "encrypted_submission" ? "encrypted" : "reference"} />
                {method.product_groups.length > 0 && <Badge value={`${method.product_groups.length} groups`} />}
              </div>
            </button>
          );
        })}
      </div>
      {unavailableMethods.length > 0 && (
        <details className="rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2">
          <summary className="cursor-pointer text-[12px] font-semibold text-[var(--text-secondary)]">
            {unavailableMethods.length} unavailable method{unavailableMethods.length === 1 ? "" : "s"}
          </summary>
          <div className="mt-3 grid gap-2 md:grid-cols-2">
            {unavailableMethods.map((method) => (
              <div key={method.id} className="rounded-md border border-[color:var(--border)] bg-[var(--surface)] p-3 opacity-75">
                <div className="flex items-center justify-between gap-3">
                  <div className="text-[12px] font-semibold text-[var(--text-primary)]">{method.shortLabel}</div>
                  <Badge value="blocked" />
                </div>
                <div className="mt-1 text-[11px] leading-4 text-[var(--text-muted)]">{method.disabledReason || method.unavailable_reason || method.label}</div>
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}

function SetupStep({
  index,
  title,
  icon,
  children,
}: {
  index: number;
  title: string;
  icon: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="min-w-0 rounded-lg border border-[color:var(--border)] bg-[var(--surface-raised)] p-4">
      <div className="mb-3 flex items-center gap-2">
        <span className="flex h-7 w-7 items-center justify-center rounded-full bg-[var(--primary-soft)] text-[12px] font-semibold text-[var(--primary)]">
          {index}
        </span>
        <span className="text-[var(--text-muted)]">{icon}</span>
        <h3 className="text-[13px] font-semibold text-[var(--text-primary)]">{title}</h3>
      </div>
      {children}
    </section>
  );
}

function StepRail({ method, storeLabel }: { method?: ConnectorConnectionMethod; storeLabel?: string }) {
  const setupSteps = [
    ["Method", method?.label || method?.shortLabel || "Choose auth"],
    ["Identity", "Tenant and connection ID"],
    ["Store", storeLabel || "Choose store"],
    ["Config", "Source settings"],
    ["Collected resources", "Collection exclusions"],
    ["Validate", "Test before saving"],
  ];
  return (
    <div className="hidden rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] p-3 text-[12px] xl:block">
      <div className="mb-3 text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Connection flow</div>
      <ol className="space-y-3">
        {setupSteps.map(([label, detail], index) => (
          <li key={label} className="flex gap-2">
            <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-[color:var(--border)] bg-[var(--surface)] text-[10px] font-semibold text-[var(--text-secondary)]">
              {index + 1}
            </span>
            <span>
              <span className="block font-semibold text-[var(--text-primary)]">{label}</span>
              <span className="block text-[11px] leading-4 text-[var(--text-muted)]">{detail}</span>
            </span>
          </li>
        ))}
      </ol>
    </div>
  );
}

function CommandBlock({ commands }: { commands: string[] }) {
  const [copied, setCopied] = useState<string | null>(null);
  if (commands.length === 0) return null;

  return (
    <div className="space-y-2">
      {commands.map((command) => (
        <div key={command} className="flex items-center gap-2 rounded-lg border border-[color:var(--border)] bg-zinc-950 px-3 py-2 text-zinc-100 dark:bg-black">
          <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap font-mono text-[12px]">{command}</code>
          <button
            type="button"
            onClick={() => {
              void navigator.clipboard.writeText(command).then(() => setCopied(command));
            }}
            className="secondary-button inline-flex shrink-0 items-center gap-1.5 px-2 py-1 text-[11px]"
          >
            <Clipboard className="h-3 w-3" />
            {copied === command ? "Copied" : "Copy"}
          </button>
        </div>
      ))}
    </div>
  );
}

function copyButtonLabel(copied: boolean) {
  return copied ? "Copied" : "Copy";
}

function DeploymentGuideCard({ guide }: { guide: ConnectorDeploymentGuide }) {
  const [copied, setCopied] = useState(false);
  if (!guide.body) return null;
  return (
    <div className="overflow-hidden rounded-lg border border-[color:var(--border)] bg-[var(--surface)]">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[color:var(--border)] bg-[var(--surface-muted)] px-4 py-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-[13px] font-semibold text-[var(--text-primary)]">
            {guide.language === "json" ? <FileJson className="h-4 w-4 text-[var(--text-muted)]" /> : <Code2 className="h-4 w-4 text-[var(--text-muted)]" />}
            {guide.label}
          </div>
          {guide.description && <div className="mt-1 text-[12px] leading-5 text-[var(--text-muted)]">{guide.description}</div>}
        </div>
        <button
          type="button"
          onClick={() => {
            void navigator.clipboard.writeText(guide.body || "").then(() => setCopied(true));
          }}
          className="secondary-button inline-flex items-center gap-1.5 px-2.5 py-1.5 text-[12px]"
        >
          <Clipboard className="h-3.5 w-3.5" />
          {copyButtonLabel(copied)}
        </button>
      </div>
      <pre className="max-h-72 overflow-auto bg-zinc-950 p-4 text-[12px] leading-5 text-zinc-100 dark:bg-black">
        <code>{guide.body}</code>
      </pre>
    </div>
  );
}

function SetupGuidancePanel({ method }: { method?: ConnectorConnectionMethod }) {
  if (!method) return null;
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(300px,0.72fr)]">
      <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-4">
        <div className="mb-3 flex items-center gap-2 text-[13px] font-semibold text-[var(--text-primary)]">
          <ListChecks className="h-4 w-4 text-[var(--text-muted)]" />
          Prerequisites
        </div>
        <div className="grid gap-2 md:grid-cols-2">
          {method.prerequisites.map((item) => (
            <div key={item.id} className="rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] p-3">
              <div className="flex items-start gap-2">
                <Circle className="mt-0.5 h-4 w-4 shrink-0 text-[var(--text-muted)]" />
                <div>
                  <div className="text-[12px] font-semibold text-[var(--text-primary)]">{item.label}</div>
                  {item.description && <div className="mt-1 text-[11px] leading-4 text-[var(--text-muted)]">{item.description}</div>}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-4">
        <div className="mb-3 flex items-center gap-2 text-[13px] font-semibold text-[var(--text-primary)]">
          <ShieldCheck className="h-4 w-4 text-[var(--text-muted)]" />
          Safety boundary
        </div>
        <div className="space-y-2">
          {method.security_notes.map((note) => (
            <div key={note} className="flex gap-2 text-[12px] leading-5 text-[var(--text-muted)]">
              <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-600" />
              <span>{note}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function RegionGuidancePanel({ method }: { method?: ConnectorConnectionMethod }) {
  const guidance = method?.region_guidance;
  if (!guidance) return null;
  return (
    <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-4">
      <div className="mb-3 flex items-center gap-2 text-[13px] font-semibold text-[var(--text-primary)]">
        <Globe2 className="h-4 w-4 text-[var(--text-muted)]" />
        Region and global coverage
      </div>
      <p className="text-[12px] leading-5 text-[var(--text-muted)]">{guidance.description}</p>
      <div className="mt-3 flex flex-wrap gap-2">
        {guidance.default_region && <Badge value={`default ${guidance.default_region}`} />}
        {guidance.supports_global && <Badge value="global resource types" />}
        {guidance.supports_multi_region && <Badge value="multi-region" />}
        {(guidance.examples ?? []).map((example) => (
          <span key={example} className="rounded-md bg-[var(--surface-muted)] px-2 py-1 font-mono text-[11px] text-[var(--text-secondary)]">
            {example}
          </span>
        ))}
      </div>
    </div>
  );
}

function ProductGroupSelector({
  groups,
  selectedFamilies,
  onEnableFamilies,
  onDisableFamilies,
}: {
  groups: ConnectorProductGroup[];
  selectedFamilies: Set<string>;
  onEnableFamilies: (families: string[]) => void;
  onDisableFamilies: (families: string[]) => void;
}) {
  if (groups.length === 0) return null;
  return (
    <div className="min-w-0 rounded-lg border border-[color:var(--border)] bg-[var(--surface)]">
      <div className="border-b border-[color:var(--border)] bg-[var(--surface-muted)] px-4 py-3">
        <div className="flex items-center gap-2 text-[13px] font-semibold text-[var(--text-primary)]">
          <PackageCheck className="h-4 w-4 text-[var(--text-muted)]" />
          Product and permission groups
        </div>
        <p className="mt-1 text-[12px] leading-5 text-[var(--text-muted)]">
          Turning a group off excludes those resource types from collection where supported.
        </p>
      </div>
      <div className="grid min-w-0 gap-3 p-4 md:grid-cols-2">
        {groups.map((group) => {
          const families = group.families ?? [];
          const enabled = group.required || families.some((family) => !selectedFamilies.has(family.trim().toLowerCase()));
          return (
            <div key={group.id} className={`min-w-0 overflow-hidden rounded-lg border border-l-4 bg-[var(--surface-raised)] p-3 ${enabled ? "border-[color:var(--border)] border-l-emerald-500" : "border-[color:var(--border)] border-l-amber-500"}`}>
              <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <div className="text-[13px] font-semibold text-[var(--text-primary)]">{group.label}</div>
                    {group.required && <Badge value="required" />}
                    {!group.required && group.default_enabled && <Badge value="default on" />}
                    {!group.required && !group.default_enabled && <Badge value="default skipped" />}
                  </div>
                  {group.description && <p className="mt-1 text-[12px] leading-5 text-[var(--text-muted)]">{group.description}</p>}
                </div>
                <button
                  type="button"
                  role="switch"
                  aria-label={`${enabled ? "Skip" : "Collect"} ${group.label}`}
                  aria-checked={enabled}
                  disabled={group.required || families.length === 0}
                  onClick={() => (enabled ? onDisableFamilies(families) : onEnableFamilies(families))}
                  className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full border transition disabled:cursor-not-allowed disabled:opacity-60 lg:mt-0 ${
                    enabled
                      ? "border-emerald-300 bg-emerald-100 dark:border-emerald-500/40 dark:bg-emerald-500/20"
                      : "border-[color:var(--border)] bg-[var(--surface)]"
                  }`}
                >
                  <span className={`h-5 w-5 rounded-full bg-white shadow-sm transition dark:bg-zinc-100 ${enabled ? "translate-x-5" : "translate-x-0.5"}`} />
                </button>
              </div>
              {(group.permission_note || group.cost_note) && (
                <div className="mt-3 space-y-1 rounded-md bg-[var(--surface)] px-3 py-2 text-[11px] leading-4 text-[var(--text-muted)]">
                  {group.permission_note && <div>{group.permission_note}</div>}
                  {group.cost_note && <div>{group.cost_note}</div>}
                </div>
              )}
              {families.length > 0 && (
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {families.slice(0, 8).map((family) => (
                    <span key={family} className="max-w-full break-all rounded bg-[var(--surface)] px-1.5 py-0.5 font-mono text-[11px] text-[var(--text-muted)]">
                      {family}
                    </span>
                  ))}
                  {families.length > 8 && <span className="rounded bg-[var(--surface)] px-1.5 py-0.5 text-[11px] font-semibold text-[var(--text-muted)]">+{families.length - 8}</span>}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function FieldGrid({
  fields,
  credential = false,
  store,
  methodID,
}: {
  fields: ConnectorField[];
  credential?: boolean;
  store?: NormalizedCredentialStore;
  methodID?: ConnectorConnectionMethodID;
}) {
  if (fields.length === 0) return null;

  return (
    <div className="grid gap-3 md:grid-cols-2">
      {fields.map((field) => {
        const referencePlaceholder = credential && methodID !== "encrypted_submission" && store?.referencePlaceholder
          ? store.referencePlaceholder.replace("<field>", field.key)
          : undefined;
        return (
          <label key={field.key} className={labelClass}>
            {field.label || field.key}{field.required ? " *" : ""}
            <input
              name={credential ? credentialInputName(field.key) : field.key}
              type={field.secret ? "password" : field.type ?? "text"}
              required={field.required}
              placeholder={referencePlaceholder || field.placeholder}
              autoComplete={field.secret ? "new-password" : "off"}
              className={inputClass}
            />
            {field.help && <span className="mt-1 block text-[11px] font-normal leading-4 text-[var(--text-muted)]">{field.help}</span>}
          </label>
        );
      })}
    </div>
  );
}

function StoreReadinessChecklist({ stores }: { stores: NormalizedCredentialStore[] }) {
  const ready = stores.filter((store) => store.available);
  return (
    <div className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-amber-950 dark:border-amber-500/25 dark:bg-amber-500/10 dark:text-amber-100">
      <div className="text-[13px] font-semibold">No credential stores are ready</div>
      <div className="mt-2 text-[12px] leading-5">
        The backend must advertise at least one ready encrypted, reference-backed, or environment-managed store before a connection can be saved.
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        {stores.map((store) => (
          <span key={store.id} className="rounded-md bg-white/70 px-2 py-1 text-[11px] font-semibold dark:bg-black/15">
            {store.label}: {store.available ? "ready" : store.disabledReason || "unavailable"}
          </span>
        ))}
        {ready.length === 0 && <span className="rounded-md bg-white/70 px-2 py-1 text-[11px] font-semibold dark:bg-black/15">waiting on backend</span>}
      </div>
    </div>
  );
}

function SetupCheckpointStrip({
  method,
  store,
  basicsReady,
  fieldsReady,
  scopeCount,
  preflight,
  canSubmit,
}: {
  method?: ConnectorConnectionMethod;
  store?: NormalizedCredentialStore;
  basicsReady: boolean;
  fieldsReady: boolean;
  scopeCount: number;
  preflight: ConnectorPreflightResponse | null;
  canSubmit: boolean;
}) {
  const checkpoints = [
    {
      label: "Method",
      value: method?.shortLabel || method?.label || "Choose",
      ready: Boolean(method),
      detail: method?.status === "guided" ? "guided" : method?.saveable === false ? "blocked" : "ready",
    },
    {
      label: "Store",
      value: store?.shortLabel || store?.label || "Choose",
      ready: Boolean(store?.available),
      detail: store?.available ? store.detail : store?.disabledReason || "not ready",
    },
    {
      label: "Config",
      value: basicsReady && fieldsReady ? "Complete" : "Missing",
      ready: basicsReady && fieldsReady,
      detail: basicsReady ? "required fields" : "tenant and ID",
    },
    {
      label: "Collected resources",
      value: scopeCount > 0 ? `${scopeCount} excluded` : "All collected",
      ready: true,
      detail: "collection policy",
    },
    {
      label: "Preflight",
      value: preflight ? preflightStatusLabel(preflight.status) : canSubmit ? "Ready" : "Waiting",
      ready: preflight?.status === "ready" || preflight?.status === "warning",
      detail: preflight?.summary || "required before save",
    },
  ];

  return (
    <div className="overflow-hidden rounded-lg border border-[color:var(--border)] bg-[var(--surface)]">
      <div className="border-b border-[color:var(--border)] bg-[var(--surface-muted)] px-4 py-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="text-[13px] font-semibold text-[var(--text-primary)]">Setup checkpoints</div>
            <div className="mt-0.5 text-[12px] leading-5 text-[var(--text-muted)]">
              Secret values never persist in the browser.
            </div>
          </div>
          <Badge value={canSubmit ? "preflight ready" : "complete required fields"} />
        </div>
      </div>
      <div className="grid gap-2 p-3 sm:grid-cols-2 xl:grid-cols-5">
        {checkpoints.map((checkpoint) => (
          <div key={checkpoint.label} className={`rounded-lg border p-3 ${checkpoint.ready ? "border-emerald-200 bg-emerald-50/70 dark:border-emerald-500/25 dark:bg-emerald-500/10" : "border-[color:var(--border)] bg-[var(--surface-muted)]"}`}>
            <div className="flex items-center justify-between gap-2">
              <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-[var(--text-muted)]">{checkpoint.label}</div>
              {checkpoint.ready ? <CheckCircle2 className="h-4 w-4 text-emerald-600" /> : <Circle className="h-4 w-4 text-[var(--text-muted)]" />}
            </div>
            <div className="mt-2 truncate text-[13px] font-semibold text-[var(--text-primary)]">{checkpoint.value}</div>
            <div className="mt-0.5 truncate text-[11px] text-[var(--text-muted)]">{checkpoint.detail}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function SecretStoreIntegrationPanel({ store, method }: { store?: NormalizedCredentialStore; method?: ConnectorConnectionMethod }) {
  if (!store || !method) return null;
  const referenceMode = method.id !== "encrypted_submission";
  const setupSteps = store.setupSteps.slice(0, 3);
  const requiredConfig = store.requiredConfig.slice(0, 5);
  return (
    <div className="mt-3 rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 text-[13px] font-semibold text-[var(--text-primary)]">
            {store.available ? <ShieldCheck className="h-4 w-4 text-emerald-600" /> : <ShieldAlert className="h-4 w-4 text-amber-600" />}
            Secret store integration
          </div>
          <div className="mt-1 max-w-3xl text-[12px] leading-5 text-[var(--text-muted)]">{store.description}</div>
        </div>
        <div className="flex flex-wrap gap-1.5">
          <span className={`rounded-md px-2 py-1 text-[11px] font-semibold ${
            store.available
              ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-100"
              : "bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-100"
          }`}>
            {store.available ? store.detail : store.disabledReason}
          </span>
          {store.nativeResolutionAvailable && (
            <span className="rounded-md bg-blue-100 px-2 py-1 text-[11px] font-semibold text-blue-700 dark:bg-blue-500/15 dark:text-blue-100">server-side resolver</span>
          )}
        </div>
      </div>

      {referenceMode && (
        <div className="mt-3 rounded-lg border border-[color:var(--border)] bg-[var(--surface-raised)] p-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="min-w-0">
              <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-[var(--text-muted)]">Accepted prefixes</div>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {store.referencePrefixes.map((prefix) => (
                  <code key={prefix} className="rounded-md bg-[var(--surface-muted)] px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)]">
                    {prefix}
                  </code>
                ))}
              </div>
            </div>
            {store.referencePlaceholder && (
              <code className="max-w-full overflow-x-auto rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-2 py-1.5 text-[11px] text-[var(--text-secondary)] sm:max-w-[50%]">
                {store.referencePlaceholder}
              </code>
            )}
          </div>
          <details className="mt-3 rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-3 py-2">
            <summary className="cursor-pointer text-[12px] font-semibold text-[var(--text-secondary)]">Deployment setup details</summary>
            <div className="mt-3 grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
              <div>
                <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-[var(--text-muted)]">Backend config</div>
                {requiredConfig.length > 0 ? (
                  <div className="mt-2 grid gap-2">
                    {requiredConfig.map((field) => (
                      <div key={field.env || field.label} className="flex items-start justify-between gap-3 border-t border-[color:var(--border)] pt-2 first:border-t-0 first:pt-0">
                        <div>
                          <div className="text-[12px] font-semibold text-[var(--text-primary)]">{field.label || field.env}</div>
                          {field.description && <div className="mt-0.5 text-[11px] leading-4 text-[var(--text-muted)]">{field.description}</div>}
                        </div>
                        {field.env && <code className="shrink-0 rounded bg-[var(--surface-muted)] px-1.5 py-0.5 text-[10px] text-[var(--text-muted)]">{field.env}</code>}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="mt-2 text-[12px] text-[var(--text-muted)]">No additional backend configuration advertised.</div>
                )}
              </div>
              {setupSteps.length > 0 && (
                <div>
                  <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-[var(--text-muted)]">Setup steps</div>
                  <div className="mt-2 grid gap-2">
                    {setupSteps.map((step, index) => (
                      <div key={step.id || step.label || index} className="rounded-lg border border-[color:var(--border)] bg-[var(--surface-raised)] p-3">
                        <div className="text-[12px] font-semibold text-[var(--text-primary)]">{step.label}</div>
                        {step.description && <div className="mt-1 text-[11px] leading-4 text-[var(--text-muted)]">{step.description}</div>}
                        {step.command && (
                          <code className="mt-2 block overflow-x-auto rounded bg-[var(--surface-muted)] px-2 py-1 text-[10px] text-[var(--text-secondary)]">{step.command}</code>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </details>
        </div>
      )}
    </div>
  );
}

type CredentialReferencePlanRow = {
  field: string;
  label: string;
  required?: boolean;
  reference: string;
  description?: string;
  source: "backend" | "suggested";
};

function referencePathSegment(value: string) {
  return value
    .trim()
    .replace(/[^A-Za-z0-9_.-]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

function envComponent(value: string) {
  const component = value.trim().replace(/[^A-Za-z0-9]+/g, "_").replace(/^_+|_+$/g, "").toUpperCase();
  return component || "CONFIG";
}

function replaceReferenceTemplate(template: string, connector: ConnectorCatalogEntry, tenantID: string, runtimeID: string, field: string) {
  const tenant = referencePathSegment(tenantID) || "<tenant>";
  const source = referencePathSegment(connector.source_id) || "<source>";
  const runtime = referencePathSegment(runtimeID) || "<runtime>";
  return template
    .replaceAll("<tenant>", tenant)
    .replaceAll("<source>", source)
    .replaceAll("<runtime>", runtime)
    .replaceAll("<SOURCE>", envComponent(connector.source_id))
    .replaceAll("<FIELD>", envComponent(field))
    .replaceAll("<field>", field)
    .replaceAll("<region>", "us-east-1");
}

function fallbackReferenceTemplate(store: NormalizedCredentialStore) {
  if (store.referenceFieldTemplate) return store.referenceFieldTemplate;
  if (store.referencePlaceholder) return store.referencePlaceholder;
  if (store.id === "aws_secrets_manager") return "aws-sm:us-east-1:cerebro/<tenant>/<source>/<runtime>/credentials#<field>";
  return "env:CEREBRO_SOURCE_<SOURCE>_<FIELD>";
}

function credentialReferenceRows({
  connector,
  method,
  store,
  tenantID,
  runtimeID,
  preflight,
}: {
  connector: ConnectorCatalogEntry;
  method?: ConnectorConnectionMethod;
  store?: NormalizedCredentialStore;
  tenantID: string;
  runtimeID: string;
  preflight: ConnectorPreflightResponse | null;
}): CredentialReferencePlanRow[] {
  if (!method || !store || method.id === "encrypted_submission") return [];
  const backendTemplates = preflight?.credential_boundary?.reference_templates ?? [];
  if (backendTemplates.length > 0 && preflight?.credential_store_id === store.id) {
    return backendTemplates.map((template) => ({
      field: template.field,
      label: template.label || template.field,
      required: template.required,
      reference: template.reference,
      description: template.description,
      source: "backend" as const,
    }));
  }
  const template = fallbackReferenceTemplate(store);
  return (method.credential_fields ?? []).map((field) => ({
    field: field.key,
    label: field.label || field.key,
    required: field.required,
    reference: replaceReferenceTemplate(template, connector, tenantID, runtimeID, field.key),
    description: store.id === "aws_secrets_manager"
      ? "Bound to this connection namespace; backend validation rejects aws-sm references outside it."
      : "Projected into the backend runtime environment before source validation.",
    source: "suggested" as const,
  }));
}

function referenceNamespaceLabel(store: NormalizedCredentialStore | undefined, connector: ConnectorCatalogEntry, tenantID: string, runtimeID: string, preflight: ConnectorPreflightResponse | null) {
  const backendNamespace = preflight?.credential_boundary?.reference_namespace;
  if (backendNamespace) return backendNamespace;
  if (!store) return "";
  const template = store.referenceNamespaceTemplate || (store.id === "aws_secrets_manager" ? "cerebro/<tenant>/<source>/<runtime>/credentials" : "CEREBRO_SOURCE_<SOURCE>_*");
  return replaceReferenceTemplate(template, connector, tenantID, runtimeID, "*");
}

function CredentialReferencePlan({
  connector,
  method,
  store,
  tenantID,
  runtimeID,
  preflight,
  onApply,
}: {
  connector: ConnectorCatalogEntry;
  method?: ConnectorConnectionMethod;
  store?: NormalizedCredentialStore;
  tenantID: string;
  runtimeID: string;
  preflight: ConnectorPreflightResponse | null;
  onApply: (rows: CredentialReferencePlanRow[]) => void;
}) {
  if (!method || !store || method.id === "encrypted_submission") return null;
  const rows = credentialReferenceRows({ connector, method, store, tenantID, runtimeID, preflight });
  const namespace = referenceNamespaceLabel(store, connector, tenantID, runtimeID, preflight);
  const hasRows = rows.length > 0;
  const hasUnresolvedReferences = namespace.includes("<") || rows.some((row) => row.reference.includes("<"));
  const planText = rows.map((row) => `${row.field}=${row.reference}`).join("\n");
  const nativeLabel = store.nativeResolutionAvailable || preflight?.credential_boundary?.native_resolution_available
    ? "server-side resolution"
    : store.id === "aws_secrets_manager"
      ? "region in reference"
      : "env projection";

  if (!hasRows) {
    return (
      <div className="mt-4 rounded-xl border border-emerald-200 bg-emerald-50/60 p-4 text-emerald-950 shadow-[var(--shadow-sm)] dark:border-emerald-500/25 dark:bg-emerald-500/10 dark:text-emerald-100">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex min-w-0 gap-3">
            <div className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-emerald-600 text-white">
              <CheckCircle2 className="h-4 w-4" />
            </div>
            <div className="min-w-0">
              <div className="text-[13px] font-semibold">No credential references required</div>
              <div className="mt-1 max-w-3xl text-[12px] leading-5 opacity-80">
                {method.id === "aws_sso_profile"
                  ? "AWS SSO uses a server-side shared config profile. Keep that profile authenticated on the backend host and preflight will verify access before save."
                  : "This method only needs non-secret runtime configuration. Preflight still validates the selected store boundary before saving."}
              </div>
            </div>
          </div>
          <div className="flex flex-wrap gap-1.5">
            <span className="rounded-md bg-white/70 px-2 py-1 text-[11px] font-semibold text-emerald-800 dark:bg-black/15 dark:text-emerald-100">{store.label}</span>
            <span className="rounded-md bg-white/70 px-2 py-1 text-[11px] font-semibold text-emerald-800 dark:bg-black/15 dark:text-emerald-100">{nativeLabel}</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="mt-4 overflow-hidden rounded-xl border border-[color:var(--border)] bg-[var(--surface)] shadow-[var(--shadow-sm)]">
      <div className="grid gap-4 border-b border-[color:var(--border)] bg-[var(--surface-raised)] p-4 lg:grid-cols-[minmax(0,1fr)_auto]">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-[color:var(--border)] bg-[var(--surface)] text-[var(--primary)]">
              <FileJson className="h-4 w-4" />
            </div>
            <div>
              <div className="text-[13px] font-semibold text-[var(--text-primary)]">Credential reference plan</div>
              <div className="text-[12px] text-[var(--text-muted)]">{store.label} · {nativeLabel}</div>
            </div>
          </div>
          <div className="mt-3 max-w-3xl text-[12px] leading-5 text-[var(--text-muted)]">
            {hasRows
              ? "Generate the non-secret references that this connection should submit. The backend still validates prefixes, store compatibility, and runtime namespace before it resolves anything."
              : "This method does not require credential reference fields. Runtime config stays non-secret and backend validation still runs before save."}
          </div>
          <div className="mt-3 grid gap-1.5 text-[11px]">
            {[
              ["1", "Create store values"],
              ["2", "Submit references only"],
              ["3", "Preflight validates boundary"],
            ].map(([step, detail]) => (
              <div key={step} className="flex items-center gap-2 rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-2.5 py-2 text-[var(--text-muted)]">
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-[var(--primary-soft)] text-[10px] font-bold text-[var(--primary)]">{step}</span>
                <span className="leading-4">{detail}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="flex flex-wrap items-start justify-end gap-2">
          <span className="rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-2.5 py-1 text-[11px] font-semibold text-[var(--text-secondary)]">
            {preflight?.credential_boundary?.store_status || store.status}
          </span>
          <button
            type="button"
            disabled={hasUnresolvedReferences}
            onClick={() => void navigator.clipboard?.writeText(planText)}
            className="secondary-button inline-flex items-center gap-2 px-3 py-2 text-[12px] disabled:cursor-not-allowed disabled:opacity-55"
          >
            <Clipboard className="h-3.5 w-3.5" />
            Copy plan
          </button>
          <button
            type="button"
            disabled={hasUnresolvedReferences}
            onClick={() => onApply(rows)}
            className="primary-button inline-flex items-center gap-2 px-3 py-2 text-[12px] disabled:cursor-not-allowed disabled:opacity-55"
          >
            <Clipboard className="h-3.5 w-3.5" />
            {hasUnresolvedReferences ? "Set tenant first" : "Apply references"}
          </button>
        </div>
      </div>

      <div className="grid gap-4 p-4 xl:grid-cols-[minmax(0,0.48fr)_minmax(0,1fr)]">
        <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] p-3">
          <div className="flex items-center justify-between gap-2">
            <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-[var(--text-muted)]">Namespace</div>
            <Badge value={store.nativeResolutionAvailable ? "backend reads store" : "projected env"} />
          </div>
          <code className="mt-2 block overflow-x-auto rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-2 py-1.5 text-[11px] text-[var(--text-secondary)]">
            {namespace || "Set tenant and connection ID to preview namespace"}
          </code>
          {hasUnresolvedReferences && (
            <div className="mt-2 rounded-md border border-amber-200 bg-amber-50 px-2 py-1.5 text-[11px] leading-4 text-amber-800 dark:border-amber-500/25 dark:bg-amber-500/10 dark:text-amber-100">
              Set tenant and connection ID before applying generated references.
            </div>
          )}
          <div className="mt-3 flex flex-wrap gap-1.5">
            {(preflight?.credential_boundary?.reference_prefixes ?? store.referencePrefixes).map((prefix) => (
              <span key={prefix} className="rounded-md bg-[var(--surface)] px-2 py-1 font-mono text-[11px] font-semibold text-[var(--text-muted)]">
                {prefix}
              </span>
            ))}
          </div>
        </div>

        <div className="overflow-hidden rounded-lg border border-[color:var(--border)]">
          {hasRows ? rows.map((row) => (
            <div key={row.field} className="grid gap-3 border-b border-[color:var(--border)] bg-[var(--surface)] p-3 last:border-b-0 lg:grid-cols-[150px_minmax(0,1fr)_auto]">
              <div className="min-w-0">
                <div className="flex items-center gap-1.5 text-[12px] font-semibold text-[var(--text-primary)]">
                  {row.label}
                  {row.required && <span className="text-[var(--status-danger)]">*</span>}
                </div>
                <div className="mt-0.5 text-[11px] text-[var(--text-muted)]">{row.source === "backend" ? "preflight plan" : "suggested plan"}</div>
              </div>
              <code className="min-w-0 overflow-x-auto rounded-md bg-[var(--surface-muted)] px-2 py-1.5 text-[11px] text-[var(--text-secondary)]">
                {row.reference}
              </code>
              <button
                type="button"
                onClick={() => void navigator.clipboard?.writeText(row.reference)}
                className="secondary-button inline-flex items-center justify-center gap-1.5 px-2.5 py-1.5 text-[11px]"
              >
                <Clipboard className="h-3.5 w-3.5" />
                Copy
              </button>
              {row.description && <div className="text-[11px] leading-4 text-[var(--text-muted)] lg:col-start-2 lg:col-end-4">{row.description}</div>}
            </div>
          )) : (
            <div className="flex items-start gap-3 bg-[var(--surface)] p-4">
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600" />
              <div>
                <div className="text-[13px] font-semibold text-[var(--text-primary)]">No credential references required</div>
                <div className="mt-1 text-[12px] leading-5 text-[var(--text-muted)]">
                  {method.id === "aws_sso_profile"
                    ? "AWS SSO uses a server-side shared config profile. Keep the profile authenticated on the backend host."
                    : "This method only needs non-secret runtime configuration."}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function requirementCount(fields: ConnectorField[] | undefined) {
  return (fields ?? []).filter((field) => field.required).length;
}

function OnboardingBrief({
  method,
  store,
  basicsReady,
  fieldsReady,
  scopeCount,
  preflight,
}: {
  method?: ConnectorConnectionMethod;
  store?: NormalizedCredentialStore;
  basicsReady: boolean;
  fieldsReady: boolean;
  scopeCount: number;
  preflight: ConnectorPreflightResponse | null;
}) {
  const configRequired = requirementCount(method?.config_fields);
  const credentialRequired = requirementCount(method?.credential_fields);
  const requiredFields = configRequired + credentialRequired;
  const requiresPreflight = (method?.commands?.length ?? 0) > 0;
  const sendsSecrets = method?.id === "encrypted_submission";
  const preflightReady = preflight?.status === "ready" || preflight?.status === "warning";
  const preflightBlocked = preflight?.status === "blocked";
  const rows = [
    {
      label: "Method",
      detail: method ? `${method.label || method.shortLabel} selected` : "Choose a supported authentication method",
      ready: Boolean(method && method.status !== "unavailable" && method.saveable !== false),
    },
    {
      label: "Store",
      detail: store?.available ? `${store.label} is ready` : store?.disabledReason || "Choose a ready credential store",
      ready: Boolean(store?.available),
    },
    {
      label: "Basics",
      detail: basicsReady ? "Tenant and connection ID are set" : "Add tenant and connection ID",
      ready: basicsReady,
    },
    {
      label: "Preflight",
      detail: preflight
        ? preflight.summary
        : requiresPreflight
          ? "Run CLI checks, then validate before save"
          : "Validate the runtime before save",
      ready: preflightReady,
    },
    {
      label: "Fields",
      detail: requiredFields === 0 ? "No required fields" : fieldsReady ? "Required fields are filled" : `${configRequired} config and ${credentialRequired} credential/reference required below`,
      ready: fieldsReady,
    },
    {
      label: "Collected resources",
      detail: scopeCount > 0 ? `${scopeCount} collection exclusion${scopeCount === 1 ? "" : "s"}` : "Collect all resources",
      ready: true,
    },
  ];
  const completed = rows.filter((row) => row.ready).length;
  const progress = Math.round((completed / rows.length) * 100);
  const nextRow = rows.find((row) => !row.ready);
  const statusTone = preflightBlocked
    ? "text-red-700 dark:text-red-200"
    : preflightReady
      ? "text-emerald-700 dark:text-emerald-100"
      : "text-[var(--text-secondary)]";
  const statusLabel = preflight?.status
    ? preflightStatusLabel(preflight.status)
    : "Ready for setup";

  return (
    <section className="overflow-hidden rounded-xl border border-[color:var(--border)] bg-[var(--surface)] shadow-[var(--shadow-sm)]">
      <div className="grid gap-4 border-b border-[color:var(--border)] bg-[var(--surface-raised)] p-4 xl:grid-cols-[minmax(0,1fr)_300px]">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-[color:var(--border)] bg-[var(--surface)] text-[var(--primary)]">
              <PackageCheck className="h-4 w-4" />
            </div>
            <div className="min-w-0">
              <div className="text-[13px] font-semibold text-[var(--text-primary)]">Connection setup</div>
              <div className="mt-0.5 truncate text-[12px] text-[var(--text-muted)]">
                {nextRow ? `Next: ${nextRow.detail}` : "All setup gates are satisfied. Run preflight once more before saving if config changed."}
              </div>
            </div>
          </div>
          <div className="mt-4 h-2 overflow-hidden rounded-full bg-[var(--surface-muted)]">
            <div
              className={`h-full rounded-full ${preflightBlocked ? "bg-red-500" : preflightReady ? "bg-emerald-500" : "bg-[var(--primary)]"}`}
              style={{ width: `${progress}%` }}
            />
          </div>
          <div className="mt-3 grid gap-2 md:grid-cols-3">
            {rows.map((row, index) => (
              <div
                key={row.label}
                className={`min-w-0 rounded-lg border p-3 ${
                  row.ready
                    ? "border-emerald-200 bg-emerald-50/70 dark:border-emerald-500/25 dark:bg-emerald-500/10"
                    : "border-[color:var(--border)] bg-[var(--surface)]"
                }`}
              >
                <div className="flex items-start gap-2">
                  <span className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[10px] font-semibold ${
                    row.ready
                      ? "bg-emerald-600 text-white"
                      : "bg-[var(--surface-muted)] text-[var(--text-muted)]"
                  }`}>
                    {row.ready ? <CheckCircle2 className="h-3 w-3" /> : index + 1}
                  </span>
                  <div className="min-w-0">
                    <div className="text-[12px] font-semibold text-[var(--text-primary)]">{row.label}</div>
                    <div className="mt-0.5 line-clamp-2 text-[11px] leading-4 text-[var(--text-muted)]">{row.detail}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="grid gap-3 rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-3">
          <div className="flex items-center justify-between gap-3">
            <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-[var(--text-muted)]">Readiness</div>
            <span className={`text-[12px] font-semibold ${statusTone}`}>{statusLabel}</span>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="rounded-md bg-[var(--surface-muted)] p-3">
              <div className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[var(--text-muted)]">Method</div>
              <div className="mt-1 truncate text-[13px] font-semibold text-[var(--text-primary)]">{method?.label || method?.shortLabel || "Choose"}</div>
            </div>
            <div className="rounded-md bg-[var(--surface-muted)] p-3">
              <div className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[var(--text-muted)]">Store</div>
              <div className="mt-1 truncate text-[13px] font-semibold text-[var(--text-primary)]">{store?.shortLabel ?? "Choose"}</div>
            </div>
          </div>
          <div className="rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] p-3">
            <div className="flex items-center gap-2 text-[12px] font-semibold text-[var(--text-primary)]">
              <ShieldCheck className="h-4 w-4 text-[var(--text-muted)]" />
              Credential boundary
            </div>
            <p className="mt-2 text-[12px] leading-5 text-[var(--text-muted)]">
              {sendsSecrets
                ? "Secret material is encrypted in browser transit, sealed at rest, and never returned by connector reads."
                : store?.nativeResolutionAvailable
                  ? "The browser submits only runtime-bound references; the backend resolves them inside the runtime boundary."
                  : "The browser submits only references; deployment automation projects the material into the backend runtime."}
            </p>
          </div>
          <div className="flex flex-wrap gap-1.5">
            <Badge value={`${completed}/${rows.length} gates`} />
            <Badge value={scopeCount > 0 ? `${scopeCount} excluded from collection` : "all resources collected"} />
            {preflight?.next_action && <Badge value={preflight.next_action.replaceAll("_", " ")} />}
          </div>
        </div>
      </div>
    </section>
  );
}

function ConnectionPathSummary({
  method,
  store,
  scopeCount,
  preflight,
}: {
  method?: ConnectorConnectionMethod;
  store?: NormalizedCredentialStore;
  scopeCount: number;
  preflight: ConnectorPreflightResponse | null;
}) {
  const sendsSecrets = method?.id === "encrypted_submission";
  const referenceOnly = Boolean(method && method.id !== "encrypted_submission");
  const boundaryTitle = sendsSecrets
    ? "Browser-encrypted secret envelope"
    : store?.nativeResolutionAvailable
      ? "Runtime-bound backend reference"
      : "Deployment-projected reference";
  const boundaryDetail = sendsSecrets
    ? "The UI encrypts credential material before transit and clears fields after every attempt."
    : referenceOnly && store?.nativeResolutionAvailable
      ? "The UI submits a non-secret pointer; the backend resolves it inside the runtime boundary."
      : "The UI submits a non-secret pointer; deployment wiring supplies the material to the backend runtime.";
  const resolverTitle = store?.label ?? "Choose a credential store";
  const resolverDetail = store
    ? store.nativeResolutionAvailable
      ? "Native resolver is configured for this backend."
      : store.mode === "environment_managed"
        ? "Values must exist in the runtime environment."
        : "External store values are projected into env references."
    : "Pick where credential material lives before preflight.";
  const preflightTitle = preflight ? preflightStatusLabel(preflight.status) : "Preflight required";
  const preflightDetail = preflight?.summary ?? "Preflight validates method, credentials, source access, and collection policy before save.";

  const items = [
    {
      label: "Auth method",
      title: method?.label || method?.shortLabel || "Choose method",
      detail: method?.category ?? "Select the identity path for this source.",
      icon: <KeyRound className="h-4 w-4" />,
    },
    {
      label: "Secret boundary",
      title: boundaryTitle,
      detail: boundaryDetail,
      icon: sendsSecrets ? <LockKeyhole className="h-4 w-4" /> : <ShieldCheck className="h-4 w-4" />,
    },
    {
      label: "Credential store",
      title: resolverTitle,
      detail: resolverDetail,
      icon: <FileJson className="h-4 w-4" />,
    },
    {
      label: "Runtime gate",
      title: preflightTitle,
      detail: scopeCount > 0 ? `${preflightDetail} ${scopeCount} resource exclusion${scopeCount === 1 ? "" : "s"} will be skipped before collection.` : preflightDetail,
      icon: <SlidersHorizontal className="h-4 w-4" />,
    },
  ];

  return (
    <section className="rounded-xl border border-[color:var(--border)] bg-[var(--surface)] p-3 shadow-[var(--shadow-sm)]">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2 px-1">
        <div>
          <div className="text-[13px] font-semibold text-[var(--text-primary)]">Connection path</div>
          <div className="mt-0.5 text-[12px] text-[var(--text-muted)]">Identity, credential boundary, resolver, and collection policy are validated as one runtime contract.</div>
        </div>
        <Badge value={preflight ? preflightStatusLabel(preflight.status) : "not tested"} />
      </div>
      <div className="grid gap-2 lg:grid-cols-4">
        {items.map((item, index) => (
          <div key={item.label} className="relative rounded-lg border border-[color:var(--border)] bg-[var(--surface-raised)] p-3">
            {index < items.length - 1 && (
              <ArrowRight className="absolute -right-3 top-5 z-10 hidden h-4 w-4 rounded-full border border-[color:var(--border)] bg-[var(--surface)] p-0.5 text-[var(--text-muted)] lg:block" />
            )}
            <div className="flex items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-[var(--surface-muted)] text-[var(--primary)]">
                {item.icon}
              </div>
              <div className="min-w-0">
                <div className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[var(--text-muted)]">{item.label}</div>
                <div className="mt-1 text-[12px] font-semibold text-[var(--text-primary)]">{item.title}</div>
                <div className="mt-1 line-clamp-3 text-[11px] leading-4 text-[var(--text-muted)]">{item.detail}</div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

const preflightAccent: Record<string, string> = {
  ready: "border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-500/30 dark:bg-emerald-500/10 dark:text-emerald-100",
  warning: "border-amber-300 bg-amber-50 text-amber-950 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-100",
  blocked: "border-red-300 bg-red-50 text-red-950 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-100",
  idle: "border-[color:var(--border)] bg-[var(--surface)] text-[var(--text-primary)]",
};

function preflightStatusLabel(status?: string) {
  switch (status) {
    case "ready":
      return "Ready to save";
    case "warning":
      return "Review warnings";
    case "blocked":
      return "Blocked";
    default:
      return "Not tested";
  }
}

function PreflightIcon({ status }: { status?: string }) {
  if (status === "ready" || status === "passed") return <CheckCircle2 className="h-4 w-4 text-emerald-600" />;
  if (status === "warning") return <AlertCircle className="h-4 w-4 text-amber-600" />;
  if (status === "blocked") return <ShieldAlert className="h-4 w-4 text-red-600" />;
  return <Circle className="h-4 w-4 text-[var(--text-muted)]" />;
}

function PreflightTile({
  label,
  value,
  detail,
}: {
  label: string;
  value: ReactNode;
  detail?: ReactNode;
}) {
  return (
    <div className="min-w-0 rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-3">
      <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">{label}</div>
      <div className="mt-1.5 truncate text-[15px] font-semibold text-[var(--text-primary)]">{value}</div>
      {detail && <div className="mt-1 truncate text-[11px] text-[var(--text-muted)]">{detail}</div>}
    </div>
  );
}

function PreflightCheckRow({ check }: { check: ConnectorPreflightCheck }) {
  return (
    <div className="flex gap-3 border-t border-[color:var(--border)] py-3 first:border-t-0 first:pt-0 last:pb-0">
      <span className="mt-0.5 shrink-0"><PreflightIcon status={check.status} /></span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <div className="text-[12px] font-semibold text-[var(--text-primary)]">{check.label}</div>
          <Badge value={check.status} />
        </div>
        {check.detail && <div className="mt-1 text-[11px] leading-4 text-[var(--text-muted)]">{check.detail}</div>}
      </div>
    </div>
  );
}

function PreflightCockpit({
  preflight,
  method,
  store,
  scopeCount,
}: {
  preflight: ConnectorPreflightResponse | null;
  method?: ConnectorConnectionMethod;
  store?: NormalizedCredentialStore;
  scopeCount: number;
}) {
  const status = preflight?.status ?? "idle";
  const checks = preflight?.checks ?? [];
  const blocking = checks.filter((check) => check.status === "blocked").length;
  const warnings = checks.filter((check) => check.status === "warning").length;
  const scopePreview = preflight?.scope_preview;
  const boundary = preflight?.credential_boundary;
  const fieldsAccepted = boundary?.fields_accepted?.length ?? 0;

  return (
    <section className={`overflow-hidden rounded-xl border ${preflightAccent[status] ?? preflightAccent.idle}`}>
      <div className="grid gap-4 border-b border-current/10 p-4 xl:grid-cols-[minmax(0,1fr)_auto]">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-[13px] font-semibold">
            <PreflightIcon status={status} />
            {preflightStatusLabel(status)}
          </div>
          <p className="mt-1 max-w-3xl text-[12px] leading-5 opacity-80">
            {preflight?.summary ?? "Run preflight before saving. The check validates method, credential boundary, source config, and collection policy without storing the runtime."}
          </p>
        </div>
        <div className="flex items-center gap-2 text-[12px] font-semibold">
          <span>{preflight?.next_action?.replaceAll("_", " ") ?? "run preflight"}</span>
          <ArrowRight className="h-3.5 w-3.5" />
        </div>
      </div>

      <div className="grid gap-3 bg-[var(--surface-muted)] p-4 md:grid-cols-2 xl:grid-cols-4">
        <PreflightTile label="Method" value={method?.label || method?.shortLabel || "Choose method"} detail={method?.category ?? "Connection"} />
        <PreflightTile label="Credential Store" value={store?.label ?? "Choose store"} detail={boundary?.reference_only ? "references only" : boundary?.sends_secrets ? "encrypted submission" : store?.detail} />
        <PreflightTile
          label="Collection"
          value={scopePreview ? `${scopePreview.enabled_resource_types ?? 0} on / ${scopePreview.disabled_resource_types ?? 0} off` : `${scopeCount} exclusions`}
          detail={scopePreview ? `${scopePreview.exact_resource_count ?? 0} exact resources` : "pending collection preview"}
        />
        <PreflightTile label="Checks" value={preflight ? `${checks.length - blocking}/${checks.length} passing` : "Not run"} detail={warnings > 0 ? `${warnings} warnings` : fieldsAccepted > 0 ? `${fieldsAccepted} credential fields` : "source check pending"} />
      </div>

      {checks.length > 0 && (
        <div className="grid gap-4 bg-[var(--surface)] p-4 xl:grid-cols-[minmax(0,1fr)_280px]">
          <div>
            <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Readiness checks</div>
            <div className="mt-2">
              {checks.map((check) => <PreflightCheckRow key={check.id} check={check} />)}
            </div>
          </div>
          <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] p-3 text-[12px] leading-5 text-[var(--text-muted)]">
            <div className="flex items-center gap-2 text-[12px] font-semibold text-[var(--text-primary)]">
              <ShieldCheck className="h-4 w-4" />
              Credential boundary
            </div>
            <div className="mt-2">
              {boundary?.sends_secrets
                ? "Secrets were encrypted for transit and are not returned by connector reads."
                : "Only backend-resolvable references are submitted for this method."}
            </div>
            {fieldsAccepted > 0 && (
              <div className="mt-3 flex flex-wrap gap-1.5">
                {boundary?.fields_accepted?.map((field) => (
                  <span key={field} className="rounded bg-[var(--surface)] px-1.5 py-0.5 font-mono text-[11px] text-[var(--text-secondary)]">{field}</span>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </section>
  );
}

type ResourceTypeFilter = "all" | "enabled" | "disabled" | "high_value" | "framework";

function scopeOptionSearchText(option: ConnectorScopeOption, families: string[]) {
  return [option.label, option.id, option.type, option.support, ...families].filter(Boolean).join(" ").toLowerCase();
}

function ScopePolicyBuilder({
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

function CredentialBrokerPanel({
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

export default function ConnectorSetupForm({
  connector,
  tenantID,
  apiKey,
  credentialStores,
  initialFramework = "",
  onConnected,
}: {
  connector: ConnectorCatalogEntry;
  tenantID: string;
  apiKey?: string;
  credentialStores: NormalizedCredentialStore[];
  initialFramework?: string;
  onConnected: (context: ConnectorConnectedContext) => Promise<void> | void;
}) {
  const formRef = useRef<HTMLFormElement>(null);
  const methods = useMemo(() => connectionMethodsForConnector(connector, credentialStores), [connector, credentialStores]);
  const preferredMethod = methods.find((method) => method.status !== "unavailable" && method.saveable !== false) ?? methods[0];
  const [selectedMethodID, setSelectedMethodID] = useState<ConnectorConnectionMethodID>(preferredMethod?.id ?? "encrypted_submission");
  const effectiveSelectedMethodID = methods.some((method) => method.id === selectedMethodID)
    ? selectedMethodID
    : preferredMethod?.id;
  const selectedMethod = methods.find((method) => method.id === effectiveSelectedMethodID) ?? preferredMethod;
  const methodStores = storesForMethod(selectedMethod, credentialStores);
  const visibleStores = methodStores.length > 0 ? methodStores : credentialStores;
  const [selectedStoreID, setSelectedStoreID] = useState<ConnectorCredentialStoreID>(() => defaultStoreForMethod(preferredMethod, credentialStores));
  const defaultSelectedStoreID = defaultStoreForMethod(selectedMethod, credentialStores);
  const selectedStore = visibleStores.find((store) => store.id === selectedStoreID && store.available)
    ?? visibleStores.find((store) => store.id === defaultSelectedStoreID && store.available)
    ?? visibleStores.find((store) => store.available)
    ?? visibleStores.find((store) => store.id === selectedStoreID)
    ?? visibleStores.find((store) => store.id === defaultSelectedStoreID)
    ?? visibleStores[0];
  const effectiveSelectedStoreID = selectedStore?.id ?? defaultSelectedStoreID;
  const selectedStoreIsValid = Boolean(selectedMethod && selectedStore && storeMatchesMethod(selectedStore, selectedMethod));
  const canSubmit = Boolean(selectedMethod && selectedStore?.available && selectedMethod.saveable !== false && selectedStoreIsValid);
  const anyStoreReady = credentialStores.some((store) => store.available);
  const [submitting, setSubmitting] = useState<"check" | "save" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<{ runtimeID: string; tenant: string; storeLabel: string; status: "checked" | "saved" } | null>(null);
  const [preflight, setPreflight] = useState<ConnectorPreflightResponse | null>(null);
  const [formValues, setFormValues] = useState<Record<string, string>>({});
  const [excludedFamilies, setExcludedFamilies] = useState<Set<string>>(() => new Set(productGroupDefaultExcludedFamilies(preferredMethod)));
  const [resourceURNs, setResourceURNs] = useState("");
  const [excludedResources, setExcludedResources] = useState<ConnectorScopeResource[]>([]);
  const [scopeEdited, setScopeEdited] = useState(false);
  const defaultRuntimeID = [tenantID, connector.source_id, "connection"].filter(Boolean).join("-") || `${connector.source_id}-connection`;
  const defaultExcludedProductFamilies = useMemo(() => productGroupDefaultExcludedFamilies(selectedMethod), [selectedMethod]);
  const defaultExcludedProductFamiliesKey = defaultExcludedProductFamilies.join("\n");
  const protectedProductFamilies = useMemo(() => productGroupRequiredFamilies(selectedMethod), [selectedMethod]);
  const scopeSelectionSignature = `${connector.source_id}:${selectedMethod?.id ?? selectedMethodID}`;
  const previousScopeSelectionSignature = useRef(scopeSelectionSignature);
  const previousScopeDefaultKey = useRef(defaultExcludedProductFamiliesKey);
  const updateFormValues = () => {
    const form = formRef.current;
    if (!form) return;
    const data = new FormData(form);
    const values: Record<string, string> = {};
    data.forEach((value, key) => {
      values[key] = String(value).trim();
    });
    setFormValues(values);
  };
  const requiredFieldKeys = useMemo(() => {
    if (!selectedMethod) return [];
    return [
      ...(selectedMethod.config_fields ?? []).filter((field) => field.required).map((field) => field.key),
      ...(selectedMethod.credential_fields ?? []).filter((field) => field.required).map((field) => credentialInputName(field.key)),
    ];
  }, [selectedMethod]);
  const basicsReady = Boolean(formValues.tenant_id && formValues.runtime_id);
  const requiredFieldsReady = requiredFieldKeys.length === 0 || requiredFieldKeys.every((key) => Boolean(formValues[key]));
  const scopePolicy = useMemo(() => normalizeScopePolicy({
    excluded_families: Array.from(excludedFamilies).filter((family) => !protectedProductFamilies.has(family)),
    excluded_resource_urns: splitScopeValues(resourceURNs),
    excluded_resources: excludedResources,
  }), [excludedFamilies, excludedResources, protectedProductFamilies, resourceURNs]);
  const scopeCount = scopePolicyExclusionCount(scopePolicy);
  const canSave = canSubmit && (preflight?.status === "ready" || preflight?.status === "warning");
  const planTenantID = formValues.tenant_id || tenantID;
  const planRuntimeID = formValues.runtime_id || defaultRuntimeID;

  const changeMethod = (methodID: ConnectorConnectionMethodID) => {
    const nextMethod = methods.find((method) => method.id === methodID);
    setSelectedMethodID(methodID);
    setSelectedStoreID(defaultStoreForMethod(nextMethod, credentialStores));
    setExcludedFamilies(new Set(productGroupDefaultExcludedFamilies(nextMethod)));
    setResourceURNs("");
    setExcludedResources([]);
    setScopeEdited(false);
    setError(null);
    setSuccess(null);
    setPreflight(null);
  };

  const updateScopeFamilies = (families: string[], disabled: boolean) => {
    setScopeEdited(true);
    setPreflight(null);
    setExcludedFamilies((previous) => {
      const next = new Set(previous);
      const normalized = families.map(normalizeFamily).filter(Boolean);
      normalized.forEach((family) => {
        if (disabled && !protectedProductFamilies.has(family)) next.add(family);
        else next.delete(family);
      });
      return next;
    });
  };

  const updateResourceURNs = (value: string) => {
    setResourceURNs(value);
    setScopeEdited(true);
    setPreflight(null);
  };

  const updateExcludedResources = (resources: ConnectorScopeResource[]) => {
    setExcludedResources(resources);
    setScopeEdited(true);
    setPreflight(null);
  };

  const applyCredentialReferenceRows = (rows: CredentialReferencePlanRow[]) => {
    const form = formRef.current;
    if (!form) return;
    rows.forEach((row) => {
      const element = form.elements.namedItem(credentialInputName(row.field));
      if (element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement) {
        element.value = row.reference;
      }
    });
    setPreflight(null);
    setSuccess(null);
    updateFormValues();
  };

  const resetForm = () => {
    formRef.current?.reset();
    setExcludedFamilies(new Set(defaultExcludedProductFamilies));
    setResourceURNs("");
    setExcludedResources([]);
    setScopeEdited(false);
    setPreflight(null);
    setSuccess(null);
    window.setTimeout(updateFormValues, 0);
  };

  useEffect(() => {
    const timer = window.setTimeout(updateFormValues, 0);
    return () => window.clearTimeout(timer);
  }, [effectiveSelectedMethodID, effectiveSelectedStoreID, tenantID]);

  useEffect(() => {
    const sourceOrMethodChanged = previousScopeSelectionSignature.current !== scopeSelectionSignature;
    const defaultsChanged = previousScopeDefaultKey.current !== defaultExcludedProductFamiliesKey;
    if (sourceOrMethodChanged || (defaultsChanged && !scopeEdited)) {
      setExcludedFamilies(new Set(defaultExcludedProductFamilies));
      if (sourceOrMethodChanged) {
        setResourceURNs("");
        setExcludedResources([]);
      }
      setScopeEdited(false);
    }
    previousScopeSelectionSignature.current = scopeSelectionSignature;
    previousScopeDefaultKey.current = defaultExcludedProductFamiliesKey;
  }, [defaultExcludedProductFamilies, defaultExcludedProductFamiliesKey, scopeEdited, scopeSelectionSignature]);

  const submitConnection = async (checkOnly: boolean) => {
    const form = formRef.current;
    if (!form || !selectedMethod || !selectedStore) return;
    if (!form.reportValidity()) return;
    if (!canSubmit) {
      setError(selectedMethod.disabledReason || "Selected auth method or credential store is not available.");
      return;
    }
    if (!checkOnly && !canSave) {
      setError("Run preflight successfully before saving this connection.");
      return;
    }

    setSubmitting(checkOnly ? "check" : "save");
    setError(null);
    setSuccess(null);
    const formData = new FormData(form);
    const runtimeID = readField(formData, "runtime_id");
    const tenant = readField(formData, "tenant_id");
    const config: Record<string, string> = {};
    const credentials: Record<string, string> = {};
    const credentialReferences: Record<string, string> = {};
    const credentialFields = selectedMethod.credential_fields ?? [];

    try {
      (selectedMethod.config_fields ?? []).forEach((field) => {
        const value = readField(formData, field.key);
        if (value) config[field.key] = value;
      });

      credentialFields.forEach((field) => {
        const value = readField(formData, credentialInputName(field.key));
        if (!value) return;
        if (selectedMethod.id === "encrypted_submission") {
          credentials[field.key] = value;
        } else {
          credentialReferences[field.key] = value;
        }
      });

      const body: Record<string, unknown> = {
        runtime_id: runtimeID,
        tenant_id: tenant,
        auth_method: selectedMethod.id,
        credential_store_id: selectedStore.id,
        config,
      };
      if (!checkOnly) {
        body.check_only = false;
      }
      if (scopePolicy) {
        body.scope_policy = scopePolicy;
      }

      if (selectedMethod.id === "encrypted_submission") {
        const keyResponse = await fetchCerebro<ConnectorCredentialKey>("/connectors/credential-key", apiKey);
        if (!keyResponse.ok) throw new Error(connectorSubmitErrorMessage(keyResponse.status));
        body.encrypted_credentials = await encryptConnectorCredentials(keyResponse.data, credentials, {
          sourceID: connector.source_id,
          tenantID: tenant,
          runtimeID,
          credentialStoreID: selectedStore.id,
        });
      } else if (Object.keys(credentialReferences).length > 0) {
        body.credential_references = credentialReferences;
      }

      const path = checkOnly
        ? `/connectors/${encodeURIComponent(connector.source_id)}/preflight`
        : `/connectors/${encodeURIComponent(connector.source_id)}/connections`;
      const response = await fetchCerebro<ConnectorPreflightResponse>(path, apiKey, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!response.ok) throw new Error(connectorSubmitErrorMessage(response.status));
      if (checkOnly) {
        setPreflight(response.data);
        setSuccess(null);
      } else {
        const connection = response.data as ConnectorConnectionResponse;
        const context = connectorConnectedContextFromResponse(connection, {
          sourceID: connector.source_id,
          tenantID: tenant,
          runtimeID,
        });
        setPreflight(null);
        resetForm();
        setSuccess({ runtimeID: context.runtimeID, tenant: context.tenantID, storeLabel: selectedStore.label, status: "saved" });
        await onConnected(context);
      }
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : connectorSubmitErrorMessage());
    } finally {
      Object.keys(credentials).forEach((key) => {
        credentials[key] = "";
      });
      clearCredentialInputs(form, credentialFields);
      setSubmitting(null);
    }
  };

  return (
    <form
      ref={formRef}
      onInput={() => {
        setPreflight(null);
        updateFormValues();
      }}
      onReset={() => window.setTimeout(updateFormValues, 0)}
      onSubmit={(event) => { event.preventDefault(); void submitConnection(false); }}
      className="surface-panel max-w-full overflow-hidden"
    >
      <div className="border-b border-[color:var(--border)] px-5 py-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-[15px] font-semibold text-[var(--text-primary)]">Add connection</h2>
            <p className="mt-1 max-w-2xl text-[13px] leading-5 text-[var(--text-muted)]">
              Choose the authentication path, select where credentials live, validate access, then save the runtime.
            </p>
          </div>
          {selectedMethod && <Badge value={selectedMethod.label || selectedMethod.shortLabel} />}
        </div>
      </div>

      <div className="grid min-w-0 max-w-full gap-5 p-5 xl:grid-cols-[220px_minmax(0,1fr)]">
        <StepRail method={selectedMethod} storeLabel={selectedStore?.label} />
        <div className="min-w-0 space-y-4">
          {!anyStoreReady && <StoreReadinessChecklist stores={credentialStores} />}
          {error && <ErrorBlock error={error} />}
          {success && (
            <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-4 text-[13px] text-emerald-800 dark:border-emerald-500/25 dark:bg-emerald-500/10 dark:text-emerald-100">
              <div className="flex items-center gap-2 font-semibold"><CheckCircle2 className="h-4 w-4" /> Connection {success.status}</div>
              <div className="mt-1 text-[12px] leading-5">
                {success.runtimeID} for {success.tenant || "default tenant"} using {success.storeLabel}.
              </div>
            </div>
          )}
          <OnboardingBrief method={selectedMethod} store={selectedStore} basicsReady={basicsReady} fieldsReady={requiredFieldsReady} scopeCount={scopeCount} preflight={preflight} />
          <SetupCheckpointStrip
            method={selectedMethod}
            store={selectedStore}
            basicsReady={basicsReady}
            fieldsReady={requiredFieldsReady}
            scopeCount={scopeCount}
            preflight={preflight}
            canSubmit={canSubmit}
          />
          <ConnectionPathSummary method={selectedMethod} store={selectedStore} scopeCount={scopeCount} preflight={preflight} />
          {preflight && <PreflightCockpit preflight={preflight} method={selectedMethod} store={selectedStore} scopeCount={scopeCount} />}
          <SetupGuidancePanel method={selectedMethod} />

          <SetupStep index={1} title="Choose authentication method" icon={<KeyRound className="h-4 w-4" />}>
            <p className="mb-3 text-[12px] leading-5 text-[var(--text-muted)]">
              Available methods are advertised by the backend for this source. Unsupported methods are collapsed below.
            </p>
            <MethodTabs methods={methods} selectedID={effectiveSelectedMethodID ?? "encrypted_submission"} onSelect={changeMethod} />
          </SetupStep>

          <SetupStep index={2} title="Name connection" icon={<TerminalSquare className="h-4 w-4" />}>
            <div className="grid gap-3 md:grid-cols-2">
              <label className={labelClass}>
                Tenant
                <input name="tenant_id" defaultValue={tenantID} required placeholder="tenant" className={inputClass} />
              </label>
              <label className={labelClass}>
                Connection ID
                <input name="runtime_id" defaultValue={defaultRuntimeID} required placeholder="tenant-source" className={inputClass} />
              </label>
            </div>
          </SetupStep>

          <SetupStep index={3} title="Choose credential store" icon={<LockKeyhole className="h-4 w-4" />}>
            {selectedMethod && (
              <>
                <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                  <p className="max-w-2xl text-[12px] leading-5 text-[var(--text-muted)]">{selectedMethod.description}</p>
                  <span className="rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-2.5 py-1 text-[12px] font-semibold text-[var(--text-secondary)]">
                    {selectedStore?.available ? selectedStore.label : "No ready store"}
                  </span>
                </div>
                <CredentialStoreSelector
                  stores={visibleStores}
                  selectedID={effectiveSelectedStoreID}
                  onSelect={(storeID) => {
                    setSelectedStoreID(storeID);
                    setPreflight(null);
                  }}
                  compact
                />
                <SecretStoreIntegrationPanel store={selectedStore} method={selectedMethod} />
				<CredentialReferencePlan
					connector={connector}
					method={selectedMethod}
					store={selectedStore}
					tenantID={planTenantID}
                  runtimeID={planRuntimeID}
					preflight={preflight}
					onApply={applyCredentialReferenceRows}
				/>
				<CredentialBrokerPanel
					connector={connector}
					method={selectedMethod}
					store={selectedStore}
					tenantID={planTenantID}
					runtimeID={planRuntimeID}
					apiKey={apiKey}
				/>
			</>
		)}
	</SetupStep>

          <SetupStep index={4} title="Configure source" icon={<TerminalSquare className="h-4 w-4" />}>
            {selectedMethod?.commands && selectedMethod.commands.length > 0 && (
              <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-4">
                <div className="mb-3 flex items-center gap-2 text-[13px] font-semibold text-[var(--text-primary)]">
                  <TerminalSquare className="h-4 w-4 text-[var(--text-muted)]" />
                  CLI preflight
                </div>
                <CommandBlock commands={selectedMethod.commands} />
              </div>
            )}

            {selectedMethod && (selectedMethod.config_fields?.length ?? 0) > 0 && (
              <div className="mt-4">
                <div className="mb-3 text-[13px] font-semibold text-[var(--text-primary)]">Configuration</div>
                <FieldGrid fields={selectedMethod.config_fields ?? []} />
              </div>
            )}

            {selectedMethod && (selectedMethod.credential_fields?.length ?? 0) > 0 && (
              <div className="mt-4">
                <div className="mb-3">
                  <div className="flex items-center gap-2 text-[13px] font-semibold text-[var(--text-primary)]">
                    {selectedMethod.id === "encrypted_submission" ? <LockKeyhole className="h-4 w-4 text-[var(--text-muted)]" /> : <AlertCircle className="h-4 w-4 text-[var(--text-muted)]" />}
                    {selectedMethod.id === "encrypted_submission" ? "Credential material" : "Credential references"}
                  </div>
                  <div className="mt-0.5 text-[12px] text-[var(--text-muted)]">
                    {selectedMethod.id === "encrypted_submission"
                      ? "Values are encrypted before submission and cleared after every attempt."
                      : "Enter server-resolvable references only; do not enter secret values."}
                  </div>
                </div>
                <FieldGrid fields={selectedMethod.credential_fields ?? []} credential store={selectedStore} methodID={selectedMethod.id} />
              </div>
            )}
            <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(260px,0.65fr)]">
              <RegionGuidancePanel method={selectedMethod} />
              {selectedMethod?.deployment_guides?.slice(0, 1).map((guide) => (
                <DeploymentGuideCard key={guide.id} guide={guide} />
              ))}
            </div>
            {(selectedMethod?.deployment_guides?.length ?? 0) > 1 && (
              <details className="mt-4 rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-4">
                <summary className="cursor-pointer list-none">
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-2 text-[13px] font-semibold text-[var(--text-primary)]">
                      <Code2 className="h-4 w-4 text-[var(--text-muted)]" />
                      Deployment snippets
                    </div>
                    <Badge value={`${(selectedMethod?.deployment_guides?.length ?? 1) - 1} more`} />
                  </div>
                </summary>
                <div className="mt-4 grid gap-3">
                  {selectedMethod?.deployment_guides?.slice(1).map((guide) => (
                    <DeploymentGuideCard key={guide.id} guide={guide} />
                  ))}
                </div>
              </details>
            )}
          </SetupStep>

          <SetupStep index={5} title="Choose collected resources" icon={<SlidersHorizontal className="h-4 w-4" />}>
            <div className="space-y-4">
              <ProductGroupSelector
                groups={selectedMethod?.product_groups ?? []}
                selectedFamilies={excludedFamilies}
                onDisableFamilies={(families) => updateScopeFamilies(families, true)}
                onEnableFamilies={(families) => updateScopeFamilies(families, false)}
              />
              <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-4">
                <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="text-[13px] font-semibold text-[var(--text-primary)]">Resource types to collect</div>
                    <div className="mt-0.5 max-w-3xl text-[12px] leading-5 text-[var(--text-muted)]">
                      Source-advertised resource types. Disabled resource types are skipped before collection where supported.
                    </div>
                  </div>
                  <Badge value={scopeCount > 0 ? `${scopeCount} excluded` : "all collected"} />
                </div>
                <ScopePolicyBuilder
                  connector={connector}
                  selectedFamilies={excludedFamilies}
                  protectedFamilies={protectedProductFamilies}
                  initialFramework={initialFramework}
                  onDisableFamilies={(families) => updateScopeFamilies(families, true)}
                  onEnableFamilies={(families) => updateScopeFamilies(families, false)}
                  resourceURNs={resourceURNs}
                  onResourceURNsChange={updateResourceURNs}
                  resources={excludedResources}
                  onResourcesChange={updateExcludedResources}
                />
              </div>
            </div>
          </SetupStep>
        </div>
      </div>

      <div className="sticky bottom-0 z-20 flex flex-wrap items-center justify-between gap-3 border-t border-[color:var(--border)] bg-[var(--surface)] px-5 py-4 shadow-[0_-16px_36px_rgba(15,23,42,0.08)]">
        <div className="flex min-w-0 items-start gap-3">
          <div className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)]">
            <PreflightIcon status={preflight?.status} />
          </div>
          <div className="min-w-0">
            <div className="text-[12px] font-semibold text-[var(--text-primary)]">
              {preflight ? preflightStatusLabel(preflight.status) : canSubmit ? "Ready for preflight" : "Complete setup fields"}
            </div>
            <div aria-live="polite" className="mt-0.5 max-w-3xl text-[12px] leading-5 text-[var(--text-muted)]">
            {preflight
              ? `${preflightStatusLabel(preflight.status)} · ${preflight.summary}`
              : canSave
                ? "Preflight passed. Save when ready."
                : "Run preflight before saving."}
            </div>
          </div>
        </div>
        <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto">
          <button type="button" onClick={resetForm} className="secondary-button w-full px-3 py-2 text-[13px] sm:w-auto">
            Reset
          </button>
          <button
            type="button"
            disabled={!canSubmit || submitting !== null}
            onClick={() => void submitConnection(true)}
            className="secondary-button w-full px-4 py-2 text-[13px] disabled:cursor-not-allowed disabled:opacity-55 sm:w-auto"
          >
            {submitting === "check" ? "Running..." : "Run preflight"}
          </button>
          <button type="submit" disabled={!canSave || submitting !== null} className="primary-button w-full px-4 py-2 text-[13px] disabled:cursor-not-allowed disabled:opacity-55 sm:w-auto">
            {submitting === "save" ? "Saving..." : "Save connection"}
          </button>
        </div>
      </div>
    </form>
  );
}
