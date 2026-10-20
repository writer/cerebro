"use client";

import Link from "next/link";
import { useMemo, type ReactNode } from "react";
import {
  AlertTriangle,
  ArrowRight,
  Bot,
  CheckCircle2,
  FileJson2,
  PlugZap,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
} from "lucide-react";

import { Badge, EmptyBlock, ErrorBlock, LoadingBlock, PageHeader, Panel, ResultLimitNotice } from "@/components/grc/Primitives";
import { extractRecords, withQuery } from "@/lib/cerebro-data";
import { useConnectorLibraryQuery } from "@/lib/connector-library-query";
import { useGRCQuery } from "@/lib/grc-client";
import { grcBoundedRows } from "@/lib/grc-list";
import { runtimeStateForError } from "@/lib/runtime-state";
import {
  ConnectorCatalogEntry,
  ConnectorDefinition,
  ConnectorDefinitionListResponse,
  connectorDefinitionBlockingChecks,
  connectorDefinitionStatus,
  connectorDefinitionValidationLabel,
  connectorDisplayMetadata,
  connectorDisplayName,
  connectorIsCatalogOnly,
  connectorSetupAllowed,
} from "@/lib/connectors";
import {
  buildConnectorCards,
  compactConnectorStatus,
  connectorCapabilities,
  connectorCapabilityLabel,
  connectorHealthyTotal,
  connectorPath,
  connectorResourceTypeStats,
  connectorResourceTypes,
  connectorRuntimeTotal,
  filterConnectorCards,
  providerAPIProofMetrics,
  providerAPIProofQueue,
  readinessDescriptions,
  type ConnectorCard,
} from "@/lib/connector-view";
import { normalizeSourceRuntimeSummary, type SourceReadiness } from "@/lib/connector-runtime";
import { useQueryParamState } from "@/lib/query-params";
import {
  sourceCredentialHealth,
  type CredentialStoreListResponse,
  type SourceCredentialHealth,
} from "@/lib/credential-stores";

type IntegrationTab = "connected" | "attention" | "available";

type ConnectorRuntimeHealthResponse = {
  runtimes?: unknown[];
  source_summaries?: unknown[];
};

const CONNECTOR_RUNTIME_LIMIT = 500;
const INTEGRATION_RENDER_LIMIT = 60;

const integrationTabs: Array<{ id: IntegrationTab; label: string; icon: ReactNode }> = [
  { id: "connected", label: "Connected", icon: <CheckCircle2 className="h-4 w-4" /> },
  { id: "attention", label: "Needs attention", icon: <AlertTriangle className="h-4 w-4" /> },
  { id: "available", label: "Available", icon: <PlugZap className="h-4 w-4" /> },
];

const tabEmptyCopy: Record<IntegrationTab, string> = {
  attention: "Every connected integration is healthy.",
  available: "No more integrations are available to connect.",
  connected: "Nothing is connected yet. Open Available to add your first integration.",
};

// Status words a person can act on, rather than the runtime's internal readiness names.
const statusPill: Record<SourceReadiness, { label: string; className: string; dot: string }> = {
  bad: { label: "Failing", className: "bg-red-50 text-red-700 ring-red-200 dark:bg-red-500/10 dark:text-red-200 dark:ring-red-500/25", dot: "bg-red-500" },
  healthy: { label: "Healthy", className: "bg-emerald-50 text-emerald-700 ring-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-200 dark:ring-emerald-500/25", dot: "bg-emerald-500" },
  needs_refresh: { label: "Stale", className: "bg-amber-50 text-amber-800 ring-amber-200 dark:bg-amber-500/10 dark:text-amber-200 dark:ring-amber-500/25", dot: "bg-amber-500" },
  not_configured: { label: "Not connected", className: "bg-[var(--surface-muted)] text-[var(--text-muted)] ring-[color:var(--border)]", dot: "bg-zinc-400" },
  poor: { label: "Degraded", className: "bg-orange-50 text-orange-700 ring-orange-200 dark:bg-orange-500/10 dark:text-orange-200 dark:ring-orange-500/25", dot: "bg-orange-500" },
};

const credentialLabels: Record<SourceCredentialHealth["state"], string> = {
  attention: "Needs attention",
  failing: "Failing",
  ok: "Valid",
};

function isConnected(card: ConnectorCard) {
  return connectorRuntimeTotal(card) > 0;
}

// Catalog entries nobody can set up from this console are left out entirely;
// there is nothing to do with them here.
function isListed(card: ConnectorCard) {
  return isConnected(card) || (connectorSetupAllowed(card) && !connectorIsCatalogOnly(card));
}

function needsAttention(card: ConnectorCard, credential?: SourceCredentialHealth) {
  if (!isConnected(card)) return false;
  const status = compactConnectorStatus(card);
  return (status !== "healthy" && status !== "not_configured") || (credential !== undefined && credential.state !== "ok");
}

function tabMatches(tab: IntegrationTab, card: ConnectorCard, credential?: SourceCredentialHealth) {
  if (tab === "connected") return isConnected(card);
  if (tab === "attention") return needsAttention(card, credential);
  return !isConnected(card);
}

function ProviderMark({ connector }: { connector: ConnectorCatalogEntry }) {
  const meta = connectorDisplayMetadata(connector);
  return (
    <div className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-xl ring-1 ${meta.accentClass}`}>
      <span className="text-[12px] font-bold tracking-tight">{meta.logoText}</span>
    </div>
  );
}

function StatusPill({ status }: { status: SourceReadiness }) {
  const pill = statusPill[status];
  return (
    <span className={`inline-flex shrink-0 items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ${pill.className}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${pill.dot}`} />
      {pill.label}
    </span>
  );
}

function Stat({ label, value, detail, attention = false }: { label: string; value: ReactNode; detail?: ReactNode; attention?: boolean }) {
  return (
    <div className="min-w-0">
      <div className="text-[10px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">{label}</div>
      <div className={`mt-0.5 truncate text-[13px] font-semibold ${attention ? "text-amber-700 dark:text-amber-200" : "text-[var(--text-primary)]"}`}>{value}</div>
      {detail && <div className="truncate text-[11px] text-[var(--text-muted)]">{detail}</div>}
    </div>
  );
}

function shortDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function credentialValue(credential: SourceCredentialHealth) {
  return credential.state === "ok" && credential.referenceOnly ? "Referenced" : credentialLabels[credential.state];
}

function IntegrationTile({ card, credential }: { card: ConnectorCard; credential?: SourceCredentialHealth }) {
  const status = compactConnectorStatus(card);
  const meta = connectorDisplayMetadata(card);
  const connected = isConnected(card);
  const total = connectorRuntimeTotal(card);
  const healthy = connectorHealthyTotal(card);
  const credentialProblem = credential !== undefined && credential.state !== "ok";
  const runtimeProblem = connected && status !== "healthy";
  const resourceTypeCount = connectorResourceTypeStats(card).resourceTypes;
  const capabilities = connectorCapabilities(card, 3);
  const lastActivity = card.coverage?.latest_activity_at;

  const issue = credentialProblem
    ? `Credential: ${credential?.detail || credentialLabels[credential.state]}`
    : runtimeProblem
      ? card.coverage?.next_action || card.nextAction || readinessDescriptions[status]
      : "";
  const href = connectorPath(card.source_id, { tab: !connected || credentialProblem ? "setup" : undefined });
  const action = !connected ? "Connect" : credentialProblem || runtimeProblem ? "Fix" : "Manage";

  return (
    <Link
      href={href}
      className="group surface-panel flex h-full flex-col p-4 transition hover:-translate-y-0.5 hover:border-[color:var(--border-strong)] hover:shadow-[var(--shadow-md)]"
    >
      <div className="flex items-start gap-3">
        <ProviderMark connector={card} />
        <div className="min-w-0 flex-1">
          <div className="flex items-start justify-between gap-2">
            <h3 className="truncate text-[15px] font-semibold leading-5 text-[var(--text-primary)]">{connectorDisplayName(card)}</h3>
            <StatusPill status={connected ? status : "not_configured"} />
          </div>
          <div className="mt-0.5 text-[12px] text-[var(--text-muted)]">{meta.category}</div>
        </div>
      </div>

      {connected ? (
        <div className="mt-4 grid grid-cols-3 gap-3 rounded-lg bg-[var(--surface-muted)] px-3 py-2.5">
          <Stat label="Connections" value={`${healthy}/${total} healthy`} attention={healthy < total} />
          <Stat label="Last sync" value={lastActivity ? shortDate(lastActivity) : "Never"} attention={!lastActivity} />
          {credential ? (
            <Stat
              label="Credential"
              value={credentialValue(credential)}
              detail={credential.lastValidatedAt ? `checked ${shortDate(credential.lastValidatedAt)}` : credential.stores.join(", ")}
              attention={credentialProblem}
            />
          ) : (
            <Stat label="Credential" value="Unknown" />
          )}
        </div>
      ) : (
        <>
          <p className="mt-3 line-clamp-2 text-[13px] leading-5 text-[var(--text-secondary)]">{card.description || meta.category}</p>
          {capabilities.length > 0 && (
            <div className="mt-3 flex flex-wrap gap-1.5">
              {capabilities.map((capability) => (
                <span key={capability} className="rounded-md bg-[var(--surface-muted)] px-2 py-0.5 text-[11px] font-semibold text-[var(--text-secondary)]">
                  {connectorCapabilityLabel(capability)}
                </span>
              ))}
            </div>
          )}
        </>
      )}

      {issue && (
        <div className="mt-3 flex items-start gap-2 text-[12px] leading-5 text-amber-800 dark:text-amber-200">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span className="line-clamp-2">{issue}</span>
        </div>
      )}

      <div className="mt-auto flex items-center justify-between gap-3 pt-4 text-[12px]">
        <span className="text-[var(--text-muted)]">
          {resourceTypeCount > 0 ? `Collects ${resourceTypeCount} resource type${resourceTypeCount === 1 ? "" : "s"}` : ""}
        </span>
        <span className={`inline-flex items-center gap-1 font-semibold ${action === "Fix" ? "text-amber-700 dark:text-amber-200" : "text-[var(--primary)]"}`}>
          {action}
          <ArrowRight className="h-3.5 w-3.5 transition group-hover:translate-x-0.5" />
        </span>
      </div>
    </Link>
  );
}

function IntegrationTabs({
  active,
  counts,
  onTab,
}: {
  active: IntegrationTab;
  counts: Record<IntegrationTab, number>;
  onTab: (tab: IntegrationTab) => void;
}) {
  return (
    <div role="tablist" className="inline-flex rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] p-1">
      {integrationTabs.map((tab) => {
        const selected = active === tab.id;
        const warn = tab.id === "attention" && counts.attention > 0;
        return (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={selected}
            onClick={() => onTab(tab.id)}
            className={`inline-flex h-8 items-center gap-1.5 rounded-md px-3 text-[13px] font-semibold transition ${
              selected
                ? "bg-[var(--surface)] text-[var(--text-primary)] shadow-[var(--shadow-sm)]"
                : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            }`}
          >
            {tab.icon}
            {tab.label}
            <span className={`rounded px-1.5 text-[11px] ${warn ? "bg-amber-100 text-amber-800 dark:bg-amber-500/20 dark:text-amber-100" : "bg-current/10 text-[var(--text-muted)]"}`}>
              {counts[tab.id]}
            </span>
          </button>
        );
      })}
    </div>
  );
}

function CustomIntegrationsPanel({
  definitions,
  error,
  onRetry,
}: {
  definitions: ConnectorDefinition[];
  error: string | null;
  onRetry: () => void;
}) {
  return (
    <Panel
      title="Custom Integrations"
      action={
        <Link href="/integrations/builder" className="secondary-button inline-flex items-center gap-1.5 px-2.5 py-1.5 text-[12px]">
          <Bot className="h-3.5 w-3.5" />
          Build
        </Link>
      }
    >
      <div className="space-y-2">
        {error && <ErrorBlock error={error} onRetry={onRetry} recoveryDetail="Custom integration definitions require backend support." />}
        {!error && definitions.slice(0, 5).map((definition) => {
          const status = connectorDefinitionStatus(definition);
          const blocking = connectorDefinitionBlockingChecks(definition);
          return (
            <Link
              key={definition.id ?? definition.source_id}
              href={`/integrations/builder?definition_id=${encodeURIComponent(definition.id ?? "")}`}
              className="block rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-3 transition hover:border-[color:var(--border-strong)]"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="truncate text-[13px] font-semibold text-[var(--text-primary)]">{definition.display_name}</div>
                  <div className="mt-1 text-[11px] text-[var(--text-muted)]">{definition.source_id} · {definition.resource_families?.length ?? 0} resource types</div>
                </div>
                <Badge value={definition.stage || "draft"} />
              </div>
              <div className="mt-3 flex items-center justify-between gap-3 text-[11px] text-[var(--text-muted)]">
                <span>{connectorDefinitionValidationLabel(status)}</span>
                <span>{blocking} blockers</span>
              </div>
            </Link>
          );
        })}
        {!error && definitions.length === 0 && <EmptyBlock label="No custom integration definitions yet." />}
      </div>
    </Panel>
  );
}

function ProviderAPIProofPanel({
  items,
  metrics,
}: {
  items: ReturnType<typeof providerAPIProofQueue>;
  metrics: ReturnType<typeof providerAPIProofMetrics>;
}) {
  return (
    <Panel title="API Proof Queue" action={<Badge value={`${metrics.needsAction} open`} />}>
      <div className="grid grid-cols-3 gap-3 rounded-lg bg-[var(--surface-muted)] px-3 py-2.5">
        <Stat label="Needs action" value={metrics.needsAction} attention={metrics.needsAction > 0} />
        <Stat label="Verified" value={metrics.verified} />
        <Stat label="Avg score" value={metrics.averageScore === null ? "No score" : `${metrics.averageScore}/100`} attention={metrics.averageScore !== null && metrics.averageScore < 90} />
      </div>
      <div className="mt-3 space-y-2">
        {items.map((item) => (
          <Link key={item.sourceID} href={item.href} className="block rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-3 transition hover:border-[color:var(--border-strong)]">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="truncate text-[13px] font-semibold text-[var(--text-primary)]">{item.displayName}</div>
                <div className="mt-1 text-[12px] leading-5 text-[var(--text-secondary)]">{item.detail}</div>
              </div>
              <div className="shrink-0 text-right">
                <Badge value={item.label} />
                <div className="mt-1 text-[11px] text-[var(--text-muted)]">{item.score === null ? item.tier : `${item.score}/100`}</div>
              </div>
            </div>
            {item.missing.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1.5">
                {item.missing.slice(0, 3).map((missing) => (
                  <span key={missing} className="rounded-md bg-[var(--surface-muted)] px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)]">
                    {connectorCapabilityLabel(missing)}
                  </span>
                ))}
              </div>
            )}
          </Link>
        ))}
        {items.length === 0 && <EmptyBlock label="No API proof work for these integrations." />}
      </div>
    </Panel>
  );
}

function ResourceTypesPanel({ cards }: { cards: ConnectorCard[] }) {
  const topCards = [...cards]
    .filter((card) => connectorResourceTypeStats(card).resourceTypes > 0)
    .sort((left, right) =>
      connectorResourceTypeStats(right).resourceTypes - connectorResourceTypeStats(left).resourceTypes ||
      connectorDisplayName(left).localeCompare(connectorDisplayName(right)),
    )
    .slice(0, 5);

  return (
    <Panel title="What Each Integration Collects">
      <div className="space-y-2">
        {topCards.map((card) => {
          const stats = connectorResourceTypeStats(card);
          return (
            <Link
              key={card.source_id}
              href={connectorPath(card.source_id, { tab: "scope" })}
              className="flex items-center justify-between gap-3 rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-3 transition hover:border-[color:var(--border-strong)]"
            >
              <div className="min-w-0">
                <div className="truncate text-[13px] font-semibold text-[var(--text-primary)]">{connectorDisplayName(card)}</div>
                <div className="mt-1 truncate text-[11px] text-[var(--text-muted)]">
                  {connectorResourceTypes(card, 3).map((item) => item.label).join(", ") || `${stats.distinctResourceTypes} type mappings`}
                </div>
              </div>
              <span className="shrink-0 text-[12px] font-semibold text-[var(--text-secondary)]">{stats.resourceTypes} types</span>
            </Link>
          );
        })}
        {topCards.length === 0 && <EmptyBlock label="No resource types listed yet." />}
      </div>
    </Panel>
  );
}

export default function IntegrationsPage() {
  const [query, setQuery] = useQueryParamState("q");
  const [tabValue, setTab] = useQueryParamState("tab", "connected");

  const libraryQuery = useConnectorLibraryQuery({ view: "summary" });
  const runtimeHealthQuery = useGRCQuery<ConnectorRuntimeHealthResponse>(withQuery("/v1/source-runtimes/health", { limit: CONNECTOR_RUNTIME_LIMIT }));
  const definitionsQuery = useGRCQuery<ConnectorDefinitionListResponse>("/connector-definitions");
  // Viewers without connector-credentials:read get an error here; tiles then
  // show the credential as unknown rather than failing the page.
  const credentialStoresQuery = useGRCQuery<CredentialStoreListResponse>(withQuery("/credential-stores", { limit: 1000 }));
  const credentialHealth = useMemo(() => sourceCredentialHealth(credentialStoresQuery.data), [credentialStoresQuery.data]);

  const runtimeSummaries = useMemo(
    () => extractRecords(runtimeHealthQuery.data, ["source_summaries"]).map(normalizeSourceRuntimeSummary),
    [runtimeHealthQuery.data],
  );
  const cards = useMemo(
    () => buildConnectorCards(libraryQuery.data?.connectors ?? [], runtimeSummaries).filter(isListed),
    [libraryQuery.data, runtimeSummaries],
  );

  const credentialFor = (card: ConnectorCard) => (isConnected(card) ? credentialHealth.get(card.source_id) : undefined);
  const tab = (integrationTabs.some((item) => item.id === tabValue) ? tabValue : "connected") as IntegrationTab;
  const counts = useMemo(
    () => integrationTabs.reduce(
      (acc, item) => ({ ...acc, [item.id]: cards.filter((card) => tabMatches(item.id, card, isConnected(card) ? credentialHealth.get(card.source_id) : undefined)).length }),
      {} as Record<IntegrationTab, number>,
    ),
    [cards, credentialHealth],
  );

  const visibleCards = useMemo(() => {
    const rank = (card: ConnectorCard) => {
      const credential = isConnected(card) ? credentialHealth.get(card.source_id) : undefined;
      if (credential?.state === "failing" || compactConnectorStatus(card) === "bad") return 2;
      return needsAttention(card, credential) ? 1 : 0;
    };
    const scoped = cards.filter((card) => tabMatches(tab, card, isConnected(card) ? credentialHealth.get(card.source_id) : undefined));
    return filterConnectorCards(scoped, query, "all")
      .map((card, index) => ({ card, index, rank: rank(card) }))
      .sort((a, b) => b.rank - a.rank || a.index - b.index)
      .map((entry) => entry.card);
  }, [cards, credentialHealth, query, tab]);
  const bounded = useMemo(
    () => grcBoundedRows({ rows: visibleCards, limit: INTEGRATION_RENDER_LIMIT, total: visibleCards.length }),
    [visibleCards],
  );

  const loading = (libraryQuery.loading && !libraryQuery.data) || (runtimeHealthQuery.loading && !runtimeHealthQuery.data);
  const loadError = libraryQuery.error || runtimeHealthQuery.error;
  const errorState = runtimeStateForError(loadError);
  const apiProofMetrics = useMemo(() => providerAPIProofMetrics(cards), [cards]);
  const apiProofQueue = useMemo(() => providerAPIProofQueue(cards, {}), [cards]);
  const reload = () => {
    void libraryQuery.reload();
    void runtimeHealthQuery.reload();
    void definitionsQuery.reload();
    void credentialStoresQuery.reload();
  };

  return (
    <div className="space-y-6">
      <PageHeader
        contractId="connectors"
        title="Integrations"
        description="The clouds, SaaS apps, identity providers, and scanners Cerebro collects from."
        action={
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={reload}
              className="secondary-button inline-flex h-9 w-9 items-center justify-center p-0"
              aria-label="Refresh integrations"
              title="Refresh integrations"
            >
              <RefreshCw className="h-4 w-4" />
            </button>
            <button type="button" onClick={() => setTab("available")} className="primary-button inline-flex h-9 items-center gap-2 px-3 text-[13px]">
              <Plus className="h-4 w-4" />
              Add Integration
            </button>
          </div>
        }
      />

      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <IntegrationTabs active={tab} counts={counts} onTab={setTab} />
        <label className="relative block md:w-80">
          <span className="sr-only">Search integrations</span>
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--text-muted)]" />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search integrations"
            className="control-input h-10 w-full px-9 text-[13px]"
          />
        </label>
      </div>

      {loading && <LoadingBlock label="Loading integrations..." />}
      {loadError && (
        <ErrorBlock
          error={loadError}
          onRetry={reload}
          recoveryDetail={errorState === "unavailable" ? "Integration health appears when the Cerebro API is reachable." : undefined}
        />
      )}

      {!loading && (
        <section aria-label="Integrations" className="space-y-3">
          {bounded.rows.length < visibleCards.length && (
            <ResultLimitNotice loaded={bounded.rows.length} meta={bounded.meta} limit={INTEGRATION_RENDER_LIMIT} noun="integrations" />
          )}
          {bounded.rows.length > 0 ? (
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
              {bounded.rows.map((card) => (
                <IntegrationTile key={card.source_id} card={card} credential={credentialFor(card)} />
              ))}
            </div>
          ) : (
            <EmptyBlock label={query.trim() ? `No integrations match "${query.trim()}".` : tabEmptyCopy[tab]} />
          )}
        </section>
      )}

      <details className="surface-panel overflow-hidden">
        <summary className="cursor-pointer list-none px-4 py-4 marker:hidden">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <div className="text-[13px] font-semibold text-[var(--text-primary)]">Advanced integration tools</div>
              <p className="mt-1 text-[12px] leading-5 text-[var(--text-muted)]">
                Build custom integrations, review activation, and check API coverage.
              </p>
            </div>
            <span className="secondary-button px-2.5 py-1.5 text-[12px]">Open tools</span>
          </div>
        </summary>
        <div className="space-y-5 border-t border-[color:var(--border)] p-4">
          <div className="flex flex-wrap gap-2">
            <Link href="/integrations/builder" className="secondary-button inline-flex items-center gap-2 px-3 py-2 text-[12px]">
              <FileJson2 className="h-4 w-4" />
              Build custom integration
            </Link>
            <Link href="/integrations/activation" className="secondary-button inline-flex items-center gap-2 px-3 py-2 text-[12px]">
              <ShieldCheck className="h-4 w-4" />
              Review activation
            </Link>
          </div>
          <div className="grid items-start gap-5 xl:grid-cols-2">
            <ProviderAPIProofPanel items={apiProofQueue} metrics={apiProofMetrics} />
            <ResourceTypesPanel cards={cards} />
            <CustomIntegrationsPanel definitions={definitionsQuery.data?.definitions ?? []} error={definitionsQuery.error} onRetry={() => void definitionsQuery.reload()} />
          </div>
        </div>
      </details>
    </div>
  );
}
