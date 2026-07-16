"use client";

import Link from "next/link";
import { useMemo, type ReactNode } from "react";
import {
  AlertTriangle,
  ArrowUpRight,
  Bot,
  CheckCircle2,
  Database,
  FileJson2,
  PlugZap,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
} from "lucide-react";

import { AppliedFilterChips, Badge, EmptyBlock, ErrorBlock, LoadingBlock, MetricCard, PageHeader, Panel, ResultLimitNotice } from "@/components/grc/Primitives";
import { extractRecords, withQuery } from "@/lib/cerebro-data";
import { useConnectorLibraryQuery } from "@/lib/connector-library-query";
import { useDebouncedValue, useGRCQuery } from "@/lib/grc-client";
import { grcBoundedRows } from "@/lib/grc-list";
import { displayDate, shortEntity } from "@/lib/grc";
import { runtimeStateForError, type RuntimeState } from "@/lib/runtime-state";
import {
  ConnectorCatalogEntry,
  ConnectorDefinition,
  ConnectorDefinitionListResponse,
  connectorDefinitionBlockingChecks,
  connectorDefinitionStatus,
  connectorDefinitionValidationLabel,
  connectorCatalogStatusLabel,
  connectorAccessStatusLabel,
  connectorIntegrationDepthLabel,
  connectorReadinessStageLabel,
  connectorRequestActionLabel,
  connectorDisplayMetadata,
  connectorDisplayName,
  connectorIsCatalogOnly,
  connectorRuntimeSurfaceLabel,
  connectorSetupAllowed,
} from "@/lib/connectors";
import {
  buildConnectorCards,
  compactConnectorStatus,
  connectorAttentionTotal,
  connectorCapabilityLabel,
  connectorCapabilities,
  connectorHealthyTotal,
  connectorPath,
  connectorPrimaryAction,
  connectorResourceTypes,
  connectorResourceTypeStats,
  connectorRuntimeTotal,
  filterConnectorCards,
  providerAPIProofMetrics,
  providerAPIProofQueue,
  readinessDescriptions,
  readinessLabels,
  readinessOrder,
  readinessRowClass,
  type ConnectorCard,
  type ReadinessFilter,
} from "@/lib/connector-view";
import {
  formatDuration,
  normalizeRuntime,
  sourceHealthBreakdown,
  type ConnectorRuntime,
  type SourceReadiness,
} from "@/lib/connector-runtime";
import { useQueryParamState } from "@/lib/query-params";

type LibraryTab = "all" | "attention" | "connected" | "available" | "backlog";

const inputClass = "control-input mt-1 w-full px-3 py-2 text-[13px]";
const labelClass = "text-[11px] font-semibold text-[var(--text-muted)]";
const CONNECTOR_RUNTIME_LIMIT = 500;
const CONNECTOR_RENDER_LIMIT = 50;

const libraryTabs: Array<{ id: LibraryTab; label: string; icon: ReactNode }> = [
  { id: "connected", label: "Connected", icon: <CheckCircle2 className="h-4 w-4" /> },
  { id: "attention", label: "Needs attention", icon: <AlertTriangle className="h-4 w-4" /> },
  { id: "available", label: "Available", icon: <PlugZap className="h-4 w-4" /> },
  { id: "backlog", label: "Backlog", icon: <Bot className="h-4 w-4" /> },
  { id: "all", label: "All", icon: <Database className="h-4 w-4" /> },
];

function tabMatchesCard(tab: LibraryTab, card: ConnectorCard) {
  const status = compactConnectorStatus(card);
  if (tab === "attention") return status !== "healthy" && status !== "not_configured";
  if (tab === "connected") return connectorRuntimeTotal(card) > 0;
  if (tab === "available") return connectorRuntimeTotal(card) === 0;
  if (tab === "backlog") return !connectorSetupAllowed(card) && Boolean(card.requestable);
  return true;
}

function ProviderMark({ connector }: { connector: ConnectorCatalogEntry }) {
  const meta = connectorDisplayMetadata(connector);
  return (
    <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ring-1 ${meta.accentClass}`}>
      <span className="text-[12px] font-bold tracking-tight">{meta.logoText}</span>
    </div>
  );
}

function LibraryTabButton({
  id,
  active,
  count,
  onClick,
}: {
  id: LibraryTab;
  active: boolean;
  count: number;
  onClick: () => void;
}) {
  const tab = libraryTabs.find((item) => item.id === id);
  if (!tab) return null;
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
      {tab.icon}
      <span>{tab.label}</span>
      <span className={`rounded bg-current/10 px-1.5 py-0.5 text-[11px] ${active ? "text-[var(--surface)]" : "text-[var(--text-muted)]"}`}>{count}</span>
    </button>
  );
}

function SourceSignal({ label, value, attention = false }: { label: string; value: ReactNode; attention?: boolean }) {
  return (
    <div className={`rounded-md border px-2.5 py-2 ${attention ? "border-amber-200 bg-amber-50 text-amber-950 dark:border-amber-500/25 dark:bg-amber-500/10 dark:text-amber-100" : "border-[color:var(--border)] bg-[var(--surface-muted)] text-[var(--text-secondary)]"}`}>
      <div className="text-[10px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">{label}</div>
      <div className="mt-0.5 text-[12px] font-semibold">{value}</div>
    </div>
  );
}

function ConnectorLibraryRow({
  card,
  active,
  tenantID,
}: {
  card: ConnectorCard;
  active: boolean;
  tenantID: string;
}) {
  const status = compactConnectorStatus(card);
  const meta = connectorDisplayMetadata(card);
  const displayName = connectorDisplayName(card);
  const capabilities = connectorCapabilities(card, 4);
  const resourceTypes = connectorResourceTypes(card, 4);
  const resourceTypeStats = connectorResourceTypeStats(card);
  const total = connectorRuntimeTotal(card);
  const healthy = connectorHealthyTotal(card);
  const attention = connectorAttentionTotal(card);
  const catalogOnly = connectorIsCatalogOnly(card);
  const setupAllowed = connectorSetupAllowed(card);
  const primaryAction = connectorPrimaryAction(card);
  const href = connectorPath(card.source_id, { tenant_id: tenantID, tab: status === "not_configured" && setupAllowed && !catalogOnly ? "setup" : undefined });
  const requestHref = !setupAllowed && card.requestable ? card.request_access_url?.trim() : "";
  const statusDescription = readinessDescriptions[status];
  const latestActivity = card.coverage?.latest_activity_at ? displayDate(card.coverage.latest_activity_at) : "Not observed";

  return (
    <article className={`surface-panel border-l-[3px] ${readinessRowClass[status]} p-4 transition hover:border-[color:var(--border-strong)] hover:shadow-[var(--shadow-md)] ${active ? "ring-2 ring-[color:var(--ring)]" : ""}`}>
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="flex min-w-0 gap-3">
          <ProviderMark connector={card} />
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-[15px] font-semibold leading-5 text-[var(--text-primary)]">{displayName}</h3>
              <Badge value={readinessLabels[status]} />
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-2 text-[12px] text-[var(--text-muted)]">
              <span>{meta.category}</span>
            </div>
            <p className="mt-2 max-w-3xl text-[13px] leading-5 text-[var(--text-secondary)]">
              {card.description || statusDescription}
            </p>
            <div className="mt-3 flex flex-wrap gap-1.5">
              {capabilities.map((capability) => (
                <span key={capability} className="rounded-md bg-[var(--surface-muted)] px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)]">
                  {connectorCapabilityLabel(capability)}
                </span>
              ))}
              {meta.authBadge && (
                <span className="rounded-md bg-emerald-50 px-2 py-1 text-[11px] font-semibold text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-100">
                  {meta.authBadge}
                </span>
              )}
              {card.catalog_status && (
                <span className="rounded-md bg-blue-50 px-2 py-1 text-[11px] font-semibold text-blue-800 dark:bg-blue-500/15 dark:text-blue-100">
                  {connectorCatalogStatusLabel(card.catalog_status)}
                </span>
              )}
              {card.catalog_status && (
                <span className="rounded-md bg-[var(--surface-muted)] px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)]">
                  {connectorRuntimeSurfaceLabel(card)}
                </span>
              )}
              {card.access_status && card.access_status !== "available" && (
                <span className="rounded-md bg-amber-50 px-2 py-1 text-[11px] font-semibold text-amber-800 dark:bg-amber-500/15 dark:text-amber-100">
                  {connectorAccessStatusLabel(card.access_status)}
                </span>
              )}
              {card.readiness_stage && (
                <span className="rounded-md bg-[var(--surface-muted)] px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)]">
                  {connectorReadinessStageLabel(card.readiness_stage)}
                </span>
              )}
              {card.integration_depth && (
                <span className="rounded-md bg-[var(--surface-muted)] px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)]">
                  {connectorIntegrationDepthLabel(card)}
                </span>
              )}
              {capabilities.length === 0 && !meta.authBadge && !card.catalog_status && <span className="text-[12px] text-[var(--text-muted)]">No capabilities configured</span>}
            </div>
            {resourceTypes.length > 0 && (
              <div className="mt-2 flex flex-wrap items-center gap-1.5">
                <span className="text-[11px] font-semibold text-[var(--text-muted)]">Resource types</span>
                {resourceTypes.map((item) => (
                  <span key={item.template} title={item.template} className="rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)]">
                    {item.label}{item.resourceFamilies > 1 ? ` (${item.resourceFamilies})` : ""}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
        <div className="flex shrink-0 flex-wrap gap-2 lg:justify-end">
          {requestHref ? (
            <a href={requestHref} target="_blank" rel="noreferrer" className="primary-button inline-flex items-center gap-1.5 px-3 py-2 text-[12px]">
              {connectorRequestActionLabel(card)}
              <ArrowUpRight className="h-3.5 w-3.5" />
            </a>
          ) : (
            <Link href={href} className={`${status === "not_configured" ? "primary-button" : "secondary-button"} inline-flex items-center gap-1.5 px-3 py-2 text-[12px]`}>
              {primaryAction}
              <ArrowUpRight className="h-3.5 w-3.5" />
            </Link>
          )}
        </div>
      </div>
      <div className="mt-4 grid grid-cols-2 gap-2 lg:grid-cols-6">
        <SourceSignal label="Connections" value={total} attention={total === 0} />
        <SourceSignal label="Healthy" value={`${healthy}/${Math.max(total, 1)}`} attention={total > 0 && healthy < total} />
        <SourceSignal label="Resource types" value={resourceTypeStats.resourceTypes > 0 ? resourceTypeStats.resourceTypes : "0 mapped"} attention={resourceTypeStats.catalogResourceTypes > 0 && resourceTypeStats.resourceTypes === 0} />
        <SourceSignal label="Depth" value={card.integration_depth ? connectorIntegrationDepthLabel(card) : "Unknown"} />
        <SourceSignal label="Action" value={attention} attention={attention > 0} />
        <SourceSignal label="Last activity" value={latestActivity} />
      </div>
      {status !== "healthy" && status !== "not_configured" && (
        <div className="mt-3 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-[12px] leading-5 text-amber-950 dark:border-amber-500/25 dark:bg-amber-500/10 dark:text-amber-100">
          <span className="font-semibold">Next action:</span> {card.coverage?.next_action || card.nextAction || statusDescription}
        </div>
      )}
      {!setupAllowed && card.access_reason && (
        <div className="mt-3 rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2 text-[12px] leading-5 text-[var(--text-secondary)]">
          <span className="font-semibold text-[var(--text-primary)]">Access:</span> {card.access_reason}
        </div>
      )}
      {!setupAllowed && card.requestable_reason && card.requestable_reason !== card.access_reason && (
        <div className="mt-3 rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2 text-[12px] leading-5 text-[var(--text-secondary)]">
          <span className="font-semibold text-[var(--text-primary)]">Request:</span> {card.requestable_reason}
        </div>
      )}
    </article>
  );
}

function runtimeNeedsAction(runtime: ConnectorRuntime) {
  return runtime.health !== "healthy" ||
    runtime.graph_freshness !== "current" ||
    runtime.cursor_state === "pending" ||
    runtime.schedule_context_configured === false;
}

function runtimeIssueTitle(runtime: ConnectorRuntime) {
  if (runtime.graph_freshness === "failed") return "Graph projection failed";
  if (runtime.health === "degraded") return "Sync degraded";
  if (runtime.health === "stale") return "Sync is stale";
  if (runtime.cursor_state === "pending") return "Cursor is pending";
  if (runtime.graph_freshness === "behind") return "Graph projection is behind";
  if (runtime.graph_freshness === "not_observed" || runtime.graph_freshness === "unknown") return "Graph telemetry is missing";
  if (runtime.schedule_context_configured === false) return "Schedule context missing";
  return "Runtime needs review";
}

function RuntimeIssueQueue({
  cards,
  runtimes,
  tenantID,
}: {
  cards: ConnectorCard[];
  runtimes: ConnectorRuntime[];
  tenantID: string;
}) {
  const runtimesBySource = useMemo(() => {
    const grouped = new Map<string, ConnectorRuntime[]>();
    runtimes.filter(runtimeNeedsAction).forEach((runtime) => {
      const sourceID = runtime.source_id || "unknown";
      grouped.set(sourceID, [...(grouped.get(sourceID) ?? []), runtime]);
    });
    return grouped;
  }, [runtimes]);

  if (cards.length === 0) {
    return <EmptyBlock label="No connector issues match these filters." />;
  }

  return (
    <div className="space-y-3">
      {cards.map((card) => {
        const sourceRuntimes = runtimesBySource.get(card.source_id) ?? [];
        const displayName = connectorDisplayName(card);
        const sourceStatus = compactConnectorStatus(card);
        const sourceAction = card.coverage?.next_action || card.nextAction || readinessDescriptions[sourceStatus];
        const sourceHref = connectorPath(card.source_id, { tenant_id: tenantID, tab: sourceStatus === "not_configured" ? "setup" : "connections" });

        if (sourceRuntimes.length === 0) {
          return (
            <article key={card.source_id} className={`surface-panel border-l-[3px] ${readinessRowClass[sourceStatus]} p-4`}>
              <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div className="flex min-w-0 gap-3">
                  <ProviderMark connector={card} />
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-[14px] font-semibold text-[var(--text-primary)]">{displayName}</h3>
                      <Badge value={readinessLabels[sourceStatus]} />
                    </div>
                    <p className="mt-1 text-[13px] leading-5 text-[var(--text-secondary)]">{sourceAction}</p>
                    <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-3">
                      <SourceSignal label="Connections affected" value={connectorAttentionTotal(card)} attention />
                      <SourceSignal label="Healthy" value={`${connectorHealthyTotal(card)}/${Math.max(connectorRuntimeTotal(card), 1)}`} attention={connectorHealthyTotal(card) < connectorRuntimeTotal(card)} />
                      <SourceSignal label="Last activity" value={card.coverage?.latest_activity_at ? displayDate(card.coverage.latest_activity_at) : "Not observed"} />
                    </div>
                  </div>
                </div>
                <Link href={sourceHref} className="secondary-button inline-flex shrink-0 items-center justify-center gap-1.5 px-3 py-2 text-[12px]">
                  Fix source
                  <ArrowUpRight className="h-3.5 w-3.5" />
                </Link>
              </div>
            </article>
          );
        }

        return sourceRuntimes.map((runtime) => {
          const href = connectorPath(runtime.source_id || card.source_id, {
            tenant_id: tenantID || runtime.tenant_id,
            tab: "connections",
            runtime_id: runtime.runtime_id,
          });
          const issueTitle = runtimeIssueTitle(runtime);
          const detail = runtime.latest_graph_run?.error ||
            runtime.latest_finding_evaluation?.error ||
            (runtime.watermark_lag_seconds ? `${formatDuration(runtime.watermark_lag_seconds)} watermark lag` : "") ||
            readinessDescriptions[sourceStatus];
          return (
            <article key={`${card.source_id}:${runtime.runtime_id}`} className={`surface-panel border-l-[3px] ${readinessRowClass[sourceStatus]} p-4`}>
              <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div className="flex min-w-0 gap-3">
                  <ProviderMark connector={card} />
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-[14px] font-semibold text-[var(--text-primary)]">{displayName}</h3>
                      <Badge value={runtime.health} />
                      <Badge value={runtime.graph_freshness} />
                    </div>
                    <div className="mt-1 font-mono text-[11px] text-[var(--text-muted)]">{shortEntity(runtime.runtime_id)}</div>
                    <p className="mt-2 text-[13px] font-semibold text-[var(--text-primary)]">{issueTitle}</p>
                    <p className="mt-0.5 text-[12px] leading-5 text-[var(--text-secondary)]">{detail}</p>
                    <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
                      <SourceSignal label="Family" value={runtime.family || "Default"} />
                      <SourceSignal label="Cursor" value={runtime.cursor_state} attention={runtime.cursor_state !== "caught_up"} />
                      <SourceSignal label="Last activity" value={runtime.last_activity_at ? displayDate(runtime.last_activity_at) : "Not observed"} attention={!runtime.last_activity_at} />
                      <SourceSignal label="Graph" value={runtime.graph_status || runtime.graph_freshness} attention={runtime.graph_freshness !== "current"} />
                    </div>
                  </div>
                </div>
                <Link href={href} className="secondary-button inline-flex shrink-0 items-center justify-center gap-1.5 px-3 py-2 text-[12px]">
                  Inspect runtime
                  <ArrowUpRight className="h-3.5 w-3.5" />
                </Link>
              </div>
            </article>
          );
        });
      })}
    </div>
  );
}

function AttentionNotice({
  actionConnections,
  attentionCount,
  onViewIssues,
}: {
  actionConnections: number;
  attentionCount: number;
  onViewIssues: () => void;
}) {
  if (attentionCount === 0) return null;
  return (
    <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-amber-950 dark:border-amber-500/25 dark:bg-amber-500/10 dark:text-amber-100">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-[13px] font-semibold">Some sources need attention</div>
          <div className="mt-0.5 text-[12px] leading-5">
            {attentionCount} source{attentionCount === 1 ? " has" : "s have"} {actionConnections} connection signal{actionConnections === 1 ? "" : "s"} to resolve.
          </div>
        </div>
        <button type="button" onClick={onViewIssues} className="secondary-button bg-white/80 px-3 py-2 text-[12px] dark:bg-black/10">
          View issues
        </button>
      </div>
    </div>
  );
}

function ReadinessMix({
  counts,
  filter,
  onFilter,
}: {
  counts: Record<SourceReadiness, number>;
  filter: ReadinessFilter;
  onFilter: (filter: ReadinessFilter) => void;
}) {
  return (
    <Panel title="Readiness mix">
      <div className="space-y-2">
        {readinessOrder.map((readiness) => (
          <button
            key={readiness}
            type="button"
            onClick={() => onFilter(filter === readiness ? "all" : readiness)}
            className={`flex w-full items-center justify-between rounded-md border px-3 py-2 text-left transition ${
              filter === readiness
                ? "border-[color:var(--border-strong)] bg-[var(--surface-hover)]"
                : "border-[color:var(--border)] bg-[var(--surface)] hover:border-[color:var(--border-strong)]"
            }`}
          >
            <Badge value={readinessLabels[readiness]} />
            <span className="text-[13px] font-semibold text-[var(--text-primary)]">{counts[readiness]}</span>
          </button>
        ))}
      </div>
    </Panel>
  );
}

function CustomConnectorPanel({
  definitions,
  error,
  onRetry,
  tenantID,
}: {
  definitions: ConnectorDefinition[];
  error: string | null;
  onRetry: () => void;
  tenantID: string;
}) {
  return (
    <Panel
      title="Custom connectors"
      action={
        <Link href={`/connectors/builder${tenantID ? `?tenant_id=${encodeURIComponent(tenantID)}` : ""}`} className="secondary-button inline-flex items-center gap-1.5 px-2.5 py-1.5 text-[12px]">
          <Bot className="h-3.5 w-3.5" />
          Build
        </Link>
      }
    >
      <div className="space-y-2">
        {error && <ErrorBlock error={error} onRetry={onRetry} recoveryDetail="Dynamic connector definitions require backend support." />}
        {!error && definitions.slice(0, 5).map((definition) => {
          const status = connectorDefinitionStatus(definition);
          const blocking = connectorDefinitionBlockingChecks(definition);
          return (
            <Link
              key={definition.id ?? definition.source_id}
              href={`/connectors/builder?definition_id=${encodeURIComponent(definition.id ?? "")}${tenantID ? `&tenant_id=${encodeURIComponent(tenantID)}` : ""}`}
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
        {!error && definitions.length === 0 && <EmptyBlock label="No custom connector definitions yet." />}
      </div>
    </Panel>
  );
}

function resourceTypeTotalsForCards(cards: ConnectorCard[]) {
  const distinctResourceTypes = new Set<string>();
  let sources = 0;
  let resourceTypes = 0;
  let highValueResourceTypes = 0;
  let coverageItems = 0;
  let depthOnlyResourceTypes = 0;

  cards.forEach((card) => {
    const stats = connectorResourceTypeStats(card);
    const cardResourceTypes = connectorResourceTypes(card, 100);
    if (stats.resourceTypes > 0) sources += 1;
    resourceTypes += stats.resourceTypes;
    highValueResourceTypes += stats.highValueResourceTypes;
    coverageItems += stats.coverageItems;
    if (cardResourceTypes.length === 0) {
      depthOnlyResourceTypes += stats.distinctResourceTypes;
      return;
    }
    cardResourceTypes.forEach((item) => distinctResourceTypes.add(item.template.toLowerCase()));
  });

  return {
    sources,
    resourceTypes,
    distinctResourceTypes: distinctResourceTypes.size + depthOnlyResourceTypes,
    highValueResourceTypes,
    coverageItems,
  };
}

function ProviderAPIProofPanel({
  items,
  metrics,
}: {
  items: ReturnType<typeof providerAPIProofQueue>;
  metrics: ReturnType<typeof providerAPIProofMetrics>;
}) {
  return (
    <Panel title="API proof queue" action={<Badge value={`${metrics.needsAction} open`} />}>
      <div className="grid grid-cols-3 gap-2">
        <SourceSignal label="Needs action" value={metrics.needsAction} attention={metrics.needsAction > 0} />
        <SourceSignal label="Verified" value={metrics.verified} />
        <SourceSignal label="Avg score" value={metrics.averageScore === null ? "No score" : `${metrics.averageScore}/100`} attention={metrics.averageScore !== null && metrics.averageScore < 90} />
      </div>
      <div className="mt-3 grid grid-cols-3 gap-2">
        <SourceSignal label="Find API" value={metrics.needsDiscovery} attention={metrics.needsDiscovery > 0} />
        <SourceSignal label="Map families" value={metrics.needsMapping} attention={metrics.needsMapping > 0} />
        <SourceSignal label="Add proof" value={metrics.needsProof} attention={metrics.needsProof > 0} />
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
            <div className="mt-2 flex flex-wrap gap-1.5">
              {item.missing.slice(0, 3).map((missing) => (
                <span key={missing} className="rounded-md bg-[var(--surface-muted)] px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)]">
                  {connectorCapabilityLabel(missing)}
                </span>
              ))}
              {item.missing.length > 3 && (
                <span className="rounded-md bg-[var(--surface-muted)] px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)]">
                  {item.missing.length - 3} more
                </span>
              )}
              {item.missing.length === 0 && item.reasons.slice(0, 2).map((reason) => (
                <span key={reason} className="rounded-md bg-[var(--surface-muted)] px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)]">
                  {connectorCapabilityLabel(reason)}
                </span>
              ))}
            </div>
          </Link>
        ))}
        {items.length === 0 && <EmptyBlock label="No API proof work in this source set." />}
      </div>
    </Panel>
  );
}

function CatalogResourceTypesPanel({ cards, tenantID }: { cards: ConnectorCard[]; tenantID: string }) {
  const requestable = cards.filter((card) => !connectorSetupAllowed(card) && card.requestable);
  const runtimeReady = requestable.filter((card) => card.readiness_stage === "sourcegen_ready").length;
  const authNeeded = requestable.filter((card) => card.readiness_stage === "auth_extension_required").length;
  const runtimeNeeded = requestable.filter((card) => card.readiness_stage === "runtime_required").length;
  const resourceTypeTotals = resourceTypeTotalsForCards(cards);
  const resourceTypeCards = [...cards]
    .filter((card) => connectorResourceTypeStats(card).resourceTypes > 0)
    .sort((left, right) =>
      connectorResourceTypeStats(right).resourceTypes - connectorResourceTypeStats(left).resourceTypes ||
      connectorDisplayName(left).localeCompare(connectorDisplayName(right)),
    )
    .slice(0, 4);

  return (
    <Panel title="Catalog resource types" action={<Badge value={`${resourceTypeTotals.sources} sources`} />}>
      <div className="grid grid-cols-3 gap-2">
        <SourceSignal label="Resource types" value={resourceTypeTotals.resourceTypes} />
        <SourceSignal label="Distinct types" value={resourceTypeTotals.distinctResourceTypes} />
        <SourceSignal label="High value" value={resourceTypeTotals.highValueResourceTypes} />
      </div>
      <div className="mt-3 grid grid-cols-3 gap-2">
        <SourceSignal label="Runtime ready" value={runtimeReady} />
        <SourceSignal label="Auth" value={authNeeded} attention={authNeeded > 0} />
        <SourceSignal label="Runtime" value={runtimeNeeded} attention={runtimeNeeded > 0} />
      </div>
      <div className="mt-3 space-y-2">
        {resourceTypeCards.map((card) => {
          const requestHref = card.request_access_url?.trim();
          const detailHref = connectorPath(card.source_id, { tenant_id: tenantID });
          const stats = connectorResourceTypeStats(card);
          const resourceTypesForCard = connectorResourceTypes(card, 3);
          return (
            <div key={card.source_id} className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-3">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="truncate text-[13px] font-semibold text-[var(--text-primary)]">{connectorDisplayName(card)}</div>
                  <div className="mt-1 text-[11px] text-[var(--text-muted)]">
                    {stats.resourceTypes} resource types · {resourceTypesForCard.map((item) => item.label).join(", ") || `${stats.distinctResourceTypes} type mappings`}
                  </div>
                </div>
                {requestHref ? (
                  <a href={requestHref} target="_blank" rel="noreferrer" className="secondary-button shrink-0 px-2.5 py-1.5 text-[11px]">
                    {connectorRequestActionLabel(card)}
                  </a>
                ) : (
                  <Link href={detailHref} className="secondary-button shrink-0 px-2.5 py-1.5 text-[11px]">
                    Inspect
                  </Link>
                )}
              </div>
            </div>
          );
        })}
        {resourceTypeCards.length === 0 && <EmptyBlock label="No resource types configured." />}
      </div>
    </Panel>
  );
}

function ConnectorViewTabs({
  libraryTab,
  tabCounts,
  onTab,
}: {
  libraryTab: LibraryTab;
  tabCounts: Record<LibraryTab, number>;
  onTab: (tab: LibraryTab) => void;
}) {
  return (
    <div className="flex flex-wrap gap-2">
      {libraryTabs.map((tab) => (
        <LibraryTabButton
          key={tab.id}
          id={tab.id}
          active={libraryTab === tab.id}
          count={tabCounts[tab.id]}
          onClick={() => onTab(tab.id)}
        />
      ))}
    </div>
  );
}

function ConnectorResultList({
  libraryTab,
  visibleCards,
  sourceRuntimes,
  tenantID,
  activeSourceID,
}: {
  libraryTab: LibraryTab;
  visibleCards: ConnectorCard[];
  sourceRuntimes: ConnectorRuntime[];
  tenantID: string;
  activeSourceID: string;
}) {
  if (libraryTab === "attention") {
    return <RuntimeIssueQueue cards={visibleCards} runtimes={sourceRuntimes} tenantID={tenantID} />;
  }
  return (
    <div className="space-y-3">
      {visibleCards.map((card) => (
        <ConnectorLibraryRow
          key={card.source_id}
          card={card}
          active={activeSourceID === card.source_id}
          tenantID={tenantID}
        />
      ))}
      {visibleCards.length === 0 && <EmptyBlock label="No connectors match these filters." />}
    </div>
  );
}

export default function ConnectorsPage() {
  const [tenantID, setTenantID] = useQueryParamState("tenant_id");
  const [sourceID, setSourceID] = useQueryParamState("source_id");
  const [sourceQuery, setSourceQuery] = useQueryParamState("q");
  const [libraryTabValue, setLibraryTab] = useQueryParamState("tab", "connected");
  const [readinessFilterValue, setReadinessFilter] = useQueryParamState("readiness", "all");
  const debouncedTenantID = useDebouncedValue(tenantID.trim());
  const debouncedSourceID = useDebouncedValue(sourceID.trim());

  const libraryQuery = useConnectorLibraryQuery({ tenantID: debouncedTenantID, view: "summary" });
  const definitionsQuery = useGRCQuery<ConnectorDefinitionListResponse>(withQuery("/connector-definitions", { tenant_id: debouncedTenantID }));

  const boundedSourceRuntimeRows = useMemo(
    () => grcBoundedRows({
      rows: extractRecords(libraryQuery.data, ["runtimes", "source_runtimes"])
        .map((runtime) => normalizeRuntime(runtime))
        .filter((runtime) => runtime.runtime_id && runtime.source_id),
      limit: CONNECTOR_RUNTIME_LIMIT,
    }),
    [libraryQuery.data],
  );
  const sourceRuntimes = boundedSourceRuntimeRows.rows;

  const connectorView = useMemo(() => {
    const library = libraryQuery.data?.connectors ?? [];
    const sources = sourceRuntimes.length > 0 ? sourceHealthBreakdown(sourceRuntimes) : [];
    const cards = buildConnectorCards(library, sources);
    return { cards };
  }, [libraryQuery.data, sourceRuntimes]);

  const { cards } = connectorView;
  const libraryTab = (libraryTabs.some((tab) => tab.id === libraryTabValue) ? libraryTabValue : "all") as LibraryTab;
  const readinessFilter = (readinessFilterValue === "all" || readinessOrder.includes(readinessFilterValue as SourceReadiness)
    ? readinessFilterValue
    : "all") as ReadinessFilter;
  const readinessCounts = useMemo(
    () =>
      readinessOrder.reduce(
        (counts, readiness) => ({ ...counts, [readiness]: cards.filter((card) => compactConnectorStatus(card) === readiness).length }),
        {} as Record<SourceReadiness, number>,
      ),
    [cards],
  );
  const tabCounts = useMemo(
    () =>
      libraryTabs.reduce(
        (counts, tab) => ({ ...counts, [tab.id]: cards.filter((card) => tabMatchesCard(tab.id, card)).length }),
        {} as Record<LibraryTab, number>,
      ),
    [cards],
  );
  const visibleCards = useMemo(() => {
    const scoped = cards.filter((card) => {
      if (!tabMatchesCard(libraryTab, card)) return false;
      const sourceFilter = debouncedSourceID.toLowerCase();
      if (sourceFilter) {
        const sourceMatches = [card.source_id, card.name, connectorDisplayName(card)]
          .filter(Boolean)
          .some((value) => String(value).toLowerCase().includes(sourceFilter));
        if (!sourceMatches) return false;
      }
      return true;
    });
    return filterConnectorCards(scoped, sourceQuery, readinessFilter);
  }, [cards, debouncedSourceID, libraryTab, readinessFilter, sourceQuery]);
  const boundedVisibleCards = useMemo(
    () => grcBoundedRows({ rows: visibleCards, limit: CONNECTOR_RENDER_LIMIT, total: visibleCards.length }),
    [visibleCards],
  );
  const renderedCards = boundedVisibleCards.rows;
  const connectedCards = cards.filter((card) => connectorRuntimeTotal(card) > 0);
  const requestableCards = cards.filter((card) => !connectorSetupAllowed(card) && Boolean(card.requestable));
  const customDefinitions = definitionsQuery.data?.definitions ?? [];
  const attentionCards = cards.filter((card) => {
    const status = compactConnectorStatus(card);
    return status !== "healthy" && status !== "not_configured";
  });
  const libraryLoading = libraryQuery.loading && !libraryQuery.data;
  const runtimeState = runtimeStateForError(libraryQuery.error);
  const metricState: RuntimeState = libraryQuery.error ? runtimeState : libraryLoading ? "loading" : "ready";
  const totalConnections = cards.reduce((sum, card) => sum + connectorRuntimeTotal(card), 0);
  const actionConnections = cards.reduce((sum, card) => sum + connectorAttentionTotal(card), 0);
  const resourceTypeTotals = resourceTypeTotalsForCards(cards);
  const apiProofMetrics = useMemo(() => providerAPIProofMetrics(cards), [cards]);
  const apiProofQueue = useMemo(() => providerAPIProofQueue(cards, { tenantID: debouncedTenantID }), [cards, debouncedTenantID]);
  const filterChips = [
    { label: "Tenant", value: tenantID, onClear: () => setTenantID("") },
    { label: "Source", value: sourceID, onClear: () => setSourceID("") },
    { label: "Search", value: sourceQuery, onClear: () => setSourceQuery("") },
    { label: "View", value: libraryTab === "connected" ? "" : libraryTabs.find((tab) => tab.id === libraryTab)?.label ?? libraryTab, onClear: () => setLibraryTab("connected") },
    { label: "Readiness", value: readinessFilter === "all" ? "" : readinessLabels[readinessFilter], onClear: () => setReadinessFilter("all") },
  ];
  const clearFilters = () => {
    setTenantID("");
    setSourceID("");
    setSourceQuery("");
    setLibraryTab("connected");
    setReadinessFilter("all");
  };
  const viewCopy: Record<LibraryTab, { title: string; detail: string }> = {
    all: { title: "All sources", detail: "Every source, connected or not." },
    attention: { title: "Sources needing attention", detail: "Fix failing, stale, or incomplete runtime signals first." },
    available: { title: "Available sources", detail: "Sources that are ready to connect." },
    backlog: { title: "Source backlog", detail: "Catalog-only and restricted sources that can be requested or promoted into setup." },
    connected: { title: "Connected sources", detail: "Monitor active sources and open their runtime details." },
  };
  const currentView = viewCopy[libraryTab];

  return (
    <div className="space-y-6">
      <PageHeader
        contractId="connectors"
        title="Sources"
        description="Connect sources, check runtime health, and control what gets collected."
        action={
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => {
                setLibraryTab("available");
                setReadinessFilter("all");
              }}
              className="secondary-button inline-flex items-center gap-2 px-3 py-2 text-[13px]"
            >
              <Plus className="h-4 w-4" />
              Add source
            </button>
            <Link href={`/connectors/builder${debouncedTenantID ? `?tenant_id=${encodeURIComponent(debouncedTenantID)}` : ""}`} className="secondary-button inline-flex items-center gap-2 px-3 py-2 text-[13px]">
              <FileJson2 className="h-4 w-4" />
              Build custom
            </Link>
            <Link href={`/connectors/activation${debouncedTenantID ? `?tenant_id=${encodeURIComponent(debouncedTenantID)}` : ""}`} className="secondary-button inline-flex items-center gap-2 px-3 py-2 text-[13px]">
              <ShieldCheck className="h-4 w-4" />
              Activation
            </Link>
            <button type="button" onClick={() => { void libraryQuery.reload(); void definitionsQuery.reload(); }} className="primary-button inline-flex items-center gap-2 px-3 py-2 text-[13px]">
              <RefreshCw className="h-4 w-4" />
              Refresh
            </button>
          </div>
        }
      />

      <div className="hidden gap-3 md:grid md:grid-cols-3 xl:grid-cols-6">
        <MetricCard label="Available" value={cards.length} detail="library connectors" state={metricState} />
        <MetricCard label="Connected" value={connectedCards.length} detail={`${totalConnections} runtime mappings`} intent="success" state={metricState} />
        <div className="hidden md:block">
          <MetricCard label="Needs Attention" value={attentionCards.length} detail={`${actionConnections} connection signals`} intent={attentionCards.length > 0 ? "warning" : "success"} state={metricState} />
        </div>
        <div className="hidden md:block">
          <MetricCard label="Backlog" value={requestableCards.length} detail="requestable catalog sources" intent={requestableCards.length > 0 ? "warning" : "neutral"} state={metricState} />
        </div>
        <div className="hidden md:block">
          <MetricCard label="Resource Types" value={resourceTypeTotals.sources} detail={`${resourceTypeTotals.resourceTypes} catalog-backed`} intent={resourceTypeTotals.sources > 0 ? "success" : "neutral"} state={metricState} />
        </div>
        <div className="hidden md:block">
          <MetricCard label="API proof" value={apiProofMetrics.needsAction} detail="sources need proof work" intent={apiProofMetrics.needsAction > 0 ? "warning" : "success"} state={metricState} />
        </div>
      </div>

      <section className="surface-panel p-4">
        <div className="space-y-3 md:hidden">
          <label className={labelClass}>
            Search connectors
            <div className="relative mt-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--text-muted)]" />
              <input
                value={sourceQuery}
                onChange={(event) => setSourceQuery(event.target.value)}
                placeholder="Provider, source, capability"
                className="control-input w-full px-9 py-2 text-[13px]"
              />
            </div>
          </label>
          <details className="rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2">
            <summary className="cursor-pointer text-[12px] font-semibold text-[var(--text-secondary)]">Tenant and source filters</summary>
            <div className="mt-3 grid gap-3">
              <label className={labelClass}>Tenant<input value={tenantID} onChange={(event) => setTenantID(event.target.value)} placeholder="All tenants" className={inputClass} /></label>
              <label className={labelClass}>Source<input value={sourceID} onChange={(event) => setSourceID(event.target.value)} placeholder="Name or source ID" className={inputClass} /></label>
            </div>
          </details>
        </div>
        <div className="hidden gap-3 md:grid lg:grid-cols-[minmax(160px,0.8fr)_minmax(160px,0.8fr)_minmax(220px,1.2fr)]">
          <label className={labelClass}>Tenant<input value={tenantID} onChange={(event) => setTenantID(event.target.value)} placeholder="All tenants" className={inputClass} /></label>
          <label className={labelClass}>Source<input value={sourceID} onChange={(event) => setSourceID(event.target.value)} placeholder="Name or source ID" className={inputClass} /></label>
          <label className={labelClass}>
            Search connectors
            <div className="relative mt-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--text-muted)]" />
              <input
                value={sourceQuery}
                onChange={(event) => setSourceQuery(event.target.value)}
                placeholder="Provider, source, capability"
                className="control-input w-full px-9 py-2 text-[13px]"
              />
            </div>
          </label>
        </div>
        <AppliedFilterChips filters={filterChips} onClearAll={clearFilters} />
      </section>

      {libraryLoading && <LoadingBlock label="Loading connectors..." />}
      {libraryQuery.error && <ErrorBlock error={libraryQuery.error} onRetry={() => void libraryQuery.reload()} recoveryDetail="Connector data will appear when the API is reachable." />}

      <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,1.45fr)_minmax(320px,0.75fr)]">
        <Panel
          title={currentView.title}
          action={<span className="text-[12px] text-[var(--text-muted)]">{renderedCards.length} shown</span>}
        >
          <div className="space-y-4">
            {libraryTab !== "attention" && (
              <AttentionNotice
                actionConnections={actionConnections}
                attentionCount={attentionCards.length}
                onViewIssues={() => {
                  setLibraryTab("attention");
                  setReadinessFilter("all");
                }}
              />
            )}
            <div className="space-y-3 md:hidden">
              <ResultLimitNotice loaded={renderedCards.length} meta={boundedVisibleCards.meta} limit={CONNECTOR_RENDER_LIMIT} noun="sources" />
              <ConnectorResultList
                libraryTab={libraryTab}
                visibleCards={renderedCards}
                sourceRuntimes={sourceRuntimes}
                tenantID={debouncedTenantID}
                activeSourceID={debouncedSourceID}
              />
              <details className="rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2">
                <summary className="cursor-pointer text-[12px] font-semibold text-[var(--text-secondary)]">View filters</summary>
                <div className="mt-3 space-y-3">
                  <ConnectorViewTabs
                    libraryTab={libraryTab}
                    tabCounts={tabCounts}
                    onTab={setLibraryTab}
                  />
                </div>
              </details>
            </div>
            <div className="hidden space-y-4 md:block">
              <div className="text-[12px] leading-5 text-[var(--text-muted)]">{currentView.detail}</div>
              <ConnectorViewTabs
                libraryTab={libraryTab}
                tabCounts={tabCounts}
                onTab={setLibraryTab}
              />
              <ResultLimitNotice loaded={renderedCards.length} meta={boundedVisibleCards.meta} limit={CONNECTOR_RENDER_LIMIT} noun="sources" />
              <ConnectorResultList
                libraryTab={libraryTab}
                visibleCards={renderedCards}
                sourceRuntimes={sourceRuntimes}
                tenantID={debouncedTenantID}
                activeSourceID={debouncedSourceID}
              />
            </div>
          </div>
        </Panel>

        <div className="space-y-5">
          <ProviderAPIProofPanel items={apiProofQueue} metrics={apiProofMetrics} />
          <CatalogResourceTypesPanel cards={cards} tenantID={debouncedTenantID} />
          <CustomConnectorPanel definitions={customDefinitions} error={definitionsQuery.error} onRetry={() => void definitionsQuery.reload()} tenantID={debouncedTenantID} />
          <ReadinessMix counts={readinessCounts} filter={readinessFilter} onFilter={setReadinessFilter} />
        </div>
      </div>
    </div>
  );
}
