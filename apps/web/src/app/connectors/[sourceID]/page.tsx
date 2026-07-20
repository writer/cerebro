"use client";

import Link from "next/link";
import { useParams, useSearchParams } from "next/navigation";
import { useMemo, useState, type ReactNode } from "react";
import {
  Activity,
  ArrowLeft,
  CheckCircle2,
  Database,
  KeyRound,
  Layers3,
  ListChecks,
  RefreshCw,
  Search,
  Settings2,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";

import ConnectorActivityTable from "@/components/connectors/ConnectorActivityTable";
import { CoverageMetadata, CoverageMetadataList } from "@/components/connectors/CoverageMetadata";
import ConnectorDiagnosticTimelinePanel from "@/components/connectors/ConnectorDiagnosticTimeline";
import ConnectorSetupForm from "@/components/connectors/ConnectorSetupForm";
import { useApiKey } from "@/components/providers";
import { Badge, EmptyBlock, ErrorBlock, LoadingBlock, Panel, ResultLimitNotice } from "@/components/grc/Primitives";
import { withQuery } from "@/lib/cerebro-data";
import { useDebouncedValue, useGRCQuery } from "@/lib/grc-client";
import { GRC_DETAIL_LIMIT, grcBoundedRows } from "@/lib/grc-list";
import { displayDate, humanize } from "@/lib/grc";
import { formatDuration } from "@/lib/connector-runtime";
import {
  connectorCapabilityLabel,
  connectorCapabilities,
  connectorProjectionTemplate,
  connectorResourceTypeLabel,
  connectorResourceTypes,
  connectorResourceTypeStats,
  connectorResourceFamilyEventKind,
  connectorResourceFamilySchemaRef,
} from "@/lib/connector-view";
import type {
  ConnectorCatalogEntry,
  ConnectorConnectionSummary,
  ConnectorDetailResponse,
  ConnectorLibraryResponse,
  ConnectorOperationsSummary,
  ConnectorScopePolicy,
} from "@/lib/connectors";
import {
  connectorAccessStatusLabel,
  connectorCatalogStatusLabel,
  connectorDefinitionOriginLabel,
  connectorDisplayMetadata,
  connectorDisplayName,
  connectorIntegrationDepthLabel,
  connectorIsCatalogOnly,
  connectorReadinessStageLabel,
  connectorRequestActionLabel,
  connectorRuntimeSurfaceLabel,
  connectorSetupAllowed,
  normalizeCredentialStores,
  scopePolicyExclusionCount,
} from "@/lib/connectors";

type DetailTab = "overview" | "setup" | "connections" | "activity" | "scope" | "data";

const tabs: Array<{ id: DetailTab; label: string; icon: ReactNode }> = [
  { id: "overview", label: "Overview", icon: <Activity className="h-4 w-4" /> },
  { id: "setup", label: "Setup", icon: <KeyRound className="h-4 w-4" /> },
  { id: "connections", label: "Connections", icon: <ListChecks className="h-4 w-4" /> },
  { id: "activity", label: "Activity", icon: <RefreshCw className="h-4 w-4" /> },
  { id: "scope", label: "Collected resources", icon: <Layers3 className="h-4 w-4" /> },
  { id: "data", label: "Data", icon: <Database className="h-4 w-4" /> },
];

const labelClass = "text-[11px] font-semibold text-[var(--text-muted)]";
const inputClass = "control-input mt-1 w-full px-3 py-2 text-[13px]";
const CONNECTOR_DETAIL_KIND_LIMIT = 24;

function ProviderMark({ connector }: { connector: ConnectorCatalogEntry }) {
  const meta = connectorDisplayMetadata(connector);
  return (
    <div className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-lg ring-1 ${meta.accentClass}`}>
      <span className="text-[13px] font-bold tracking-tight">{meta.logoText}</span>
    </div>
  );
}

function SummaryTile({
  label,
  value,
  detail,
  icon,
}: {
  label: string;
  value: ReactNode;
  detail?: ReactNode;
  icon: ReactNode;
}) {
  return (
    <div className="min-w-[150px] border-b border-[color:var(--border)] p-4 last:border-b-0 sm:border-b-0 sm:border-r sm:last:border-r-0">
      <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
        {icon}
        {label}
      </div>
      <div className="mt-2 text-2xl font-semibold tabular-nums text-[var(--text-primary)]">{value}</div>
      {detail && <div className="mt-1 text-[12px] text-[var(--text-muted)]">{detail}</div>}
    </div>
  );
}

function TabButton({
  id,
  active,
  onClick,
}: {
  id: DetailTab;
  active: boolean;
  onClick: (tab: DetailTab) => void;
}) {
  const tab = tabs.find((item) => item.id === id);
  if (!tab) return null;
  return (
    <button
      type="button"
      onClick={() => onClick(id)}
      className={`inline-flex h-10 shrink-0 items-center gap-2 border-b-2 px-1 text-[13px] font-semibold transition ${
        active
          ? "border-[var(--text-primary)] text-[var(--text-primary)]"
          : "border-transparent text-[var(--text-muted)] hover:text-[var(--text-primary)]"
      }`}
    >
      {tab.icon}
      {tab.label}
    </button>
  );
}

function connectorStatusTone(status?: string) {
  switch (status) {
    case "healthy":
      return "text-emerald-700 dark:text-emerald-200";
    case "bad":
      return "text-red-700 dark:text-red-200";
    case "needs_refresh":
      return "text-amber-700 dark:text-amber-200";
    case "poor":
      return "text-orange-700 dark:text-orange-200";
    default:
      return "text-[var(--text-secondary)]";
  }
}

function StatusIcon({ status }: { status?: string }) {
  if (status === "healthy") return <CheckCircle2 className="h-4 w-4 text-emerald-500" />;
  if (status === "bad") return <TriangleAlert className="h-4 w-4 text-red-500" />;
  if (status === "needs_refresh" || status === "poor") return <RefreshCw className="h-4 w-4 text-amber-500" />;
  return <Settings2 className="h-4 w-4 text-[var(--text-muted)]" />;
}

function OperationsSummary({
  connector,
  summary,
  secretStoreCount,
}: {
  connector: ConnectorCatalogEntry;
  summary: ConnectorOperationsSummary;
  secretStoreCount: number;
}) {
  const resourceTypeStats = connectorResourceTypeStats(connector);
  return (
    <div className="surface-panel grid overflow-hidden sm:grid-cols-2 xl:grid-cols-5">
      <SummaryTile
        label="Status"
        value={<span className={`inline-flex items-center gap-2 text-[16px] ${connectorStatusTone(summary.status)}`}><StatusIcon status={summary.status} />{humanize(summary.status || "not_configured")}</span>}
        detail={summary.status_reason || "Connection state"}
        icon={<ShieldCheck className="h-3.5 w-3.5" />}
      />
      <SummaryTile
        label="Connections"
        value={summary.total_connections ?? 0}
        detail={`${summary.healthy_connections ?? 0} healthy`}
        icon={<ListChecks className="h-3.5 w-3.5" />}
      />
      <SummaryTile
        label="Last Activity"
        value={<span className="text-[16px]">{summary.last_activity_at ? displayDate(summary.last_activity_at) : "Not observed"}</span>}
        detail={summary.sync_frequency_seconds ? `Every ${formatDuration(summary.sync_frequency_seconds)}` : "Sync cadence unavailable"}
        icon={<Activity className="h-3.5 w-3.5" />}
      />
      <SummaryTile
        label="Resource Types"
        value={resourceTypeStats.resourceTypes}
        detail={resourceTypeStats.distinctResourceTypes > 0 ? `${resourceTypeStats.distinctResourceTypes} catalog-backed types` : "No catalog resource types"}
        icon={<Database className="h-3.5 w-3.5" />}
      />
      <SummaryTile
        label="Credential stores"
        value={secretStoreCount}
        detail="Available for setup"
        icon={<KeyRound className="h-3.5 w-3.5" />}
      />
    </div>
  );
}

function AttentionNotice({ summary, setupAllowed, onSetup }: { summary: ConnectorOperationsSummary; setupAllowed: boolean; onSetup: () => void }) {
  if (summary.status === "healthy") {
    return null;
  }
  const title = summary.status === "not_configured" ? "This connector is not configured yet" : "This connector needs attention";
  const detail = summary.top_issue || summary.status_reason || "Review setup, sync freshness, or graph readiness.";
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-[13px] text-amber-950 dark:border-amber-500/25 dark:bg-amber-500/10 dark:text-amber-100">
      <div className="flex min-w-0 items-center gap-2.5">
        <TriangleAlert className="h-4 w-4 shrink-0 text-amber-600" />
        <div>
          <div className="font-semibold">{title}</div>
          <div className="text-[12px] leading-5">{detail}</div>
        </div>
      </div>
      {setupAllowed && (
        <button type="button" onClick={onSetup} className="secondary-button px-3 py-2 text-[12px]">
          {summary.status === "not_configured" ? "Configure" : "Review setup"}
        </button>
      )}
    </div>
  );
}

function ConnectionsTable({ connections, activeRuntimeID = "" }: { connections: ConnectorConnectionSummary[]; activeRuntimeID?: string }) {
  if (connections.length === 0) return <EmptyBlock label="No connections match these filters." />;
  return (
    <div className="overflow-x-auto rounded-lg border border-[color:var(--border)] bg-[var(--surface)]">
      <table className="data-table">
        <thead>
          <tr>
            <th>Connection</th>
            <th>Status</th>
            <th>Graph</th>
            <th>Records</th>
            <th>Projected</th>
            <th>Collected resources</th>
            <th>Last Activity</th>
            <th>Next Action</th>
          </tr>
        </thead>
        <tbody>
          {connections.map((connection) => (
            <tr key={connection.runtime_id} className={activeRuntimeID === connection.runtime_id ? "bg-[var(--surface-hover)]" : undefined}>
              <td>
                <div className="font-medium text-[var(--text-primary)]">{connection.family || "Default resource type"}</div>
                <div className="mt-0.5 font-mono text-[11px] text-[var(--text-muted)]">{connection.runtime_id}</div>
              </td>
              <td><Badge value={connection.status || "unknown"} /></td>
              <td><Badge value={connection.graph_status || "not_observed"} /></td>
              <td>
                <div>{connection.records_accepted ?? 0} accepted</div>
                <div className="mt-0.5 text-[11px] text-[var(--text-muted)]">{connection.records_rejected ?? 0} rejected</div>
              </td>
              <td>
                <div>{connection.entities_projected ?? 0} entities</div>
                <div className="mt-0.5 text-[11px] text-[var(--text-muted)]">{connection.links_projected ?? 0} links</div>
              </td>
              <td><Badge value={scopePolicyExclusionCount(connection.scope_policy) > 0 ? `${scopePolicyExclusionCount(connection.scope_policy)} excluded` : "all collected"} /></td>
              <td>
                <div>{displayDate(connection.last_activity_at)}</div>
                <div className="mt-0.5 text-[11px] text-[var(--text-muted)]">{formatDuration(connection.watermark_lag_seconds)} lag</div>
              </td>
              <td>{humanize(connection.next_action || "inspect")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function scopeList(policy: ConnectorScopePolicy | undefined, key: keyof ConnectorScopePolicy) {
  const value = policy?.[key];
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && item.trim().length > 0) : [];
}

function ScopePolicyCard({ connection }: { connection: ConnectorConnectionSummary }) {
  const policy = connection.scope_policy;
  const count = scopePolicyExclusionCount(policy);
  const families = scopeList(policy, "excluded_families");
  const assetClasses = scopeList(policy, "excluded_asset_classes");
  const kinds = scopeList(policy, "excluded_kinds");
  const resourceURNs = scopeList(policy, "excluded_resource_urns");
  const resources = policy?.excluded_resources ?? [];
  return (
    <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-[13px] font-semibold text-[var(--text-primary)]">{connection.family || "Default resource type"}</div>
          <div className="mt-0.5 font-mono text-[11px] text-[var(--text-muted)]">{connection.runtime_id}</div>
        </div>
        <Badge value={count > 0 ? `${count} excluded` : "all collected"} />
      </div>
      {count === 0 ? (
        <div className="mt-3 rounded-md bg-[var(--surface-muted)] px-3 py-2 text-[12px] text-[var(--text-muted)]">
          This connection has no collection exclusions. The runtime will attempt to collect every configured resource type.
        </div>
      ) : (
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          {families.length > 0 && <ScopeListBlock title="Resource types skipped before fetch" items={families} />}
          {assetClasses.length > 0 && <ScopeListBlock title="Asset classes" items={assetClasses} />}
          {kinds.length > 0 && <ScopeListBlock title="Event kinds" items={kinds} />}
          {resourceURNs.length > 0 && <ScopeListBlock title="Exact URNs" items={resourceURNs} mono />}
          {resources.length > 0 && <ScopeListBlock title="Typed resources" items={resources.map((resource) => `${resource.type}:${resource.id}`)} mono />}
        </div>
      )}
    </div>
  );
}

function ScopeListBlock({ title, items, mono = false }: { title: string; items: string[]; mono?: boolean }) {
  return (
    <div className="rounded-md bg-[var(--surface-muted)] p-3">
      <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">{title}</div>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {items.slice(0, 12).map((item) => (
          <span key={item} className={`max-w-full truncate rounded-md bg-[var(--surface)] px-2 py-1 text-[11px] text-[var(--text-secondary)] ${mono ? "font-mono" : "font-semibold"}`}>
            {item}
          </span>
        ))}
        {items.length > 12 && <span className="rounded-md bg-[var(--surface)] px-2 py-1 text-[11px] font-semibold text-[var(--text-muted)]">+{items.length - 12} more</span>}
      </div>
    </div>
  );
}

function DataKinds({ connector }: { connector: ConnectorCatalogEntry }) {
  const kinds = connector.emitted_kinds ?? [];
  const boundedKinds = grcBoundedRows({ rows: kinds, limit: CONNECTOR_DETAIL_KIND_LIMIT });
  const resourceTypes = connectorResourceTypes(connector, 12);
  if (kinds.length === 0 && resourceTypes.length === 0) return <EmptyBlock label="No emitted kinds or resource types configured." />;
  return (
    <div className="space-y-4">
      {resourceTypes.length > 0 && (
        <div>
          <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Resource types</div>
          <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
            {resourceTypes.map((item) => (
              <div key={item.template} className="rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-3 py-2">
                <div className="text-[13px] font-semibold text-[var(--text-primary)]">{item.label}</div>
                <div className="mt-0.5 font-mono text-[11px] text-[var(--text-muted)]">{item.template}</div>
                <div className="mt-1 text-[11px] text-[var(--text-muted)]">{item.resourceFamilies} catalog mapping{item.resourceFamilies === 1 ? "" : "s"}</div>
              </div>
            ))}
          </div>
        </div>
      )}
      {kinds.length > 0 && (
        <div>
          <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Emitted kinds</div>
          <ResultLimitNotice className="mb-3" loaded={boundedKinds.rows.length} meta={boundedKinds.meta} limit={CONNECTOR_DETAIL_KIND_LIMIT} noun="emitted kinds" />
          <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
            {boundedKinds.rows.map((kind) => (
              <div key={kind} className="rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-3 py-2">
                <div className="font-mono text-[12px] text-[var(--text-primary)]">{kind}</div>
                <div className="mt-0.5 text-[11px] text-[var(--text-muted)]">{connectorCapabilityLabel(kind.split(".")[0] || "data")} data</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function CatalogDefinitionPanel({ connector }: { connector: ConnectorCatalogEntry }) {
  const families = connector.resource_families ?? [];
  const boundedFamilies = grcBoundedRows({ rows: families, limit: GRC_DETAIL_LIMIT });
  const resourceTypeStats = connectorResourceTypeStats(connector);
  const resourceTypes = connectorResourceTypes(connector, 8);
  if (!connector.catalog_status && families.length === 0) return null;
  return (
    <Panel title="Catalog definition" action={<Badge value={connectorRuntimeSurfaceLabel(connector)} />}>
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
        <div className="rounded-lg bg-[var(--surface-muted)] p-3">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Readiness</div>
          <div className="mt-1 text-[13px] font-semibold text-[var(--text-primary)]">{connectorReadinessStageLabel(connector.readiness_stage || connector.catalog_status)}</div>
        </div>
        <div className="rounded-lg bg-[var(--surface-muted)] p-3">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Depth</div>
          <div className="mt-1 text-[13px] font-semibold text-[var(--text-primary)]">{connector.integration_depth ? connectorIntegrationDepthLabel(connector) : "Depth unknown"}</div>
        </div>
        <div className="rounded-lg bg-[var(--surface-muted)] p-3">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Catalog resource types</div>
          <div className="mt-1 text-[13px] font-semibold text-[var(--text-primary)]">{families.length}</div>
        </div>
        <div className="rounded-lg bg-[var(--surface-muted)] p-3">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Mapped resource types</div>
          <div className="mt-1 text-[13px] font-semibold text-[var(--text-primary)]">{resourceTypeStats.distinctResourceTypes}</div>
        </div>
        <div className="rounded-lg bg-[var(--surface-muted)] p-3">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Verification</div>
          <div className="mt-1 truncate font-mono text-[12px] text-[var(--text-primary)]">{connector.verification_endpoint || "No verification endpoint"}</div>
        </div>
      </div>
      <div className="mt-3 grid gap-3 md:grid-cols-3">
        <div className="rounded-lg bg-[var(--surface-muted)] p-3">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Auth</div>
          <div className="mt-1 text-[13px] font-semibold text-[var(--text-primary)]">{humanize(connector.auth_model || "unknown")}</div>
        </div>
        <div className="rounded-lg bg-[var(--surface-muted)] p-3">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Origin</div>
          <div className="mt-1 text-[13px] font-semibold text-[var(--text-primary)]">{connectorDefinitionOriginLabel(connector.definition_origin)}</div>
        </div>
        <div className="rounded-lg bg-[var(--surface-muted)] p-3">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Catalog path</div>
          <div className="mt-1 truncate font-mono text-[12px] text-[var(--text-primary)]">{connector.catalog_source_path || connector.catalog_schema_version || "Not cataloged"}</div>
        </div>
      </div>
      {resourceTypes.length > 0 && (
        <div className="mt-4 rounded-lg border border-[color:var(--border)] bg-[var(--surface)] px-3 py-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <div className="text-[12px] font-semibold text-[var(--text-primary)]">Resource types</div>
              <div className="mt-0.5 text-[11px] text-[var(--text-muted)]">
                {resourceTypeStats.resourceTypes} of {resourceTypeStats.catalogResourceTypes} catalog resource types have graph mappings.
              </div>
            </div>
            <Badge value={`${resourceTypeStats.highValueResourceTypes} high value`} />
          </div>
          <div className="mt-3 flex flex-wrap gap-1.5">
            {resourceTypes.map((item) => (
              <span key={item.template} title={item.template} className="rounded-md bg-[var(--surface-muted)] px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)]">
                {item.label}{item.resourceFamilies > 1 ? ` (${item.resourceFamilies})` : ""}
              </span>
            ))}
          </div>
        </div>
      )}
      {connector.missing_features && connector.missing_features.length > 0 && (
        <div className="mt-4 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-[12px] leading-5 text-amber-950 dark:border-amber-500/25 dark:bg-amber-500/10 dark:text-amber-100">
          <span className="font-semibold">Missing runtime features:</span> {connector.missing_features.join(", ")}
        </div>
      )}
      {families.length > 0 && (
        <>
          <ResultLimitNotice className="mt-4" loaded={boundedFamilies.rows.length} meta={boundedFamilies.meta} limit={GRC_DETAIL_LIMIT} noun="resource families" />
          <div className="mt-3 grid gap-2 lg:grid-cols-2">
            {boundedFamilies.rows.map((family) => {
              const projectionTemplate = connectorProjectionTemplate(family);
              const eventKind = connectorResourceFamilyEventKind(family);
              const schemaRef = connectorResourceFamilySchemaRef(family);
              const endpoint = [family.method, family.path].filter(Boolean).join(" ") || eventKind || family.id;
              return (
                <div key={family.id} className="rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-3 py-2">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="truncate text-[12px] font-semibold text-[var(--text-primary)]">{family.label || humanize(family.id)}</div>
                      <div className="mt-1 truncate font-mono text-[11px] text-[var(--text-muted)]">{endpoint}</div>
                    </div>
                    {family.high_value && <Badge value="high value" />}
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {projectionTemplate && (
                      <span title={projectionTemplate} className="rounded bg-[var(--surface-muted)] px-2 py-1 text-[10px] font-semibold text-[var(--text-secondary)]">
                        {connectorResourceTypeLabel(projectionTemplate)}
                      </span>
                    )}
                    {eventKind && <span className="rounded bg-[var(--surface-muted)] px-2 py-1 font-mono text-[10px] text-[var(--text-secondary)]">{eventKind}</span>}
                    {schemaRef && <span className="rounded bg-[var(--surface-muted)] px-2 py-1 font-mono text-[10px] text-[var(--text-secondary)]">{schemaRef}</span>}
                  </div>
                  {family.coverage && family.coverage.length > 0 && (
                    <div className="mt-3 border-t border-[color:var(--border)] pt-2">
                      <CoverageMetadataList items={family.coverage} compact showNotes />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </>
      )}
    </Panel>
  );
}

function CatalogSetupNotice({ connector }: { connector: ConnectorCatalogEntry }) {
  const accessLabel = connectorAccessStatusLabel(connector.access_status);
  const requestHref = connector.request_access_url?.trim();
  const availabilityDetail = connector.access_reason || (
    connector.runtime_executable
      ? "Generate and register the source runtime before saving connections."
      : connectorCatalogStatusLabel(connector.catalog_status)
  );
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
      <CatalogDefinitionPanel connector={connector} />
      <Panel title="Runtime status" action={<Badge value={connector.access_status ? accessLabel : connector.catalog_status || "catalog"} />}>
        <div className="space-y-3 text-[13px] leading-5 text-[var(--text-secondary)]">
          <p>
            {connector.access_reason
              ? "Connector metadata is visible, but setup is not enabled by this API."
              : "This catalog definition is not enabled by the backend as a live setup target."}
          </p>
          <div className="rounded-lg bg-[var(--surface-muted)] px-3 py-2">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Availability</div>
            <div className="mt-1 text-[var(--text-primary)]">{availabilityDetail}</div>
          </div>
          {connector.classifier_output && (
            <div className="rounded-lg bg-[var(--surface-muted)] px-3 py-2">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Classifier</div>
              <div className="mt-1 text-[var(--text-primary)]">{humanize(connector.classifier_output)}</div>
            </div>
          )}
          {connector.requestable && (
            <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] px-3 py-2">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Request path</div>
              <div className="mt-1 text-[var(--text-primary)]">{connector.requestable_reason || connector.access_reason || "This connector can be requested for this deployment."}</div>
              {requestHref && (
                <a href={requestHref} target="_blank" rel="noreferrer" className="primary-button mt-3 inline-flex px-3 py-2 text-[12px]">
                  {connectorRequestActionLabel(connector)}
                </a>
              )}
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
}

function ScopeView({ connector, connections }: { connector: ConnectorCatalogEntry; connections: ConnectorConnectionSummary[] }) {
  const capabilities = connectorCapabilities(connector, 8);
  const scopeOptions = connector.scope_options ?? [];
  const excludedConnections = connections.filter((connection) => scopePolicyExclusionCount(connection.scope_policy) > 0);
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
      <Panel title="Collection policy">
        <div className="grid gap-3 md:grid-cols-3">
          <div className="rounded-lg bg-[var(--surface-muted)] p-3">
            <div className="text-xl font-semibold text-[var(--text-primary)]">{scopeOptions.length}</div>
            <div className="text-[11px] text-[var(--text-muted)]">available classes</div>
          </div>
          <div className="rounded-lg bg-[var(--surface-muted)] p-3">
            <div className="text-xl font-semibold text-[var(--text-primary)]">{excludedConnections.length}</div>
            <div className="text-[11px] text-[var(--text-muted)]">connections with exclusions</div>
          </div>
          <div className="rounded-lg bg-[var(--surface-muted)] p-3">
            <div className="text-xl font-semibold text-[var(--text-primary)]">{connections.reduce((sum, connection) => sum + scopePolicyExclusionCount(connection.scope_policy), 0)}</div>
            <div className="text-[11px] text-[var(--text-muted)]">total exclusions</div>
          </div>
        </div>
        <div className="mt-4 space-y-3">
          {connections.length === 0 && <EmptyBlock label="Connect this source before collection exclusions can be evaluated." />}
          {connections.map((connection) => (
            <ScopePolicyCard key={connection.runtime_id} connection={connection} />
          ))}
        </div>
      </Panel>
      <Panel title="Capability coverage">
        {scopeOptions.length > 0 && (
          <div className="mb-4 space-y-2">
            {scopeOptions.slice(0, 10).map((option) => (
              <div key={option.id} className="rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-3 py-2">
                <div className="text-[12px] font-semibold text-[var(--text-primary)]">{option.label}</div>
                <div className="mt-1 font-mono text-[11px] text-[var(--text-muted)]">{option.families?.join(", ") || option.id}</div>
                <div className="mt-2">
                  <CoverageMetadata item={option} compact showNotes />
                </div>
              </div>
            ))}
          </div>
        )}
        <div className="flex flex-wrap gap-2">
          {capabilities.length > 0 ? capabilities.map((capability) => (
            <span key={capability} className="rounded-md bg-[var(--surface-muted)] px-2 py-1 text-[12px] font-semibold text-[var(--text-secondary)]">
              {connectorCapabilityLabel(capability)}
            </span>
          )) : <span className="text-[13px] text-[var(--text-muted)]">No capability groups configured.</span>}
        </div>
      </Panel>
    </div>
  );
}

function setupHref(sourceID: string, tenantID: string, framework = "") {
  const params = new URLSearchParams();
  if (tenantID.trim()) params.set("tenant_id", tenantID.trim());
  if (framework.trim()) params.set("framework", framework.trim());
  const query = params.toString();
  return `/connectors/${encodeURIComponent(sourceID)}/setup${query ? `?${query}` : ""}`;
}

function detailHref(sourceID: string, tenantID: string, framework = "") {
  const params = new URLSearchParams();
  if (tenantID.trim()) params.set("tenant_id", tenantID.trim());
  if (framework.trim()) params.set("framework", framework.trim());
  const query = params.toString();
  return `/connectors/${encodeURIComponent(sourceID)}${query ? `?${query}` : ""}`;
}

export function ConnectorDetailContent({ setupOnly = false }: { setupOnly?: boolean }) {
  const params = useParams<{ sourceID: string }>();
  const searchParams = useSearchParams();
  const { apiKey } = useApiKey();
  const sourceID = useMemo(() => decodeURIComponent(params.sourceID ?? ""), [params.sourceID]);
  const runtimeID = searchParams.get("runtime_id") ?? "";
  const framework = searchParams.get("framework") ?? "";
  const initialTab = setupOnly ? "setup" : (searchParams.get("tab") as DetailTab | null) ?? (runtimeID ? "connections" : "overview");
  const [activeTab, setActiveTab] = useState<DetailTab>(tabs.some((tab) => tab.id === initialTab) ? initialTab : "overview");
  const [tenantID, setTenantID] = useState(searchParams.get("tenant_id") ?? "");
  const debouncedTenantID = useDebouncedValue(tenantID.trim());

  const detailQuery = useGRCQuery<ConnectorDetailResponse>(withQuery(`/connectors/${encodeURIComponent(sourceID)}`, { tenant_id: debouncedTenantID, limit: GRC_DETAIL_LIMIT }));
  const libraryQuery = useGRCQuery<ConnectorLibraryResponse>(withQuery("/connectors", { tenant_id: debouncedTenantID, view: "full", limit: 1 }));

  const credentialStores = useMemo(() => normalizeCredentialStores(libraryQuery.data), [libraryQuery.data]);
  const connector = detailQuery.data?.connector;
  const summary: ConnectorOperationsSummary = detailQuery.data?.summary ?? { status: "not_configured" };
  const boundedConnectionRows = useMemo(
    () => grcBoundedRows({ rows: detailQuery.data?.connections, limit: GRC_DETAIL_LIMIT, total: summary.total_connections }),
    [detailQuery.data?.connections, summary.total_connections],
  );
  const boundedActivityRows = useMemo(
    () => grcBoundedRows({ rows: detailQuery.data?.activity, limit: GRC_DETAIL_LIMIT }),
    [detailQuery.data?.activity],
  );
  const boundedDiagnosticRows = useMemo(
    () => grcBoundedRows({ rows: detailQuery.data?.diagnostic_timeline, limit: GRC_DETAIL_LIMIT }),
    [detailQuery.data?.diagnostic_timeline],
  );
  const connections = boundedConnectionRows.rows;
  const activity = boundedActivityRows.rows;
  const diagnosticTimeline = boundedDiagnosticRows.rows;
  const loading = detailQuery.loading && !detailQuery.data;

  if (loading) return <LoadingBlock label="Loading connector..." />;
  if (detailQuery.error) {
    return (
      <ErrorBlock
        error={detailQuery.error}
        onRetry={() => { void detailQuery.reload(); void libraryQuery.reload(); }}
        recoveryDetail="Connector details will appear when the API is reachable."
      />
    );
  }
  if (!connector) {
    return (
      <div className="space-y-4">
        <ErrorBlock error="Connector source was not found." />
        <Link href="/connectors" className="secondary-button inline-flex px-3 py-2 text-[13px]">Back to connectors</Link>
      </div>
    );
  }

  const displayName = connectorDisplayName(connector);
  const meta = connectorDisplayMetadata(connector);
  const readyStores = credentialStores.filter((store) => store.available);
  const capabilityLabels = connectorCapabilities(connector, 4);
  const resourceTypes = connectorResourceTypes(connector, 4);
  const resourceTypeStats = connectorResourceTypeStats(connector);
  const catalogOnly = connectorIsCatalogOnly(connector);
  const setupAllowed = connectorSetupAllowed(connector);

  if (setupOnly) {
    const setupStats = [
      { label: "Ready stores", value: String(readyStores.length) },
      { label: "Source", value: meta.category },
      { label: "Connections", value: String(connections.length) },
      { label: "Resource types", value: String(resourceTypeStats.resourceTypes) },
    ];

    return (
      <div className="space-y-5">
        <section className="overflow-hidden rounded-xl border border-[color:var(--border)] bg-[var(--surface)] shadow-[var(--shadow-sm)]">
          <div className="grid gap-5 p-5 xl:grid-cols-[minmax(0,1fr)_340px]">
            <div className="min-w-0">
              <Link href={detailHref(sourceID, tenantID, framework)} className="mb-4 inline-flex items-center gap-1.5 text-[12px] font-semibold text-[var(--text-muted)] hover:text-[var(--text-primary)]">
                <ArrowLeft className="h-3.5 w-3.5" />
                Back to {displayName}
              </Link>
              <div className="flex items-start gap-3">
                <ProviderMark connector={connector} />
                <div className="min-w-0">
                  <h1 className="text-2xl font-semibold tracking-tight text-[var(--text-primary)]">Connect {displayName}</h1>
                  <p className="mt-1 max-w-3xl text-[13px] leading-5 text-[var(--text-muted)]">
                    Choose identity, bind credentials to a backend store, validate access, then save a collector runtime with optional collection exclusions.
                  </p>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {capabilityLabels.map((capability) => (
                      <span key={capability} className="rounded-md bg-[var(--surface-muted)] px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)]">
                        {connectorCapabilityLabel(capability)}
                      </span>
                    ))}
                    {resourceTypes.map((item) => (
                      <span key={item.template} title={item.template} className="rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)]">
                        {item.label}
                      </span>
                    ))}
                    {capabilityLabels.length === 0 && resourceTypes.length === 0 && <Badge value="connector runtime" />}
                  </div>
                </div>
              </div>
            </div>
            <div className="grid gap-3">
              <div className="grid overflow-hidden rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] text-center sm:grid-cols-4">
                {setupStats.map((item) => (
                  <div key={item.label} className="border-t border-[color:var(--border)] px-3 py-3 first:border-t-0 sm:border-l sm:border-t-0 sm:first:border-l-0">
                    <div className="text-[15px] font-semibold leading-5 text-[var(--text-primary)]">{item.value}</div>
                    <div className="mt-0.5 text-[10px] font-semibold uppercase tracking-[0.08em] text-[var(--text-muted)]">{item.label}</div>
                  </div>
                ))}
              </div>
              <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-3 text-[12px] leading-5 text-[var(--text-secondary)]">
                <span className="font-semibold text-[var(--text-primary)]">Credentials:</span>
                <span className="ml-1">encrypted submit or backend references only.</span>
              </div>
            </div>
          </div>

          <div className="grid gap-3 border-t border-[color:var(--border)] bg-[var(--surface-muted)] p-4 md:grid-cols-[minmax(220px,0.45fr)_minmax(0,1fr)_auto]">
            <label className={labelClass}>
              Tenant
              <input value={tenantID} onChange={(event) => setTenantID(event.target.value)} placeholder="All tenants" className={inputClass} />
            </label>
            <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] px-3 py-2 text-[12px] leading-5 text-[var(--text-secondary)]">
              <span className="font-semibold text-[var(--text-primary)]">Dedicated setup:</span>
              <span className="ml-1">monitoring and activity remain on the connector detail page.</span>
            </div>
            <button type="button" onClick={() => void Promise.all([detailQuery.reload(), libraryQuery.reload()])} className="secondary-button inline-flex items-center justify-center gap-2 px-3 py-2 text-[13px]">
              <RefreshCw className="h-4 w-4" />
              Refresh metadata
            </button>
          </div>
        </section>

        {!setupAllowed ? (
          <CatalogSetupNotice connector={connector} />
        ) : (
          <ConnectorSetupForm
            connector={connector}
            tenantID={tenantID.trim()}
            apiKey={apiKey}
            credentialStores={credentialStores}
            initialFramework={framework}
            onConnected={() => Promise.all([detailQuery.reload(), libraryQuery.reload()]).then(() => undefined)}
          />
        )}
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <Link href="/connectors" className="mb-3 inline-flex items-center gap-1.5 text-[12px] font-semibold text-[var(--text-muted)] hover:text-[var(--text-primary)]">
            <ArrowLeft className="h-3.5 w-3.5" />
            Back to connectors
          </Link>
          <div className="flex items-start gap-3">
            <ProviderMark connector={connector} />
            <div className="min-w-0">
              <h1 className="text-2xl font-semibold tracking-tight text-[var(--text-primary)]">{displayName}</h1>
              <p className="mt-1 max-w-3xl text-[13px] leading-5 text-[var(--text-muted)]">
                {connector.description || "Connector setup, credential store selection, and runtime health."}
              </p>
              <div className="mt-3 flex flex-wrap gap-2">
                <Badge value={summary.status || "not_configured"} />
                <span className="rounded-md bg-[var(--surface-muted)] px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)]">{meta.category}</span>
                {connector.access_status && connector.access_status !== "available" && (
                  <span className="rounded-md bg-amber-50 px-2 py-1 text-[11px] font-semibold text-amber-800 dark:bg-amber-500/15 dark:text-amber-100">
                    {connectorAccessStatusLabel(connector.access_status)}
                  </span>
                )}
                {capabilityLabels.map((capability) => (
                  <span key={capability} className="rounded-md bg-[var(--surface-muted)] px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)]">
                    {connectorCapabilityLabel(capability)}
                  </span>
                ))}
                {resourceTypes.map((item) => (
                  <span key={item.template} title={item.template} className="rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)]">
                    {item.label}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          {setupAllowed && !catalogOnly && (
            <Link href={setupHref(sourceID, tenantID, framework)} className="secondary-button px-3 py-2 text-[13px]">
              Add connection
            </Link>
          )}
          <button type="button" onClick={() => void Promise.all([detailQuery.reload(), libraryQuery.reload()])} className="primary-button inline-flex items-center gap-2 px-3 py-2 text-[13px]">
            <RefreshCw className="h-4 w-4" />
            Refresh
          </button>
        </div>
      </div>

      <OperationsSummary connector={connector} summary={summary} secretStoreCount={readyStores.length} />
      <AttentionNotice summary={summary} setupAllowed={setupAllowed} onSetup={() => setActiveTab("setup")} />

      <section className="surface-panel p-4">
        <div className="grid gap-3 md:grid-cols-[minmax(220px,0.6fr)_minmax(0,1fr)]">
          <label className={labelClass}>
            Tenant filter
            <input value={tenantID} onChange={(event) => setTenantID(event.target.value)} placeholder="All tenants" className={inputClass} />
          </label>
          <details className="rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2 text-[12px] leading-5 text-[var(--text-secondary)]">
            <summary className="cursor-pointer font-semibold text-[var(--text-primary)]">Technical details</summary>
            <div className="mt-2 grid gap-2 sm:grid-cols-3">
              <div><span className="text-[var(--text-muted)]">Source ID</span><div className="font-mono">{connector.source_id}</div></div>
              <div><span className="text-[var(--text-muted)]">Generated</span><div>{displayDate(detailQuery.data?.generated_at)}</div></div>
              <div><span className="text-[var(--text-muted)]">Credential stores</span><div>{readyStores.map((store) => store.shortLabel).join(", ") || "none"}</div></div>
              <div><span className="text-[var(--text-muted)]">Catalog</span><div>{connector.catalog_status ? connectorCatalogStatusLabel(connector.catalog_status) : "Compiled source"}</div></div>
              <div><span className="text-[var(--text-muted)]">Runtime surface</span><div>{connectorRuntimeSurfaceLabel(connector)}</div></div>
              <div><span className="text-[var(--text-muted)]">Access</span><div>{connectorAccessStatusLabel(connector.access_status)}</div></div>
              <div><span className="text-[var(--text-muted)]">Stage</span><div>{connectorReadinessStageLabel(connector.readiness_stage)}</div></div>
              <div><span className="text-[var(--text-muted)]">Depth</span><div>{connector.integration_depth ? connectorIntegrationDepthLabel(connector) : "Depth unknown"}</div></div>
              <div><span className="text-[var(--text-muted)]">Resource types</span><div>{resourceTypeStats.resourceTypes}</div></div>
              <div><span className="text-[var(--text-muted)]">Origin</span><div>{connectorDefinitionOriginLabel(connector.definition_origin)}</div></div>
              <div><span className="text-[var(--text-muted)]">Auth model</span><div>{humanize(connector.auth_model || "unknown")}</div></div>
            </div>
          </details>
        </div>
      </section>

      <div className="flex gap-4 overflow-x-auto border-b border-[color:var(--border)] pb-1">
        {tabs.map((tab) => (
          <TabButton key={tab.id} id={tab.id} active={activeTab === tab.id} onClick={setActiveTab} />
        ))}
      </div>

      {activeTab === "overview" && (
        <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1.35fr)_minmax(320px,0.75fr)]">
          <Panel title="Activity summary" action={<button type="button" onClick={() => setActiveTab("activity")} className="secondary-button px-3 py-1.5 text-[12px]">View activity</button>}>
            <p className="text-[15px] leading-7 text-[var(--text-primary)]">
              {summary.status === "healthy"
                ? `${displayName} syncs are running successfully and current.`
                : summary.status_reason || `${displayName} needs configuration or freshness review.`}
            </p>
            <div className="mt-4 grid gap-3 md:grid-cols-4">
              <div className="rounded-lg bg-[var(--surface-muted)] p-3">
                <div className="text-xl font-semibold text-[var(--text-primary)]">{summary.total_connections ?? 0}</div>
                <div className="text-[11px] text-[var(--text-muted)]">connections</div>
              </div>
              <div className="rounded-lg bg-[var(--surface-muted)] p-3">
                <div className="text-xl font-semibold text-[var(--text-primary)]">{summary.needs_attention ?? 0}</div>
                <div className="text-[11px] text-[var(--text-muted)]">need attention</div>
              </div>
              <div className="rounded-lg bg-[var(--surface-muted)] p-3">
                <div className="text-xl font-semibold text-[var(--text-primary)]">{summary.resource_types ?? connector.emitted_kinds?.length ?? 0}</div>
                <div className="text-[11px] text-[var(--text-muted)]">resource types</div>
              </div>
              <div className="rounded-lg bg-[var(--surface-muted)] p-3">
                <div className="text-xl font-semibold text-[var(--text-primary)]">{resourceTypeStats.resourceTypes}</div>
                <div className="text-[11px] text-[var(--text-muted)]">catalog-backed resource types</div>
              </div>
            </div>
          </Panel>
          <Panel title="Connection details">
            <div className="space-y-3 text-[13px]">
              {[
                ["Last activity", summary.last_activity_at ? displayDate(summary.last_activity_at) : "Not observed"],
                ["Sync frequency", summary.sync_frequency_seconds ? `Every ${formatDuration(summary.sync_frequency_seconds)}` : "Deployment managed"],
                ["Credential stores", readyStores.map((store) => store.label).join(", ") || "No ready credential store"],
                ["Catalog", connector.catalog_status ? connectorCatalogStatusLabel(connector.catalog_status) : "Compiled source"],
                ["Runtime", connectorRuntimeSurfaceLabel(connector)],
                ["Access", connectorAccessStatusLabel(connector.access_status)],
                ["Stage", connectorReadinessStageLabel(connector.readiness_stage)],
                ["Depth", connector.integration_depth ? connectorIntegrationDepthLabel(connector) : "Depth unknown"],
                ["Resource types", String(resourceTypeStats.resourceTypes)],
                ["Provider", meta.provider],
              ].map(([label, value]) => (
                <div key={label} className="flex justify-between gap-4 border-b border-[color:var(--border)] pb-2 last:border-0 last:pb-0">
                  <span className="text-[var(--text-muted)]">{label}</span>
                  <span className="text-right text-[var(--text-primary)]">{value}</span>
                </div>
              ))}
              {!setupAllowed && connector.access_reason && (
                <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2 text-[12px] leading-5 text-[var(--text-secondary)]">
                  <span className="font-semibold text-[var(--text-primary)]">Availability:</span> {connector.access_reason}
                </div>
              )}
            </div>
          </Panel>
          <CatalogDefinitionPanel connector={connector} />
          <Panel title="Recent activity" action={<span className="text-[12px] text-[var(--text-muted)]">{activity.slice(0, 5).length} events</span>}>
            <ConnectorActivityTable activity={activity.slice(0, 5)} />
          </Panel>
        </div>
      )}

      {activeTab === "setup" && (!setupAllowed ? (
        <CatalogSetupNotice connector={connector} />
      ) : (
        <ConnectorSetupForm
          connector={connector}
          tenantID={tenantID.trim()}
          apiKey={apiKey}
          credentialStores={credentialStores}
          initialFramework={framework}
          onConnected={() => Promise.all([detailQuery.reload(), libraryQuery.reload()]).then(() => undefined)}
        />
      ))}

      {activeTab === "connections" && (
        <Panel title="Connections" action={<span className="text-[12px] text-[var(--text-muted)]">{connections.length} shown</span>}>
          <ResultLimitNotice className="mb-3" loaded={connections.length} meta={boundedConnectionRows.meta} limit={GRC_DETAIL_LIMIT} noun="connections" />
          <ConnectionsTable connections={connections} activeRuntimeID={runtimeID} />
        </Panel>
      )}

      {activeTab === "activity" && (
        <div className="space-y-4">
          <Panel title="Diagnostic timeline" action={<span className="text-[12px] text-[var(--text-muted)]">{diagnosticTimeline.length} stages</span>}>
            <ResultLimitNotice className="mb-3" loaded={diagnosticTimeline.length} meta={boundedDiagnosticRows.meta} limit={GRC_DETAIL_LIMIT} noun="diagnostic stages" />
            <ConnectorDiagnosticTimelinePanel timeline={diagnosticTimeline} />
          </Panel>
          <Panel title="Activity" action={<span className="text-[12px] text-[var(--text-muted)]">{activity.length} events</span>}>
            <ResultLimitNotice className="mb-3" loaded={activity.length} meta={boundedActivityRows.meta} limit={GRC_DETAIL_LIMIT} noun="activity events" />
            <ConnectorActivityTable activity={activity} />
          </Panel>
        </div>
      )}

      {activeTab === "scope" && <ScopeView connector={connector} connections={connections} />}

      {activeTab === "data" && (
        <Panel title="Data and graph" action={<Search className="h-4 w-4 text-[var(--text-muted)]" />}>
          <DataKinds connector={connector} />
        </Panel>
      )}
    </div>
  );
}

export default function ConnectorDetailPage() {
  return <ConnectorDetailContent />;
}
