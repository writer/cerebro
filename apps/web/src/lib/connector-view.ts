import type { ConnectorCatalogEntry, ConnectorCatalogResourceFamily } from "@/lib/connectors";
import {
  connectorDisplayMetadata,
  connectorDisplayName,
  connectorIsCatalogOnly,
  connectorRequestActionLabel,
  connectorSearchText,
  connectorSetupAllowed,
  connectorStatus,
} from "@/lib/connectors";
import type { SourceCoverageSummary, SourceReadiness } from "@/lib/connector-runtime";

export type ReadinessFilter = SourceReadiness | "all";

export type ConnectorCard = ConnectorCatalogEntry & {
  coverage?: SourceCoverageSummary;
  readiness: SourceReadiness;
  nextAction: string;
};

export type ProviderAPIProofState = "needs_discovery" | "needs_mapping" | "needs_proof" | "verified";

export type ProviderAPIProofQueueItem = {
  sourceID: string;
  displayName: string;
  state: ProviderAPIProofState;
  label: string;
  detail: string;
  priority: number;
  score: number | null;
  tier: string;
  missing: string[];
  reasons: string[];
  references: string[];
  href: string;
};

export type ProviderAPIProofMetrics = {
  total: number;
  needsAction: number;
  needsDiscovery: number;
  needsMapping: number;
  needsProof: number;
  verified: number;
  averageScore: number | null;
};

export const readinessOrder: SourceReadiness[] = ["bad", "needs_refresh", "poor", "healthy", "not_configured"];

export const readinessLabels: Record<ReadinessFilter, string> = {
  all: "All",
  bad: "Failed",
  needs_refresh: "Needs refresh",
  poor: "Poor",
  healthy: "Healthy",
  not_configured: "Not configured",
};

export const readinessDescriptions: Record<SourceReadiness, string> = {
  bad: "Sync or graph projection failed.",
  needs_refresh: "Freshness, cursor, or schedule is behind.",
  poor: "Telemetry is incomplete or graph projection is lagging.",
  healthy: "Sync and graph signals are current.",
  not_configured: "No active connection is configured.",
};

export const readinessAccentClass: Record<SourceReadiness, string> = {
  bad: "bg-red-500",
  needs_refresh: "bg-amber-500",
  poor: "bg-orange-500",
  healthy: "bg-emerald-500",
  not_configured: "bg-zinc-400",
};

export const readinessRowClass: Record<SourceReadiness, string> = {
  bad: "border-l-red-500",
  needs_refresh: "border-l-amber-500",
  poor: "border-l-orange-500",
  healthy: "border-l-emerald-500",
  not_configured: "border-l-zinc-400",
};

const providerAPIStateLabels: Record<ProviderAPIProofState, string> = {
  needs_discovery: "Find API source",
  needs_mapping: "Map runtime families",
  needs_proof: "Add proof",
  verified: "Verified",
};

const providerAPIStateSort: Record<ProviderAPIProofState, number> = {
  needs_discovery: 0,
  needs_mapping: 1,
  needs_proof: 2,
  verified: 3,
};

const providerAPITierScore: Record<string, number> = {
  urgent: 90,
  high: 70,
  standard: 45,
  backlog: 20,
};

const runtimeAttentionCount = (source: SourceCoverageSummary) =>
  source.degraded + source.stale + source.unknown + source.graph_failed + source.graph_behind + source.cursor_pending;

const normalizedStrings = (items?: string[]) =>
  (items ?? []).map((item) => item.trim()).filter(Boolean);

const positiveNumber = (value: unknown) => (typeof value === "number" && Number.isFinite(value) && value > 0 ? value : 0);

const proofScoreFor = (card: Pick<ConnectorCatalogEntry, "provider_api_proof_score">) =>
  typeof card.provider_api_proof_score === "number" && Number.isFinite(card.provider_api_proof_score)
    ? Math.max(0, Math.min(100, Math.round(card.provider_api_proof_score)))
    : null;

const providerAPIMissingFamilies = (card: Pick<ConnectorCatalogEntry, "provider_api_missing_families" | "missing_families">) =>
  normalizedStrings(card.provider_api_missing_families).length > 0
    ? normalizedStrings(card.provider_api_missing_families)
    : normalizedStrings(card.missing_families);

const providerAPIProofGaps = (card: Pick<ConnectorCatalogEntry, "provider_api_proof_gaps">) =>
  normalizedStrings(card.provider_api_proof_gaps);

const providerAPIReferences = (card: Pick<ConnectorCatalogEntry, "provider_api_references" | "existing_references" | "provider_api_spec_url">) =>
  [
    ...normalizedStrings(card.provider_api_references),
    ...normalizedStrings(card.existing_references),
    card.provider_api_spec_url?.trim(),
  ].filter((value): value is string => Boolean(value));

const providerAPIEvidenceCount = (
  card: Pick<ConnectorCatalogEntry, "provider_api_references" | "existing_references" | "provider_api_spec_url" | "provider_api_auth_evidence" | "provider_api_scope_evidence">,
) =>
  providerAPIReferences(card).length +
  normalizedStrings(card.provider_api_auth_evidence).length +
  normalizedStrings(card.provider_api_scope_evidence).length;

const providerAPIHasContract = (
  card: Pick<ConnectorCatalogEntry, "has_provider_api_contract" | "provider_api_status" | "provider_api_spec_url" | "provider_api_references" | "existing_references">,
) =>
  Boolean(card.has_provider_api_contract || card.provider_api_status || providerAPIReferences(card).length > 0);

const providerAPIHasMapping = (
  card: Pick<ConnectorCatalogEntry, "has_provider_api_mapping" | "provider_api_mapped_families">,
) =>
  Boolean(card.has_provider_api_mapping || normalizedStrings(card.provider_api_mapped_families).length > 0);

const providerAPIBasePriority = (card: Pick<ConnectorCatalogEntry, "priority" | "priority_tier">) => {
  const priority = positiveNumber(card.priority);
  if (priority > 0) return priority;
  const tier = card.priority_tier?.trim().toLowerCase();
  return tier ? providerAPITierScore[tier] ?? 0 : 0;
};

const providerAPIProofApplies = (card: ConnectorCatalogEntry | ConnectorCard) =>
  Boolean(
    providerAPIHasContract(card) ||
    providerAPIHasMapping(card) ||
    card.has_provider_api_proof ||
    proofScoreFor(card) !== null ||
    providerAPIBasePriority(card) > 0 ||
    normalizedStrings(card.priority_reasons).length > 0 ||
    normalizedStrings(card.search_queries).length > 0 ||
    normalizedStrings(card.provider_api_auth_evidence).length > 0 ||
    normalizedStrings(card.provider_api_scope_evidence).length > 0 ||
    normalizedStrings(card.provider_api_missing_families).length > 0 ||
    normalizedStrings(card.provider_api_proof_gaps).length > 0 ||
    Boolean(card.catalog_path?.trim() || card.package_path?.trim() || card.next_action?.trim()),
  );

export function providerAPIProofState(card: ConnectorCatalogEntry | ConnectorCard): ProviderAPIProofState {
  const hasContract = providerAPIHasContract(card);
  if (!hasContract) return "needs_discovery";

  const missingFamilies = providerAPIMissingFamilies(card);
  if (!providerAPIHasMapping(card) || missingFamilies.length > 0) return "needs_mapping";

  const proofGaps = providerAPIProofGaps(card);
  const score = proofScoreFor(card);
  const hasProof = Boolean(card.has_provider_api_proof || score === 100);
  if (!hasProof || proofGaps.length > 0 || (score !== null && score < 100) || providerAPIEvidenceCount(card) === 0) {
    return "needs_proof";
  }
  return "verified";
}

export function providerAPIProofStateLabel(state: ProviderAPIProofState) {
  return providerAPIStateLabels[state];
}

export function providerAPIProofStateIntent(state: ProviderAPIProofState): "neutral" | "danger" | "warning" | "success" {
  if (state === "needs_discovery") return "danger";
  if (state === "needs_mapping" || state === "needs_proof") return "warning";
  return "success";
}

export function providerAPIProofDetail(card: ConnectorCatalogEntry | ConnectorCard, state = providerAPIProofState(card)) {
  const missingFamilies = providerAPIMissingFamilies(card);
  const proofGaps = providerAPIProofGaps(card);
  if (state === "needs_discovery") {
    return card.next_action || "Find provider API documentation, auth details, and a machine-readable spec or reference.";
  }
  if (state === "needs_mapping") {
    return missingFamilies.length > 0
      ? `${missingFamilies.length} runtime families need method or operation mapping.`
      : "Map runtime families to documented provider API methods.";
  }
  if (state === "needs_proof") {
    return proofGaps[0] || "Attach spec, auth, scope, and fixture evidence for the mapped API surface.";
  }
  return "Provider API proof is current.";
}

export function providerAPIProofMetrics(cards: Array<ConnectorCatalogEntry | ConnectorCard>): ProviderAPIProofMetrics {
  const scopedCards = cards.filter(providerAPIProofApplies);
  const metrics: ProviderAPIProofMetrics = {
    total: scopedCards.length,
    needsAction: 0,
    needsDiscovery: 0,
    needsMapping: 0,
    needsProof: 0,
    verified: 0,
    averageScore: null,
  };
  const scores: number[] = [];
  scopedCards.forEach((card) => {
    const state = providerAPIProofState(card);
    if (state === "needs_discovery") metrics.needsDiscovery += 1;
    else if (state === "needs_mapping") metrics.needsMapping += 1;
    else if (state === "needs_proof") metrics.needsProof += 1;
    else metrics.verified += 1;
    const score = proofScoreFor(card);
    if (score !== null) scores.push(score);
  });
  metrics.needsAction = metrics.needsDiscovery + metrics.needsMapping + metrics.needsProof;
  metrics.averageScore = scores.length ? Math.round(scores.reduce((sum, score) => sum + score, 0) / scores.length) : null;
  return metrics;
}

export function providerAPIProofQueue(
  cards: ConnectorCard[],
  { limit = 6, tenantID = "" }: { limit?: number; tenantID?: string } = {},
): ProviderAPIProofQueueItem[] {
  return cards
    .filter(providerAPIProofApplies)
    .map((card) => {
      const state = providerAPIProofState(card);
      const score = proofScoreFor(card);
      const missing = state === "needs_proof" ? providerAPIProofGaps(card) : providerAPIMissingFamilies(card);
      const priority = providerAPIBasePriority(card) + missing.length * 4 + (score === null ? 0 : 100 - score);
      return {
        sourceID: card.source_id,
        displayName: connectorDisplayName(card),
        state,
        label: providerAPIProofStateLabel(state),
        detail: providerAPIProofDetail(card, state),
        priority,
        score,
        tier: card.priority_tier?.trim() || (priority >= 90 ? "urgent" : priority >= 70 ? "high" : priority >= 40 ? "standard" : "backlog"),
        missing,
        reasons: normalizedStrings(card.priority_reasons),
        references: providerAPIReferences(card),
        href: connectorPath(card.source_id, { tenant_id: tenantID }),
      } satisfies ProviderAPIProofQueueItem;
    })
    .filter((item) => item.state !== "verified")
    .sort((left, right) =>
      providerAPIStateSort[left.state] - providerAPIStateSort[right.state] ||
      right.priority - left.priority ||
      (left.score ?? 101) - (right.score ?? 101) ||
      left.displayName.localeCompare(right.displayName),
    )
    .slice(0, limit);
}

export function compactConnectorStatus(card: ConnectorCatalogEntry | ConnectorCard): SourceReadiness {
  const cardWithCoverage = card as ConnectorCard;
  if (cardWithCoverage.coverage) return cardWithCoverage.coverage.performance;
  if (connectorIsCatalogOnly(card)) {
    if (card.catalog_status === "generateable" || card.catalog_status === "catalog_ready") return "not_configured";
    return "poor";
  }
  const status = connectorStatus(card);
  if (["bad", "needs_refresh", "poor", "healthy", "not_configured"].includes(status)) {
    return status as SourceReadiness;
  }
  return status === "available" ? "not_configured" : "poor";
}

export function connectorRuntimeTotal(card: ConnectorCard) {
  return card.coverage?.total ?? card.configured_runtimes ?? 0;
}

export function connectorHealthyTotal(card: ConnectorCard) {
  return card.coverage?.healthy ?? card.healthy_runtimes ?? 0;
}

export function connectorAttentionTotal(card: ConnectorCard) {
  const total = connectorRuntimeTotal(card);
  const healthy = connectorHealthyTotal(card);
  return Math.max(card.coverage ? runtimeAttentionCount(card.coverage) : (card.needs_attention_runtimes ?? total - healthy), 0);
}

export function connectorPrimaryAction(card: ConnectorCard) {
  if (!connectorSetupAllowed(card) && card.requestable && card.request_access_url) return connectorRequestActionLabel(card);
  if (connectorIsCatalogOnly(card)) return "Inspect";
  if (!connectorSetupAllowed(card)) return card.requestable ? "Inspect" : "View";
  const status = compactConnectorStatus(card);
  if (status === "not_configured") return "Connect";
  if (status === "healthy") return "View";
  if (status === "needs_refresh") return "Refresh";
  return "Fix";
}

export function connectorCapabilities(card: Pick<ConnectorCatalogEntry, "emitted_kinds" | "resource_families" | "catalog_categories">, limit = 3) {
  const seen = new Set<string>();
  (card.resource_families ?? []).forEach((family) => {
    const label = family.label?.trim() || family.id?.trim();
    if (label) seen.add(label);
  });
  if (seen.size === 0) {
    (card.catalog_categories ?? []).forEach((category) => {
      const normalized = category.trim();
      if (normalized) seen.add(normalized);
    });
  }
  if (seen.size === 0) {
    (card.emitted_kinds ?? []).forEach((kind) => {
      const prefix = kind.split(".")[0]?.trim();
      if (prefix) seen.add(prefix);
    });
  }
  return [...seen].slice(0, limit);
}

const connectorCapabilityLabels: Record<string, string> = {
  anthropic: "Anthropic",
  asset: "Assets",
  aws: "Amazon Web Services",
  azure: "Microsoft Azure",
  cloudflare: "Cloudflare",
  grc: "GRC",
  gcp: "Google Cloud Platform",
  github: "GitHub",
  google_workspace: "Google Workspace",
  iac: "IaC",
  itsm: "ITSM",
  mdm: "MDM",
  okta: "Okta",
  openai: "OpenAI",
  saas: "SaaS",
  sca: "SCA",
  siem: "SIEM",
  soar: "SOAR",
};

export function connectorCapabilityLabel(capability: string) {
  const normalized = capability.trim().toLowerCase();
  const label = connectorCapabilityLabels[normalized];
  if (label) return label;
  return normalized
    .split(/[_-]+/)
    .filter(Boolean)
    .map((part) => part.slice(0, 1).toUpperCase() + part.slice(1))
    .join(" ");
}

const connectorResourceTypeLabels: Record<string, string> = {
  account: "Accounts",
  alert: "Alerts",
  api_key: "API keys",
  app_entitlement: "App entitlements",
  approval: "Approvals",
  asset: "Assets",
  audit_event: "Audit events",
  cloud_account: "Cloud accounts",
  cloud_resource: "Cloud resources",
  control: "Controls",
  credential: "Credentials",
  data_table: "Data tables",
  dataset: "Datasets",
  deployment: "Deployments",
  device: "Devices",
  document: "Documents",
  endpoint_device: "Endpoint devices",
  finding: "Findings",
  group_membership: "Group memberships",
  identity_group: "Groups",
  identity_user: "Users",
  incident: "Incidents",
  model: "Models",
  package: "Packages",
  policy: "Policies",
  project: "Projects",
  pull_request: "Pull requests",
  repository: "Repositories",
  secret: "Secrets",
  service_account: "Service accounts",
  ticket: "Tickets",
  token: "Tokens",
  user_session: "User sessions",
  vulnerability: "Vulnerabilities",
  workspace: "Workspaces",
};

export type ConnectorResourceTypeSummary = {
  template: string;
  label: string;
  resourceFamilies: number;
};

export type ConnectorResourceTypeStats = {
  catalogResourceTypes: number;
  resourceTypes: number;
  distinctResourceTypes: number;
  highValueResourceTypes: number;
  coverageItems: number;
};

export function connectorProjectionTemplate(family: ConnectorCatalogResourceFamily) {
  return family.projection_template?.trim() || family.projection?.template?.trim() || "";
}

export function connectorResourceFamilyEventKind(family: ConnectorCatalogResourceFamily) {
  return family.event_kind?.trim() || family.event?.kind?.trim() || "";
}

export function connectorResourceFamilySchemaRef(family: ConnectorCatalogResourceFamily) {
  return family.schema_ref?.trim() || family.event?.schema_ref?.trim() || "";
}

export function connectorResourceTypeLabel(template: string) {
  const normalized = template.trim().toLowerCase();
  if (!normalized) return "";
  const label = connectorResourceTypeLabels[normalized];
  if (label) return label;
  return normalized
    .split(/[._-]+/)
    .filter(Boolean)
    .map((part) => part.slice(0, 1).toUpperCase() + part.slice(1))
    .join(" ");
}

export function connectorResourceTypes(
  card: Pick<ConnectorCatalogEntry, "resource_families">,
  limit = 5,
): ConnectorResourceTypeSummary[] {
  const itemsByTemplate = new Map<string, ConnectorResourceTypeSummary>();
  (card.resource_families ?? []).forEach((family) => {
    const template = connectorProjectionTemplate(family);
    if (!template) return;
    const key = template.toLowerCase();
    const existing = itemsByTemplate.get(key);
    if (existing) {
      existing.resourceFamilies += 1;
      return;
    }
    itemsByTemplate.set(key, { template, label: connectorResourceTypeLabel(template), resourceFamilies: 1 });
  });
  return [...itemsByTemplate.values()]
    .sort((left, right) => right.resourceFamilies - left.resourceFamilies || left.label.localeCompare(right.label))
    .slice(0, limit);
}

export function connectorResourceTypeStats(
  card: Pick<ConnectorCatalogEntry, "resource_families" | "integration_depth" | "resource_family_count" | "emitted_kind_count">,
): ConnectorResourceTypeStats {
  const families = card.resource_families ?? [];
  const templates = new Set<string>();
  let mappedResourceTypes = 0;
  let highValueResourceTypes = 0;
  let coverageItems = 0;

  families.forEach((family) => {
    if (connectorProjectionTemplate(family)) {
      mappedResourceTypes += 1;
      templates.add(connectorProjectionTemplate(family).toLowerCase());
    }
    if (family.high_value) highValueResourceTypes += 1;
    coverageItems += family.coverage?.length ?? 0;
  });

  return {
    catalogResourceTypes: Math.max(
      families.length,
      positiveNumber(card.integration_depth?.resource_families),
      positiveNumber(card.resource_family_count),
    ),
    resourceTypes: Math.max(
      mappedResourceTypes,
      positiveNumber(card.integration_depth?.projection_templates),
      positiveNumber(card.emitted_kind_count),
    ),
    distinctResourceTypes: Math.max(templates.size, positiveNumber(card.integration_depth?.projection_templates)),
    highValueResourceTypes: Math.max(highValueResourceTypes, positiveNumber(card.integration_depth?.high_value_families)),
    coverageItems: Math.max(coverageItems, positiveNumber(card.integration_depth?.coverage_dimensions)),
  };
}

export function connectorCardSummary(card: ConnectorCard) {
  return {
    meta: connectorDisplayMetadata(card),
    capabilities: connectorCapabilities(card),
    connectionLabel: `${connectorRuntimeTotal(card)} connection${connectorRuntimeTotal(card) === 1 ? "" : "s"}`,
    attentionLabel: `${connectorAttentionTotal(card)} needs action`,
    healthLabel: `${connectorHealthyTotal(card)} healthy`,
  };
}

export function buildConnectorCards(library: ConnectorCatalogEntry[], sources: SourceCoverageSummary[]): ConnectorCard[] {
  const sourceByID = new Map(sources.map((source) => [source.source_id, source]));
  const seen = new Set<string>();
  const cards = library.map((connector) => {
    const coverage = sourceByID.get(connector.source_id);
    seen.add(connector.source_id);
    const readiness = coverage?.performance ?? compactConnectorStatus(connector);
    return {
      ...connector,
      coverage,
      readiness,
      nextAction: coverage?.next_action ?? (
        !connectorSetupAllowed(connector)
          ? (connector.requestable_reason || connector.access_reason || "Inspect connector availability")
          : ((connector.configured_runtimes ?? 0) > 0 ? "Monitor connection health" : "Connect credential")
      ),
    };
  });
  sources.forEach((source) => {
    if (seen.has(source.source_id)) return;
    cards.push({
      source_id: source.source_id,
      name: source.name || source.source_id,
      description: source.description,
      configured_runtimes: source.total,
      healthy_runtimes: source.healthy,
      needs_attention_runtimes: runtimeAttentionCount(source),
      status: source.performance,
      coverage: source,
      readiness: source.performance,
      nextAction: source.next_action,
    });
  });
  return cards.sort((left, right) =>
    readinessOrder.indexOf(left.readiness) - readinessOrder.indexOf(right.readiness) ||
    connectorRuntimeTotal(right) - connectorRuntimeTotal(left) ||
    connectorDisplayName(left).localeCompare(connectorDisplayName(right)),
  );
}

export function filterConnectorCards(cards: ConnectorCard[], query: string, readinessFilter: ReadinessFilter) {
  const normalizedQuery = query.trim().toLowerCase();
  return cards.filter((card) => {
    if (readinessFilter !== "all" && card.readiness !== readinessFilter) return false;
    if (!normalizedQuery) return true;
    return connectorSearchText(card).includes(normalizedQuery) || card.nextAction.toLowerCase().includes(normalizedQuery);
  });
}

export function connectorPath(sourceID: string, params: Record<string, string | undefined> = {}) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value && value.trim()) query.set(key, value.trim());
  });
  const queryString = query.toString();
  return `/connectors/${encodeURIComponent(sourceID)}${queryString ? `?${queryString}` : ""}`;
}
