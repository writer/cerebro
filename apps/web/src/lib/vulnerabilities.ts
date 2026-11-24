import { grcPath } from "@/lib/grc-client";

export const VULNERABILITY_SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"] as const;
export const VULNERABILITY_STATUSES = ["open", "in_progress", "suppressed", "not_affected", "fixed"] as const;
export const VULNERABILITY_PAGE_LIMIT = 50;

export type VulnerabilityObservation = {
  id: string;
  profile_id: string;
  source_id: string;
  scanner?: string;
  source_record_id: string;
  correlation_key: string;
  format: string;
  title: string;
  description?: string;
  class: string;
  primary_vulnerability_id?: string;
  vulnerability_ids?: string[];
  cwes?: string[];
  severity: string;
  source_severity?: string;
  cvss_score?: number;
  status: string;
  source_status?: string;
  asset: { type?: string; identifier?: string; name?: string; image_digest?: string };
  package?: { ecosystem?: string; name?: string; version?: string; fixed_version?: string; purl?: string };
  location?: string;
  references?: string[];
  first_seen_at?: string;
  last_seen_at?: string;
  observed_at: string;
  ingested_at: string;
  resolved_at?: string;
};

export type VulnerabilityObservationPage = {
  observations: VulnerabilityObservation[];
  next_cursor?: string;
};

export type VulnerabilitySourceSummary = {
  source_id: string;
  total: number;
  open: number;
  by_severity: Record<string, number>;
  last_ingest_at?: string;
};

export type VulnerabilitySummary = {
  total: number;
  open: number;
  distinct_open_vulnerabilities: number;
  multi_source_open: number;
  oldest_open_seen_at?: string;
  by_severity: Record<string, number>;
  by_class: Record<string, number>;
  by_status: Record<string, number>;
  by_source: VulnerabilitySourceSummary[];
  profiles: number;
  profiles_needing_attention: number;
};

export type VulnerabilityFieldInference = {
  path: string;
  confidence: number;
  coverage: number;
  reason: string;
};

export type VulnerabilityInferenceReport = {
  detected_format: string;
  records_path: string;
  sample_size: number;
  fields: Record<string, VulnerabilityFieldInference>;
  confidence: number;
  ready_to_activate: boolean;
  unmapped_paths?: string[];
  warnings?: string[];
};

export type VulnerabilityProfile = {
  tenant_id: string;
  id: string;
  source_id: string;
  display_name: string;
  description?: string;
  format: string;
  enabled: boolean;
  mapping_version: number;
  mapping_activated_by?: string;
  mapping_activated_at?: string;
  draft_mapping?: { mapping: unknown; report: VulnerabilityInferenceReport };
  draft_created_at?: string;
  transports: string[];
  pull_kind?: string;
  pull_interval_seconds?: number;
  next_pull_at?: string;
  last_ingest_at?: string;
  last_status?: string;
  last_error?: string;
};

export type VulnerabilityFilters = {
  tenantID: string;
  sourceID: string;
  severity: string;
  status: string;
  query: string;
  cursor?: string;
};

export const vulnerabilityObservationsPath = (filters: VulnerabilityFilters) =>
  grcPath("/vulnerabilities", {
    tenant_id: filters.tenantID,
    source_id: filters.sourceID,
    severity: filters.severity,
    status: filters.status,
    q: filters.query,
    cursor: filters.cursor,
    limit: VULNERABILITY_PAGE_LIMIT,
  });

export const vulnerabilityProfilePath = (profileID: string, action: "sync" | "mapping/activate", tenantID: string) =>
  grcPath(`/vulnerabilities/profiles/${encodeURIComponent(profileID)}/${action}`, { tenant_id: tenantID });

// Profiles with a reviewable draft or a failing delivery need an operator
// before their records flow into the dashboard.
export const profileNeedsAttention = (profile: VulnerabilityProfile) =>
  Boolean(profile.draft_mapping) || profile.last_status === "failed" || profile.last_status === "drift" || profile.last_status === "pending_mapping";

export const percentLabel = (value: number | undefined) =>
  `${Math.round(Math.max(0, Math.min(1, value ?? 0)) * 100)}%`;

export const observationAssetLabel = (observation: VulnerabilityObservation) =>
  observation.asset.name || observation.asset.identifier || observation.location || "Unknown asset";

export const observationPackageLabel = (observation: VulnerabilityObservation) => {
  const pkg = observation.package;
  if (!pkg?.name) return "";
  const version = pkg.version ? `@${pkg.version}` : "";
  const fixed = pkg.fixed_version ? ` (fix ${pkg.fixed_version})` : "";
  return `${pkg.name}${version}${fixed}`;
};

export const severityCount = (counts: Record<string, number> | undefined, severity: string) => counts?.[severity] ?? 0;

export const sortedDraftFields = (report: VulnerabilityInferenceReport) =>
  Object.entries(report.fields ?? {}).sort(([left], [right]) => left.localeCompare(right));
