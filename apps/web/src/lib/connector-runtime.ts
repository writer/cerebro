export type RuntimeHealth = "healthy" | "stale" | "unknown" | "degraded";
export type GraphFreshness = "current" | "behind" | "running" | "failed" | "not_observed" | "unknown";
export type CursorState = "pending" | "caught_up" | "unknown";
export type SourceReadiness = "healthy" | "needs_refresh" | "poor" | "bad" | "not_configured";

export type ConnectorRuntimeGraphRun = {
  id?: string;
  status?: string;
  started_at?: string;
  finished_at?: string;
  error?: string;
  pages_read?: number;
  events_read?: number;
  entities_projected?: number;
  links_projected?: number;
  graph_nodes_before?: number;
  graph_nodes_after?: number;
  graph_links_before?: number;
  graph_links_after?: number;
  graph_node_delta?: number;
  graph_link_delta?: number;
  duration_seconds?: number;
};

export type ConnectorRuntimeFindingEvaluation = {
  id?: string;
  runtime_id?: string;
  rule_id?: string;
  status?: string;
  started_at?: string;
  finished_at?: string;
  error?: string;
  events_evaluated?: number;
  events_processed?: number;
  events_matched?: number;
  findings_upserted?: number;
  findings_emitted?: number;
  graph_rule?: boolean;
  graph_rows_read?: number;
  duration_seconds?: number;
};

export type ConnectorRuntime = {
  runtime_id: string;
  source_id: string;
  tenant_id: string;
  family: string;
  health: RuntimeHealth;
  status: string;
  last_activity_at?: string;
  age_hours?: number;
  sync_lag_seconds?: number;
  checkpoint_watermark?: string;
  watermark_lag_seconds?: number;
  watermark_age_hours?: number;
  cursor_pending?: boolean;
  checkpoint_cursor_present?: boolean;
  cursor_state: CursorState;
  graph_freshness: GraphFreshness;
  graph_run_id?: string;
  graph_status?: string;
  graph_finished_at?: string;
  graph_age_hours?: number;
  graph_lag_seconds?: number;
  latest_graph_run?: ConnectorRuntimeGraphRun;
  latest_finding_evaluation?: ConnectorRuntimeFindingEvaluation;
  finding_evaluation_status?: string;
  finding_evaluation_duration_seconds?: number;
  expected_cadence_seconds?: number;
  stale_after_seconds?: number;
  schedule_context_configured?: boolean;
  generated_at?: string;
  backfill: boolean;
  config: Record<string, unknown>;
};

export type ConnectorRuntimeSummary = {
  total: number;
  healthy: number;
  stale: number;
  unknown: number;
  degraded: number;
  backfills: number;
  sources: number;
  tenants: number;
  graph_current: number;
  graph_behind: number;
  graph_running: number;
  graph_failed: number;
  graph_not_observed: number;
};

export type SourceCoverageSummary = {
  source_id: string;
  name?: string;
  description?: string;
  status?: string;
  performance: SourceReadiness;
  next_action: string;
  total: number;
  healthy: number;
  stale: number;
  degraded: number;
  unknown: number;
  cursor_pending: number;
  cursor_unknown: number;
  graph_current: number;
  graph_behind: number;
  graph_running: number;
  graph_failed: number;
  graph_not_observed: number;
  graph_unknown: number;
  backfills: number;
  schedule_context_missing: number;
  latest_activity_at?: string;
};

const asRecord = (value: unknown): Record<string, unknown> =>
  value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};

const stringField = (record: Record<string, unknown>, keys: string[]) => {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }
  return "";
};

const numberField = (record: Record<string, unknown>, keys: string[]) => {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "number" && Number.isFinite(value)) {
      return value;
    }
    if (typeof value === "string" && value.trim() && Number.isFinite(Number(value))) {
      return Number(value);
    }
  }
  return undefined;
};

const boolField = (record: Record<string, unknown>, keys: string[]) => {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "boolean") {
      return value;
    }
  }
  return undefined;
};

const statusFailed = (status: string) =>
  status.includes("fail") || status.includes("error") || status.includes("cancel") || status.includes("degraded");

const statusRunning = (status: string) => status.includes("running") || status.includes("pending");

const parseTime = (value: string) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
};

export const runtimeLastActivity = (runtime: Record<string, unknown>) => {
  const value = stringField(runtime, ["last_synced_at", "lastSyncedAt", "last_sync_at", "updated_at", "updatedAt", "last_run_at", "lastRunAt"]);
  return value ? parseTime(value) : null;
};

export const runtimeCheckpointWatermark = (runtime: Record<string, unknown>) => {
  const value = stringField(runtime, ["checkpoint_watermark", "checkpointWatermark", "watermark"]);
  return value ? parseTime(value) : null;
};

export const runtimeFamily = (runtime: Record<string, unknown>) => {
  const config = asRecord(runtime.config);
  const family = config.family;
  return typeof family === "string" ? family : "";
};

export const runtimeIsBackfill = (runtime: Record<string, unknown>) => {
  const runtimeID = stringField(runtime, ["id", "runtime_id"]);
  const config = asRecord(runtime.config);
  return runtimeID.toLowerCase().includes("backfill") || typeof config.since === "string";
};

export const runtimeHealth = (
  runtime: Record<string, unknown>,
  now: Date,
  staleAfterHours: number,
): { health: RuntimeHealth; ageHours?: number; lastActivityAt?: string } => {
  const status = stringField(runtime, ["status", "state", "sync_status"]).toLowerCase();
  const latestGraphRun = asRecord(runtime.latest_graph_run ?? runtime.latestGraphRun);
  const latestFindingEvaluation = asRecord(runtime.latest_finding_evaluation ?? runtime.latestFindingEvaluation);
  const graphStatus = stringField(latestGraphRun, ["status", "state"]).toLowerCase();
  const findingStatus = stringField(latestFindingEvaluation, ["status", "state"]).toLowerCase();
  if (statusFailed(status) || statusFailed(graphStatus) || statusFailed(findingStatus)) {
    const last = runtimeLastActivity(runtime);
    return { health: "degraded", ...(last ? activityFields(last, now) : {}) };
  }

  const last = runtimeLastActivity(runtime);
  const staleAfterSeconds = numberField(runtime, ["stale_after_seconds", "staleAfterSeconds"]);
  const staleSeconds = staleAfterSeconds && staleAfterSeconds > 0 ? staleAfterSeconds : staleAfterHours * 3_600;
  const syncLagSeconds = numberField(runtime, ["sync_lag_seconds", "syncLagSeconds"]);
  const watermarkLagSeconds = numberField(runtime, ["watermark_lag_seconds", "watermarkLagSeconds"]);
  const lagSeconds = Math.max(syncLagSeconds ?? 0, watermarkLagSeconds ?? 0);
  if (staleSeconds > 0 && lagSeconds > staleSeconds) {
    const fields = last ? activityFields(last, now) : {};
    return { health: "stale", ...fields };
  }

  if (!last) {
    const watermark = runtimeCheckpointWatermark(runtime);
    if (!watermark) {
      return { health: "unknown" };
    }
    const fields = activityFields(watermark, now);
    if (staleAfterHours > 0 && fields.ageHours !== undefined && fields.ageHours > staleAfterHours) {
      return { health: "stale" };
    }
    return { health: "healthy" };
  }
  const fields = activityFields(last, now);
  if (staleAfterHours > 0 && fields.ageHours !== undefined && fields.ageHours > staleAfterHours) {
    return { health: "stale", ...fields };
  }
  return { health: "healthy", ...fields };
};

const normalizeNumber = (value: unknown) =>
  typeof value === "number" && Number.isFinite(value)
    ? value
    : typeof value === "string" && value.trim() && Number.isFinite(Number(value))
      ? Number(value)
      : undefined;

const normalizeGraphRun = (value: unknown): ConnectorRuntimeGraphRun | undefined => {
  const run = asRecord(value);
  if (Object.keys(run).length === 0) {
    return undefined;
  }
  return {
    id: stringField(run, ["id", "run_id"]) || undefined,
    status: stringField(run, ["status", "state"]) || undefined,
    started_at: stringField(run, ["started_at", "startedAt"]) || undefined,
    finished_at: stringField(run, ["finished_at", "finishedAt"]) || undefined,
    error: stringField(run, ["error", "error_message", "message"]) || undefined,
    pages_read: normalizeNumber(run.pages_read ?? run.pagesRead),
    events_read: normalizeNumber(run.events_read ?? run.eventsRead),
    entities_projected: normalizeNumber(run.entities_projected ?? run.entitiesProjected),
    links_projected: normalizeNumber(run.links_projected ?? run.linksProjected),
    graph_nodes_before: normalizeNumber(run.graph_nodes_before ?? run.graphNodesBefore),
    graph_nodes_after: normalizeNumber(run.graph_nodes_after ?? run.graphNodesAfter),
    graph_links_before: normalizeNumber(run.graph_links_before ?? run.graphLinksBefore),
    graph_links_after: normalizeNumber(run.graph_links_after ?? run.graphLinksAfter),
    graph_node_delta: normalizeNumber(run.graph_node_delta ?? run.graphNodeDelta),
    graph_link_delta: normalizeNumber(run.graph_link_delta ?? run.graphLinkDelta),
    duration_seconds: normalizeNumber(run.duration_seconds ?? run.durationSeconds),
  };
};

const normalizeFindingEvaluation = (value: unknown): ConnectorRuntimeFindingEvaluation | undefined => {
  const run = asRecord(value);
  if (Object.keys(run).length === 0) {
    return undefined;
  }
  return {
    id: stringField(run, ["id", "run_id"]) || undefined,
    runtime_id: stringField(run, ["runtime_id", "runtimeId"]) || undefined,
    rule_id: stringField(run, ["rule_id", "ruleId"]) || undefined,
    status: stringField(run, ["status", "state"]) || undefined,
    started_at: stringField(run, ["started_at", "startedAt"]) || undefined,
    finished_at: stringField(run, ["finished_at", "finishedAt"]) || undefined,
    error: stringField(run, ["error", "error_message", "message"]) || undefined,
    events_evaluated: normalizeNumber(run.events_evaluated ?? run.eventsEvaluated),
    events_processed: normalizeNumber(run.events_processed ?? run.eventsProcessed),
    events_matched: normalizeNumber(run.events_matched ?? run.eventsMatched),
    findings_upserted: normalizeNumber(run.findings_upserted ?? run.findingsUpserted),
    findings_emitted: normalizeNumber(run.findings_emitted ?? run.findingsEmitted),
    graph_rule: boolField(run, ["graph_rule", "graphRule"]),
    graph_rows_read: normalizeNumber(run.graph_rows_read ?? run.graphRowsRead),
    duration_seconds: normalizeNumber(run.duration_seconds ?? run.durationSeconds),
  };
};

const activityFields = (last: Date, now: Date) => {
  const ageHours = Math.max(0, (now.getTime() - last.getTime()) / 3_600_000);
  return {
    ageHours: Math.round(ageHours * 10) / 10,
    lastActivityAt: last.toISOString(),
  };
};

const runTimestamp = (run: Record<string, unknown>) => {
  const value = stringField(run, ["finished_at", "finishedAt", "started_at", "startedAt"]);
  return value ? parseTime(value) : null;
};

export const latestGraphRunsByRuntime = (runs: Record<string, unknown>[]) => {
  const latest = new Map<string, Record<string, unknown>>();
  for (const run of runs) {
    const runtimeID = stringField(run, ["runtime_id", "runtimeId"]);
    if (!runtimeID) {
      continue;
    }
    const current = latest.get(runtimeID);
    if (!current) {
      latest.set(runtimeID, run);
      continue;
    }
    const runTime = runTimestamp(run)?.getTime() ?? 0;
    const currentTime = runTimestamp(current)?.getTime() ?? 0;
    if (runTime >= currentTime) {
      latest.set(runtimeID, run);
    }
  }
  return latest;
};

export const graphFreshnessForRuntime = (
  runtime: Pick<ConnectorRuntime, "last_activity_at">,
  graphRun: Record<string, unknown> | undefined,
  now: Date,
): Pick<ConnectorRuntime, "graph_freshness" | "graph_run_id" | "graph_status" | "graph_finished_at" | "graph_age_hours" | "latest_graph_run"> => {
  if (!graphRun) {
    return { graph_freshness: "not_observed" };
  }

  const status = stringField(graphRun, ["status", "state"]).toLowerCase();
  const graphRunID = stringField(graphRun, ["id", "run_id"]);
  const latestGraphRun = normalizeGraphRun(graphRun);
  if (statusRunning(status)) {
    return { graph_freshness: "running", graph_run_id: graphRunID, graph_status: status, latest_graph_run: latestGraphRun };
  }
  if (statusFailed(status)) {
    return { graph_freshness: "failed", graph_run_id: graphRunID, graph_status: status, latest_graph_run: latestGraphRun };
  }

  const finished = runTimestamp(graphRun);
  if (!finished) {
    return { graph_freshness: "unknown", graph_run_id: graphRunID, graph_status: status, latest_graph_run: latestGraphRun };
  }

  const sourceSync = runtime.last_activity_at ? parseTime(runtime.last_activity_at) : null;
  const fields = activityFields(finished, now);
  const graphFields = {
    graph_run_id: graphRunID,
    graph_status: status || "completed",
    graph_finished_at: fields.lastActivityAt,
    graph_age_hours: fields.ageHours,
    latest_graph_run: latestGraphRun,
  };
  if (sourceSync && finished.getTime() + 60_000 < sourceSync.getTime()) {
    return { graph_freshness: "behind", ...graphFields };
  }
  return { graph_freshness: "current", ...graphFields };
};

export const attachGraphFreshness = (
  runtime: ConnectorRuntime,
  graphRun: Record<string, unknown> | undefined,
  now: Date = new Date(),
): ConnectorRuntime => graphRun
  ? ({
      ...runtime,
      ...graphFreshnessForRuntime(runtime, graphRun, now),
    })
  : runtime;

export const normalizeRuntime = (
  runtime: Record<string, unknown>,
  now: Date = new Date(),
  staleAfterHours = 24,
): ConnectorRuntime => {
  const config = asRecord(runtime.config);
  const health = runtimeHealth(runtime, now, staleAfterHours);
  const latestGraphRun = normalizeGraphRun(runtime.latest_graph_run ?? runtime.latestGraphRun);
  const latestFindingEvaluation = normalizeFindingEvaluation(runtime.latest_finding_evaluation ?? runtime.latestFindingEvaluation);
  const graphFields = latestGraphRun ? graphFreshnessForRuntime({ last_activity_at: health.lastActivityAt }, latestGraphRun as Record<string, unknown>, now) : { graph_freshness: "not_observed" as GraphFreshness };
  const cursorPending = boolField(runtime, ["cursor_pending", "cursorPending"]);
  const checkpointCursorPresent = boolField(runtime, ["checkpoint_cursor_present", "checkpointCursorPresent"]);
  const watermarkLagSeconds = numberField(runtime, ["watermark_lag_seconds", "watermarkLagSeconds"]);
  const syncLagSeconds = numberField(runtime, ["sync_lag_seconds", "syncLagSeconds"]);
  const scheduleStaleSeconds = numberField(runtime, ["stale_after_seconds", "staleAfterSeconds"]);
  return {
    runtime_id: stringField(runtime, ["id", "runtime_id"]),
    source_id: stringField(runtime, ["source_id", "sourceId"]),
    tenant_id: stringField(runtime, ["tenant_id", "tenantId"]),
    family: stringField(runtime, ["family"]) || runtimeFamily(runtime),
    health: health.health,
    status: stringField(runtime, ["status", "state", "sync_status"]) || health.health,
    last_activity_at: health.lastActivityAt,
    age_hours: health.ageHours,
    sync_lag_seconds: syncLagSeconds,
    checkpoint_watermark: stringField(runtime, ["checkpoint_watermark", "checkpointWatermark", "watermark"]) || undefined,
    watermark_lag_seconds: watermarkLagSeconds,
    watermark_age_hours: watermarkLagSeconds === undefined ? undefined : Math.round((watermarkLagSeconds / 3_600) * 10) / 10,
    cursor_pending: cursorPending,
    checkpoint_cursor_present: checkpointCursorPresent,
    cursor_state: cursorPending === true ? "pending" : cursorPending === false ? "caught_up" : "unknown",
    graph_lag_seconds: numberField(runtime, ["graph_lag_seconds", "graphLagSeconds"]),
    latest_graph_run: latestGraphRun,
    ...graphFields,
    latest_finding_evaluation: latestFindingEvaluation,
    finding_evaluation_status: latestFindingEvaluation?.status,
    finding_evaluation_duration_seconds: latestFindingEvaluation?.duration_seconds,
    expected_cadence_seconds: numberField(runtime, ["expected_cadence_seconds", "expectedCadenceSeconds"]),
    stale_after_seconds: scheduleStaleSeconds,
    schedule_context_configured: boolField(runtime, ["schedule_context_configured", "scheduleContextConfigured"]),
    generated_at: stringField(runtime, ["generated_at", "generatedAt"]) || undefined,
    backfill: runtimeIsBackfill(runtime),
    config,
  };
};

export const formatDuration = (seconds?: number) => {
  if (typeof seconds !== "number" || !Number.isFinite(seconds)) {
    return "—";
  }
  const safeSeconds = Math.max(0, seconds);
  if (safeSeconds < 60) return `${Math.round(safeSeconds)}s`;
  const minutes = safeSeconds / 60;
  if (minutes < 60) return `${Math.round(minutes)}m`;
  const hours = minutes / 60;
  if (hours < 48) return `${hours < 10 ? hours.toFixed(1) : Math.round(hours)}h`;
  const days = hours / 24;
  return `${days < 10 ? days.toFixed(1) : Math.round(days)}d`;
};

export const formatCount = (value?: number) => {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return "—";
  }
  return new Intl.NumberFormat(undefined, { notation: Math.abs(value) >= 10_000 ? "compact" : "standard", maximumFractionDigits: 1 }).format(value);
};

export const formatDelta = (value?: number) => {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return "—";
  }
  if (value === 0) return "±0";
  return `${value > 0 ? "+" : ""}${formatCount(value)}`;
};

export const formatLagAge = (seconds?: number) => formatDuration(seconds);

export const snippet = (value?: string, maxLength = 96) => {
  const text = value?.trim();
  if (!text) return "";
  return text.length > maxLength ? `${text.slice(0, maxLength - 1)}…` : text;
};

export const summarizeConnectorRuntime = (runtimes: ConnectorRuntime[]): ConnectorRuntimeSummary => {
  const sources = new Set<string>();
  const tenants = new Set<string>();
  const summary: ConnectorRuntimeSummary = {
    total: runtimes.length,
    healthy: 0,
    stale: 0,
    unknown: 0,
    degraded: 0,
    backfills: 0,
    sources: 0,
    tenants: 0,
    graph_current: 0,
    graph_behind: 0,
    graph_running: 0,
    graph_failed: 0,
    graph_not_observed: 0,
  };
  for (const runtime of runtimes) {
    if (runtime.source_id) sources.add(runtime.source_id);
    if (runtime.tenant_id) tenants.add(runtime.tenant_id);
    if (runtime.backfill) summary.backfills += 1;
    summary[runtime.health] += 1;
    switch (runtime.graph_freshness) {
      case "current":
        summary.graph_current += 1;
        break;
      case "behind":
        summary.graph_behind += 1;
        break;
      case "running":
        summary.graph_running += 1;
        break;
      case "failed":
        summary.graph_failed += 1;
        break;
      case "not_observed":
      case "unknown":
        summary.graph_not_observed += 1;
        break;
    }
  }
  summary.sources = sources.size;
  summary.tenants = tenants.size;
  return summary;
};

const emptySourceSummary = (sourceID: string): SourceCoverageSummary => ({
  source_id: sourceID || "unknown",
  performance: "not_configured",
  next_action: "Configure runtime coverage",
  total: 0,
  healthy: 0,
  stale: 0,
  degraded: 0,
  unknown: 0,
  cursor_pending: 0,
  cursor_unknown: 0,
  graph_current: 0,
  graph_behind: 0,
  graph_running: 0,
  graph_failed: 0,
  graph_not_observed: 0,
  graph_unknown: 0,
  backfills: 0,
  schedule_context_missing: 0,
});

const sourceCatalogSummary = (source: Record<string, unknown>): SourceCoverageSummary => {
  const sourceID = stringField(source, ["id", "source_id", "sourceId", "name"]) || "unknown";
  return {
    ...emptySourceSummary(sourceID),
    name: stringField(source, ["name", "label", "source_id", "sourceId", "id"]) || undefined,
    description: stringField(source, ["description", "summary"]) || undefined,
    status: stringField(source, ["status", "state"]) || undefined,
  };
};

const updateLatestActivity = (summary: SourceCoverageSummary, activity?: string) => {
  if (!activity) return;
  const next = parseTime(activity);
  if (!next) return;
  const current = summary.latest_activity_at ? parseTime(summary.latest_activity_at) : null;
  if (!current || next.getTime() > current.getTime()) {
    summary.latest_activity_at = next.toISOString();
  }
};

const sourceReadiness = (summary: SourceCoverageSummary): Pick<SourceCoverageSummary, "performance" | "next_action"> => {
  if (summary.total === 0) {
    return { performance: "not_configured", next_action: "Configure runtime coverage" };
  }
  if (summary.degraded > 0 || summary.graph_failed > 0) {
    return { performance: "bad", next_action: summary.graph_failed > 0 ? "Inspect failed graph projection" : "Investigate failed sync" };
  }
  if (summary.stale > 0 || summary.cursor_pending > 0 || summary.schedule_context_missing > 0) {
    return { performance: "needs_refresh", next_action: "Refresh source sync" };
  }
  if (summary.unknown > 0 || summary.graph_behind > 0 || summary.graph_not_observed > 0 || summary.graph_unknown > 0) {
    return { performance: "poor", next_action: "Verify runtime and graph telemetry" };
  }
  return { performance: "healthy", next_action: "No action" };
};

export const sourceReadinessRank = (value: SourceReadiness) => {
  const rank: Record<SourceReadiness, number> = {
    bad: 0,
    needs_refresh: 1,
    poor: 2,
    not_configured: 3,
    healthy: 4,
  };
  return rank[value] ?? 5;
};

export const sourceHealthBreakdown = (
  runtimes: ConnectorRuntime[],
  sourceCatalog: Record<string, unknown>[] = [],
): SourceCoverageSummary[] => {
  const counts = new Map<string, SourceCoverageSummary>();
  for (const source of sourceCatalog) {
    const summary = sourceCatalogSummary(source);
    counts.set(summary.source_id, summary);
  }

  for (const runtime of runtimes) {
    const sourceID = runtime.source_id || "unknown";
    const current = counts.get(sourceID) ?? emptySourceSummary(sourceID);
    current.total += 1;
    current[runtime.health] += 1;
    if (runtime.cursor_state === "pending") current.cursor_pending += 1;
    if (runtime.cursor_state === "unknown") current.cursor_unknown += 1;
    if (runtime.backfill) current.backfills += 1;
    if (runtime.schedule_context_configured === false) current.schedule_context_missing += 1;
    updateLatestActivity(current, runtime.last_activity_at);

    switch (runtime.graph_freshness) {
      case "current":
        current.graph_current += 1;
        break;
      case "behind":
        current.graph_behind += 1;
        break;
      case "running":
        current.graph_running += 1;
        break;
      case "failed":
        current.graph_failed += 1;
        break;
      case "not_observed":
        current.graph_not_observed += 1;
        break;
      case "unknown":
        current.graph_unknown += 1;
        break;
    }
    counts.set(sourceID, current);
  }

  return Array.from(counts.values())
    .map((source) => ({ ...source, ...sourceReadiness(source) }))
    .sort((left, right) =>
      sourceReadinessRank(left.performance) - sourceReadinessRank(right.performance) ||
      right.total - left.total ||
      left.source_id.localeCompare(right.source_id),
    );
};

export const sourceBreakdown = (runtimes: ConnectorRuntime[]) => {
  const counts = new Map<string, { total: number; stale: number; degraded: number; unknown: number }>();
  for (const runtime of runtimes) {
    const source = runtime.source_id || "unknown";
    const current = counts.get(source) ?? { total: 0, stale: 0, degraded: 0, unknown: 0 };
    current.total += 1;
    if (runtime.health === "stale") current.stale += 1;
    if (runtime.health === "degraded") current.degraded += 1;
    if (runtime.health === "unknown") current.unknown += 1;
    counts.set(source, current);
  }
  return Array.from(counts.entries())
    .map(([source_id, values]) => ({ source_id, ...values }))
    .sort((left, right) => right.total - left.total || left.source_id.localeCompare(right.source_id));
};
