import { asRecord, extractRecords, firstString } from "@/lib/cerebro-data";

export type RuntimeFreshnessRow = {
  id: string;
  runtime_id: string;
  source_id: string;
  freshness_state: string;
  source_sync_state: string;
  graph_ingest_state: string;
  finding_evaluation_state: string;
  next_action: string;
  failure_class: string;
  failure_reason: string;
  backfill_eligible: boolean;
  last_synced_at: string;
  graph_lag_seconds?: number;
};

export type RuntimeFreshnessSummaryRow = {
  id: string;
  source_id: string;
  total: number;
  healthy: number;
  needs_attention: number;
  backfill_eligible: number;
  source_failed: number;
  graph_missing: number;
  graph_failed: number;
  graph_behind: number;
};

export type RuntimeFreshnessView = {
  generated_at: string;
  status: string;
  rows: RuntimeFreshnessRow[];
  summaries: RuntimeFreshnessSummaryRow[];
  source: "canonical" | "graph-ingest-health";
};

const sourceFromRuntimeId = (runtimeId: string) => {
  if (runtimeId.includes("-aws-")) return "aws";
  if (runtimeId.includes("-gcp-")) return "gcp";
  if (runtimeId.includes("-okta-")) return "okta";
  if (runtimeId.includes("-panopticon-")) return "panopticon";
  if (runtimeId.includes("-cosmo-")) return "cosmo";
  return "unknown";
};

const stringArray = (value: unknown) =>
  Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string" && item.length > 0)
    : [];

const numberValue = (record: Record<string, unknown>, key: string) => {
  const value = record[key];
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
};

const boolValue = (value: unknown) => value === true || value === "true";

export const normalizeRuntimeFreshness = (data: unknown): RuntimeFreshnessView => {
  const record = asRecord(data) ?? {};
  const canonicalRows = extractRecords(record, ["runtimes"]);
  if (canonicalRows.length > 0 || Array.isArray(record.summaries)) {
    const rows = canonicalRows.map((row) => {
      const runtimeId = firstString(row, ["runtime_id", "runtimeId"]) ?? "";
      return {
        id: runtimeId,
        runtime_id: runtimeId,
        source_id: firstString(row, ["source_id", "sourceId"]) ?? "unknown",
        freshness_state: firstString(row, ["freshness_state", "freshnessState"]) ?? "unknown",
        source_sync_state: firstString(row, ["source_sync_state", "sourceSyncState"]) ?? "unknown",
        graph_ingest_state: firstString(row, ["graph_ingest_state", "graphIngestState"]) ?? "unknown",
        finding_evaluation_state: firstString(row, ["finding_evaluation_state", "findingEvaluationState"]) ?? "unknown",
        next_action: firstString(row, ["next_action", "nextAction"]) ?? "inspect_runtime",
        failure_class: firstString(row, ["failure_class", "failureClass"]) ?? "",
        failure_reason: firstString(row, ["failure_reason", "failureReason"]) ?? "",
        backfill_eligible: boolValue(row.backfill_eligible ?? row.backfillEligible),
        last_synced_at: firstString(row, ["last_synced_at", "lastSyncedAt"]) ?? "",
        graph_lag_seconds: typeof row.graph_lag_seconds === "number" ? row.graph_lag_seconds : undefined,
      };
    });
    const summaries = extractRecords(record, ["summaries"]).map((summary) => {
      const sourceId = firstString(summary, ["source_id", "sourceId"]) ?? "unknown";
      return {
        id: sourceId,
        source_id: sourceId,
        total: numberValue(summary, "total"),
        healthy: numberValue(summary, "healthy"),
        needs_attention: numberValue(summary, "needs_attention"),
        backfill_eligible: numberValue(summary, "backfill_eligible"),
        source_failed: numberValue(summary, "source_failed"),
        graph_missing: numberValue(summary, "graph_missing"),
        graph_failed: numberValue(summary, "graph_failed"),
        graph_behind: numberValue(summary, "graph_behind"),
      };
    });
    return {
      generated_at: firstString(record, ["generated_at", "generatedAt"]) ?? "",
      status: firstString(record, ["status"]) ?? (rows.some((row) => row.freshness_state !== "healthy") ? "degraded" : "healthy"),
      rows,
      summaries,
      source: "canonical",
    };
  }
  return normalizeGraphIngestHealthFreshness(record);
};

const normalizeGraphIngestHealthFreshness = (record: Record<string, unknown>): RuntimeFreshnessView => {
  const ingest = asRecord(record.ingest) ?? record;
  const missingRows = stringArray(ingest.missing_runtime_ids).map((runtimeId) => ({
    id: runtimeId,
    runtime_id: runtimeId,
    source_id: sourceFromRuntimeId(runtimeId),
    freshness_state: "graph_missing",
    source_sync_state: "unknown",
    graph_ingest_state: "not_observed",
    finding_evaluation_state: "not_observed",
    next_action: "plan_backfill",
    failure_class: "graph_ingest_missing",
    failure_reason: "no graph ingest run has been observed",
    backfill_eligible: true,
    last_synced_at: "",
  }));
  const failedRuntimeIds = new Set<string>();
  stringArray(record.failures).forEach((failure) => {
    for (const match of failure.matchAll(/([A-Za-z0-9_.-]+):graph-ingest:\1(?::|$)/g)) {
      failedRuntimeIds.add(match[1]);
    }
  });
  const failedRows = [...failedRuntimeIds].sort().map((runtimeId) => ({
    id: runtimeId,
    runtime_id: runtimeId,
    source_id: sourceFromRuntimeId(runtimeId),
    freshness_state: "graph_failed",
    source_sync_state: "unknown",
    graph_ingest_state: "failed",
    finding_evaluation_state: "not_observed",
    next_action: "inspect_graph_ingest",
    failure_class: "graph_ingest_failed",
    failure_reason: "latest graph ingest failed",
    backfill_eligible: true,
    last_synced_at: "",
  }));
  const rows = [...missingRows, ...failedRows];
  const bySource = new Map<string, RuntimeFreshnessSummaryRow>();
  rows.forEach((row) => {
    const summary = bySource.get(row.source_id) ?? {
      id: row.source_id,
      source_id: row.source_id,
      total: 0,
      healthy: 0,
      needs_attention: 0,
      backfill_eligible: 0,
      source_failed: 0,
      graph_missing: 0,
      graph_failed: 0,
      graph_behind: 0,
    };
    summary.total += 1;
    summary.needs_attention += 1;
    if (row.backfill_eligible) summary.backfill_eligible += 1;
    if (row.freshness_state === "graph_missing") summary.graph_missing += 1;
    if (row.freshness_state === "graph_failed") summary.graph_failed += 1;
    bySource.set(row.source_id, summary);
  });
  return {
    generated_at: firstString(record, ["generated_at", "generatedAt"]) ?? "",
    status: rows.length > 0 ? "degraded" : firstString(record, ["status"]) ?? "unknown",
    rows,
    summaries: [...bySource.values()].sort((left, right) => right.needs_attention - left.needs_attention || left.source_id.localeCompare(right.source_id)),
    source: "graph-ingest-health",
  };
};
