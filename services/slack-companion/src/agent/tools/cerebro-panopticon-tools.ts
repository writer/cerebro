import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import type { JsonRecord } from "../../cerebro/types.js";
import { limit, shortError } from "./normalizers.js";
import type { SecurityToolDeps } from "./types.js";
import { objectValue, toolResult } from "./tool-result.js";

const DEFAULT_PANOPTICON_ALERT_RUNTIME_ID = "writer-panopticon-alerts";
const DEFAULT_STATUSES = ["closed", "resolved"];

const ALERT_DATE_FIELDS = [
  "closed_at",
  "resolved_at",
  "updated_at",
  "last_observed_at",
  "observed_at",
  "created_at",
  "alert_closed_time",
  "alert_resolved_time",
  "alert_source_event_time",
  "alert_creation_time",
  "close_date",
  "resolved_date",
  "initial_date",
  "open_date",
];

export function createCerebroPanopticonTools(deps: SecurityToolDeps): AgentTool[] {
  const alertParams = Type.Object({
    runtime_id: Type.Optional(Type.String()),
    status: Type.Optional(Type.String()),
    date: Type.Optional(Type.String()),
    since: Type.Optional(Type.String()),
    until: Type.Optional(Type.String()),
    limit: Type.Optional(Type.Number()),
  });

  return [
    {
      name: "cerebro_panopticon_alerts",
      label: "Panopticon alerts",
      description: "Read Panopticon alert state without falling back to Cerebro findings. For current projected alerts, this uses graph alert nodes. For dated closed/resolved alert reviews, this fails closed unless raw Panopticon source-event audit rows are available; do not answer dated closures from graph projection.",
      parameters: alertParams,
      execute: async (_toolCallId, params) => {
        const args = params as PanopticonAlertArgs;
        return toolResult(await panopticonAlertDetails(deps, args));
      },
    },
  ];
}

interface PanopticonAlertArgs {
  runtime_id?: string;
  status?: string;
  date?: string;
  since?: string;
  until?: string;
  limit?: number;
}

interface NormalizedAlert {
  urn: string;
  label?: string;
  alert_id?: string;
  title?: string;
  severity?: string;
  status?: string;
  date_field?: string;
  date_value?: string;
  source_id?: string;
  runtime_id?: string;
  attributes: JsonRecord;
  related_entities: RelatedEntity[];
}

interface RelatedEntity {
  urn?: string;
  label?: string;
  entity_type?: string;
  relation?: string;
  attributes?: JsonRecord;
}

async function panopticonAlertDetails(deps: SecurityToolDeps, args: PanopticonAlertArgs): Promise<Record<string, unknown>> {
  const rowLimit = limit(args.limit, 50);
  const statuses = normalizeStatuses(args.status);
  const window = normalizeDateWindow(args);
  const runtimeId = normalizeRuntimeId(args.runtime_id);
  const base = panopticonAlertBase(runtimeId, statuses, window);
  if (needsSourceEventAudit(statuses, window)) {
    return panopticonAlertEventAuditUnavailable(deps, base, runtimeId);
  }

  let response: JsonRecord;
  try {
    response = await deps.cerebro.reasonGraph({
      question: panopticonAlertQuestion({
        runtimeId,
        statuses,
        dateHint: args.date?.trim().match(/^\d{4}-\d{2}-\d{2}$/) ? args.date.trim() : undefined,
        limit: Math.min(100, rowLimit),
      }),
    });
  } catch (error) {
    return panopticonAlertUnavailable(base, {
      error: "cerebro_graph_request_failed",
      message: shortError(error),
    });
  }

  const graph = graphExecutionSummary(response);
  const blocker = graphBlocker(graph);
  if (blocker) {
    return panopticonAlertUnavailable(base, {
      error: blocker.code,
      message: blocker.message,
      graph,
    });
  }

  const graphRows = graphRowsFrom(response);
  const normalizedAlerts = normalizeAlerts(graphRows);
  const alerts = normalizedAlerts
    .filter((alert) => statusMatches(alert.status, statuses))
    .filter((alert) => dateMatches(alert.date_value, window))
    .slice(0, rowLimit);
  const missingDateCount = normalizedAlerts
    .filter((alert) => statusMatches(alert.status, statuses))
    .filter((alert) => !alert.date_value)
    .length;

  return {
    ...base,
    answerable: true,
    result_state: "complete",
    graph_row_count: graphRows.length,
    matched_alert_count: alerts.length,
    alerts,
    missing_context: missingDateCount > 0
      ? [`${missingDateCount} Panopticon alert row(s) lacked a projected closure or observation timestamp, so date filtering may exclude older graph records until the source is reingested.`]
      : [],
    graph,
    note: "Panopticon alerts are source alert records. Cerebro findings and cases are separate records.",
  };
}

function panopticonAlertBase(
  runtimeId: string,
  statuses: string[],
  window: { since?: string; until?: string },
): Record<string, unknown> {
  return {
    source: "panopticon.alert graph nodes",
    runtime_id: runtimeId,
    requested_statuses: statuses,
    date_window: window,
    note: "Panopticon alerts are source alert records. Cerebro findings and cases are separate records.",
  };
}

function panopticonAlertUnavailable(
  base: Record<string, unknown>,
  input: { error: string; message: string; graph?: Record<string, unknown> },
): Record<string, unknown> {
  return {
    ...base,
    answerable: false,
    result_state: "source_unavailable",
    error: "panopticon_alert_source_unavailable",
    blocker: input.error,
    matched_alert_count: null,
    alerts: [],
    missing_context: [
      `Panopticon alert rows were not available: ${input.message}`,
      "Panopticon alert count is unknown until that source read succeeds.",
    ],
    graph: input.graph,
  };
}

async function panopticonAlertEventAuditUnavailable(
  deps: SecurityToolDeps,
  base: Record<string, unknown>,
  runtimeId: string,
): Promise<Record<string, unknown>> {
  const runtimeHealth = await runtimeHealthContext(deps, runtimeId);
  return {
    ...base,
    source: "panopticon source event audit",
    answerable: false,
    result_state: "source_event_audit_unavailable",
    error: "panopticon_alert_event_audit_unavailable",
    blocker: "raw_runtime_source_events_unavailable",
    matched_alert_count: null,
    alerts: [],
    runtime_health: runtimeHealth,
    missing_context: [
      "Dated closed/resolved Panopticon alert reviews require raw source events from the runtime pull or append-log page ledger.",
      "The companion can read runtime health and graph projections, but graph alert nodes are current projected state and can collapse multiple source events by alert_id.",
      `No read-only raw source-event audit API is available to this companion for runtime ${runtimeId}.`,
    ],
    note: "Do not answer dated Panopticon closures from Cerebro findings or current graph projection.",
  };
}

function panopticonAlertQuestion(input: { runtimeId: string; statuses: string[]; dateHint?: string; limit: number }): string {
  const statusClauses = input.statuses
    .map((status) => `attrs CONTAINS '"status":"${status}"' OR attrs CONTAINS '"alert_status":"${status}"'`)
    .join(" OR ");
  const runtimeClause = `\n  AND (coalesce(alert.runtime_id, '') = '${input.runtimeId}' OR attrs CONTAINS '"source_runtime_id":"${input.runtimeId}"' OR attrs CONTAINS '"runtime_id":"${input.runtimeId}"')`;
  const dateClause = input.dateHint ? `\n  AND attrs CONTAINS '${input.dateHint}'` : "";
  return [
    "Run this read-only Cypher to list Panopticon alert graph nodes.",
    "Use this exact alert-node query shape. Do not rewrite it into findings or cases.",
    "Return attributes_json as text. Do not parse JSON in Cypher, do not use relationship expansion, and do not use APOC or procedures.",
    `Runtime to inspect: ${input.runtimeId}.`,
    "Proposed Cypher:",
    `MATCH (alert:Entity {tenant_id: $tenant_id, entity_type: 'panopticon.alert'})
WITH alert, coalesce(alert.attributes_json, '') AS attrs
WHERE (${statusClauses || "attrs CONTAINS '\"status\":\"closed\"'"})${runtimeClause}${dateClause}
RETURN alert.urn AS alert_urn,
       coalesce(alert.label, alert.urn) AS alert_label,
       alert.source_id AS alert_source_id,
       alert.runtime_id AS alert_runtime_id,
       attrs AS alert_attributes_json
ORDER BY alert_urn
LIMIT ${input.limit}`,
  ].join("\n");
}

function graphExecutionSummary(response: JsonRecord): Record<string, unknown> {
  const cypher = objectValue(response.cypher);
  const queryPlan = objectValue(response.query_plan);
  const provenance = objectValue(response.provenance);
  return {
    answer_markdown: response.answer_markdown,
    unsupported_query: objectValue(response.unsupported_query),
    validator: objectValue(cypher?.validator),
    query_source: queryPlan?.source,
    fallback_reason: provenance?.fallback_reason,
    trace_id: response.trace_id ?? provenance?.trace_id,
  };
}

function graphBlocker(graph: Record<string, unknown>): { code: string; message: string } | undefined {
  const unsupported = objectValue(graph.unsupported_query);
  if (unsupported) {
    return {
      code: stringField(unsupported, "code") ?? "unsupported_query",
      message: stringField(unsupported, "reason") ?? "Cerebro graph reasoning refused the Panopticon alert query.",
    };
  }

  const validator = objectValue(graph.validator);
  if (validator?.ok === false) {
    return {
      code: stringField(validator, "code") ?? "validator_refusal",
      message: stringField(validator, "reason") ?? "Cerebro graph validation refused the Panopticon alert query.",
    };
  }

  const fallbackReason = typeof graph.fallback_reason === "string" ? graph.fallback_reason.trim() : "";
  if (fallbackReason && fallbackReason !== "not_applicable") {
    return {
      code: fallbackReason,
      message: "Cerebro graph reasoning did not execute the Panopticon alert query.",
    };
  }

  return undefined;
}

function graphRowsFrom(response: JsonRecord): JsonRecord[] {
  return Array.isArray(response.rows) ? response.rows.filter(isRecord) : [];
}

function normalizeAlerts(rows: JsonRecord[]): NormalizedAlert[] {
  const alerts = new Map<string, NormalizedAlert>();
  for (const row of rows) {
    const urn = stringField(row, "alert_urn", "urn");
    if (!urn) continue;
    const attrs = parseAttributes(row.alert_attributes_json) ?? parseAttributes(row.attributes_json) ?? {};
    const alert = alerts.get(urn) ?? {
      urn,
      label: stringField(row, "alert_label", "label"),
      alert_id: stringField(attrs, "alert_id", "id"),
      title: stringField(attrs, "title", "alert_title"),
      severity: stringField(attrs, "severity", "alert_severity"),
      status: stringField(attrs, "status", "alert_status"),
      source_id: stringField(row, "alert_source_id", "source_id"),
      runtime_id: stringField(row, "alert_runtime_id", "runtime_id") || stringField(attrs, "source_runtime_id", "runtime_id"),
      attributes: attrs,
      related_entities: [],
    };
    const date = alertDate(attrs);
    alert.date_field = date?.field;
    alert.date_value = date?.value;
    const relatedURN = stringField(row, "related_urn");
    if (relatedURN && !alert.related_entities.some((entity) => entity.urn === relatedURN)) {
      alert.related_entities.push({
        urn: relatedURN,
        label: stringField(row, "related_label"),
        entity_type: stringField(row, "related_type"),
        relation: stringField(row, "relation"),
        attributes: parseAttributes(row.related_attributes_json) ?? undefined,
      });
    }
    alerts.set(urn, alert);
  }
  return [...alerts.values()];
}

function normalizeStatuses(input: string | undefined): string[] {
  const statuses = (input ?? DEFAULT_STATUSES.join(","))
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter((item) => /^[a-z0-9_.-]{1,40}$/.test(item));
  return statuses.length > 0 ? [...new Set(statuses)] : DEFAULT_STATUSES;
}

function normalizeRuntimeId(input: string | undefined): string {
  const runtimeId = input?.trim();
  if (runtimeId && /^[A-Za-z0-9_.:-]{1,120}$/.test(runtimeId)) return runtimeId;
  return DEFAULT_PANOPTICON_ALERT_RUNTIME_ID;
}

function needsSourceEventAudit(statuses: string[], window: { since?: string; until?: string }): boolean {
  if (!window.since && !window.until) return false;
  return statuses.some((status) => status === "closed" || status === "resolved");
}

async function runtimeHealthContext(deps: SecurityToolDeps, runtimeId: string): Promise<unknown> {
  try {
    return await deps.cerebro.listRuntimeHealth({ runtimeId, limit: 1 });
  } catch (error) {
    return { error: shortError(error) };
  }
}

function statusMatches(status: string | undefined, statuses: string[]): boolean {
  if (!status) return false;
  return statuses.includes(status.trim().toLowerCase());
}

function normalizeDateWindow(args: PanopticonAlertArgs): { since?: string; until?: string } {
  const date = args.date?.trim();
  if (date && /^\d{4}-\d{2}-\d{2}$/.test(date)) {
    const start = new Date(`${date}T00:00:00.000Z`);
    const end = new Date(start.getTime() + 24 * 60 * 60 * 1000);
    return { since: start.toISOString(), until: end.toISOString() };
  }
  return {
    since: args.since?.trim() || undefined,
    until: args.until?.trim() || undefined,
  };
}

function dateMatches(value: string | undefined, window: { since?: string; until?: string }): boolean {
  if (!window.since && !window.until) return true;
  if (!value) return false;
  const timestamp = Date.parse(value);
  if (Number.isNaN(timestamp)) return false;
  if (window.since && timestamp < Date.parse(window.since)) return false;
  if (window.until && timestamp >= Date.parse(window.until)) return false;
  return true;
}

function alertDate(attrs: JsonRecord): { field: string; value: string } | undefined {
  for (const field of ALERT_DATE_FIELDS) {
    const value = stringField(attrs, field);
    if (value) return { field, value };
  }
  return undefined;
}

function parseAttributes(value: unknown): JsonRecord | undefined {
  if (isRecord(value)) return value;
  if (typeof value !== "string" || !value.trim()) return undefined;
  try {
    const parsed = JSON.parse(value);
    return isRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function stringField(record: JsonRecord, ...keys: string[]): string | undefined {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.trim()) return value.trim();
    if (typeof value === "number" && Number.isFinite(value)) return String(value);
  }
  return undefined;
}

function isRecord(value: unknown): value is JsonRecord {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
