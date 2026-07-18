export type AuditOutcome = "success" | "failure" | "denied" | "unknown";

export type AuditActor = {
  id: string;
  kind: string;
  label: string;
};

export type AuditResource = {
  id: string;
  type: string;
  label: string;
};

export type AuditEvent = {
  action: string;
  actor: AuditActor | null;
  category: string;
  durationMs: number | null;
  id: string;
  occurredAt: string;
  outcome: AuditOutcome;
  requestId: string;
  resource: AuditResource | null;
  service: string;
  summary: string;
  traceId: string;
};

export type AuditLogQuery = {
  action: string;
  actor: string;
  cursor: string;
  limit: number;
  minutes: number;
  outcome: AuditOutcome | "";
  query: string;
  resourceType: string;
  service: string;
  traceId: string;
};

export type AuditLogSummary = {
  actions: Array<{ count: number; label: string }>;
  averageDurationMs: number | null;
  denied: number;
  failures: number;
  p95DurationMs: number | null;
  services: Array<{ count: number; label: string }>;
  total: number;
};

export type AuditLogPage = {
  events: AuditEvent[];
  nextCursor: string;
  status: "complete" | "partial";
  summary: AuditLogSummary;
  window: {
    endTime: string;
    startTime: string;
  } | null;
};

const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 500;
const DEFAULT_MINUTES = 60;
const MAX_MINUTES = 24 * 60;
const MAX_FILTER_LENGTH = 200;
const MAX_CURSOR_LENGTH = 512;
const MAX_SUMMARY_LENGTH = 500;

export const defaultAuditLogQuery = (): AuditLogQuery => ({
  action: "",
  actor: "",
  cursor: "",
  limit: DEFAULT_LIMIT,
  minutes: DEFAULT_MINUTES,
  outcome: "",
  query: "",
  resourceType: "",
  service: "",
  traceId: "",
});

export function auditLogQueryFromSearchParams(params: URLSearchParams): AuditLogQuery {
  return {
    action: boundedText(params.get("action"), MAX_FILTER_LENGTH),
    actor: boundedText(params.get("actor"), MAX_FILTER_LENGTH),
    cursor: boundedText(params.get("cursor"), MAX_CURSOR_LENGTH),
    limit: boundedInteger(params.get("limit"), DEFAULT_LIMIT, 1, MAX_LIMIT),
    minutes: boundedInteger(params.get("minutes"), DEFAULT_MINUTES, 5, MAX_MINUTES),
    outcome: auditOutcomeFilter(params.get("outcome")),
    query: boundedText(params.get("q"), MAX_FILTER_LENGTH),
    resourceType: boundedText(params.get("resource_type"), MAX_FILTER_LENGTH),
    service: boundedText(params.get("service"), MAX_FILTER_LENGTH),
    traceId: boundedText(params.get("trace_id"), MAX_FILTER_LENGTH),
  };
}

export function auditLogSearchParams(query: AuditLogQuery): URLSearchParams {
  const params = new URLSearchParams({
    limit: String(boundedInteger(query.limit, DEFAULT_LIMIT, 1, MAX_LIMIT)),
    minutes: String(boundedInteger(query.minutes, DEFAULT_MINUTES, 5, MAX_MINUTES)),
  });
  addSearchParam(params, "action", query.action, MAX_FILTER_LENGTH);
  addSearchParam(params, "actor", query.actor, MAX_FILTER_LENGTH);
  addSearchParam(params, "cursor", query.cursor, MAX_CURSOR_LENGTH);
  addSearchParam(params, "outcome", query.outcome, MAX_FILTER_LENGTH);
  addSearchParam(params, "q", query.query, MAX_FILTER_LENGTH);
  addSearchParam(params, "resource_type", query.resourceType, MAX_FILTER_LENGTH);
  addSearchParam(params, "service", query.service, MAX_FILTER_LENGTH);
  addSearchParam(params, "trace_id", query.traceId, MAX_FILTER_LENGTH);
  return params;
}

export function normalizeAuditLogPage(value: unknown): AuditLogPage {
  const record = objectValue(value);
  if (!Array.isArray(record.events)) {
    throw new TypeError("Audit event response must include an events array.");
  }
  const inputEvents = record.events;
  const events = inputEvents
    .map(normalizeAuditEvent)
    .filter((event): event is AuditEvent => event !== null);
  const rawWindow = objectValue(record.window);
  const startTime = isoTime(rawWindow.start_time ?? rawWindow.startTime);
  const endTime = isoTime(rawWindow.end_time ?? rawWindow.endTime);

  return {
    events,
    nextCursor: boundedText(record.next_cursor ?? record.nextCursor, MAX_CURSOR_LENGTH),
    status: boundedText(record.status, 40).toLowerCase() === "partial" || events.length !== inputEvents.length
      ? "partial"
      : "complete",
    summary: summarizeAuditLog(events),
    window: startTime && endTime ? { startTime, endTime } : null,
  };
}

export function normalizeAuditEvent(value: unknown): AuditEvent | null {
  const record = objectValue(value);
  const id = boundedText(record.id ?? record.event_id, MAX_FILTER_LENGTH);
  const occurredAt = isoTime(record.occurred_at ?? record.occurredAt ?? record.timestamp);
  const action = boundedText(record.action ?? record.name, MAX_FILTER_LENGTH);
  if (!id || !occurredAt || !action) {
    return null;
  }

  const actor = normalizeActor(record.actor);
  const resource = normalizeResource(record.resource);
  return {
    action,
    actor,
    category: boundedText(record.category, MAX_FILTER_LENGTH),
    durationMs: nonNegativeNumber(record.duration_ms ?? record.durationMs),
    id,
    occurredAt,
    outcome: normalizeAuditOutcome(record.outcome ?? record.status),
    requestId: boundedText(record.request_id ?? record.requestId, MAX_FILTER_LENGTH),
    resource,
    service: boundedText(record.service, MAX_FILTER_LENGTH),
    summary: boundedText(record.summary, MAX_SUMMARY_LENGTH),
    traceId: boundedText(record.trace_id ?? record.traceId, MAX_FILTER_LENGTH),
  };
}

export function summarizeAuditLog(events: AuditEvent[]): AuditLogSummary {
  const durations = events
    .map((event) => event.durationMs)
    .filter((duration): duration is number => duration !== null)
    .sort((left, right) => left - right);
  return {
    actions: topCounts(events.map((event) => event.action), 8),
    averageDurationMs: durations.length > 0
      ? Math.round(durations.reduce((total, duration) => total + duration, 0) / durations.length)
      : null,
    denied: events.filter((event) => event.outcome === "denied").length,
    failures: events.filter((event) => event.outcome === "failure").length,
    p95DurationMs: percentile(durations, 0.95),
    services: topCounts(events.map((event) => event.service).filter(Boolean), 8),
    total: events.length,
  };
}

export function normalizeAuditOutcome(value: unknown): AuditOutcome {
  const outcome = boundedText(value, 40).toLowerCase();
  if (["success", "succeeded", "completed", "complete", "allowed"].includes(outcome)) {
    return "success";
  }
  if (["failure", "failed", "error", "errored", "timeout", "timed_out", "cancelled"].includes(outcome)) {
    return "failure";
  }
  if (["denied", "rejected", "blocked", "forbidden"].includes(outcome)) {
    return "denied";
  }
  return "unknown";
}

const normalizeActor = (value: unknown): AuditActor | null => {
  const record = objectValue(value);
  const id = boundedText(record.id, MAX_FILTER_LENGTH);
  const kind = boundedText(record.kind ?? record.type, MAX_FILTER_LENGTH);
  const label = boundedText(record.label ?? record.display_name ?? record.displayName, MAX_FILTER_LENGTH);
  return id || kind || label ? { id, kind, label } : null;
};

const normalizeResource = (value: unknown): AuditResource | null => {
  const record = objectValue(value);
  const id = boundedText(record.id, MAX_FILTER_LENGTH);
  const type = boundedText(record.type ?? record.kind, MAX_FILTER_LENGTH);
  const label = boundedText(record.label ?? record.name, MAX_FILTER_LENGTH);
  return id || type || label ? { id, type, label } : null;
};

const objectValue = (value: unknown): Record<string, unknown> =>
  value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};

const boundedText = (value: unknown, maximum: number) =>
  typeof value === "string" ? value.trim().slice(0, maximum) : "";

const boundedInteger = (value: unknown, fallback: number, minimum: number, maximum: number) => {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(minimum, Math.min(maximum, parsed));
};

const nonNegativeNumber = (value: unknown) => {
  if (value === null || value === undefined || value === "") return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
};

const isoTime = (value: unknown) => {
  const text = boundedText(value, 100);
  if (!text || !Number.isFinite(Date.parse(text))) return "";
  return text;
};

const auditOutcomeFilter = (value: unknown): AuditOutcome | "" => {
  const text = boundedText(value, 40).toLowerCase();
  return ["success", "failure", "denied", "unknown"].includes(text)
    ? text as AuditOutcome
    : "";
};

const addSearchParam = (params: URLSearchParams, key: string, value: unknown, maximum: number) => {
  const text = boundedText(value, maximum);
  if (text) params.set(key, text);
};

const topCounts = (values: string[], limit: number) => {
  const counts = new Map<string, number>();
  for (const value of values) {
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([label, count]) => ({ count, label }))
    .sort((left, right) => right.count - left.count || left.label.localeCompare(right.label))
    .slice(0, limit);
};

const percentile = (values: number[], rank: number) => {
  if (values.length === 0) return null;
  const index = Math.min(values.length - 1, Math.max(0, Math.ceil(values.length * rank) - 1));
  return values[index];
};
