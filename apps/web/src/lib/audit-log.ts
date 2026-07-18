export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };
export type JsonRecord = Record<string, JsonValue>;

export type AuditLogEvent = {
  id: string;
  timestamp: string;
  service: string;
  name: string;
  status: string;
  outcome: string;
  durationMs: number | null;
  traceId: string;
  runtimeId: string;
  sourceId: string;
  phase: string;
  dependency: string;
  errorKind: string;
  attributes: Record<string, string | number | boolean | null>;
  rawEvent: JsonRecord;
};

export type AuditLogSummary = {
  total: number;
  failures: number;
  failureRate: number;
  averageDurationMs: number | null;
  p95DurationMs: number | null;
  services: { label: string; count: number }[];
  runtimes: { label: string; count: number }[];
  phases: { label: string; count: number }[];
  dependencies: { label: string; count: number }[];
  errors: { label: string; count: number }[];
};

const MAX_LIMIT = 500;
const DEFAULT_LIMIT = 100;
const MAX_MINUTES = 24 * 60;
const DEFAULT_MINUTES = 60;

export const auditLogWindowMinutes = (value: unknown) =>
  clampInteger(value, DEFAULT_MINUTES, 5, MAX_MINUTES);

export const auditLogLimit = (value: unknown) =>
  clampInteger(value, DEFAULT_LIMIT, 1, MAX_LIMIT);

export function summarizeAuditLog(events: AuditLogEvent[]): AuditLogSummary {
  const durations = events
    .map((event) => event.durationMs)
    .filter((duration): duration is number =>
      typeof duration === "number" && Number.isFinite(duration) && duration >= 0,
    )
    .sort((left, right) => left - right);
  const failures = events.filter((event) =>
    isFailureStatus(event.status) || isFailureStatus(event.outcome),
  ).length;

  return {
    total: events.length,
    failures,
    failureRate: events.length > 0 ? failures / events.length : 0,
    averageDurationMs: durations.length > 0
      ? Math.round(durations.reduce((sum, value) => sum + value, 0) / durations.length)
      : null,
    p95DurationMs: percentile(durations, 0.95),
    services: topCounts(events.map((event) => event.service).filter(Boolean), 6),
    runtimes: topCounts(events.map((event) => event.runtimeId).filter(Boolean), 8),
    phases: topCounts(events.map((event) => event.phase).filter(Boolean), 8),
    dependencies: topCounts(events.map((event) => event.dependency).filter(Boolean), 8),
    errors: topCounts(events.map((event) => event.errorKind).filter(Boolean), 8),
  };
}

export const isFailureStatus = (value: string) =>
  /^(failed|failure|error|errored|timeout|timed_out|cancelled|denied)$/i.test(value.trim());

const clampInteger = (value: unknown, fallback: number, minimum: number, maximum: number) => {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(minimum, Math.min(maximum, parsed));
};

const percentile = (values: number[], quantile: number) => {
  if (values.length === 0) return null;
  const index = Math.max(0, Math.ceil(values.length * quantile) - 1);
  return values[index] ?? null;
};

const topCounts = (values: string[], limit: number) => {
  const counts = new Map<string, number>();
  values.forEach((value) => counts.set(value, (counts.get(value) ?? 0) + 1));
  return [...counts.entries()]
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .slice(0, limit)
    .map(([label, count]) => ({ label, count }));
};
