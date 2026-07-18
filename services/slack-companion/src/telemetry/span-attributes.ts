import type { TelemetryAttributes } from "./types.js";

export const telemetrySchemaVersion = "2026-06-26.1";

export function spanBaseAttributes(name: string, main: boolean): TelemetryAttributes {
  return {
    "telemetry.schema.version": telemetrySchemaVersion,
    "event.dataset": main ? "cerebro_slack_companion.wide_events" : "cerebro_slack_companion.telemetry",
    "telemetry.signal.kind": "span",
    "event.category": "operation",
    "event.type": "start",
    "operation.name": name,
    ...(main ? {
      "wide_event.schema.version": telemetrySchemaVersion,
      "wide_event.contract": "main-span",
    } : {}),
  };
}

export function eventOutcomeForStatus(status: string): string {
  switch (String(status).trim().toLowerCase()) {
    case "failed":
    case "error":
      return "failure";
    case "completed":
    case "matched":
      return "success";
    case "skipped":
    case "miss":
    case "queued":
    case "suppressed":
    case "degraded":
      return "neutral";
    default:
      return "unknown";
  }
}

export function durationBucket(durationMs: number): string {
  if (durationMs < 10) return "lt_10ms";
  if (durationMs < 50) return "lt_50ms";
  if (durationMs < 100) return "lt_100ms";
  if (durationMs < 250) return "lt_250ms";
  if (durationMs < 500) return "lt_500ms";
  if (durationMs < 1_000) return "lt_1s";
  if (durationMs < 5_000) return "lt_5s";
  if (durationMs < 30_000) return "lt_30s";
  if (durationMs < 60_000) return "lt_1m";
  if (durationMs < 300_000) return "lt_5m";
  if (durationMs < 1_800_000) return "lt_30m";
  return "gte_30m";
}
