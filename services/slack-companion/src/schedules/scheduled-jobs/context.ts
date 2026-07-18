import type { Finding, RuntimeHealth } from "../../cerebro/types.js";
import { trimForSlack } from "../../slack/format.js";
import {
  SCHEDULE_CONTEXT_PROVIDERS,
  type ScheduledContextProviderId,
} from "../schedule-parser.js";
import type { ScheduledJobContextResult } from "./types.js";

export function runtimeLooksUnhealthy(runtime: RuntimeHealth): boolean {
  const values = Object.values(runtime).map((value) => String(value).toLowerCase());
  if (values.some((value) => /\b(failed|failure|error|blocked|stale|unhealthy|degraded|timeout)\b/.test(value))) {
    return true;
  }
  const statusValues = Object.entries(runtime)
    .filter(([key]) => /status|state|health/i.test(key))
    .map(([, value]) => String(value).toLowerCase());
  return statusValues.length > 0 && !statusValues.some((value) => /\b(healthy|ok|success|succeeded|complete|completed|ready)\b/.test(value));
}

export function contextProviderTitle(providerId: ScheduledContextProviderId): string {
  return SCHEDULE_CONTEXT_PROVIDERS.find((provider) => provider.id === providerId)?.title ?? providerId;
}

export function scheduleContextPromptBlock(contextResults: ScheduledJobContextResult[]): string {
  if (contextResults.length === 0) return "";
  const payload = contextResults.map((context) => ({
    provider_id: context.providerId,
    title: context.title,
    status: context.status,
    summary: context.summary,
    details: context.details,
  }));
  return [
    "Pre-run context gathered before this scheduled check:",
    "```json",
    trimForSlack(JSON.stringify(payload, null, 2), 6000),
    "```",
    "Treat this as a read-only snapshot. Verify with live tools if it is partial, stale, or conflicts with current evidence.",
  ].join("\n");
}

export function compactRuntimeHealth(runtime: RuntimeHealth): Record<string, unknown> {
  return {
    runtime_id: runtimeIdForHealth(runtime),
    source_id: runtime.source_id,
    status: runtime.status,
    sync_status: runtime.sync_status,
    graph_status: runtime.graph_status,
    finding_status: runtime.finding_status,
    last_sync_at: runtime.last_sync_at,
    last_observed_at: runtime.last_observed_at,
    last_graph_ingest_at: runtime.last_graph_ingest_at,
    open_finding_count: runtime.open_finding_count,
    invalid_event_count: runtime.invalid_event_count,
  };
}

export function runtimeIdForHealth(runtime: RuntimeHealth): string | undefined {
  return runtime.runtime_id ?? runtime.id;
}

export function compactFinding(finding: Finding): Record<string, unknown> {
  return {
    id: finding.id,
    runtime_id: finding.runtime_id,
    rule_id: finding.rule_id,
    title: finding.title,
    severity: finding.severity,
    risk_score: finding.risk_score,
    status: finding.status,
    resource_urn: finding.primary_resource_urn ?? finding.resource_urn,
    assignee: finding.assignee,
    due_at: finding.due_at,
    last_observed_at: finding.last_observed_at ?? finding.observed_at,
  };
}
