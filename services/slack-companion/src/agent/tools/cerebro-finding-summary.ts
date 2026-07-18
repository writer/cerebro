import type { Finding } from "../../cerebro/types.js";
import type { AppConfig } from "../../config/index.js";
import { stringValue } from "./normalizers.js";

export function findingSummary(config: AppConfig, runtimeId: string, finding: Finding) {
  const findingId = stringValue(finding.id);
  const observedAt = stringValue(finding.last_observed_at ?? finding.observed_at ?? finding.created_at);
  const observedAtMs = observedAt ? Date.parse(observedAt) : Number.NaN;
  const severity = stringValue(finding.severity)?.toLowerCase();
  const riskScore = typeof finding.risk_score === "number" ? finding.risk_score : undefined;
  const scareScore = severityWeight(severity) * 10_000 + (riskScore ?? 0) * 100 + (Number.isFinite(observedAtMs) ? Math.floor(observedAtMs / 86_400_000) : 0);
  return {
    runtime_id: runtimeId,
    finding_id: findingId,
    title: stringValue(finding.title ?? finding.summary ?? finding.id) ?? "Untitled finding",
    severity: severity ?? "unknown",
    status: stringValue(finding.status) ?? "open",
    risk_score: riskScore,
    resource: stringValue(finding.primary_resource_urn ?? finding.resource_urn),
    assignee: stringValue(finding.assignee),
    last_observed_at: observedAt,
    web_url: findingId && config.cerebro.webBaseUrl ? `${config.cerebro.webBaseUrl}/findings/${encodeURIComponent(findingId)}` : undefined,
    observed_at_ms: Number.isFinite(observedAtMs) ? observedAtMs : undefined,
    scare_score: scareScore,
  };
}

export type FindingSummary = ReturnType<typeof findingSummary>;

export function compareScaryFindings(left: FindingSummary, right: FindingSummary): number {
  return right.scare_score - left.scare_score
    || (right.observed_at_ms ?? 0) - (left.observed_at_ms ?? 0)
    || (right.risk_score ?? 0) - (left.risk_score ?? 0)
    || right.severity.localeCompare(left.severity);
}

function severityWeight(severity: string | undefined): number {
  switch (severity) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    case "info":
      return 1;
    default:
      return 0;
  }
}
