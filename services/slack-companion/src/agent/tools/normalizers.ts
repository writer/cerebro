import type { SecurityMemoryKind, SecurityMemoryPromotionState, SecurityMemoryStalenessPolicy } from "../../learning/memory-types.js";

export function limit(value: number | undefined, max: number): number {
  if (!value || Number.isNaN(value)) return max;
  return Math.max(1, Math.min(max, Math.floor(value)));
}

export function normalizeFindingStatus(value: string | undefined): "open" | "resolved" | "suppressed" | undefined {
  if (value === "open" || value === "resolved" || value === "suppressed") return value;
  return undefined;
}

export function normalizeFindingOrder(value: string | undefined): "last_observed" | "priority" | "risk_score" | undefined {
  if (value === "last_observed" || value === "priority" || value === "risk_score") return value;
  return undefined;
}

export function normalizeMemoryKind(value: string): SecurityMemoryKind {
  const normalized = value.trim().toLowerCase();
  if (normalized === "access_context" || normalized === "asset_context" || normalized === "connector_context" || normalized === "detection_context" || normalized === "exception_context" || normalized === "normal_pattern" || normalized === "owner_context" || normalized === "severity_context" || normalized === "team_context" || normalized === "explicit_memory" || normalized === "triage_outcome" || normalized === "assistant_answer" || normalized === "encounter_story" || normalized === "skill_improvement" || normalized === "investigation_note" || normalized === "runbook_note" || normalized === "operator_fact" || normalized === "operator_claim" || normalized === "operator_decision" || normalized === "operator_correction" || normalized === "operator_risk" || normalized === "operator_blocker" || normalized === "operator_handoff" || normalized === "source_health_note") {
    return normalized;
  }
  return "investigation_note";
}

export function normalizePromotionState(value: string | undefined): SecurityMemoryPromotionState | undefined {
  const normalized = value?.trim().toLowerCase();
  if (normalized === "transient" || normalized === "candidate" || normalized === "promoted" || normalized === "rejected") {
    return normalized;
  }
  return undefined;
}

export function normalizeStalenessPolicy(value: string | undefined): SecurityMemoryStalenessPolicy | undefined {
  const normalized = value?.trim().toLowerCase();
  if (normalized === "ephemeral" || normalized === "short_lived" || normalized === "until_reverified" || normalized === "durable") {
    return normalized;
  }
  return undefined;
}

export function normalizeSlackSearchSort(value: string | undefined): "score" | "timestamp" | undefined {
  if (value === "score" || value === "timestamp") return value;
  return undefined;
}

export function normalizeSlackSearchSortDir(value: string | undefined): "asc" | "desc" | undefined {
  if (value === "asc" || value === "desc") return value;
  return undefined;
}

export function shortError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.replace(/\s+/g, " ").slice(0, 240);
}

export function stringList(values: string[] | undefined): string[] | undefined {
  const cleaned = (values ?? []).map((value) => value.trim()).filter(Boolean);
  return cleaned.length > 0 ? cleaned : undefined;
}

export function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

export function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}
