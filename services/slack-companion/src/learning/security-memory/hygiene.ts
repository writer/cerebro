import type { SecurityMemoryRecord } from "../memory-types.js";
import { normalizeSearchText } from "./normalization.js";

export function isExpired(record: SecurityMemoryRecord): boolean {
  if (!record.expiresAt) return false;
  const parsed = Date.parse(record.expiresAt);
  return Number.isFinite(parsed) && parsed <= Date.now();
}

export function shouldExpireTransient(record: SecurityMemoryRecord, now: Date): boolean {
  if (record.expiresAt) return false;
  if (record.promotionState !== "transient" && record.kind !== "assistant_answer" && record.kind !== "encounter_story" && record.kind !== "triage_outcome") return false;
  const created = Date.parse(record.createdAt);
  if (!Number.isFinite(created)) return false;
  const age = Math.max(0, now.getTime() - created) / 86_400_000;
  return age > transientTtlDays(record);
}

export function countBy(values: string[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const value of values) counts[value] = (counts[value] ?? 0) + 1;
  return counts;
}

export function average(values: number[]): number {
  if (values.length === 0) return 0;
  return roundScore(values.reduce((sum, value) => sum + value, 0) / values.length);
}

export function ageDays(createdAt: string): number {
  const parsed = Date.parse(createdAt);
  if (!Number.isFinite(parsed)) return 0;
  return Math.max(0, (Date.now() - parsed) / 86_400_000);
}

export function roundScore(value: number): number {
  return Math.round(value * 100) / 100;
}

function transientTtlDays(record: SecurityMemoryRecord): number {
  if (record.kind === "assistant_answer") return 14;
  if (record.kind === "encounter_story") return 30;
  if (record.kind === "triage_outcome") {
    const tags = (record.tags ?? []).map(normalizeSearchText);
    if (record.classification === "likely_security_issue" || tags.includes("critical") || tags.includes("high")) return 30;
    if ((record.tags ?? []).some((tag) => normalizeSearchText(tag) === "auto reply posted")) return 14;
    return 7;
  }
  return 14;
}
