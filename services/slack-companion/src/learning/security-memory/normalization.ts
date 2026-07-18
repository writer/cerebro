import { createHash } from "node:crypto";
import { redactSecurityText } from "../../security/redaction.js";
import type {
  SecurityMemoryPromotionState,
  SecurityMemorySourceKind,
  SecurityMemoryStalenessPolicy,
} from "../memory-types.js";

export function clean(value: string, max: number): string {
  return redactSecurityText(value).replace(/\s+/g, " ").trim().slice(0, max);
}

export function cleanArray(values: string[] | undefined, max: number, limit: number): string[] | undefined {
  const cleaned = (values ?? []).map((value) => clean(value, max)).filter(Boolean).slice(0, limit);
  return cleaned.length > 0 ? cleaned : undefined;
}

export function stableId(parts: string[]): string {
  return createHash("sha256").update(parts.join("\u0000")).digest("hex").slice(0, 32);
}

export function boundedLimit(value: number, max: number): number {
  if (!Number.isFinite(value)) return max;
  return Math.max(1, Math.min(Math.floor(value), Math.max(1, max)));
}

export function parseSince(value: string | undefined): number | undefined {
  if (!value?.trim()) return undefined;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? undefined : parsed;
}

export function normalizeSearchText(value: string): string {
  return value
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

export function cleanEntity(value: string): string {
  return normalizeSearchText(value)
    .replace(/^@+/, "")
    .replace(/^[^a-z0-9]+|[^a-z0-9_.:-]+$/g, "")
    .trim();
}

export function futureIso(value: string | undefined): string | undefined {
  if (!value?.trim()) return undefined;
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed) || parsed <= Date.now()) return undefined;
  return new Date(parsed).toISOString();
}

export function futureOrPastIso(value: string | undefined): string | undefined {
  if (!value?.trim()) return undefined;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? undefined : new Date(parsed).toISOString();
}

export function isPromotionState(value: unknown): value is SecurityMemoryPromotionState {
  return value === "transient" || value === "candidate" || value === "promoted" || value === "rejected";
}

export function isStalenessPolicy(value: unknown): value is SecurityMemoryStalenessPolicy {
  return value === "ephemeral" || value === "short_lived" || value === "until_reverified" || value === "durable";
}

export function isMemorySourceKind(value: unknown): value is SecurityMemorySourceKind {
  return value === "slack_remember"
    || value === "slack_channel"
    || value === "assistant_answer"
    || value === "alert_triage"
    || value === "daily_notes"
    || value === "manual"
    || value === "tool";
}

export function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}
