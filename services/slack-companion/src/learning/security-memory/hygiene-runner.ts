import { annotateMain, recordMetric } from "../../telemetry.js";
import type { CuratedMemoryHygieneDecision } from "../security-memory-curator.js";
import type { MemoryRecordItem, SecurityMemoryHygieneResult } from "./types.js";
import { isExpired, shouldExpireTransient } from "./hygiene.js";

export type MemoryExpirationReason = "duplicate" | "stale_transient";

export interface MemoryExpiration {
  item: MemoryRecordItem;
  reason: MemoryExpirationReason;
}

export function planMemoryHygieneExpirations(items: MemoryRecordItem[], now: Date): MemoryExpiration[] {
  const seenContent = new Set<string>();
  const expirations: MemoryExpiration[] = [];
  for (const item of items) {
    const { record } = item;
    if (isExpired(record)) continue;
    const duplicateKey = record.contentHash ? `${record.kind}:${record.channelId ?? ""}:${record.contentHash}` : "";
    if (duplicateKey) {
      if (seenContent.has(duplicateKey)) {
        expirations.push({ item, reason: "duplicate" });
        continue;
      }
      seenContent.add(duplicateKey);
    }
    if (shouldExpireTransient(record, now)) {
      expirations.push({ item, reason: "stale_transient" });
    }
  }
  return expirations;
}

export function memoryHygieneResult(items: MemoryRecordItem[], expirations: MemoryExpiration[], dryRun: boolean): SecurityMemoryHygieneResult {
  return {
    checked: items.length,
    expired: expirations.length,
    duplicateExpired: expirations.filter((item) => item.reason === "duplicate").length,
    staleTransientExpired: expirations.filter((item) => item.reason === "stale_transient").length,
    dryRun,
  };
}

export function activeMemoryItems(items: MemoryRecordItem[]): MemoryRecordItem[] {
  return items.filter((item) => !isExpired(item.record));
}

export function curatedMemoryExpirations(
  active: MemoryRecordItem[],
  decision: CuratedMemoryHygieneDecision,
): MemoryRecordItem[] {
  const expireReasons = new Map(decision.expire.map((item) => [item.id, item.reason]));
  return active.filter((item) => expireReasons.has(item.record.id));
}

export function curatedMemoryHygieneResult(
  active: MemoryRecordItem[],
  expirations: MemoryRecordItem[],
  dryRun: boolean,
): SecurityMemoryHygieneResult {
  return {
    checked: active.length,
    expired: expirations.length,
    duplicateExpired: 0,
    staleTransientExpired: expirations.length,
    dryRun,
  };
}

export function recordMemoryHygieneTelemetry(result: SecurityMemoryHygieneResult): void {
  annotateMain({
    "memory.hygiene.checked": result.checked,
    "memory.hygiene.expired": result.expired,
    "memory.hygiene.duplicate_expired": result.duplicateExpired,
    "memory.hygiene.stale_transient_expired": result.staleTransientExpired,
    "memory.hygiene.dry_run": result.dryRun,
  });
  recordMetric("cerebro_slack_companion_memory_hygiene_checked_total", {}, result.checked);
  recordMetric("cerebro_slack_companion_memory_hygiene_expired_total", { dry_run: result.dryRun }, result.expired);
}

export function recordCuratedMemoryHygieneTelemetry(result: SecurityMemoryHygieneResult): void {
  annotateMain({
    "memory.curator.hygiene.checked": result.checked,
    "memory.curator.hygiene.expired": result.expired,
    "memory.curator.hygiene.dry_run": result.dryRun,
  });
  recordMetric("cerebro_slack_companion_memory_curator_hygiene_checked_total", {}, result.checked);
  recordMetric("cerebro_slack_companion_memory_curator_hygiene_expired_total", { dry_run: result.dryRun }, result.expired);
}
