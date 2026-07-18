import type {
  SecurityMemoryFreshness,
  SecurityMemoryQuality,
  SecurityMemoryRecallConflict,
  SecurityMemoryRecallCoverage,
  SecurityMemoryRecallQualitySummary,
  SecurityMemoryRecord,
} from "../memory-types.js";
import { average, roundScore } from "./hygiene.js";
import { normalizeSearchText, unique } from "./normalization.js";

export interface MemoryIntelligence {
  trustScore: number;
  quality: SecurityMemoryQuality;
  freshness: SecurityMemoryFreshness;
  trustBoost: number;
}

export interface MemoryQualityInput {
  record: SecurityMemoryRecord;
  trustScore: number;
  quality: SecurityMemoryQuality;
  freshness: SecurityMemoryFreshness;
  matchedEntities: string[];
}

export function memoryIntelligence(record: SecurityMemoryRecord, now = new Date()): MemoryIntelligence {
  const freshness = memoryFreshness(record, now);
  const quality = memoryQuality(record, freshness);
  const trustScore = memoryTrustScore(record, freshness, quality, now);
  return {
    freshness,
    quality,
    trustScore,
    trustBoost: roundScore((trustScore - 0.5) * 1.8),
  };
}

export function memoryFreshness(record: SecurityMemoryRecord, now = new Date()): SecurityMemoryFreshness {
  if (isExpiredAt(record, now)) return "expired";
  const createdAge = ageDaysAt(record.createdAt, now);
  const verifiedAge = record.verifiedAt ? ageDaysAt(record.verifiedAt, now) : undefined;
  switch (record.stalenessPolicy) {
    case "ephemeral":
      return createdAge <= 1 ? "current" : "stale";
    case "short_lived":
      if (createdAge <= 3) return "current";
      return createdAge <= 14 ? "recent" : "stale";
    case "until_reverified":
      if (verifiedAge !== undefined && verifiedAge <= 7) return "current";
      if (verifiedAge !== undefined && verifiedAge <= 30) return "aging";
      return "stale";
    case "durable":
      if (createdAge <= 30) return "current";
      if (createdAge <= 180) return "recent";
      return createdAge <= 365 ? "aging" : "stale";
    default:
      if (createdAge <= 14) return "recent";
      return createdAge <= 90 ? "aging" : "stale";
  }
}

export function memoryQuality(record: SecurityMemoryRecord, freshness = memoryFreshness(record)): SecurityMemoryQuality {
  if (record.promotionState === "rejected") return "rejected";
  if (freshness === "expired" || freshness === "stale") return "stale";
  const hasVerifier = Boolean(record.verifiedBy?.length || record.verifiedAt);
  const hasSourceArtifact = Boolean(record.sourceArtifacts?.length);
  if (hasVerifier && hasSourceArtifact) return "source_verified";
  if (hasVerifier || hasSourceArtifact) return "source_backed";
  if (record.promotionState === "promoted") return "promoted";
  if (record.promotionState === "candidate") return "candidate";
  if (record.promotionState === "transient") return "transient";
  return "unverified";
}

export function summarizeRecallQuality(items: MemoryQualityInput[]): SecurityMemoryRecallQualitySummary {
  return {
    averageTrustScore: average(items.map((item) => item.trustScore)),
    sourceVerifiedCount: items.filter((item) => item.quality === "source_verified").length,
    sourceBackedCount: items.filter((item) => item.quality === "source_backed").length,
    promotedCount: items.filter((item) => item.record.promotionState === "promoted" || item.quality === "promoted").length,
    candidateCount: items.filter((item) => item.record.promotionState === "candidate" || item.quality === "candidate").length,
    transientCount: items.filter((item) => item.record.promotionState === "transient" || item.quality === "transient").length,
    staleCount: items.filter((item) => item.freshness === "stale" || item.quality === "stale").length,
    unverifiedCount: items.filter((item) => item.quality === "unverified").length,
  };
}

export function recallCoverage(queryEntities: string[], items: MemoryQualityInput[]): SecurityMemoryRecallCoverage {
  const normalizedQueryEntities = unique(queryEntities.map(normalizeSearchText).filter(Boolean));
  const matched = unique(items.flatMap((item) => [
    ...item.matchedEntities,
    ...(item.record.entities ?? []).filter((entity) => normalizedQueryEntities.includes(entity)),
  ]).map(normalizeSearchText).filter(Boolean));
  const missing = normalizedQueryEntities.filter((entity) => !matched.includes(entity));
  return {
    queryEntities: normalizedQueryEntities,
    matchedEntities: matched,
    missingEntities: missing,
    coverageRatio: normalizedQueryEntities.length === 0
      ? 1
      : roundScore((normalizedQueryEntities.length - missing.length) / normalizedQueryEntities.length),
  };
}

export function detectMemoryConflicts(records: SecurityMemoryRecord[]): SecurityMemoryRecallConflict[] {
  const groups = new Map<string, SecurityMemoryRecord[]>();
  for (const record of records) {
    for (const key of conflictKeys(record)) {
      const bucket = groups.get(key) ?? [];
      bucket.push(record);
      groups.set(key, bucket);
    }
  }
  const conflicts: SecurityMemoryRecallConflict[] = [];
  const seen = new Set<string>();
  for (const [key, group] of groups) {
    if (group.length < 2) continue;
    const positive = group.filter((record) => conflictSignals(record).includes("positive_state"));
    const negative = group.filter((record) => conflictSignals(record).includes("negative_state"));
    if (positive.length === 0 || negative.length === 0) continue;
    const recordIds = unique([...positive, ...negative].map((record) => record.id));
    const stableKey = recordIds.sort().join(":");
    if (seen.has(stableKey)) continue;
    seen.add(stableKey);
    const first = group[0]!;
    conflicts.push({
      topic: first.scope ?? first.topic,
      scope: first.scope,
      recordIds,
      summaries: unique([...positive, ...negative].map((record) => record.summary)).slice(0, 4),
      reason: `Memory graph has opposing state signals for ${key}.`,
      signals: ["positive_state", "negative_state"],
    });
  }
  return conflicts.slice(0, 5);
}

export function recallWarnings(input: {
  returnedCount: number;
  coverage: SecurityMemoryRecallCoverage;
  quality: SecurityMemoryRecallQualitySummary;
  conflicts: SecurityMemoryRecallConflict[];
}): string[] {
  const warnings: string[] = [];
  if (input.returnedCount === 0) {
    warnings.push("No memory matched the query.");
  }
  if (input.coverage.missingEntities.length > 0) {
    warnings.push(`No returned memory covered these query entities: ${input.coverage.missingEntities.slice(0, 5).join(", ")}.`);
  }
  if (input.returnedCount > 0 && input.quality.sourceVerifiedCount === 0 && input.quality.sourceBackedCount === 0) {
    warnings.push("Returned memory has no verifier or source artifact.");
  }
  if (input.quality.staleCount > 0) {
    warnings.push("Returned memory includes stale records that need current-source verification.");
  }
  if (input.returnedCount > 0 && input.quality.transientCount >= input.returnedCount && input.quality.promotedCount === 0) {
    warnings.push("Returned memory is transient only.");
  }
  if (input.conflicts.length > 0) {
    warnings.push("Memory graph contains conflicting state signals.");
  }
  return unique(warnings);
}

function memoryTrustScore(
  record: SecurityMemoryRecord,
  freshness: SecurityMemoryFreshness,
  quality: SecurityMemoryQuality,
  now: Date,
): number {
  let score = 0.36;
  if (isSecurityKnowledgeContext(record)) score += 0.12;
  if (record.kind === "runbook_note" || record.kind === "investigation_note") score += 0.1;
  if (record.kind === "team_context" || record.kind === "explicit_memory") score += 0.08;
  if (record.kind === "normal_pattern") score += 0.05;
  if (record.kind === "assistant_answer" || record.kind === "encounter_story") score -= 0.18;
  if (record.kind === "triage_outcome") score -= 0.04;

  if (record.promotionState === "promoted") score += 0.16;
  if (record.promotionState === "candidate") score += 0.04;
  if (record.promotionState === "transient") score -= 0.12;
  if (record.promotionState === "rejected") score -= 0.5;

  if (record.stalenessPolicy === "durable") score += 0.1;
  if (record.stalenessPolicy === "until_reverified") score -= 0.02;
  if (record.stalenessPolicy === "short_lived") score -= 0.06;
  if (record.stalenessPolicy === "ephemeral") score -= 0.1;

  if (record.verifiedBy?.length) score += 0.13;
  if (record.verifiedAt) score += ageDaysAt(record.verifiedAt, now) <= 30 ? 0.08 : 0.02;
  if (record.sourceArtifacts?.length) score += 0.12;
  if (record.sourceKind === "slack_remember") score += 0.06;
  if (record.sourceKind === "tool") score += 0.03;
  if (record.sourceKind === "assistant_answer") score -= 0.12;

  if (freshness === "current") score += 0.06;
  if (freshness === "aging") score -= 0.07;
  if (freshness === "stale") score -= 0.24;
  if (freshness === "expired") score -= 0.7;
  if (quality === "source_verified") score += 0.08;
  if (quality === "stale" || quality === "rejected") score -= 0.12;
  if (Number.isFinite(record.confidence)) score += ((record.confidence ?? 0) - 0.5) * 0.14;
  return roundScore(Math.max(0, Math.min(1, score)));
}

function isSecurityKnowledgeContext(record: SecurityMemoryRecord): boolean {
  return record.kind === "access_context"
    || record.kind === "asset_context"
    || record.kind === "connector_context"
    || record.kind === "detection_context"
    || record.kind === "exception_context"
    || record.kind === "owner_context"
    || record.kind === "severity_context";
}

function conflictKeys(record: SecurityMemoryRecord): string[] {
  const keys = [record.scope, record.topic].map((value) => normalizeSearchText(value ?? "")).filter(Boolean);
  const artifacts = (record.sourceArtifacts ?? []).map((value) => `artifact:${normalizeSearchText(value)}`).filter((value) => value.length > "artifact:".length);
  return unique([...keys, ...artifacts]).slice(0, 6);
}

function conflictSignals(record: SecurityMemoryRecord): string[] {
  const text = normalizeSearchText([record.topic, record.summary, record.details ?? "", record.classification ?? "", ...record.tags].join(" "));
  const negativeText = /\b(not deployed|not live|not enabled|not linked|disabled|inactive|stopped|unhealthy|failed|failure|blocked|missing|stale|unverified|denied|unlinked|rolled back)\b/.test(text);
  const positiveText = text.replace(/\bnot (deployed|live|enabled|linked|verified|resolved|complete|completed|healthy)\b/g, "");
  const signals: string[] = [];
  if (/\b(enabled|active|running|healthy|resolved|complete|completed|deployed|rolled out|live|verified|passes|allowed|linked)\b/.test(positiveText)) {
    signals.push("positive_state");
  }
  if (negativeText) signals.push("negative_state");
  return signals;
}

function ageDaysAt(value: string, now: Date): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return 0;
  return Math.max(0, (now.getTime() - parsed) / 86_400_000);
}

function isExpiredAt(record: SecurityMemoryRecord, now: Date): boolean {
  if (!record.expiresAt) return false;
  const parsed = Date.parse(record.expiresAt);
  return Number.isFinite(parsed) && parsed <= now.getTime();
}
