import type { SecurityMemoryRecord, SecurityMemoryWriteInput } from "../memory-types.js";
import {
  clean,
  cleanArray,
  cleanEntity,
  futureIso,
  futureOrPastIso,
  stableId,
  unique,
} from "./normalization.js";
import { extractMemoryEntities } from "./scoring.js";

export interface SecurityMemoryRecordBuildResult {
  record: SecurityMemoryRecord;
  contentHash: string;
}

export function buildSecurityMemoryRecord(
  rawInput: SecurityMemoryWriteInput,
  input: { now: Date; extractEntities: boolean },
): SecurityMemoryRecordBuildResult {
  const tags = (rawInput.tags ?? []).map((tag) => clean(tag, 48)).filter(Boolean).slice(0, 12);
  const sourceText = [
    rawInput.topic,
    rawInput.summary,
    rawInput.details ?? "",
    ...tags,
  ].join(" ");
  const entities = unique([
    ...(rawInput.entities ?? []).map((entity) => cleanEntity(entity)),
    ...(input.extractEntities ? extractMemoryEntities(sourceText) : []),
  ].filter(Boolean)).slice(0, 20);
  const contentHash = stableId([
    rawInput.kind,
    clean(rawInput.topic, 160),
    clean(rawInput.summary, 900),
    rawInput.details ? clean(rawInput.details, 1500) : "",
  ]);
  const record: SecurityMemoryRecord = {
    id: stableId([rawInput.kind, rawInput.topic, rawInput.summary, rawInput.channelId ?? "", rawInput.sourceTs ?? ""]),
    kind: rawInput.kind,
    topic: clean(rawInput.topic, 160),
    summary: clean(rawInput.summary, 900),
    details: rawInput.details ? clean(rawInput.details, 1500) : undefined,
    tags,
    channelId: rawInput.channelId,
    sourceTs: rawInput.sourceTs,
    classification: rawInput.classification,
    confidence: rawInput.confidence,
    sourceKind: rawInput.sourceKind,
    entities,
    contentHash,
    expiresAt: futureIso(rawInput.expiresAt),
    scope: rawInput.scope ? clean(rawInput.scope, 160) : undefined,
    verifiedBy: cleanArray(rawInput.verifiedBy, 48, 12),
    verifiedAt: futureOrPastIso(rawInput.verifiedAt),
    sourceArtifacts: cleanArray(rawInput.sourceArtifacts, 180, 16),
    stalenessPolicy: rawInput.stalenessPolicy,
    promotionState: rawInput.promotionState,
    createdAt: input.now.toISOString(),
  };
  return { record, contentHash };
}
