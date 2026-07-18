import type { CuratedMemoryWriteDecision } from "../security-memory-curator.js";
import type {
  SecurityMemoryKind,
  SecurityMemoryRecord,
  SecurityMemoryWriteInput,
} from "../memory-types.js";
import {
  cleanArray,
  cleanEntity,
  isMemorySourceKind,
  isPromotionState,
  isStalenessPolicy,
  unique,
} from "./normalization.js";

export function toMemoryRecord(item: Record<string, unknown>): SecurityMemoryRecord | undefined {
  if (typeof item.id !== "string" || typeof item.kind !== "string" || typeof item.topic !== "string" || typeof item.summary !== "string" || typeof item.createdAt !== "string") {
    return undefined;
  }
  return {
    id: item.id,
    kind: item.kind as SecurityMemoryKind,
    topic: item.topic,
    summary: item.summary,
    details: typeof item.details === "string" ? item.details : undefined,
    tags: Array.isArray(item.tags) ? item.tags.map(String) : [],
    channelId: typeof item.channelId === "string" ? item.channelId : undefined,
    sourceTs: typeof item.sourceTs === "string" ? item.sourceTs : undefined,
    classification: typeof item.classification === "string" ? item.classification : undefined,
    confidence: typeof item.confidence === "number" ? item.confidence : undefined,
    sourceKind: isMemorySourceKind(item.sourceKind) ? item.sourceKind : undefined,
    entities: Array.isArray(item.entities) ? unique(item.entities.map(String).map(cleanEntity).filter(Boolean)).slice(0, 20) : undefined,
    contentHash: typeof item.contentHash === "string" ? item.contentHash : undefined,
    expiresAt: typeof item.expiresAt === "string" ? item.expiresAt : undefined,
    scope: typeof item.scope === "string" ? item.scope : undefined,
    verifiedBy: Array.isArray(item.verifiedBy) ? cleanArray(item.verifiedBy.map(String), 48, 12) : undefined,
    verifiedAt: typeof item.verifiedAt === "string" ? item.verifiedAt : undefined,
    sourceArtifacts: Array.isArray(item.sourceArtifacts) ? cleanArray(item.sourceArtifacts.map(String), 180, 16) : undefined,
    stalenessPolicy: isStalenessPolicy(item.stalenessPolicy) ? item.stalenessPolicy : undefined,
    promotionState: isPromotionState(item.promotionState) ? item.promotionState : undefined,
    createdAt: item.createdAt,
  };
}

export function curatedDecisionToWriteInput(original: SecurityMemoryWriteInput, decision: CuratedMemoryWriteDecision): SecurityMemoryWriteInput {
  if (!decision.kind || !decision.topic || !decision.summary || !decision.promotionState || !decision.stalenessPolicy) {
    throw new Error("Pi memory curator returned an incomplete store decision.");
  }
  const curated: SecurityMemoryWriteInput = {
    kind: decision.kind,
    topic: decision.topic,
    summary: decision.summary,
    details: decision.details,
    tags: decision.tags,
    channelId: original.channelId,
    sourceTs: original.sourceTs,
    classification: decision.classification,
    confidence: decision.confidence,
    sourceKind: decision.sourceKind ?? original.sourceKind,
    entities: decision.entities,
    expiresAt: decision.expiresAt,
    scope: decision.scope,
    verifiedBy: decision.verifiedBy,
    verifiedAt: decision.verifiedAt,
    sourceArtifacts: decision.sourceArtifacts,
    stalenessPolicy: decision.stalenessPolicy,
    promotionState: decision.promotionState,
  };
  if (original.sourceKind !== "slack_channel") return curated;
  return {
    ...curated,
    details: undefined,
    sourceKind: "slack_channel",
    sourceArtifacts: original.sourceArtifacts,
    verifiedBy: undefined,
    verifiedAt: undefined,
    stalenessPolicy: "until_reverified",
    promotionState: "candidate",
    confidence: Math.min(curated.confidence ?? 0.75, 0.85),
  };
}
