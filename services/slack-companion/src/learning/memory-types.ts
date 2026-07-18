export type SecurityMemoryKind =
  | "access_context"
  | "asset_context"
  | "connector_context"
  | "detection_context"
  | "exception_context"
  | "normal_pattern"
  | "owner_context"
  | "severity_context"
  | "team_context"
  | "explicit_memory"
  | "triage_outcome"
  | "assistant_answer"
  | "encounter_story"
  | "skill_improvement"
  | "investigation_note"
  | "runbook_note"
  | "operator_fact"
  | "operator_claim"
  | "operator_decision"
  | "operator_correction"
  | "operator_risk"
  | "operator_blocker"
  | "operator_handoff"
  | "source_health_note";

export type SecurityMemorySourceKind =
  | "slack_remember"
  | "slack_channel"
  | "assistant_answer"
  | "alert_triage"
  | "daily_notes"
  | "manual"
  | "tool";

export type SecurityMemoryPromotionState = "transient" | "candidate" | "promoted" | "rejected";
export type SecurityMemoryStalenessPolicy = "ephemeral" | "short_lived" | "until_reverified" | "durable";
export type MemoryQueryIntent = string;
export type SecurityMemoryFreshness = "current" | "recent" | "aging" | "stale" | "expired";
export type SecurityMemoryQuality =
  | "source_verified"
  | "source_backed"
  | "promoted"
  | "candidate"
  | "transient"
  | "unverified"
  | "stale"
  | "rejected";

export interface SecurityMemoryRecord {
  id: string;
  kind: SecurityMemoryKind;
  topic: string;
  summary: string;
  details?: string;
  tags: string[];
  channelId?: string;
  sourceTs?: string;
  classification?: string;
  confidence?: number;
  sourceKind?: SecurityMemorySourceKind;
  entities?: string[];
  contentHash?: string;
  expiresAt?: string;
  scope?: string;
  verifiedBy?: string[];
  verifiedAt?: string;
  sourceArtifacts?: string[];
  stalenessPolicy?: SecurityMemoryStalenessPolicy;
  promotionState?: SecurityMemoryPromotionState;
  createdAt: string;
}

export interface SecurityMemoryWriteInput {
  kind: SecurityMemoryKind;
  topic: string;
  summary: string;
  details?: string;
  tags?: string[];
  channelId?: string;
  sourceTs?: string;
  classification?: string;
  confidence?: number;
  sourceKind?: SecurityMemorySourceKind;
  entities?: string[];
  expiresAt?: string;
  scope?: string;
  verifiedBy?: string[];
  verifiedAt?: string;
  sourceArtifacts?: string[];
  stalenessPolicy?: SecurityMemoryStalenessPolicy;
  promotionState?: SecurityMemoryPromotionState;
}

export interface SecurityMemoryRecallInput {
  query?: string;
  kinds?: SecurityMemoryKind[];
  channelId?: string;
  audienceChannelId?: string;
  since?: string;
  limit?: number;
}

export interface SecurityMemoryRecallMatch {
  id: string;
  kind: SecurityMemoryKind;
  topic: string;
  score: number;
  baseScore: number;
  trustScore: number;
  ageDays: number;
  quality: SecurityMemoryQuality;
  freshness: SecurityMemoryFreshness;
  scope?: string;
  sourceKind?: SecurityMemorySourceKind;
  verifiedBy?: string[];
  verifiedAt?: string;
  sourceArtifacts?: string[];
  promotionState?: SecurityMemoryPromotionState;
  stalenessPolicy?: SecurityMemoryStalenessPolicy;
  matchReason: string;
  matchedTerms: string[];
  matchedEntities: string[];
}

export interface SecurityMemoryRecallCoverage {
  queryEntities: string[];
  matchedEntities: string[];
  missingEntities: string[];
  coverageRatio: number;
}

export interface SecurityMemoryRecallQualitySummary {
  averageTrustScore: number;
  sourceVerifiedCount: number;
  sourceBackedCount: number;
  promotedCount: number;
  candidateCount: number;
  transientCount: number;
  staleCount: number;
  unverifiedCount: number;
}

export interface SecurityMemoryRecallConflict {
  topic: string;
  scope?: string;
  recordIds: string[];
  summaries: string[];
  reason: string;
  signals: string[];
}

export type SecurityMemoryGraphNodeKind =
  | "query"
  | "memory"
  | "entity"
  | "scope"
  | "source_artifact"
  | "verifier"
  | "warning"
  | "conflict";

export type SecurityMemoryGraphEdgeKind =
  | "matches"
  | "mentions"
  | "scoped_to"
  | "supported_by"
  | "verified_by"
  | "warns"
  | "conflicts_with";

export interface SecurityMemoryGraphNode {
  id: string;
  kind: SecurityMemoryGraphNodeKind;
  label: string;
  recordId?: string;
  weight?: number;
}

export interface SecurityMemoryGraphEdge {
  from: string;
  to: string;
  kind: SecurityMemoryGraphEdgeKind;
  weight?: number;
  reason?: string;
}

export interface SecurityMemoryGraphProjection {
  rootId: string;
  nodes: SecurityMemoryGraphNode[];
  edges: SecurityMemoryGraphEdge[];
  focusMemoryIds: string[];
  entityCount: number;
  sourceArtifactCount: number;
  conflictCount: number;
}

export type SecurityMemoryDagNodeKind =
  | "query"
  | "source_artifact"
  | "verifier"
  | "memory"
  | "conflict"
  | "warning"
  | "answer_constraint";

export interface SecurityMemoryDagNode {
  id: string;
  kind: SecurityMemoryDagNodeKind;
  label: string;
  recordId?: string;
  weight?: number;
}

export interface SecurityMemoryDagEdge {
  from: string;
  to: string;
  relation: string;
  reason?: string;
}

export interface SecurityMemoryLineageDag {
  rootId: string;
  nodes: SecurityMemoryDagNode[];
  edges: SecurityMemoryDagEdge[];
  topologicalOrder: string[];
}

export interface SecurityMemoryRecallDiagnostics {
  queryIntent: MemoryQueryIntent;
  queryEntities: string[];
  candidateCount: number;
  matchedCount: number;
  returnedCount: number;
  suppressedByZeroScoreCount: number;
  suppressedByIntentCount: number;
  returnedKinds: Record<string, number>;
  averageAgeDays: number;
  coverage: SecurityMemoryRecallCoverage;
  quality: SecurityMemoryRecallQualitySummary;
  conflicts: SecurityMemoryRecallConflict[];
  warnings: string[];
  memoryGraph: SecurityMemoryGraphProjection;
  lineageDag: SecurityMemoryLineageDag;
  results: SecurityMemoryRecallMatch[];
}

export interface SecurityMemoryRecallResult {
  memories: SecurityMemoryRecord[];
  diagnostics: SecurityMemoryRecallDiagnostics;
}
