import { annotateMain, recordMetric } from "../../telemetry.js";
import type { CuratedMemoryRecallDecision } from "../security-memory-curator.js";
import type {
  SecurityMemoryRecallDiagnostics,
  SecurityMemoryRecallInput,
  SecurityMemoryRecallResult,
  SecurityMemoryRecord,
} from "../memory-types.js";
import { buildLineageDag, buildMemoryGraph } from "./graph.js";
import { ageDays, average, countBy, roundScore } from "./hygiene.js";
import {
  detectMemoryConflicts,
  memoryIntelligence,
  recallCoverage,
  recallWarnings,
  summarizeRecallQuality,
} from "./intelligence.js";
import { extractMemoryEntities, matchReason, recencyBoost, scoreRecordDetail, termsFor } from "./scoring.js";

export function lexicalRecall(input: {
  recall: SecurityMemoryRecallInput;
  candidates: SecurityMemoryRecord[];
  limit: number;
}): SecurityMemoryRecallResult {
  const terms = termsFor(input.recall.query ?? "");
  const entities = extractMemoryEntities(input.recall.query ?? "");
  const normalizedQuery = (input.recall.query ?? "").trim();
  const queryIntent = "uncurated lexical recall";
  const scoredCandidates = input.candidates
    .map((record) => {
      const detail = scoreRecordDetail(record, terms, normalizedQuery, entities);
      const intelligence = memoryIntelligence(record);
      const baseScore = detail.score;
      return {
        record,
        baseScore,
        score: baseScore + recencyBoost(record.createdAt) + intelligence.trustBoost,
        detail,
        intelligence,
      };
    })
    .filter((item) => terms.length === 0 || item.baseScore > 0)
    .sort((left, right) => right.score - left.score || right.record.createdAt.localeCompare(left.record.createdAt));
  const scored = scoredCandidates.slice(0, input.limit);
  const memories = scored.map((item) => item.record);
  const qualityInputs = scored.map((item) => ({
    record: item.record,
    trustScore: item.intelligence.trustScore,
    quality: item.intelligence.quality,
    freshness: item.intelligence.freshness,
    matchedEntities: item.detail.matchedEntities,
  }));
  const quality = summarizeRecallQuality(qualityInputs);
  const coverage = recallCoverage(entities, qualityInputs);
  const conflicts = detectMemoryConflicts(scoredCandidates.slice(0, Math.max(20, input.limit * 4)).map((item) => item.record));
  const warnings = recallWarnings({
    returnedCount: memories.length,
    coverage,
    quality,
    conflicts,
  });
  const graphMatches = scored.map((item) => ({
    record: item.record,
    score: item.score,
    trustScore: item.intelligence.trustScore,
    matchedEntities: item.detail.matchedEntities,
  }));
  const diagnostics: SecurityMemoryRecallDiagnostics = {
    queryIntent,
    queryEntities: entities,
    candidateCount: input.candidates.length,
    matchedCount: scoredCandidates.length,
    returnedCount: memories.length,
    suppressedByZeroScoreCount: input.candidates.length - scoredCandidates.length,
    suppressedByIntentCount: 0,
    returnedKinds: countBy(memories.map((record) => record.kind)),
    averageAgeDays: average(memories.map((record) => ageDays(record.createdAt))),
    coverage,
    quality,
    conflicts,
    warnings,
    memoryGraph: buildMemoryGraph({
      query: normalizedQuery,
      queryEntities: entities,
      matches: graphMatches,
      conflicts,
      warnings,
    }),
    lineageDag: buildLineageDag({
      query: normalizedQuery,
      matches: graphMatches,
      conflicts,
      warnings,
    }),
    results: scored.map((item) => ({
      id: item.record.id,
      kind: item.record.kind,
      topic: item.record.topic,
      score: roundScore(item.score),
      baseScore: roundScore(item.baseScore),
      trustScore: item.intelligence.trustScore,
      ageDays: roundScore(ageDays(item.record.createdAt)),
      quality: item.intelligence.quality,
      freshness: item.intelligence.freshness,
      scope: item.record.scope,
      sourceKind: item.record.sourceKind,
      verifiedBy: item.record.verifiedBy,
      verifiedAt: item.record.verifiedAt,
      sourceArtifacts: item.record.sourceArtifacts,
      promotionState: item.record.promotionState,
      stalenessPolicy: item.record.stalenessPolicy,
      matchReason: [
        matchReason(item.detail, queryIntent, item.record),
        `quality=${item.intelligence.quality}`,
        `freshness=${item.intelligence.freshness}`,
        `trust=${item.intelligence.trustScore}`,
      ].join("; "),
      matchedTerms: item.detail.matchedTerms,
      matchedEntities: item.detail.matchedEntities,
    })),
  };
  recordLexicalRecallTelemetry(diagnostics);
  return { memories, diagnostics };
}

export function curatedRecall(input: {
  recall: SecurityMemoryRecallInput;
  candidates: SecurityMemoryRecord[];
  limit: number;
  consideredCount: number;
  decision: CuratedMemoryRecallDecision;
}): SecurityMemoryRecallResult {
  const byId = new Map(input.candidates.map((record) => [record.id, record]));
  const selected = input.decision.selections
    .map((selection) => ({ selection, record: byId.get(selection.id) }))
    .filter((item): item is { selection: typeof item.selection; record: SecurityMemoryRecord } => Boolean(item.record))
    .slice(0, input.limit);
  const memories = selected.map((item) => item.record);
  const entities = extractMemoryEntities(input.recall.query ?? "");
  const selectedWithIntelligence = selected.map((item) => ({
    ...item,
    intelligence: memoryIntelligence(item.record),
    matchedEntities: (item.record.entities ?? []).filter((entity) => entities.includes(entity)),
  }));
  const qualityInputs = selectedWithIntelligence.map((item) => ({
    record: item.record,
    trustScore: item.intelligence.trustScore,
    quality: item.intelligence.quality,
    freshness: item.intelligence.freshness,
    matchedEntities: item.matchedEntities,
  }));
  const quality = summarizeRecallQuality(qualityInputs);
  const coverage = recallCoverage(entities, qualityInputs);
  const conflicts = detectMemoryConflicts(memories);
  const warnings = recallWarnings({
    returnedCount: memories.length,
    coverage,
    quality,
    conflicts,
  });
  const graphMatches = selectedWithIntelligence.map((item) => ({
    record: item.record,
    score: item.selection.relevance,
    trustScore: item.intelligence.trustScore,
    matchedEntities: item.matchedEntities,
  }));
  const diagnostics: SecurityMemoryRecallDiagnostics = {
    queryIntent: input.decision.queryIntent,
    queryEntities: entities,
    candidateCount: input.candidates.length,
    matchedCount: selected.length,
    returnedCount: memories.length,
    suppressedByZeroScoreCount: 0,
    suppressedByIntentCount: input.decision.rejected.length,
    returnedKinds: countBy(memories.map((record) => record.kind)),
    averageAgeDays: average(memories.map((record) => ageDays(record.createdAt))),
    coverage,
    quality,
    conflicts,
    warnings,
    memoryGraph: buildMemoryGraph({
      query: input.recall.query ?? "",
      queryEntities: entities,
      matches: graphMatches,
      conflicts,
      warnings,
    }),
    lineageDag: buildLineageDag({
      query: input.recall.query ?? "",
      matches: graphMatches,
      conflicts,
      warnings,
    }),
    results: selectedWithIntelligence.map((item) => ({
      id: item.record.id,
      kind: item.record.kind,
      topic: item.record.topic,
      score: roundScore(item.selection.relevance),
      baseScore: roundScore(item.selection.relevance),
      trustScore: item.intelligence.trustScore,
      ageDays: roundScore(ageDays(item.record.createdAt)),
      quality: item.intelligence.quality,
      freshness: item.intelligence.freshness,
      scope: item.record.scope,
      sourceKind: item.record.sourceKind,
      verifiedBy: item.record.verifiedBy,
      verifiedAt: item.record.verifiedAt,
      sourceArtifacts: item.record.sourceArtifacts,
      promotionState: item.record.promotionState,
      stalenessPolicy: item.record.stalenessPolicy,
      matchReason: `${item.selection.reason}; quality=${item.intelligence.quality}; freshness=${item.intelligence.freshness}; trust=${item.intelligence.trustScore}`,
      matchedTerms: [],
      matchedEntities: item.matchedEntities,
    })),
  };
  recordCuratedRecallTelemetry(diagnostics, input.consideredCount);
  return { memories, diagnostics };
}

function recordLexicalRecallTelemetry(diagnostics: SecurityMemoryRecallDiagnostics): void {
  annotateMain({
    "memory.recall.query_intent": diagnostics.queryIntent,
    "memory.recall.candidate_count": diagnostics.candidateCount,
    "memory.recall.matched_count": diagnostics.matchedCount,
    "memory.recall.returned_count": diagnostics.returnedCount,
    "memory.recall.suppressed_zero_score_count": diagnostics.suppressedByZeroScoreCount,
    "memory.recall.suppressed_intent_count": diagnostics.suppressedByIntentCount,
    "memory.recall.average_age_days": diagnostics.averageAgeDays,
    "memory.recall.average_trust_score": diagnostics.quality.averageTrustScore,
    "memory.recall.warning_count": diagnostics.warnings.length,
    "memory.recall.conflict_count": diagnostics.conflicts.length,
  });
  recordMetric("cerebro_slack_companion_memory_recall_total", { query_intent: diagnostics.queryIntent }, 1);
  recordMetric("cerebro_slack_companion_memory_recall_candidates_total", { query_intent: diagnostics.queryIntent }, diagnostics.candidateCount);
  recordMetric("cerebro_slack_companion_memory_recall_returned_total", { query_intent: diagnostics.queryIntent }, diagnostics.returnedCount);
}

function recordCuratedRecallTelemetry(diagnostics: SecurityMemoryRecallDiagnostics, consideredCount: number): void {
  annotateMain({
    "memory.curator.recall.query_intent": diagnostics.queryIntent,
    "memory.curator.recall.candidate_count": diagnostics.candidateCount,
    "memory.curator.recall.considered_count": consideredCount,
    "memory.curator.recall.returned_count": diagnostics.returnedCount,
    "memory.curator.recall.rejected_count": diagnostics.suppressedByIntentCount,
    "memory.curator.recall.average_trust_score": diagnostics.quality.averageTrustScore,
    "memory.curator.recall.warning_count": diagnostics.warnings.length,
    "memory.curator.recall.conflict_count": diagnostics.conflicts.length,
  });
  recordMetric("cerebro_slack_companion_memory_curator_recall_total", { query_intent: diagnostics.queryIntent }, 1);
  recordMetric("cerebro_slack_companion_memory_curator_recall_returned_total", { query_intent: diagnostics.queryIntent }, diagnostics.returnedCount);
}
