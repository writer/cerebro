import type {
  MemoryQueryIntent,
  SecurityMemoryRecallDiagnostics,
  SecurityMemoryRecord,
} from "../memory-types.js";
import { emptyLineageDag, emptyMemoryGraph } from "./graph.js";
import { cleanEntity, normalizeSearchText, unique } from "./normalization.js";

export interface MemoryScoreDetail {
  score: number;
  matchedTerms: string[];
  matchedEntities: string[];
  phraseMatch: boolean;
  rejectedReason?: string;
}

export function termsFor(query: string): string[] {
  const normalized = normalizeSearchText(query);
  return Array.from(new Set(normalized.match(/[a-z0-9_.@:-]{2,}/g) ?? []))
    .filter((term) => !TERM_STOP_WORDS.has(term))
    .map((term, index) => ({ term, index, priority: termPriority(term) }))
    .sort((left, right) => right.priority - left.priority || left.index - right.index)
    .slice(0, 18)
    .map((item) => item.term);
}

export function scoreRecord(record: SecurityMemoryRecord, terms: string[], query: string, queryEntities: string[] = []): number {
  return scoreRecordDetail(record, terms, query, queryEntities).score;
}

export function scoreRecordDetail(record: SecurityMemoryRecord, terms: string[], query: string, queryEntities: string[] = []): MemoryScoreDetail {
  const topic = normalizeSearchText(record.topic);
  const summary = normalizeSearchText(record.summary);
  const details = normalizeSearchText(record.details ?? "");
  const tags = normalizeSearchText(record.tags.join(" "));
  const classification = normalizeSearchText(record.classification ?? "");
  const entities = record.entities ?? extractMemoryEntities([record.topic, record.summary, record.details ?? "", ...record.tags].join(" "));
  const entitySet = new Set(entities);
  const normalizedHaystack = [record.kind, topic, summary, details, tags, classification, entities.join(" ")].join(" ");
  const normalizedQuery = normalizeSearchText(query);
  const phraseMatch = Boolean(normalizedQuery && normalizedHaystack.includes(normalizedQuery));
  let score = phraseMatch ? 4 : 0;
  let termMatches = 0;
  let specificTermMatches = 0;
  let entityMatches = 0;
  const matchedTerms: string[] = [];
  const matchedEntities: string[] = [];
  for (const term of terms) {
    let termScore = 0;
    if (topic.includes(term)) termScore = 1.6;
    else if (summary.includes(term)) termScore = 1.2;
    else if (details.includes(term)) termScore = 0.8;
    else if (tags.includes(term) || classification.includes(term)) termScore = 0.7;
    else if (normalizedHaystack.includes(term)) termScore = 0.4;
    if (termScore > 0) {
      termMatches += 1;
      if (isSpecificMemoryTerm(term)) specificTermMatches += 1;
      matchedTerms.push(term);
      score += termScore;
    }
  }
  for (const entity of queryEntities) {
    if (!isSpecificMemoryEntity(entity)) continue;
    if (entitySet.has(entity)) {
      entityMatches += 1;
      matchedEntities.push(entity);
      score += 2.5;
    } else if (normalizedHaystack.includes(entity)) {
      entityMatches += 1;
      matchedEntities.push(entity);
      score += 1;
    }
  }
  if (terms.length > 0 && !phraseMatch) {
    if (termMatches + entityMatches === 0) return { score: 0, matchedTerms, matchedEntities, phraseMatch, rejectedReason: "no_query_overlap" };
    if (termMatches + entityMatches < minimumTermMatches(terms)) return { score: 0, matchedTerms, matchedEntities, phraseMatch, rejectedReason: "too_few_matches" };
    const specificTerms = terms.filter(isSpecificMemoryTerm);
    if (specificTermMatches + entityMatches < minimumSpecificTermMatches(specificTerms.length)) return { score: 0, matchedTerms, matchedEntities, phraseMatch, rejectedReason: "too_few_specific_matches" };
  }
  if (isTeamContext(record)) score += 2.5;
  else if (isSecurityKnowledgeContext(record)) score += 1.6;
  else if (record.kind === "normal_pattern") score += 0.7;
  if (record.classification === "user_provided_context") score += 1.5;
  if (record.sourceKind === "slack_remember") score += 1.5;
  if (record.kind === "explicit_memory") score += 1.2;
  if (record.kind === "triage_outcome") score -= 0.4;
  if (record.kind === "encounter_story") score -= 0.7;
  if (record.kind === "skill_improvement") score -= isSkillQuery(terms) ? 0 : 0.4;
  if (record.kind === "assistant_answer" || record.sourceKind === "assistant_answer") score -= 3.5;
  if (isLikelyNoise(record)) score -= 3;
  if (Number.isFinite(record.confidence)) score += Math.max(0, Math.min(record.confidence ?? 0, 1));
  return {
    score: Math.max(0, score),
    matchedTerms: unique(matchedTerms).slice(0, 8),
    matchedEntities: unique(matchedEntities).slice(0, 8),
    phraseMatch,
  };
}

export function recencyBoost(createdAt: string): number {
  const created = Date.parse(createdAt);
  if (Number.isNaN(created)) return 0;
  const ageDays = Math.max(0, (Date.now() - created) / 86_400_000);
  return Math.max(0, 1 - Math.min(ageDays, 30) / 30);
}

export function extractMemoryEntities(value: string): string[] {
  const entities = new Set<string>();
  const original = value.replace(/\s+/g, " ");
  for (const match of original.matchAll(/@?[\p{L}0-9][\p{L}0-9_.-]{1,48}/gu)) {
    const raw = match[0];
    const normalized = cleanEntity(raw);
    if (normalized && isEntityLike(raw, normalized)) entities.add(normalized);
  }
  for (const match of original.matchAll(/\b[A-Z][\p{L}0-9_.-]*(?:\s+[A-Z][\p{L}0-9_.-]*){0,3}\b/gu)) {
    const normalized = cleanEntity(match[0]);
    if (normalized && !GENERIC_ENTITY_WORDS.has(normalized)) entities.add(normalized);
  }
  return [...entities].slice(0, 20);
}

export function matchReason(detail: MemoryScoreDetail, queryIntent: MemoryQueryIntent, record: SecurityMemoryRecord): string {
  if (detail.rejectedReason) return detail.rejectedReason;
  const parts = [
    `intent=${queryIntent}`,
    detail.phraseMatch ? "phrase_match" : "",
    detail.matchedTerms.length > 0 ? `terms=${detail.matchedTerms.join(",")}` : "",
    detail.matchedEntities.length > 0 ? `entities=${detail.matchedEntities.join(",")}` : "",
    record.promotionState ? `promotion=${record.promotionState}` : "",
    record.stalenessPolicy ? `staleness=${record.stalenessPolicy}` : "",
  ].filter(Boolean);
  return parts.join("; ");
}

export function emptyRecallDiagnostics(queryIntent: MemoryQueryIntent): SecurityMemoryRecallDiagnostics {
  return {
    queryIntent,
    queryEntities: [],
    candidateCount: 0,
    matchedCount: 0,
    returnedCount: 0,
    suppressedByZeroScoreCount: 0,
    suppressedByIntentCount: 0,
    returnedKinds: {},
    averageAgeDays: 0,
    coverage: {
      queryEntities: [],
      matchedEntities: [],
      missingEntities: [],
      coverageRatio: 1,
    },
    quality: {
      averageTrustScore: 0,
      sourceVerifiedCount: 0,
      sourceBackedCount: 0,
      promotedCount: 0,
      candidateCount: 0,
      transientCount: 0,
      staleCount: 0,
      unverifiedCount: 0,
    },
    conflicts: [],
    warnings: queryIntent === "memory disabled" ? ["Memory is disabled."] : [],
    memoryGraph: emptyMemoryGraph(),
    lineageDag: emptyLineageDag(),
    results: [],
  };
}

function termPriority(term: string): number {
  let priority = 0;
  if (/[0-9]/.test(term) && term.length >= 4) priority += 6;
  if (/[_.@:-]/.test(term)) priority += 4;
  if (term.length >= 8) priority += 3;
  else if (term.length >= 5) priority += 1;
  if (isSpecificMemoryTerm(term)) priority += 3;
  return priority;
}

function minimumTermMatches(terms: string[]): number {
  if (terms.length >= 8) return 3;
  if (terms.length >= 4) return 2;
  return 1;
}

function minimumSpecificTermMatches(specificTermCount: number): number {
  if (specificTermCount >= 8) return 3;
  if (specificTermCount >= 4) return 2;
  if (specificTermCount >= 1) return 1;
  return 0;
}

function isSpecificMemoryTerm(term: string): boolean {
  return !GENERIC_MEMORY_TERMS.has(term);
}

function isSpecificMemoryEntity(entity: string): boolean {
  return entity.length >= 4 && !GENERIC_MEMORY_TERMS.has(entity);
}

function isSkillQuery(terms: string[]): boolean {
  return terms.some((term) => term === "skill" || term === "skills" || term === "procedural" || term === "procedure" || term === "improvement");
}

function isEntityLike(raw: string, normalized: string): boolean {
  if (GENERIC_ENTITY_WORDS.has(normalized)) return false;
  if (raw.startsWith("@")) return true;
  if (/^[A-Z][A-Z0-9_]{2,}$/.test(raw)) return true;
  if (/^[a-z]+[._-][a-z0-9_.-]+$/i.test(raw)) return true;
  if (/[0-9]/.test(raw) && raw.length >= 4) return true;
  if (/^[A-Z][\p{L}'’-]{1,}$/u.test(raw)) return true;
  return /^[A-Z][A-Za-z0-9]{1,3}$/.test(raw);
}

function isTeamContext(record: SecurityMemoryRecord): boolean {
  const tags = record.tags.map(normalizeSearchText);
  return record.kind === "team_context" || tags.includes("team context") || tags.includes("slack remember") || record.sourceKind === "slack_remember";
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

function isLikelyNoise(record: SecurityMemoryRecord): boolean {
  const tags = record.tags.map(normalizeSearchText);
  const classification = normalizeSearchText(record.classification ?? "");
  const text = normalizeSearchText([record.topic, record.summary].join(" "));
  return tags.includes("likely noise") || classification === "likely noise" || text.includes("no security relevant action is needed");
}

const GENERIC_ENTITY_WORDS = new Set([
  "actions",
  "about",
  "assistant",
  "answer",
  "asked",
  "blocking",
  "cerebro",
  "checked",
  "context",
  "did",
  "does",
  "evidence",
  "finding",
  "findings",
  "from",
  "github",
  "graph",
  "great",
  "identity",
  "ingest",
  "login",
  "memory",
  "note",
  "notes",
  "okta",
  "pr",
  "question",
  "remember",
  "research",
  "security",
  "slack",
  "team",
  "that",
  "the",
  "user",
  "what",
  "you",
]);

const TERM_STOP_WORDS = new Set([
  "a",
  "about",
  "after",
  "all",
  "an",
  "and",
  "are",
  "as",
  "at",
  "be",
  "been",
  "but",
  "by",
  "can",
  "do",
  "for",
  "from",
  "had",
  "has",
  "have",
  "how",
  "if",
  "in",
  "into",
  "is",
  "it",
  "its",
  "me",
  "my",
  "no",
  "not",
  "of",
  "on",
  "one",
  "or",
  "our",
  "out",
  "per",
  "so",
  "that",
  "the",
  "then",
  "this",
  "to",
  "under",
  "us",
  "use",
  "via",
  "was",
  "we",
  "were",
  "what",
  "when",
  "while",
  "with",
  "you",
]);

const GENERIC_MEMORY_TERMS = new Set([
  "actions",
  "alert",
  "alerts",
  "answer",
  "asked",
  "cerebro",
  "checked",
  "context",
  "deploy",
  "deployment",
  "evidence",
  "finding",
  "findings",
  "github",
  "graph",
  "health",
  "image",
  "ingest",
  "issue",
  "memory",
  "message",
  "messages",
  "note",
  "notes",
  "question",
  "pr",
  "reply",
  "research",
  "runtime",
  "security",
  "service",
  "services",
  "slack",
  "source",
  "status",
  "summary",
  "task",
  "tasks",
  "tenant",
  "triage",
  "user",
  "version",
  "writer",
]);
