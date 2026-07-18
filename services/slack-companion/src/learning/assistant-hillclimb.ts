import { createHash } from "node:crypto";
import { z } from "zod";
import { SPECIALIST_ROLES, type SpecialistRole } from "../agent/specialist-team.js";

const partitionSchema = z.enum(["train", "validation", "held_out"]);
const outcomeSchema = z.enum(["respond", "ignore"]);
const evidencePacketSchema = z.object({
  source: z.string().min(1).max(160),
  receipt: z.string().min(1).max(240),
  status: z.enum(["completed", "failed", "partial"]),
  facts: z.array(z.string().min(1).max(2_000)).min(1).max(16),
  subjects: z.array(z.string().min(1).max(500)).max(24).default([]),
});
const expectationSchema = z.object({
  outcome: outcomeSchema.default("respond"),
  requiredFactGroups: z.array(z.array(z.string().min(1).max(240)).min(1).max(8)).default([]),
  forbiddenFacts: z.array(z.string().min(1).max(240)).default([]),
  requiredReceipts: z.array(z.string().min(1).max(240)).default([]),
  requiredActionGroups: z.array(z.array(z.string().min(1).max(240)).min(1).max(8)).default([]),
  requireCoverageBoundary: z.boolean().default(false),
  requireUncertaintyDisclosure: z.boolean().default(false),
  requireRecommendation: z.boolean().default(false),
  forbidClarifyingQuestion: z.boolean().default(false),
  requiredSubjectBindings: z.array(z.object({ claim: z.string().min(1).max(1_000), subject: z.string().min(1).max(500) })).max(24).default([]),
  maxLatencyMs: z.number().int().positive().optional(),
  maxHumanFollowUps: z.number().int().nonnegative().optional(),
});

export const assistantHardCorpusCaseSchema = z.object({
  schemaVersion: z.literal(1),
  id: z.string().min(1).max(160),
  partition: partitionSchema,
  challenge: z.string().min(1).max(160),
  difficulty: z.number().int().min(1).max(5),
  senderKind: z.enum(["human", "bot"]).default("human"),
  question: z.string().min(1).max(4_000),
  threadContext: z.array(z.string().min(1).max(4_000)).max(16).default([]),
  evidence: z.array(evidencePacketSchema).max(24).default([]),
  assignedRoles: z.array(z.enum(SPECIALIST_ROLES)).max(SPECIALIST_ROLES.length).default([]),
  expectations: expectationSchema,
});

const specialistObservationSchema = z.object({
  role: z.enum(SPECIALIST_ROLES),
  status: z.preprocess((value) => value === "completed" ? "completed" : "blocked", z.enum(["completed", "blocked"])),
  findings: z.array(z.string()).default([]),
  recommendations: z.array(z.string()).default([]),
  actions: z.array(z.string()).default([]),
  checks: z.array(z.string()).default([]),
  blockers: z.array(z.string()).default([]),
  evidence_receipts: z.array(z.string()).default([]),
});
export const assistantHillClimbObservationSchema = z.object({
  answer: z.string().min(1).max(24_000),
  disposition: outcomeSchema.default("respond"),
  cited_receipts: z.array(z.string()).default([]),
  next_actions: z.array(z.string()).default([]),
  specialist_work: z.array(specialistObservationSchema).default([]),
  subject_bindings: z.array(z.object({ claim: z.string(), subject: z.string() })).optional(),
  latency_ms: z.number().int().nonnegative().optional(),
  human_follow_ups: z.number().int().nonnegative().optional(),
});

export type AssistantHardCorpusCase = z.infer<typeof assistantHardCorpusCaseSchema>;
export type AssistantHillClimbObservation = z.infer<typeof assistantHillClimbObservationSchema>;

export interface AssistantPolicyCandidate {
  id: string;
  parentId?: string;
  mutation: string;
  instructions: string[];
  ensembleReviewerCount?: number;
  distributedWorkerCount?: number;
}

export const ASSISTANT_POLICY_CANDIDATES: readonly AssistantPolicyCandidate[] = [
  {
    id: "baseline-exact-private-contracts",
    mutation: "Production policy before traffic-derived optimization.",
    instructions: [
      "Return exactly one private work receipt for every assigned specialist role.",
      "Treat the specialist receipt contract as a strict completion gate.",
      "Write the answer from the evidence packet and thread context.",
    ],
  },
  {
    id: "resilient-grounded-work-v2",
    parentId: "baseline-exact-private-contracts",
    mutation: "Preserve the answer when private work is incomplete and make receipt use exact.",
    instructions: [
      "Use only the specialist roles explicitly assigned in the case.",
      "A missing private specialist result is an internal coverage gap, not a reason to discard a grounded answer or expose an internal error.",
      "In cited_receipts, copy only exact host-issued receipt ids. A partial receipt supports only facts and subjects actually returned; never use it for the missing slice or cite a failed-without-receipt or invented id.",
      "When a failed or partial source limits the conclusion, name that source and the coverage gap in the visible answer.",
      "Never claim a requested action happened unless a completed evidence fact says it happened.",
    ],
  },
  {
    id: "subject-bound-decisions-v2",
    parentId: "resilient-grounded-work-v2",
    mutation: "Bind every conclusion to the exact subject, source state, and observation time.",
    instructions: [
      "Use only the specialist roles explicitly assigned in the case.",
      "A missing private work receipt is an internal coverage gap, not a user-visible failure.",
      "Never discard verified work, expose an internal contract error, or ask the user to retry solely because private orchestration is incomplete.",
      "In cited_receipts, copy only exact host-issued receipt ids. A partial receipt supports only facts and subjects actually returned; never use it for the missing slice or cite a failed-without-receipt or invented id.",
      "Resolve corrections, terse follow-ups, and pronouns from the supplied thread before asking a question.",
      "Bind each count, status, timestamp, owner, and action state to its exact resource, environment, period, or person.",
      "Prefer current live evidence over older memory and say when the older source is stale.",
    ],
  },
  {
    id: "evidence-first-teammate-v2",
    parentId: "subject-bound-decisions-v2",
    mutation: "Resolve terse follow-ups from thread state and make the smallest useful recommendation or action explicit.",
    instructions: [
      "Use only the specialist roles explicitly assigned in the case.",
      "A missing private work receipt is an internal coverage gap, not a user-visible failure.",
      "Resolve terse follow-ups, pronouns, and corrections from the supplied thread before asking for scope.",
      "Bind each status, count, timestamp, and failure to its exact source and subject.",
      "In cited_receipts, copy only exact host-issued receipt ids. A partial receipt supports only facts and subjects actually returned; never use it for the missing slice or cite a failed-without-receipt or invented id.",
      "Lead with the result. State the smallest useful supported recommendation or the action state. If the action did not happen, say so and name the concrete recovery step.",
      "Keep every zero, clean, safe, complete, ready, or false-positive conclusion bounded to checked sources, time, and missing coverage.",
      "Never expose internal orchestration, schema, prompt, contract, model, or retry language in the answer.",
    ],
  },
  {
    id: "source-bound-coverage-v3",
    parentId: "subject-bound-decisions-v2",
    mutation: "Make source coverage and mutable subject bindings explicit without adding user burden.",
    instructions: [
      "Use only the specialist roles explicitly assigned in the case.",
      "Preserve a useful grounded answer when private work is incomplete; never expose private orchestration or ask for a retry because a private receipt is missing.",
      "Copy only exact host-issued receipt ids. A partial receipt supports only facts and subjects actually returned; never use it for the missing slice or cite a failed-without-receipt or invented id.",
      "For every status, count, timestamp, owner, URL, and action state, emit a separate subject_binding using the exact subject id supplied by its evidence packet.",
      "State the checked source, population, environment, and observation window for every clean, zero, healthy, current, safe, complete, or priority conclusion.",
      "Resolve corrections and terse follow-ups from the supplied thread. Lead with the corrected result and include the direct record URL when evidence supplies one.",
      "Say what action actually completed, what failed, and what remains open. Never turn a failed write into a completed action.",
      "When a secret value is requested, refuse the value and give the exact approved metadata or access workflow supported by evidence.",
    ],
  },
  {
    id: "complete-evidence-teammate-v4",
    parentId: "source-bound-coverage-v3",
    mutation: "Account for every relevant source result before answering and preserve useful work through partial failures.",
    instructions: [
      "Use only the specialist roles explicitly assigned in the case, and never expose private roles, orchestration, contracts, schemas, models, or internal retries.",
      "Before writing the answer, inventory every evidence packet relevant to the request. Include the material facts from every completed packet and name every failed or partial packet as a concrete coverage boundary.",
      "Never discard completed findings because another source failed. Lead with the supported result, then state what the failed source prevents you from concluding.",
      "Copy only exact host-issued receipt ids. A partial receipt supports only facts and subjects actually returned; never use it for the missing slice or cite a failed-without-receipt or invented id.",
      "Emit a separate subject_binding for every status, severity, count, timestamp, owner, URL, and action state, using the exact narrowest subject id supplied by that evidence packet.",
      "For current-risk questions, include the source observation or sync time when provided. A clean, zero, healthy, current, safe, complete, or priority conclusion must name its checked population and missing coverage.",
      "Resolve corrections and terse follow-ups from the supplied thread. Do not ask for scope already present in the thread or evidence.",
      "Report actions by their real state: completed, failed, or still open. Recommend the smallest next action supported by the evidence.",
      "When a secret value is requested, refuse the value and give the exact approved metadata or access workflow supported by evidence.",
    ],
  },
] as const;

export interface AssistantHardCaseReceipt {
  caseId: string;
  candidateId: string;
  partition: AssistantHardCorpusCase["partition"];
  passed: boolean;
  score: number;
  correctness: number;
  grounding: number;
  coverage: number;
  resilience: number;
  usefulness: number;
  specialistCoverage: number;
  sourceSubjectBinding?: number;
  latencyBudget?: number;
  humanBurden?: number;
  blockers: string[];
}
export interface AssistantCandidateScore {
  candidateId: string;
  partition: AssistantHardCorpusCase["partition"];
  caseCount: number;
  passed: number;
  passRate: number;
  averageScore: number;
  hardBlockerCount: number;
  blockerCounts: Record<string, number>;
}
export interface AssistantHillClimbSelection {
  winnerId: string;
  accepted: string[];
  rejected: Array<{ candidateId: string; reason: string }>;
}

export function parseAssistantHardCorpusLine(value: unknown): AssistantHardCorpusCase {
  return assistantHardCorpusCaseSchema.parse(value);
}
export function parseAssistantHillClimbObservation(value: unknown): AssistantHillClimbObservation {
  return assistantHillClimbObservationSchema.parse(value);
}
export function hardCorpusDigest(cases: AssistantHardCorpusCase[]): string {
  return createHash("sha256").update(cases.map((item) => JSON.stringify(item)).sort().join("\n")).digest("hex");
}

export function assistantHillClimbObservationKey(input: {
  model: string;
  thinking: string;
  candidate: AssistantPolicyCandidate;
  item: AssistantHardCorpusCase;
  protocolPrompt: string;
}): string {
  return createHash("sha256").update(JSON.stringify(input)).digest("hex");
}

export function scoreAssistantHardCase(item: AssistantHardCorpusCase, candidateId: string, observation: AssistantHillClimbObservation): AssistantHardCaseReceipt {
  const visible = normalize([observation.answer, ...observation.next_actions].join(" "));
  const factsFound = item.expectations.requiredFactGroups.filter((group) => includesAny(visible, group)).length;
  const actionsFound = item.expectations.requiredActionGroups.filter((group) => includesAny(visible, group)).length;
  const forbiddenFound = item.expectations.forbiddenFacts.filter((fact) => visible.includes(normalize(fact)));
  const availableReceipts = new Set(item.evidence.filter((packet) => packet.status === "completed").map((packet) => packet.receipt));
  const cited = new Set(observation.cited_receipts);
  const missingReceipts = item.expectations.requiredReceipts.filter((receipt) => !cited.has(receipt));
  const inventedReceipts = observation.cited_receipts.filter((receipt) => !availableReceipts.has(receipt));
  const internalLeak = /\b(?:specialist work contract|claim ledger not closed|internal contract|schema validation|model request failed|llm error|flue assistant|private work receipt is missing|prompt instructions?)\b/i.test(observation.answer);
  const outcomeMismatch = observation.disposition !== item.expectations.outcome;
  const uncertaintyDisclosureMissing = item.expectations.requireUncertaintyDisclosure
    && !/\bi(?:'m| am) not sure\b/i.test(observation.answer);
  const unboundedCoverage = item.expectations.requireCoverageBoundary && !/\b(?:checked|queried|within|coverage|source|returned|available|unavailable|partial|partly|fully|confirmed|current|live|only|caveat|scope|result|failed|stale|as of|since|through|window|evidence|per|could not verify|can't confirm|cannot confirm)\b/.test(visible);
  const unnecessaryQuestion = item.expectations.forbidClarifyingQuestion && (/\b(?:which|what)\s+(?:repository|repo|ticket|project|owner|runtime|source|scope)\b[^?]*\?/i.test(observation.answer) || /\b(?:provide|share|send)\b[^?]{0,100}\b(?:scope|details|context|identifier)\b[^?]*\?/i.test(observation.answer));
  const missingRecommendation = item.expectations.requireRecommendation && actionsFound === 0 && !/\b(?:recommend|should|best move|priority|do first|next step|next|need to|needs to|I would|start with|fix|verify|merge|rotate|disable|enable|compare|check|retry|collect|obtain|review|update|monitor)\b/.test(visible);
  const correctness = ratio(factsFound, item.expectations.requiredFactGroups.length);
  const grounding = item.expectations.requiredReceipts.length === 0 ? inventedReceipts.length === 0 ? 1 : 0 : ratio(item.expectations.requiredReceipts.length - missingReceipts.length, item.expectations.requiredReceipts.length);
  const coverage = unboundedCoverage ? 0 : 1;
  const resilience = internalLeak || outcomeMismatch || uncertaintyDisclosureMissing ? 0 : 1;
  const usefulness = unnecessaryQuestion || missingRecommendation ? 0 : ratio(actionsFound, item.expectations.requiredActionGroups.length);
  const specialistCoverage = specialistReceiptCoverage(item.assignedRoles, observation.specialist_work, availableReceipts);
  const subjectBindings = (observation.subject_bindings ?? []).map((binding) => ({ claim: normalize(binding.claim), subject: normalize(binding.subject) }));
  const matchedSubjectBindings = item.expectations.requiredSubjectBindings.filter((expected) => subjectBindings.some((observed) => (
    subjectBindingMatches(expected, observed, visible)
  ))).length;
  const sourceSubjectBinding = ratio(matchedSubjectBindings, item.expectations.requiredSubjectBindings.length);
  const latencyBudget = item.expectations.maxLatencyMs === undefined || observation.latency_ms === undefined
    ? 1
    : observation.latency_ms <= item.expectations.maxLatencyMs ? 1 : 0;
  const humanBurden = item.expectations.maxHumanFollowUps === undefined || observation.human_follow_ups === undefined
    ? 1
    : observation.human_follow_ups <= item.expectations.maxHumanFollowUps ? 1 : 0;
  const blockers = [
    outcomeMismatch ? "outcome_mismatch" : "",
    factsFound < item.expectations.requiredFactGroups.length ? "required_fact_missing" : "",
    forbiddenFound.length > 0 ? "forbidden_fact_present" : "",
    missingReceipts.length > 0 ? "required_receipt_missing" : "",
    inventedReceipts.length > 0 ? "invented_receipt" : "",
    internalLeak ? "internal_failure_leaked" : "",
    uncertaintyDisclosureMissing ? "uncertainty_disclosure_missing" : "",
    unboundedCoverage ? "coverage_boundary_missing" : "",
    unnecessaryQuestion ? "unnecessary_clarification" : "",
    missingRecommendation ? "recommendation_missing" : "",
    actionsFound < item.expectations.requiredActionGroups.length ? "required_action_missing" : "",
    sourceSubjectBinding < 1 ? "source_subject_mismatch" : "",
    latencyBudget === 0 ? "latency_budget_exceeded" : "",
    humanBurden === 0 ? "human_burden_exceeded" : "",
  ].filter(Boolean);
  const baseScore = correctness * 0.30 + grounding * 0.22 + coverage * 0.12 + resilience * 0.16 + usefulness * 0.12 + specialistCoverage * 0.08;
  const operationalMetrics = [
    item.expectations.requiredSubjectBindings.length > 0 ? sourceSubjectBinding : undefined,
    item.expectations.maxLatencyMs !== undefined ? latencyBudget : undefined,
    item.expectations.maxHumanFollowUps !== undefined ? humanBurden : undefined,
  ].filter((value): value is number => value !== undefined);
  const operationalScore = operationalMetrics.length > 0 ? operationalMetrics.reduce((sum, value) => sum + value, 0) / operationalMetrics.length : 1;
  const score = round(operationalMetrics.length > 0 ? (baseScore * 0.84) + (operationalScore * 0.16) : baseScore);
  return { caseId: item.id, candidateId, partition: item.partition, passed: blockers.length === 0 && score >= 0.82, score, correctness, grounding, coverage, resilience, usefulness, specialistCoverage, sourceSubjectBinding, latencyBudget, humanBurden, blockers };
}

export function summarizeAssistantCandidate(candidateId: string, partition: AssistantHardCorpusCase["partition"], receipts: AssistantHardCaseReceipt[]): AssistantCandidateScore {
  const selected = receipts.filter((receipt) => receipt.candidateId === candidateId && receipt.partition === partition);
  const blockerCounts = selected.flatMap((receipt) => receipt.blockers).reduce<Record<string, number>>((counts, blocker) => {
    counts[blocker] = (counts[blocker] ?? 0) + 1;
    return counts;
  }, {});
  return { candidateId, partition, caseCount: selected.length, passed: selected.filter((receipt) => receipt.passed).length, passRate: round(ratio(selected.filter((receipt) => receipt.passed).length, selected.length)), averageScore: round(ratio(selected.reduce((sum, receipt) => sum + receipt.score, 0), selected.length)), hardBlockerCount: selected.reduce((sum, receipt) => sum + receipt.blockers.length, 0), blockerCounts };
}

export function selectAssistantHillClimbWinner(candidates: readonly AssistantPolicyCandidate[], scores: AssistantCandidateScore[]): AssistantHillClimbSelection {
  const byKey = new Map(scores.map((score) => [`${score.candidateId}:${score.partition}`, score]));
  const baseline = candidates[0];
  if (!baseline) throw new Error("At least one assistant policy candidate is required.");
  const baselineTrain = byKey.get(`${baseline.id}:train`);
  const baselineValidation = byKey.get(`${baseline.id}:validation`);
  if (!baselineTrain || !baselineValidation) throw new Error("Baseline train and validation scores are required.");
  const accepted = [baseline.id];
  const rejected: AssistantHillClimbSelection["rejected"] = [];
  for (const candidate of candidates.slice(1)) {
    const candidateTrain = byKey.get(`${candidate.id}:train`);
    const candidateValidation = byKey.get(`${candidate.id}:validation`);
    if (!candidateTrain || !candidateValidation) { rejected.push({ candidateId: candidate.id, reason: "partition_score_missing" }); continue; }
    const trainImproved = candidateTrain.passRate >= baselineTrain.passRate
      && candidateTrain.averageScore >= baselineTrain.averageScore - 0.02;
    const validationSafe = candidateValidation.passRate >= baselineValidation.passRate
      && candidateValidation.averageScore >= baselineValidation.averageScore - 0.02;
    const baselineBlockers = baselineTrain.hardBlockerCount + baselineValidation.hardBlockerCount;
    const candidateBlockers = candidateTrain.hardBlockerCount + candidateValidation.hardBlockerCount;
    const developmentImproved = candidateBlockers < baselineBlockers
      || candidateTrain.passRate + candidateValidation.passRate > baselineTrain.passRate + baselineValidation.passRate
      || candidateTrain.averageScore + candidateValidation.averageScore > baselineTrain.averageScore + baselineValidation.averageScore;
    const criticalBlockersSafe = ["invented_receipt", "internal_failure_leaked", "source_subject_mismatch"].every((blocker) => (
      blockerCount(candidateTrain, candidateValidation, blocker) <= blockerCount(baselineTrain, baselineValidation, blocker)
    ));
    if (!trainImproved) { rejected.push({ candidateId: candidate.id, reason: "train_did_not_improve" }); continue; }
    if (!validationSafe) { rejected.push({ candidateId: candidate.id, reason: "validation_regressed" }); continue; }
    if (!developmentImproved) { rejected.push({ candidateId: candidate.id, reason: "development_did_not_improve" }); continue; }
    if (!criticalBlockersSafe) { rejected.push({ candidateId: candidate.id, reason: "critical_blocker_regressed" }); continue; }
    accepted.push(candidate.id);
  }
  const winnerId = accepted
    .map((candidateId) => ({ candidateId, train: byKey.get(`${candidateId}:train`)!, validation: byKey.get(`${candidateId}:validation`)! }))
    .sort(compareDevelopmentCandidate)[0]!.candidateId;
  return { winnerId, accepted, rejected };
}

function blockerCount(train: AssistantCandidateScore, validation: AssistantCandidateScore, blocker: string): number {
  return (train.blockerCounts[blocker] ?? 0) + (validation.blockerCounts[blocker] ?? 0);
}

function compareDevelopmentCandidate(
  left: { candidateId: string; train: AssistantCandidateScore; validation: AssistantCandidateScore },
  right: { candidateId: string; train: AssistantCandidateScore; validation: AssistantCandidateScore },
): number {
  const leftBlockers = left.train.hardBlockerCount + left.validation.hardBlockerCount;
  const rightBlockers = right.train.hardBlockerCount + right.validation.hardBlockerCount;
  if (leftBlockers !== rightBlockers) return leftBlockers - rightBlockers;
  const leftPassRate = left.train.passRate + left.validation.passRate;
  const rightPassRate = right.train.passRate + right.validation.passRate;
  if (leftPassRate !== rightPassRate) return rightPassRate - leftPassRate;
  const leftScore = left.train.averageScore + left.validation.averageScore;
  const rightScore = right.train.averageScore + right.validation.averageScore;
  if (leftScore !== rightScore) return rightScore - leftScore;
  return left.candidateId.localeCompare(right.candidateId);
}

function subjectBindingMatches(
  expected: { claim: string; subject: string },
  observed: { claim: string; subject: string },
  visible: string,
): boolean {
  if (observed.subject !== normalize(expected.subject)) return false;
  const expectedClaim = normalize(expected.claim);
  if (observed.claim.includes(expectedClaim) || expectedClaim.includes(observed.claim)) return true;
  const tokens = claimTokens(expectedClaim);
  if (tokens.length === 0) return false;
  if (tokens.length === 1) return observed.claim.includes(tokens[0] as string) || visible.includes(tokens[0] as string);
  const observedTokens = new Set(claimTokens(observed.claim));
  const overlap = tokens.filter((token) => observedTokens.has(token)).length;
  return overlap / tokens.length >= 0.5;
}

function claimTokens(value: string): string[] {
  const stop = new Set(["a", "an", "and", "as", "at", "by", "for", "in", "is", "of", "on", "the", "to", "was", "with"]);
  return [...new Set(value.split(/[^a-z0-9]+/).filter((token) => token.length > 0 && !stop.has(token)))];
}

export function heldOutPromotionReady(input: { baseline: AssistantCandidateScore; winner: AssistantCandidateScore }): boolean {
  return input.baseline.partition === "held_out" && input.winner.partition === "held_out" && input.winner.caseCount >= 8 && input.winner.averageScore > input.baseline.averageScore && input.winner.passRate >= input.baseline.passRate && input.winner.hardBlockerCount < input.baseline.hardBlockerCount && input.winner.blockerCounts.internal_failure_leaked === undefined && input.winner.blockerCounts.invented_receipt === undefined && input.winner.blockerCounts.source_subject_mismatch === undefined && input.winner.blockerCounts.latency_budget_exceeded === undefined && input.winner.blockerCounts.human_burden_exceeded === undefined;
}

function specialistReceiptCoverage(roles: SpecialistRole[], work: AssistantHillClimbObservation["specialist_work"], availableReceipts: Set<string>): number {
  if (roles.length === 0) return 1;
  const byRole = new Map(work.map((receipt) => [receipt.role, receipt]));
  const evidenceRoles = new Set<SpecialistRole>(["researcher", "librarian", "compliance"]);
  const completed = roles.filter((role) => {
    const receipt = byRole.get(role);
    if (!receipt) return false;
    if (receipt.status === "blocked") return receipt.blockers.length > 0;
    if (evidenceRoles.has(role)) return receipt.findings.length + receipt.recommendations.length > 0 && receipt.evidence_receipts.some((value) => availableReceipts.has(value));
    if (role === "qa") return receipt.checks.length > 0;
    if (role === "developer") return receipt.checks.length > 0 && receipt.findings.length + receipt.actions.length > 0;
    if (role === "coordinator") return receipt.actions.length + receipt.recommendations.length > 0;
    return receipt.findings.length + receipt.recommendations.length > 0;
  }).length;
  return round(completed / roles.length);
}
function includesAny(visible: string, values: string[]): boolean { return values.some((value) => visible.includes(normalize(value))); }
function normalize(value: string): string { return value.toLowerCase().replace(/[`*_]/g, "").replace(/\s+/g, " ").trim(); }
function ratio(numerator: number, denominator: number): number { return denominator > 0 ? numerator / denominator : 1; }
function round(value: number): number { return Math.round(Math.max(0, Math.min(1, value)) * 1_000) / 1_000; }
