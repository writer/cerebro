import { z } from "zod";
import { evaluateAssistantReplayTurn, type AssistantReplayQualityReceipt } from "./assistant-replay-eval.js";
import type { SecurityAssistantAnswer } from "../agent/security-assistant-types.js";
import { citationQualityMetrics } from "../agent/evidence.js";

const laneSchema = z.enum(["ignore", "converse", "continue", "lookup", "investigate", "act"]);
const toolCapabilitySchema = z.enum(["slack_search", "slack_identity", "runtime_health", "graph_investigation", "source_claims"]);
const answerSchema = z.object({
  answer: z.string(),
  messages: z.array(z.string()).default([]),
  reaction: z.string().optional(),
  keyPoints: z.array(z.string()).default([]),
  evidence: z.array(z.string()).default([]),
  actionsTaken: z.array(z.string()).default([]),
  nextActions: z.array(z.string()).default([]),
  research: z.array(z.string()).default([]),
  memoryUpdates: z.array(z.unknown()).default([]),
  source: z.enum(["pi", "flue", "blocked"]),
  executionLane: laneSchema.optional(),
  presentationReady: z.boolean().optional(),
  delivery: z.enum(["respond", "suppress"]).optional(),
  dispositionReason: z.string().optional(),
}).passthrough();

const observationSchema = z.object({
  answer: answerSchema,
  toolCount: z.number().int().min(0),
  toolNames: z.array(z.string()).default([]),
  claimCoverage: z.number().min(0).max(1).optional(),
  threadStateUsed: z.boolean().optional(),
  userCorrected: z.boolean().optional(),
  correctionApplied: z.boolean().optional(),
  correctionSourceVerified: z.boolean().optional(),
  feedbackContext: z.object({
    available: z.boolean(),
    evaluated: z.boolean().optional(),
    applied: z.boolean().optional(),
    disclosed: z.boolean().optional(),
    followedUntrustedInstruction: z.boolean().optional(),
  }).optional(),
  artifactCount: z.number().int().min(0).default(0),
  completionReceiptStatus: z.enum(["complete", "partial", "blocked"]).optional(),
  deliveryReceipt: z.object({
    plannedMessages: z.number().int().min(0),
    postedMessages: z.number().int().min(0),
    complete: z.boolean(),
  }).optional(),
  citationOverheadMs: z.number().min(0).max(60_000).optional(),
});

const expectationSchema = z.object({
  executionLanes: z.array(laneSchema).min(1).optional(),
  requiredToolsAnyOf: z.array(z.string()).min(1).optional(),
  requiredToolCapabilitiesAnyOf: z.array(toolCapabilitySchema).min(1).optional(),
  requiredEvidenceRefs: z.array(z.string()).optional(),
  requiredAnswerFacts: z.array(z.string().min(1)).optional(),
  forbiddenAnswerFacts: z.array(z.string().min(1)).optional(),
  outcome: z.enum(["respond", "suppress", "action_complete", "bounded_blocker"]).optional(),
  correctionRequired: z.boolean().optional(),
  teammate: z.object({
    captureObjective: z.boolean().optional(),
    resolveScope: z.boolean().optional(),
    ownFollowUp: z.boolean().optional(),
    makeRecommendation: z.boolean().optional(),
    avoidUserDecision: z.boolean().optional(),
  }).optional(),
});

const trafficReplayCaseSchema = z.object({
  id: z.string().min(1).max(200),
  senderKind: z.enum(["human", "bot"]).default("human"),
  question: z.string().min(1).max(12_000),
  expected: expectationSchema.default({}),
  candidate: observationSchema,
  baseline: observationSchema.optional(),
});

export type TrafficReplayCase = z.infer<typeof trafficReplayCaseSchema>;
export type TrafficReplayObservation = z.infer<typeof observationSchema>;

export interface TrafficReplayReceipt {
  id: string;
  passed: boolean;
  score: number;
  baseQuality: AssistantReplayQualityReceipt;
  laneFit: number;
  toolFit: number;
  evidenceFit: number;
  outcomeFit: number;
  teammateFit: number;
  semanticFit: number;
  citationPrecision: number;
  citationAccess: number;
  currentStateVerification: number;
  counterfactualSafety: number;
  citationOverheadMs?: number;
  blockers: string[];
}

export interface TrafficReplayThresholds {
  minimumCases: number;
  minimumPassRate: number;
  minimumAverageScore: number;
  minimumCorrectionClosureRate: number;
  maximumRegressionRate: number;
  maximumCitationP95OverheadMs: number;
}

export interface TrafficReplayReport {
  releaseReady: boolean;
  caseCount: number;
  ignoredMachineCaseCount: number;
  passed: number;
  passRate: number;
  averageScore: number;
  correctionCaseCount: number;
  correctionClosureRate: number;
  regressionRate?: number;
  citationP95OverheadMs?: number;
  blockers: string[];
  blockerCounts: Record<string, number>;
  receipts: TrafficReplayReceipt[];
}

const DEFAULT_THRESHOLDS: TrafficReplayThresholds = {
  minimumCases: 25,
  minimumPassRate: 0.85,
  minimumAverageScore: 0.82,
  minimumCorrectionClosureRate: 0.9,
  maximumRegressionRate: 0.01,
  maximumCitationP95OverheadMs: 150,
};

export function parseTrafficReplayCase(value: unknown): TrafficReplayCase {
  return trafficReplayCaseSchema.parse(value);
}

export function evaluateTrafficReplayCase(input: TrafficReplayCase, observation = input.candidate): TrafficReplayReceipt {
  const answer = observation.answer as SecurityAssistantAnswer;
  const baseQuality = evaluateAssistantReplayTurn({
    question: input.question,
    answer,
    toolCount: observation.toolCount,
    claimCoverage: observation.claimCoverage,
    threadStateUsed: observation.threadStateUsed,
    userCorrected: observation.userCorrected ?? input.expected.correctionRequired,
    correctionApplied: observation.correctionApplied,
    correctionSourceVerified: observation.correctionSourceVerified,
    feedbackContext: observation.feedbackContext,
    deliveryReceipt: observation.deliveryReceipt,
  });
  const laneFit = !input.expected.executionLanes?.length || (answer.executionLane && input.expected.executionLanes.includes(answer.executionLane)) ? 1 : 0;
  const exactToolFit = !input.expected.requiredToolsAnyOf?.length
    || input.expected.requiredToolsAnyOf.some((tool) => observation.toolNames.includes(tool));
  const capabilityToolFit = !input.expected.requiredToolCapabilitiesAnyOf?.length
    || input.expected.requiredToolCapabilitiesAnyOf.some((capability) => observation.toolNames.some((tool) => toolHasCapability(tool, capability)));
  const toolFit = exactToolFit && capabilityToolFit ? 1 : 0;
  const evidenceText = answer.evidence.join(" ");
  const evidenceFit = !input.expected.requiredEvidenceRefs?.length
    || input.expected.requiredEvidenceRefs.every((ref) => evidenceText.includes(ref)) ? 1 : 0;
  const outcomeFit = expectedOutcomeMatches(input.expected.outcome, observation) ? 1 : 0;
  const teammateFit = expectedTeammateMatches(input.expected.teammate, answer) ? 1 : 0;
  const semanticFit = expectedAnswerFactsMatch(input.expected, answer) ? 1 : 0;
  const counterfactualSafety = evaluateEvidenceCounterfactualSafety(answer);
  const blockers = [
    ...baseQuality.blockers,
    laneFit === 0 ? "unexpected_execution_lane" : "",
    toolFit === 0 ? "required_tool_not_used" : "",
    evidenceFit === 0 ? "required_evidence_missing" : "",
    outcomeFit === 0 ? "expected_outcome_missing" : "",
    teammateFit === 0 ? "teammate_expectation_missing" : "",
    semanticFit === 0 ? "answer_fact_mismatch" : "",
    counterfactualSafety < 1 ? "evidence_counterfactual_not_detected" : "",
  ].filter(Boolean);
  const fitWeight = 0.0733;
  const score = round((baseQuality.score * 0.56)
    + (laneFit * fitWeight)
    + (toolFit * fitWeight)
    + (evidenceFit * fitWeight)
    + (outcomeFit * fitWeight)
    + (teammateFit * fitWeight)
    + (semanticFit * fitWeight));
  return {
    id: input.id,
    passed: blockers.length === 0 && score >= 0.8,
    score,
    baseQuality,
    laneFit,
    toolFit,
    evidenceFit,
    outcomeFit,
    teammateFit,
    semanticFit,
    citationPrecision: baseQuality.citationPrecision,
    citationAccess: baseQuality.citationAccess,
    currentStateVerification: baseQuality.currentStateVerification,
    counterfactualSafety,
    citationOverheadMs: observation.citationOverheadMs,
    blockers,
  };
}

export function buildTrafficReplayReport(
  cases: TrafficReplayCase[],
  thresholds: Partial<TrafficReplayThresholds> = {},
): TrafficReplayReport {
  const gate = { ...DEFAULT_THRESHOLDS, ...thresholds };
  const humanCases = cases.filter((item) => item.senderKind === "human");
  const receipts = humanCases.map((item) => evaluateTrafficReplayCase(item));
  const baselineReceipts = humanCases.map((item) => item.baseline ? evaluateTrafficReplayCase(item, item.baseline) : undefined);
  const correctionReceipts = receipts.filter((_receipt, index) => humanCases[index]?.expected.correctionRequired || humanCases[index]?.candidate.userCorrected);
  const comparable = receipts.flatMap((receipt, index) => baselineReceipts[index]
    ? [{ candidate: receipt.score, baseline: baselineReceipts[index]!.score }]
    : []);
  const regressionRate = comparable.length > 0
    ? comparable.filter((item) => item.candidate + 0.02 < item.baseline).length / comparable.length
    : undefined;
  const passed = receipts.filter((receipt) => receipt.passed).length;
  const passRate = ratio(passed, receipts.length);
  const averageScore = ratio(receipts.reduce((sum, receipt) => sum + receipt.score, 0), receipts.length);
  const correctionClosureRate = correctionReceipts.length > 0
    ? ratio(correctionReceipts.filter((receipt) => receipt.baseQuality.correctionLearning === 1).length, correctionReceipts.length)
    : 1;
  const citationP95OverheadMs = percentile(receipts.flatMap((receipt) => receipt.citationOverheadMs ?? []), 0.95);
  const blockers = [
    humanCases.length < gate.minimumCases ? `needs_${gate.minimumCases}_traffic_cases` : "",
    passRate < gate.minimumPassRate ? "traffic_pass_rate_below_gate" : "",
    averageScore < gate.minimumAverageScore ? "traffic_average_score_below_gate" : "",
    correctionReceipts.length > 0 && correctionClosureRate < gate.minimumCorrectionClosureRate ? "correction_closure_below_gate" : "",
    regressionRate !== undefined && regressionRate > gate.maximumRegressionRate ? "candidate_regression_above_gate" : "",
    receipts.some((receipt) => receipt.blockers.includes("unsupported_absolute_negative")) ? "unsupported_absolute_negative_present" : "",
    citationP95OverheadMs !== undefined && citationP95OverheadMs > gate.maximumCitationP95OverheadMs ? "citation_p95_overhead_above_gate" : "",
  ].filter(Boolean);
  return {
    releaseReady: blockers.length === 0,
    caseCount: humanCases.length,
    ignoredMachineCaseCount: cases.length - humanCases.length,
    passed,
    passRate: round(passRate),
    averageScore: round(averageScore),
    correctionCaseCount: correctionReceipts.length,
    correctionClosureRate: round(correctionClosureRate),
    regressionRate: regressionRate === undefined ? undefined : round(regressionRate),
    citationP95OverheadMs,
    blockers,
    blockerCounts: receipts.flatMap((receipt) => receipt.blockers).reduce<Record<string, number>>((counts, blocker) => {
      counts[blocker] = (counts[blocker] ?? 0) + 1;
      return counts;
    }, {}),
    receipts,
  };
}

export function evaluateEvidenceCounterfactualSafety(answer: SecurityAssistantAnswer): number {
  const packets = answer.claimEvidence ?? [];
  if (packets.length === 0) return 1;
  const first = packets[0];
  if (!first) return 1;
  const missing = cloneAnswer(answer);
  if (missing.claimEvidence?.[0]) missing.claimEvidence[0].evidence = [];
  const restricted = cloneAnswer(answer);
  if (restricted.claimEvidence?.[0]?.evidence[0]) restricted.claimEvidence[0].evidence[0].access = "restricted";
  const scenarios = [
    citationQualityMetrics(missing).blockers.includes("citation_claim_not_visible"),
    citationQualityMetrics(restricted).blockers.includes("citation_source_not_accessible"),
  ];
  const currentIndex = packets.findIndex((packet) => packet.temporalScope === "current");
  if (currentIndex >= 0) {
    const stale = cloneAnswer(answer);
    if (stale.claimEvidence?.[currentIndex]) stale.claimEvidence[currentIndex].verification = "historical_only";
    scenarios.push(citationQualityMetrics(stale).blockers.includes("current_claim_not_live_verified"));
  }
  const contradicted = cloneAnswer(answer);
  if (contradicted.claimEvidence?.[0]) contradicted.claimEvidence[0].verification = "contradicted";
  const contradictionMetrics = citationQualityMetrics(contradicted);
  scenarios.push(contradictionMetrics.blockers.includes("evidence_conflict_not_disclosed") || contradictionMetrics.conflictDisclosure === 1);
  return scenarios.every(Boolean) ? 1 : 0;
}

function expectedOutcomeMatches(outcome: TrafficReplayCase["expected"]["outcome"], observation: TrafficReplayObservation): boolean {
  if (!outcome) return true;
  if (outcome === "respond") return observation.answer.delivery !== "suppress" && observation.answer.messages.length > 0;
  if (outcome === "suppress") return observation.answer.delivery === "suppress";
  if (outcome === "action_complete") return observation.completionReceiptStatus === "complete" && observation.artifactCount > 0;
  const text = [observation.answer.answer, ...observation.answer.messages].join(" ").toLowerCase();
  return observation.answer.source === "blocked" || /\b(blocked|unavailable|missing|partial|could not)\b/.test(text);
}

function expectedTeammateMatches(
  expectation: TrafficReplayCase["expected"]["teammate"],
  answer: SecurityAssistantAnswer,
): boolean {
  if (!expectation) return true;
  const teammate = answer.teammate;
  if (expectation.captureObjective && !teammate?.objective) return false;
  if (expectation.resolveScope && !teammate?.resolvedScope.length) return false;
  if (expectation.ownFollowUp) {
    const ownedCommitment = teammate?.commitments.some((item) => item.status === "completed" || Boolean(item.nextAction || item.blocker));
    const ownedLoop = teammate?.openLoops.some((item) => item.owner !== "user" && Boolean(item.nextAction || item.blockedBy));
    if (!ownedCommitment && !ownedLoop && answer.actionsTaken.length === 0) return false;
  }
  if (expectation.makeRecommendation) {
    const visible = [answer.answer, ...answer.messages].join(" ");
    const explicitJudgment = /\b(?:recommend(?:ation|ed)?|best move|useful move|useful signal|should|my read|the right move|sensible next step|I would|do first|start with|priority is|focus on|look for|dominant|most common|most often|ranks? first|ranked)\b/i.test(visible);
    const executablePlan = answer.nextActions.some((action) => /\b(?:check|compare|confirm|create|deploy|disable|enable|fix|land|merge|move|open|query|remove|replace|resolve|review|rotate|run|ship|verify)\b/i.test(action));
    const conditionalAction = /\bif\b[^.!?]{0,180},\s*(?:check|compare|confirm|create|disable|enable|fix|open|query|remove|replace|resolve|review|rotate|run|verify)\b/i.test(visible);
    if (!explicitJudgment && !executablePlan && !conditionalAction) return false;
  }
  if (expectation.avoidUserDecision && teammate?.userDecision?.required) return false;
  return true;
}

function expectedAnswerFactsMatch(
  expectation: TrafficReplayCase["expected"],
  answer: SecurityAssistantAnswer,
): boolean {
  const visible = normalizeFactText([answer.answer, ...answer.messages].join(" "));
  const required = expectation.requiredAnswerFacts ?? [];
  const forbidden = expectation.forbiddenAnswerFacts ?? [];
  return required.every((fact) => visible.includes(normalizeFactText(fact)))
    && forbidden.every((fact) => !visible.includes(normalizeFactText(fact)));
}

function normalizeFactText(value: string): string {
  return value.toLowerCase().replace(/\s+/g, " ").trim();
}

function toolHasCapability(tool: string, capability: z.infer<typeof toolCapabilitySchema>): boolean {
  const toolsByCapability: Record<z.infer<typeof toolCapabilitySchema>, ReadonlySet<string>> = {
    slack_search: new Set(["slack_ai_search_context", "slack_message_search", "slack_cerebro_recent_questions"]),
    slack_identity: new Set(["slack_ai_search_context", "slack_message_search", "slack_user_context"]),
    runtime_health: new Set(["cerebro_runtime_health", "cerebro_source_runtimes", "operator_source_run_status"]),
    graph_investigation: new Set(["cerebro_graph_reason", "cerebro_graph_cypher_investigate", "cerebro_entity_neighborhood"]),
    source_claims: new Set(["cerebro_source_claims", "cerebro_runtime_claims"]),
  };
  return toolsByCapability[capability].has(tool);
}

function ratio(numerator: number, denominator: number): number {
  return denominator > 0 ? numerator / denominator : 0;
}

function round(value: number): number {
  return Math.round(Math.max(0, Math.min(1, value)) * 1000) / 1000;
}

function percentile(values: number[], quantile: number): number | undefined {
  if (values.length === 0) return undefined;
  const ordered = [...values].sort((left, right) => left - right);
  return Math.round(ordered[Math.min(ordered.length - 1, Math.ceil(ordered.length * quantile) - 1)] ?? 0);
}

function cloneAnswer(answer: SecurityAssistantAnswer): SecurityAssistantAnswer {
  return JSON.parse(JSON.stringify(answer)) as SecurityAssistantAnswer;
}
