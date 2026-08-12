import type { AssistantExecutionLaneV1 } from "./contracts.js";
import { assistantTurnBudget } from "./policy.js";
import {
  ANSWER_FEEDBACK_CATEGORIES,
  type AnswerFeedbackCategoryV1,
} from "../feedback/policy.js";

export const ASSISTANT_TURN_OUTCOME_STATES = [
  "completed",
  "owned",
  "needs_user",
  "blocked",
  "unknown",
] as const;

export type AssistantTurnOutcomeStateV1 =
  (typeof ASSISTANT_TURN_OUTCOME_STATES)[number];

export const ASSISTANT_TURN_EVALUATION_BLOCKERS = [
  "unwanted_intervention",
  "missed_response",
  "incomplete_delivery",
  "required_action_missing",
  "claim_not_grounded",
  "claim_subject_misbound",
  "available_evidence_not_used",
  "coverage_boundary_missing",
  "source_failure_not_disclosed",
  "internal_machinery_exposed",
  "redundant_tool_call",
  "tool_budget_exceeded",
  "latency_budget_exceeded",
  "unnecessary_clarification",
  "user_correction",
  "negative_feedback",
  "missed_source_feedback",
  "wrong_owner_feedback",
  "followup_requested",
  "outcome_unknown",
] as const;

export type AssistantTurnEvaluationBlockerV1 =
  (typeof ASSISTANT_TURN_EVALUATION_BLOCKERS)[number];

export const ASSISTANT_TURN_EVALUATION_PARTITIONS = [
  "train",
  "validation",
  "held_out",
  "shadow",
] as const;

export type AssistantTurnEvaluationPartitionV1 =
  (typeof ASSISTANT_TURN_EVALUATION_PARTITIONS)[number];

export interface AssistantTurnDeliveryObservationV1 {
  complete: boolean;
  disposition: "respond" | "suppress";
  planned_part_count: number;
  posted_part_count: number;
}

/**
 * Bounded, text-free inputs for evaluating one delivered assistant turn.
 * An independent evaluator derives these fields from durable delivery, claim,
 * source, feedback, and outcome records. A candidate does not self-report them.
 */
export interface AssistantTurnEvaluationInputV1 {
  case_digest: string;
  case_ref: string;
  claim_count: number;
  coverage_boundary_disclosed: boolean;
  coverage_boundary_required: boolean;
  delivery: AssistantTurnDeliveryObservationV1;
  delivered_action_count: number;
  disclosed_source_failure_count: number;
  evaluator_ref: string;
  execution_lane: AssistantExecutionLaneV1;
  explicit_feedback?: "positive" | "negative";
  explicit_feedback_category?: AnswerFeedbackCategoryV1;
  grounded_claim_count: number;
  internal_machinery_exposure_count: number;
  latency_ms: number;
  observation_digest: string;
  observation_ref: string;
  outcome_state: AssistantTurnOutcomeStateV1;
  partition: AssistantTurnEvaluationPartitionV1;
  policy_ref: string;
  redundant_tool_call_count: number;
  relevant_evidence_source_count: number;
  required_action_count: number;
  requires_evidence: boolean;
  response_expected: boolean;
  selected_capability_count: number;
  source_failure_count: number;
  subject_bound_claim_count: number;
  tool_call_count: number;
  unnecessary_clarification_count: number;
  used_evidence_source_count: number;
  user_correction: boolean;
}

export interface AssistantTurnEvaluationDimensionsV1 {
  coverage_honesty: number;
  delivery_completeness: number;
  evidence_use: number;
  execution_efficiency: number;
  grounding: number;
  human_burden: number;
  intervention_fit: number;
  latency_budget: number;
  outcome_closure: number;
}

export interface AssistantTurnEvaluationV1 {
  blockers: AssistantTurnEvaluationBlockerV1[];
  case_digest: string;
  case_ref: string;
  dimensions: AssistantTurnEvaluationDimensionsV1;
  evaluator_ref: string;
  observation_digest: string;
  observation_ref: string;
  partition: AssistantTurnEvaluationPartitionV1;
  passed: boolean;
  policy_ref: string;
  schema_version: "assistant-turn-evaluation/v1";
  score: number;
}

export interface AssistantTurnPromotionDecisionV1 {
  baseline_average_score: number;
  baseline_blocker_count: number;
  baseline_pass_rate: number;
  baseline_policy_ref: string;
  blockers: string[];
  candidate_average_score: number;
  candidate_blocker_count: number;
  candidate_pass_rate: number;
  candidate_policy_ref: string;
  case_count: number;
  evaluator_ref: string;
  held_out_case_count: number;
  promotion_ready: boolean;
  regression_count: number;
  schema_version: "assistant-turn-promotion-decision/v1";
  score_gain: number;
  shadow_case_count: number;
}

const MINIMUM_HELD_OUT_CASES = 8;
const MINIMUM_SHADOW_CASES = 8;
const MINIMUM_SCORE_GAIN = 0.02;
const MAXIMUM_CASE_REGRESSION = 0.05;
const PASS_SCORE = 0.8;

export class AssistantTurnEvaluationInputError extends Error {}

export function evaluateAssistantTurn(
  input: AssistantTurnEvaluationInputV1,
): AssistantTurnEvaluationV1 {
  validateEvaluationInput(input);
  const budget = assistantTurnBudget(input.execution_lane);
  const shouldRespond = input.response_expected;
  const didRespond = input.delivery.disposition === "respond";
  const interventionFit = shouldRespond === didRespond ? 1 : 0;
  const physicalDelivery = deliveryScore(input.delivery, shouldRespond);
  const deliveryCompleteness = physicalDelivery
    * ratio(input.delivered_action_count, input.required_action_count);
  const grounding = Math.min(
    input.requires_evidence
      ? ratio(input.grounded_claim_count, input.claim_count)
      : 1,
    ratio(input.subject_bound_claim_count, input.claim_count),
  );
  const evidenceUse = input.requires_evidence
    ? ratio(input.used_evidence_source_count, input.relevant_evidence_source_count)
    : 1;
  const coverageHonesty = Math.min(
    input.source_failure_count === 0
      ? 1
      : ratio(input.disclosed_source_failure_count, input.source_failure_count),
    input.coverage_boundary_required && !input.coverage_boundary_disclosed ? 0 : 1,
  );
  const executionEfficiency = (input.redundant_tool_call_count === 0 ? 1 : 0)
    * boundedEfficiency(input.tool_call_count, budget.max_tool_calls)
    * boundedEfficiency(
      input.selected_capability_count,
      budget.max_selected_capabilities,
    );
  const executionWithinBudget = input.tool_call_count <= budget.max_tool_calls
    && input.selected_capability_count <= budget.max_selected_capabilities;
  const latencyBudget = input.latency_ms <= budget.latency_budget_ms ? 1 : 0;
  const humanBurden = input.unnecessary_clarification_count === 0
    && !input.user_correction
    && input.explicit_feedback !== "negative"
    && input.explicit_feedback_category !== "missed_source"
    && input.explicit_feedback_category !== "wrong_owner"
    && input.explicit_feedback_category !== "needs_followup"
    && input.internal_machinery_exposure_count === 0
    ? 1
    : 0;
  const outcomeClosure = outcomeScore(input.outcome_state);
  const blockers: AssistantTurnEvaluationBlockerV1[] = [
    !shouldRespond && didRespond ? "unwanted_intervention" : undefined,
    shouldRespond && !didRespond ? "missed_response" : undefined,
    physicalDelivery === 0 ? "incomplete_delivery" : undefined,
    input.delivered_action_count < input.required_action_count
      ? "required_action_missing"
      : undefined,
    input.requires_evidence && input.grounded_claim_count < input.claim_count
      ? "claim_not_grounded"
      : undefined,
    input.subject_bound_claim_count < input.claim_count
      ? "claim_subject_misbound"
      : undefined,
    evidenceUse < 1 ? "available_evidence_not_used" : undefined,
    input.coverage_boundary_required && !input.coverage_boundary_disclosed
      ? "coverage_boundary_missing"
      : undefined,
    input.disclosed_source_failure_count < input.source_failure_count
      ? "source_failure_not_disclosed"
      : undefined,
    input.internal_machinery_exposure_count > 0
      ? "internal_machinery_exposed"
      : undefined,
    input.redundant_tool_call_count > 0 ? "redundant_tool_call" : undefined,
    !executionWithinBudget ? "tool_budget_exceeded" : undefined,
    latencyBudget === 0 ? "latency_budget_exceeded" : undefined,
    input.unnecessary_clarification_count > 0
      ? "unnecessary_clarification"
      : undefined,
    input.user_correction ? "user_correction" : undefined,
    input.explicit_feedback === "negative" ? "negative_feedback" : undefined,
    input.explicit_feedback_category === "missed_source"
      ? "missed_source_feedback" : undefined,
    input.explicit_feedback_category === "wrong_owner"
      ? "wrong_owner_feedback" : undefined,
    input.explicit_feedback_category === "needs_followup"
      ? "followup_requested" : undefined,
    input.outcome_state === "unknown" ? "outcome_unknown" : undefined,
  ].filter((value): value is AssistantTurnEvaluationBlockerV1 => value !== undefined);
  const dimensions: AssistantTurnEvaluationDimensionsV1 = {
    coverage_honesty: round(coverageHonesty),
    delivery_completeness: round(deliveryCompleteness),
    evidence_use: round(evidenceUse),
    execution_efficiency: round(executionEfficiency),
    grounding: round(grounding),
    human_burden: round(humanBurden),
    intervention_fit: round(interventionFit),
    latency_budget: round(latencyBudget),
    outcome_closure: round(outcomeClosure),
  };
  const score = scoreDimensions(dimensions);
  return {
    blockers,
    case_digest: input.case_digest,
    case_ref: input.case_ref,
    dimensions,
    evaluator_ref: input.evaluator_ref,
    observation_digest: input.observation_digest,
    observation_ref: input.observation_ref,
    partition: input.partition,
    passed: blockers.length === 0 && score >= PASS_SCORE,
    policy_ref: input.policy_ref,
    schema_version: "assistant-turn-evaluation/v1",
    score,
  };
}

/**
 * Compare one candidate with its exact baseline on sealed static and
 * independently generated shadow cases. The candidate must improve score and
 * blockers without adding a per-case failure mode.
 */
export function decideAssistantTurnPromotion(
  baseline: readonly AssistantTurnEvaluationV1[],
  candidate: readonly AssistantTurnEvaluationV1[],
): AssistantTurnPromotionDecisionV1 {
  const baselineSet = evaluationSet(baseline, "baseline");
  const candidateSet = evaluationSet(candidate, "candidate");
  if (baselineSet.policyRef === candidateSet.policyRef) {
    throw new AssistantTurnEvaluationInputError(
      "Promotion requires distinct baseline and candidate policies.",
    );
  }
  if (baselineSet.evaluatorRef !== candidateSet.evaluatorRef) {
    throw new AssistantTurnEvaluationInputError(
      "Promotion requires one evaluator receipt across both policies.",
    );
  }
  if (baselineSet.rows.size !== candidateSet.rows.size) {
    throw new AssistantTurnEvaluationInputError(
      "Promotion requires the exact same static and shadow cases.",
    );
  }

  let regressionCount = 0;
  const blockers: string[] = [];
  for (const [caseRef, baselineRow] of baselineSet.rows) {
    const candidateRow = candidateSet.rows.get(caseRef);
    if (!candidateRow || candidateRow.case_digest !== baselineRow.case_digest) {
      throw new AssistantTurnEvaluationInputError(
        "Promotion requires matching static and shadow case identities and digests.",
      );
    }
    if (candidateRow.score + MAXIMUM_CASE_REGRESSION < baselineRow.score) {
      regressionCount += 1;
    }
    const baselineBlockers = new Set(baselineRow.blockers);
    const newBlockers = candidateRow.blockers.filter(
      (value) => !baselineBlockers.has(value),
    );
    for (const blocker of newBlockers) blockers.push(`new_${blocker}`);
  }

  const baselineAverage = average([...baselineSet.rows.values()].map((row) => row.score));
  const candidateAverage = average([...candidateSet.rows.values()].map((row) => row.score));
  const baselinePassRate = average(
    [...baselineSet.rows.values()].map((row) => row.passed ? 1 : 0),
  );
  const candidatePassRate = average(
    [...candidateSet.rows.values()].map((row) => row.passed ? 1 : 0),
  );
  const baselineBlockerCount = blockerCount(baselineSet.rows);
  const candidateBlockerCount = blockerCount(candidateSet.rows);
  const rawScoreGain = candidateAverage - baselineAverage;
  const scoreGain = round(rawScoreGain);

  if (rawScoreGain < MINIMUM_SCORE_GAIN) blockers.push("score_gain_below_gate");
  if (candidatePassRate < baselinePassRate) blockers.push("pass_rate_regressed");
  if (
    candidateBlockerCount > baselineBlockerCount
    || (baselineBlockerCount > 0 && candidateBlockerCount === baselineBlockerCount)
  ) {
    blockers.push("blocker_count_not_reduced");
  }
  if (regressionCount > 0) blockers.push("case_regression_present");
  const uniqueBlockers = [...new Set(blockers)].sort();

  return {
    baseline_average_score: round(baselineAverage),
    baseline_blocker_count: baselineBlockerCount,
    baseline_pass_rate: round(baselinePassRate),
    baseline_policy_ref: baselineSet.policyRef,
    blockers: uniqueBlockers,
    candidate_average_score: round(candidateAverage),
    candidate_blocker_count: candidateBlockerCount,
    candidate_pass_rate: round(candidatePassRate),
    candidate_policy_ref: candidateSet.policyRef,
    case_count: baselineSet.rows.size,
    evaluator_ref: baselineSet.evaluatorRef,
    held_out_case_count: baselineSet.heldOutCount,
    promotion_ready: uniqueBlockers.length === 0,
    regression_count: regressionCount,
    schema_version: "assistant-turn-promotion-decision/v1",
    score_gain: scoreGain,
    shadow_case_count: baselineSet.shadowCount,
  };
}

function validateEvaluationInput(input: AssistantTurnEvaluationInputV1): void {
  for (const [name, value] of [
    ["case_ref", input.case_ref],
    ["case_digest", input.case_digest],
    ["evaluator_ref", input.evaluator_ref],
    ["observation_ref", input.observation_ref],
    ["observation_digest", input.observation_digest],
    ["policy_ref", input.policy_ref],
  ] as const) {
    if (!value.trim() || value.length > 2_048) {
      throw new AssistantTurnEvaluationInputError(`${name} is required and bounded.`);
    }
  }
  for (const [name, value] of [
    ["claim_count", input.claim_count],
    ["grounded_claim_count", input.grounded_claim_count],
    ["subject_bound_claim_count", input.subject_bound_claim_count],
    ["required_action_count", input.required_action_count],
    ["delivered_action_count", input.delivered_action_count],
    ["internal_machinery_exposure_count", input.internal_machinery_exposure_count],
    ["source_failure_count", input.source_failure_count],
    ["disclosed_source_failure_count", input.disclosed_source_failure_count],
    ["relevant_evidence_source_count", input.relevant_evidence_source_count],
    ["used_evidence_source_count", input.used_evidence_source_count],
    ["tool_call_count", input.tool_call_count],
    ["redundant_tool_call_count", input.redundant_tool_call_count],
    ["selected_capability_count", input.selected_capability_count],
    ["latency_ms", input.latency_ms],
    ["unnecessary_clarification_count", input.unnecessary_clarification_count],
    ["planned_part_count", input.delivery.planned_part_count],
    ["posted_part_count", input.delivery.posted_part_count],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 0 || value > 1_000_000) {
      throw new AssistantTurnEvaluationInputError(`${name} must be a bounded non-negative integer.`);
    }
  }
  if (input.grounded_claim_count > input.claim_count) {
    throw new AssistantTurnEvaluationInputError(
      "Grounded claims cannot exceed observed claims.",
    );
  }
  if (input.subject_bound_claim_count > input.claim_count) {
    throw new AssistantTurnEvaluationInputError(
      "Subject-bound claims cannot exceed observed claims.",
    );
  }
  if (input.disclosed_source_failure_count > input.source_failure_count) {
    throw new AssistantTurnEvaluationInputError(
      "Disclosed source failures cannot exceed observed source failures.",
    );
  }
  if (input.used_evidence_source_count > input.relevant_evidence_source_count) {
    throw new AssistantTurnEvaluationInputError(
      "Used evidence sources cannot exceed relevant available sources.",
    );
  }
  if (input.delivery.posted_part_count > input.delivery.planned_part_count) {
    throw new AssistantTurnEvaluationInputError(
      "Posted delivery parts cannot exceed planned parts.",
    );
  }
  if (
    input.delivery.disposition === "suppress"
    && (input.delivery.planned_part_count !== 0 || input.delivery.posted_part_count !== 0)
  ) {
    throw new AssistantTurnEvaluationInputError(
      "Suppressed turns cannot include delivery parts.",
    );
  }
  if (
    input.requires_evidence
    && (input.claim_count === 0 || input.relevant_evidence_source_count === 0)
  ) {
    throw new AssistantTurnEvaluationInputError(
      "Evidence-required turns must report claims and relevant evidence sources.",
    );
  }
  if (!ASSISTANT_TURN_OUTCOME_STATES.includes(input.outcome_state)) {
    throw new AssistantTurnEvaluationInputError("The assistant outcome state is unsupported.");
  }
  if (!ASSISTANT_TURN_EVALUATION_PARTITIONS.includes(input.partition)) {
    throw new AssistantTurnEvaluationInputError("The evaluation partition is unsupported.");
  }
  if (
    input.delivery.disposition !== "respond"
    && input.delivery.disposition !== "suppress"
  ) {
    throw new AssistantTurnEvaluationInputError("The delivery disposition is unsupported.");
  }
  if (
    input.explicit_feedback !== undefined
    && input.explicit_feedback !== "positive"
    && input.explicit_feedback !== "negative"
  ) {
    throw new AssistantTurnEvaluationInputError("The explicit feedback value is unsupported.");
  }
  if (
    input.explicit_feedback_category !== undefined
    && !ANSWER_FEEDBACK_CATEGORIES.includes(input.explicit_feedback_category)
  ) {
    throw new AssistantTurnEvaluationInputError("The explicit feedback category is unsupported.");
  }
  if (
    input.explicit_feedback_category !== undefined
    && input.explicit_feedback !== undefined
    && (input.explicit_feedback_category === "helpful") !== (input.explicit_feedback === "positive")
  ) {
    throw new AssistantTurnEvaluationInputError("The explicit feedback value and category conflict.");
  }
  for (const [name, value] of [
    ["delivery.complete", input.delivery.complete],
    ["coverage_boundary_disclosed", input.coverage_boundary_disclosed],
    ["coverage_boundary_required", input.coverage_boundary_required],
    ["requires_evidence", input.requires_evidence],
    ["response_expected", input.response_expected],
    ["user_correction", input.user_correction],
  ] as const) {
    if (typeof value !== "boolean") {
      throw new AssistantTurnEvaluationInputError(`${name} must be boolean.`);
    }
  }
}

function evaluationSet(
  values: readonly AssistantTurnEvaluationV1[],
  label: string,
): {
  evaluatorRef: string;
  heldOutCount: number;
  policyRef: string;
  rows: Map<string, AssistantTurnEvaluationV1>;
  shadowCount: number;
} {
  if (values.length === 0) {
    throw new AssistantTurnEvaluationInputError(`${label} evaluations are required.`);
  }
  const policyRef = values[0]!.policy_ref;
  const evaluatorRef = values[0]!.evaluator_ref;
  const rows = new Map<string, AssistantTurnEvaluationV1>();
  const caseDigests = new Set<string>();
  let heldOutCount = 0;
  let shadowCount = 0;
  for (const value of values) {
    validateEvaluationReceipt(value);
    if (value.schema_version !== "assistant-turn-evaluation/v1") {
      throw new AssistantTurnEvaluationInputError("The evaluation schema is unsupported.");
    }
    if (value.partition !== "held_out" && value.partition !== "shadow") {
      throw new AssistantTurnEvaluationInputError(
        "Promotion accepts static held-out and shadow evaluations only.",
      );
    }
    if (value.policy_ref !== policyRef || value.evaluator_ref !== evaluatorRef) {
      throw new AssistantTurnEvaluationInputError(
        `All ${label} evaluations must use one policy and evaluator.`,
      );
    }
    const caseKey = `${value.partition}:${value.case_ref}`;
    if (rows.has(caseKey)) {
      throw new AssistantTurnEvaluationInputError(
        `Duplicate ${label} promotion case identity.`,
      );
    }
    if (caseDigests.has(value.case_digest)) {
      throw new AssistantTurnEvaluationInputError(
        `Duplicate ${label} case content cannot count in both evaluation partitions.`,
      );
    }
    if (value.partition === "held_out") heldOutCount += 1;
    else shadowCount += 1;
    caseDigests.add(value.case_digest);
    rows.set(caseKey, value);
  }
  if (heldOutCount < MINIMUM_HELD_OUT_CASES) {
    throw new AssistantTurnEvaluationInputError(
      `Promotion requires at least ${MINIMUM_HELD_OUT_CASES} static held-out cases.`,
    );
  }
  if (shadowCount < MINIMUM_SHADOW_CASES) {
    throw new AssistantTurnEvaluationInputError(
      `Promotion requires at least ${MINIMUM_SHADOW_CASES} shadow cases.`,
    );
  }
  return { evaluatorRef, heldOutCount, policyRef, rows, shadowCount };
}

function validateEvaluationReceipt(value: AssistantTurnEvaluationV1): void {
  for (const ref of [
    value.case_ref,
    value.case_digest,
    value.evaluator_ref,
    value.observation_ref,
    value.observation_digest,
    value.policy_ref,
  ]) {
    if (!ref.trim() || ref.length > 2_048) {
      throw new AssistantTurnEvaluationInputError(
        "Evaluation references and digests are required and bounded.",
      );
    }
  }
  if (!Number.isFinite(value.score) || value.score < 0 || value.score > 1) {
    throw new AssistantTurnEvaluationInputError(
      "Evaluation scores must be between zero and one.",
    );
  }
  for (const [name, dimension] of Object.entries(value.dimensions)) {
    if (!Number.isFinite(dimension) || dimension < 0 || dimension > 1) {
      throw new AssistantTurnEvaluationInputError(
        `Evaluation dimension ${name} must be between zero and one.`,
      );
    }
  }
  if (value.score !== scoreDimensions(value.dimensions)) {
    throw new AssistantTurnEvaluationInputError(
      "Evaluation score conflicts with its dimensions.",
    );
  }
  if (
    new Set(value.blockers).size !== value.blockers.length
    || value.blockers.some(
      (blocker) => !ASSISTANT_TURN_EVALUATION_BLOCKERS.includes(blocker),
    )
  ) {
    throw new AssistantTurnEvaluationInputError(
      "Evaluation blockers must be unique supported values.",
    );
  }
  if (value.passed !== (value.blockers.length === 0 && value.score >= PASS_SCORE)) {
    throw new AssistantTurnEvaluationInputError(
      "Evaluation pass state conflicts with its score or blockers.",
    );
  }
}

function deliveryScore(
  delivery: AssistantTurnDeliveryObservationV1,
  responseExpected: boolean,
): number {
  if (!responseExpected && delivery.disposition === "suppress") {
    return delivery.complete ? 1 : 0;
  }
  if (delivery.disposition !== "respond") return 0;
  return delivery.complete
    && delivery.planned_part_count > 0
    && delivery.posted_part_count === delivery.planned_part_count
    ? 1
    : 0;
}

function outcomeScore(value: AssistantTurnOutcomeStateV1): number {
  switch (value) {
    case "completed": return 1;
    case "owned": return 0.8;
    case "needs_user": return 0.5;
    case "blocked": return 0.25;
    case "unknown": return 0;
  }
}

function scoreDimensions(dimensions: AssistantTurnEvaluationDimensionsV1): number {
  return round(
    (dimensions.intervention_fit * 0.2)
    + (dimensions.outcome_closure * 0.2)
    + (dimensions.grounding * 0.15)
    + (dimensions.evidence_use * 0.1)
    + (dimensions.coverage_honesty * 0.1)
    + (dimensions.delivery_completeness * 0.1)
    + (dimensions.human_burden * 0.1)
    + (dimensions.execution_efficiency * 0.025)
    + (dimensions.latency_budget * 0.025),
  );
}

function boundedEfficiency(actual: number, budget: number): number {
  if (budget === 0) return actual === 0 ? 1 : 0;
  if (actual <= budget) return 1;
  return Math.max(0, 1 - ((actual - budget) / budget));
}

function blockerCount(rows: Map<string, AssistantTurnEvaluationV1>): number {
  return [...rows.values()].reduce((sum, row) => sum + row.blockers.length, 0);
}

function average(values: readonly number[]): number {
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function ratio(numerator: number, denominator: number): number {
  return denominator === 0 ? 1 : Math.max(0, Math.min(1, numerator / denominator));
}

function round(value: number): number {
  return Math.round(Math.max(-1, Math.min(1, value)) * 1_000) / 1_000;
}
