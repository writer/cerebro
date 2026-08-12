import assert from "node:assert/strict";
import test from "node:test";
import {
  AssistantTurnEvaluationInputError,
  decideAssistantTurnPromotion,
  evaluateAssistantTurn,
  type AssistantTurnEvaluationInputV1,
  type AssistantTurnEvaluationV1,
} from "../src/index.js";

test("a machine handoff that needs no response completes with zero tools", () => {
  const receipt = evaluateAssistantTurn(observation({
    delivery: suppressedDelivery(),
    execution_lane: "ignore",
    outcome_state: "completed",
    response_expected: false,
  }));

  assert.equal(receipt.passed, true);
  assert.equal(receipt.score, 1);
  assert.deepEqual(receipt.blockers, []);
});

test("an unwanted response fails even when Slack accepted it", () => {
  const receipt = evaluateAssistantTurn(observation({
    delivery: completeDelivery(),
    execution_lane: "converse",
    outcome_state: "completed",
    response_expected: false,
  }));

  assert.equal(receipt.passed, false);
  assert.equal(receipt.dimensions.intervention_fit, 0);
  assert.ok(receipt.blockers.includes("unwanted_intervention"));
});

test("a grounded lookup passes with disclosed partial coverage", () => {
  const receipt = evaluateAssistantTurn(observation({
    claim_count: 2,
    disclosed_source_failure_count: 1,
    execution_lane: "lookup",
    grounded_claim_count: 2,
    latency_ms: 20_000,
    outcome_state: "completed",
    redundant_tool_call_count: 0,
    relevant_evidence_source_count: 2,
    requires_evidence: true,
    selected_capability_count: 2,
    source_failure_count: 1,
    tool_call_count: 2,
    used_evidence_source_count: 2,
  }));

  assert.equal(receipt.passed, true);
  assert.equal(receipt.score, 1);
  assert.equal(receipt.dimensions.coverage_honesty, 1);
  assert.equal(receipt.dimensions.grounding, 1);
});

test("direct conversation fails when it spends tools", () => {
  const receipt = evaluateAssistantTurn(observation({
    execution_lane: "converse",
    selected_capability_count: 1,
    tool_call_count: 1,
  }));

  assert.equal(receipt.passed, false);
  assert.equal(receipt.dimensions.execution_efficiency, 0);
  assert.ok(receipt.blockers.includes("tool_budget_exceeded"));
});

test("redundant retries and unused available evidence block the turn", () => {
  const receipt = evaluateAssistantTurn(observation({
    claim_count: 2,
    execution_lane: "investigate",
    grounded_claim_count: 2,
    redundant_tool_call_count: 1,
    relevant_evidence_source_count: 3,
    requires_evidence: true,
    tool_call_count: 4,
    used_evidence_source_count: 2,
  }));

  assert.equal(receipt.passed, false);
  assert.ok(receipt.blockers.includes("redundant_tool_call"));
  assert.ok(receipt.blockers.includes("available_evidence_not_used"));
});

test("delivery, clarification, correction, and feedback failures stay explicit", () => {
  const receipt = evaluateAssistantTurn(observation({
    delivery: {
      complete: false,
      disposition: "respond",
      planned_part_count: 2,
      posted_part_count: 1,
    },
    explicit_feedback: "negative",
    unnecessary_clarification_count: 1,
    user_correction: true,
  }));

  assert.equal(receipt.passed, false);
  assert.deepEqual(receipt.blockers, [
    "incomplete_delivery",
    "unnecessary_clarification",
    "user_correction",
    "negative_feedback",
  ]);
});

test("category feedback names the concrete answer failure", () => {
  const receipt = evaluateAssistantTurn(observation({
    explicit_feedback: "negative",
    explicit_feedback_category: "missed_source",
  }));

  assert.equal(receipt.passed, false);
  assert.deepEqual(receipt.blockers, [
    "negative_feedback",
    "missed_source_feedback",
  ]);
});

test("action, coverage, subject, and machinery failures stay explicit", () => {
  const receipt = evaluateAssistantTurn(observation({
    claim_count: 2,
    coverage_boundary_required: true,
    delivered_action_count: 1,
    grounded_claim_count: 2,
    internal_machinery_exposure_count: 1,
    relevant_evidence_source_count: 1,
    required_action_count: 2,
    requires_evidence: true,
    subject_bound_claim_count: 1,
    used_evidence_source_count: 1,
  }));

  assert.deepEqual(receipt.blockers, [
    "required_action_missing",
    "claim_subject_misbound",
    "coverage_boundary_missing",
    "internal_machinery_exposed",
  ]);
  assert.equal(receipt.dimensions.delivery_completeness, 0.5);
  assert.equal(receipt.dimensions.grounding, 0.5);
  assert.equal(receipt.dimensions.coverage_honesty, 0);
  assert.equal(receipt.dimensions.human_burden, 0);
});

test("observation counts and suppressed delivery fail closed", () => {
  assert.throws(
    () => evaluateAssistantTurn(observation({
      claim_count: 1,
      grounded_claim_count: 2,
    })),
    AssistantTurnEvaluationInputError,
  );
  assert.throws(
    () => evaluateAssistantTurn(observation({
      delivery: {
        complete: true,
        disposition: "suppress",
        planned_part_count: 1,
        posted_part_count: 0,
      },
    })),
    AssistantTurnEvaluationInputError,
  );
  const incompleteSuppression = evaluateAssistantTurn(observation({
    delivery: {
      complete: false,
      disposition: "suppress",
      planned_part_count: 0,
      posted_part_count: 0,
    },
    execution_lane: "ignore",
    response_expected: false,
  }));
  assert.ok(incompleteSuppression.blockers.includes("incomplete_delivery"));
});

test("promotion requires strict static and shadow outcome improvement", () => {
  const baseline = promotionSet((index, partition) => evaluation({
    case_ref: `case://${partition}-${index}`,
    partition,
    policy_ref: "policy://baseline",
    score: 0.72,
    blockers: ["outcome_unknown"],
  }));
  const candidate = promotionSet((index, partition) => evaluation({
    case_ref: `case://${partition}-${index}`,
    partition,
    policy_ref: "policy://candidate",
    score: 0.94,
    passed: true,
    blockers: [],
  }));

  const decision = decideAssistantTurnPromotion(baseline, candidate);
  assert.equal(decision.promotion_ready, true);
  assert.equal(decision.case_count, 16);
  assert.equal(decision.held_out_case_count, 8);
  assert.equal(decision.shadow_case_count, 8);
  assert.equal(decision.score_gain, 0.22);
  assert.equal(decision.candidate_blocker_count, 0);
});

test("promotion permits an outcome gain when both policies have zero blockers", () => {
  const baseline = promotionSet((index, partition) => evaluation({
    case_ref: `case://${partition}-${index}`,
    partition,
    policy_ref: "policy://baseline",
    score: 0.82,
    passed: true,
  }));
  const candidate = promotionSet((index, partition) => evaluation({
    case_ref: `case://${partition}-${index}`,
    partition,
    policy_ref: "policy://candidate",
    score: 0.9,
    passed: true,
  }));

  const decision = decideAssistantTurnPromotion(baseline, candidate);
  assert.equal(decision.promotion_ready, true);
  assert.equal(decision.baseline_blocker_count, 0);
  assert.equal(decision.candidate_blocker_count, 0);
});

test("a higher average cannot hide a new unwanted intervention", () => {
  const baseline = promotionSet((index, partition) => evaluation({
    case_ref: `case://${partition}-${index}`,
    partition,
    policy_ref: "policy://baseline",
    score: 0.7,
    blockers: ["outcome_unknown"],
  }));
  const candidate = promotionSet((index, partition) => evaluation({
    case_ref: `case://${partition}-${index}`,
    partition,
    policy_ref: "policy://candidate",
    score: index === 0 ? 0.75 : 0.95,
    passed: index !== 0,
    blockers: index === 0 ? ["unwanted_intervention"] : [],
  }));

  const decision = decideAssistantTurnPromotion(baseline, candidate);
  assert.equal(decision.candidate_average_score > decision.baseline_average_score, true);
  assert.equal(decision.promotion_ready, false);
  assert.ok(decision.blockers.includes("new_unwanted_intervention"));
});

test("promotion rejects mismatched static or shadow case digests", () => {
  const baseline = promotionSet((index, partition) => evaluation({
    case_ref: `case://${partition}-${index}`,
    partition,
    policy_ref: "policy://baseline",
  }));
  const candidate = promotionSet((index, partition) => evaluation({
    case_digest: partition === "shadow" && index === 7
      ? "sha256:changed"
      : `sha256:case-${partition}-${index}`,
    case_ref: `case://${partition}-${index}`,
    partition,
    policy_ref: "policy://candidate",
  }));

  assert.throws(
    () => decideAssistantTurnPromotion(baseline, candidate),
    AssistantTurnEvaluationInputError,
  );
});

test("promotion rejects a run without independently generated shadow cases", () => {
  const baseline = Array.from({ length: 8 }, (_, index) => evaluation({
    case_ref: `case://held-out-${index}`,
    partition: "held_out",
    policy_ref: "policy://baseline",
  }));
  const candidate = baseline.map((value) => ({
    ...value,
    policy_ref: "policy://candidate",
  }));

  assert.throws(
    () => decideAssistantTurnPromotion(baseline, candidate),
    /requires at least 8 shadow cases/,
  );
});

test("promotion rejects shadow cases copied from the static set", () => {
  const baseline = promotionSet((index, partition) => evaluation({
    case_digest: `sha256:case-${index}`,
    case_ref: `case://${partition}-${index}`,
    partition,
    policy_ref: "policy://baseline",
  }));
  const candidate = baseline.map((value) => ({
    ...value,
    policy_ref: "policy://candidate",
  }));

  assert.throws(
    () => decideAssistantTurnPromotion(baseline, candidate),
    /cannot count in both evaluation partitions/,
  );
});

test("promotion rejects a receipt whose score does not match its dimensions", () => {
  const baseline = promotionSet((index, partition) => evaluation({
    case_ref: `case://${partition}-${index}`,
    partition,
    policy_ref: "policy://baseline",
  }));
  baseline[15] = { ...baseline[15]!, score: 0.99 };
  const candidate = promotionSet((index, partition) => evaluation({
    case_ref: `case://${partition}-${index}`,
    partition,
    policy_ref: "policy://candidate",
  }));

  assert.throws(
    () => decideAssistantTurnPromotion(baseline, candidate),
    /score conflicts with its dimensions/,
  );
});

function observation(
  changes: Partial<AssistantTurnEvaluationInputV1> = {},
): AssistantTurnEvaluationInputV1 {
  const claimCount = changes.claim_count ?? 0;
  return {
    case_digest: "sha256:case",
    case_ref: "case://turn-1",
    claim_count: claimCount,
    coverage_boundary_disclosed: false,
    coverage_boundary_required: false,
    delivery: completeDelivery(),
    delivered_action_count: 0,
    disclosed_source_failure_count: 0,
    evaluator_ref: "evaluation://held-out-1",
    execution_lane: "continue",
    grounded_claim_count: 0,
    internal_machinery_exposure_count: 0,
    latency_ms: 1_000,
    observation_digest: "sha256:observation",
    observation_ref: "observation://turn-1",
    outcome_state: "completed",
    partition: "held_out",
    policy_ref: "policy://candidate",
    redundant_tool_call_count: 0,
    relevant_evidence_source_count: 0,
    required_action_count: 0,
    requires_evidence: false,
    response_expected: true,
    selected_capability_count: 0,
    source_failure_count: 0,
    subject_bound_claim_count: claimCount,
    tool_call_count: 0,
    unnecessary_clarification_count: 0,
    used_evidence_source_count: 0,
    user_correction: false,
    ...changes,
  };
}

function completeDelivery() {
  return {
    complete: true,
    disposition: "respond" as const,
    planned_part_count: 1,
    posted_part_count: 1,
  };
}

function suppressedDelivery() {
  return {
    complete: true,
    disposition: "suppress" as const,
    planned_part_count: 0,
    posted_part_count: 0,
  };
}

function promotionSet(
  create: (
    index: number,
    partition: "held_out" | "shadow",
  ) => AssistantTurnEvaluationV1,
): AssistantTurnEvaluationV1[] {
  return (["held_out", "shadow"] as const).flatMap((partition) => (
    Array.from({ length: 8 }, (_, index) => create(index, partition))
  ));
}

function evaluation(
  changes: Partial<AssistantTurnEvaluationV1> = {},
): AssistantTurnEvaluationV1 {
  const caseRef = changes.case_ref ?? "case://0";
  const suffix = caseRef.slice("case://".length);
  const score = changes.score ?? 0.7;
  return {
    blockers: [],
    case_digest: `sha256:case-${suffix}`,
    case_ref: caseRef,
    dimensions: {
      coverage_honesty: score,
      delivery_completeness: score,
      evidence_use: score,
      execution_efficiency: score,
      grounding: score,
      human_burden: score,
      intervention_fit: score,
      latency_budget: score,
      outcome_closure: score,
    },
    evaluator_ref: "evaluation://sealed-held-out-1",
    observation_digest: `sha256:observation-${suffix}`,
    observation_ref: `observation://${suffix}`,
    partition: "held_out",
    passed: false,
    policy_ref: "policy://candidate",
    schema_version: "assistant-turn-evaluation/v1",
    score,
    ...changes,
  };
}
