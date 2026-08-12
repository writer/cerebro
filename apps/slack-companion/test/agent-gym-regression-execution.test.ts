import assert from "node:assert/strict";
import test from "node:test";
import { digestAgentGymJson } from "../src/agent-gym/canonical-json.js";
import { planAgentGymRegressionReplay, validateAgentGymRegressionReplayPlan } from "../src/agent-gym/regression-replay-plan.js";
import { recordAgentGymRegressionReplayResult, validateAgentGymRegressionReplayResult } from "../src/agent-gym/regression-replay-result.js";
import { evaluateAgentGymRegressionReplay, validateAgentGymRegressionReplayEvaluation } from "../src/agent-gym/regression-replay-evaluation.js";
import { compareAgentGymRegressionReplay, validateAgentGymRegressionReplayComparison } from "../src/agent-gym/regression-replay-comparison.js";
import type { AgentGymRegressionReplayRequestV1 } from "../src/agent-gym/regression-replay-request.js";

const sha = (value: string): string => `sha256:${value.repeat(64).slice(0, 64)}`;

function request(): AgentGymRegressionReplayRequestV1 {
  const body = {
    augmentation_digest: sha("a"), baseline_candidate_ref: "agent-gym-candidate://baseline/one",
    case_digest: sha("b"), case_ref: "agent-gym-case://regression/one",
    challenger_candidate_ref: "agent-gym-candidate://challenger/one", fixture_receipt_digest: sha("c"),
    maximum_model_calls: 2, planned_at: "2026-08-12T13:00:00.000Z",
    request_ref: "agent-gym-replay-request://regression/one",
    schema_version: "agent-gym-regression-replay-request/v1" as const,
  };
  return { ...body, request_digest: digestAgentGymJson(body) };
}

function replayResult() {
  const plan = planAgentGymRegressionReplay(request(), { baseline_invocation_ref: "agent-gym-invocation://baseline/one", challenger_invocation_ref: "agent-gym-invocation://challenger/one", plan_ref: "agent-gym-replay-plan://regression/one", planned_at: "2026-08-12T13:01:00.000Z" });
  return recordAgentGymRegressionReplayResult(plan, {
    baseline: { candidate_ref: "agent-gym-candidate://baseline/one", invocation_receipt_digest: sha("d"), invocation_ref: plan.baseline_invocation_ref, latency_ms: 120, response_digest: sha("e"), total_tokens: 80 },
    challenger: { candidate_ref: "agent-gym-candidate://challenger/one", invocation_receipt_digest: sha("f"), invocation_ref: plan.challenger_invocation_ref, latency_ms: 100, response_digest: sha("1"), total_tokens: 72 },
    completed_at: "2026-08-12T13:02:00.000Z", result_ref: "agent-gym-replay-result://regression/one",
  });
}

function replayEvaluation() {
  const result = replayResult();
  const evaluation = evaluateAgentGymRegressionReplay(result, {
    baseline: { blocker_codes: [], candidate_ref: result.baseline.candidate_ref, evidence_digest: sha("2"), safety_passed: true, score: 0.72 },
    challenger: { blocker_codes: [], candidate_ref: result.challenger.candidate_ref, evidence_digest: sha("3"), safety_passed: true, score: 0.86 },
    evaluated_at: "2026-08-12T13:03:00.000Z", evaluation_ref: "agent-gym-replay-evaluation://regression/one",
  });
  return { evaluation, result };
}

test("seals an exact paired regression replay plan", () => {
  const plan = planAgentGymRegressionReplay(request(), {
    baseline_invocation_ref: "agent-gym-invocation://baseline/one",
    challenger_invocation_ref: "agent-gym-invocation://challenger/one",
    plan_ref: "agent-gym-replay-plan://regression/one", planned_at: "2026-08-12T13:01:00.000Z",
  });
  assert.equal(validateAgentGymRegressionReplayPlan(plan).replay_request_digest, request().request_digest);
  assert.throws(() => validateAgentGymRegressionReplayPlan({ ...plan, maximum_model_calls: 3 }));
});

test("records paired replay evidence without retaining model output", () => {
  const plan = planAgentGymRegressionReplay(request(), {
    baseline_invocation_ref: "agent-gym-invocation://baseline/one", challenger_invocation_ref: "agent-gym-invocation://challenger/one",
    plan_ref: "agent-gym-replay-plan://regression/one", planned_at: "2026-08-12T13:01:00.000Z",
  });
  const result = recordAgentGymRegressionReplayResult(plan, {
    baseline: { candidate_ref: "agent-gym-candidate://baseline/one", invocation_receipt_digest: sha("d"), invocation_ref: plan.baseline_invocation_ref, latency_ms: 120, response_digest: sha("e"), total_tokens: 80 },
    challenger: { candidate_ref: "agent-gym-candidate://challenger/one", invocation_receipt_digest: sha("f"), invocation_ref: plan.challenger_invocation_ref, latency_ms: 100, response_digest: sha("1"), total_tokens: 72 },
    completed_at: "2026-08-12T13:02:00.000Z", result_ref: "agent-gym-replay-result://regression/one",
  });
  assert.equal(validateAgentGymRegressionReplayResult(result).challenger.total_tokens, 72);
  assert.throws(() => recordAgentGymRegressionReplayResult(plan, { ...result, challenger: { ...result.challenger, invocation_ref: plan.baseline_invocation_ref } }));
});

test("binds independent scores to both replay candidates", () => {
  const result = replayResult();
  const evaluation = evaluateAgentGymRegressionReplay(result, {
    baseline: { blocker_codes: [], candidate_ref: result.baseline.candidate_ref, evidence_digest: sha("2"), safety_passed: true, score: 0.72 },
    challenger: { blocker_codes: [], candidate_ref: result.challenger.candidate_ref, evidence_digest: sha("3"), safety_passed: true, score: 0.86 },
    evaluated_at: "2026-08-12T13:03:00.000Z", evaluation_ref: "agent-gym-replay-evaluation://regression/one",
  });
  assert.equal(validateAgentGymRegressionReplayEvaluation(evaluation).challenger.score, 0.86);
  assert.throws(() => evaluateAgentGymRegressionReplay(result, { ...evaluation, challenger: { ...evaluation.challenger, safety_passed: true, blocker_codes: ["unsafe"] } }));
});

test("compares paired replay scores and latency deterministically", () => {
  const { evaluation, result } = replayEvaluation();
  const comparison = compareAgentGymRegressionReplay(result, evaluation, {
    compared_at: "2026-08-12T13:04:00.000Z", comparison_ref: "agent-gym-replay-comparison://regression/one",
  });
  assert.equal(comparison.outcome, "improved");
  assert.equal(comparison.latency_delta_ms, -20);
  assert.equal(validateAgentGymRegressionReplayComparison(comparison).score_delta, 0.14);
});
