import assert from "node:assert/strict";
import test from "node:test";
import { defineAgentGymEvaluatorRubric } from "../src/agent-gym/evaluator-rubric.js";
import { defineAgentGymEvaluatorManifest } from "../src/agent-gym/evaluator-manifest.js";
import { decideAgentGymEvaluatorAdmission } from "../src/agent-gym/evaluator-admission.js";
import { bindAgentGymRegressionReplayEvaluators, validateAgentGymRegressionReplayEvaluatorBinding } from "../src/agent-gym/regression-replay-evaluator-binding.js";
import { validateAgentGymRegressionReplayEvaluatorInput, validateAgentGymRegressionReplayEvaluatorOutput } from "../src/agent-gym/regression-replay-evaluator-port.js";
import { recordAgentGymRegressionReplayResult } from "../src/agent-gym/regression-replay-result.js";
import { digestAgentGymJson } from "../src/agent-gym/canonical-json.js";

const sha = (value: string): string => `sha256:${value.repeat(64).slice(0, 64)}`;
const rubric = defineAgentGymEvaluatorRubric({ metrics: [{ blocking: true, evaluator_kind: "deterministic", metric_id: "safety", minimum_score: 1, weight: 1 }], rubric_ref: "agent-gym-rubric://regression/runtime", schema_version: "agent-gym-evaluator-rubric/v1" });
const evaluator = defineAgentGymEvaluatorManifest({ evaluator_kind: "deterministic", evaluator_ref: "agent-gym-evaluator://regression/safety", implementation_digest: sha("a"), output_schema_digest: sha("b"), rubric_digest: rubric.rubric_digest, schema_version: "agent-gym-evaluator-manifest/v1" });
const admission = decideAgentGymEvaluatorAdmission(rubric, [evaluator], [], { maximum_calibration_age_ms: 86_400_000, policy_ref: "agent-gym-evaluator-policy://regression/one", required_calibration_dataset_digest: sha("c"), required_calibration_policy_digest: sha("d"), schema_version: "agent-gym-evaluator-admission-policy/v1" }, "2026-08-12T14:00:00.000Z");

function result() {
  const planBody = { baseline_invocation_ref: "agent-gym-invocation://baseline/one", case_digest: sha("e"), case_ref: "agent-gym-case://regression/one", challenger_invocation_ref: "agent-gym-invocation://challenger/one", maximum_model_calls: 2, plan_ref: "agent-gym-replay-plan://regression/one", planned_at: "2026-08-12T13:00:00.000Z", replay_request_digest: sha("f"), schema_version: "agent-gym-regression-replay-plan/v1" as const };
  const plan = { ...planBody, plan_digest: digestAgentGymJson(planBody) };
  return recordAgentGymRegressionReplayResult(plan, { baseline: { candidate_ref: "agent-gym-candidate://baseline/one", invocation_receipt_digest: sha("1"), invocation_ref: plan.baseline_invocation_ref, latency_ms: 10, response_digest: sha("2"), total_tokens: 20 }, challenger: { candidate_ref: "agent-gym-candidate://challenger/one", invocation_receipt_digest: sha("3"), invocation_ref: plan.challenger_invocation_ref, latency_ms: 9, response_digest: sha("4"), total_tokens: 18 }, completed_at: "2026-08-12T13:30:00.000Z", result_ref: "agent-gym-replay-result://regression/one" });
}

function binding() {
  return bindAgentGymRegressionReplayEvaluators(result(), rubric, [evaluator], admission, { binding_ref: "agent-gym-evaluator-binding://regression/one", bound_at: "2026-08-12T14:01:00.000Z" });
}

test("binds replay scoring to admitted exact evaluator evidence", () => {
  assert.equal(validateAgentGymRegressionReplayEvaluatorBinding(binding()).evaluator_admission_digest, admission.decision_digest);
});

test("validates bounded evaluator inputs and fail-closed outputs", () => {
  const bound = binding();
  const input = validateAgentGymRegressionReplayEvaluatorInput({ binding_digest: bound.binding_digest,
    candidate_ref: bound.baseline_candidate_ref, case_ref: "agent-gym-case://regression/one",
    evaluator_digests: bound.evaluator_digests, output_text: "A bounded candidate answer.", response_digest: sha("2"),
    rubric_digest: bound.rubric_digest, schema_version: "agent-gym-regression-replay-evaluator-input/v1" });
  assert.equal(input.output_text, "A bounded candidate answer.");
  assert.equal(validateAgentGymRegressionReplayEvaluatorOutput({ binding_digest: bound.binding_digest, blocker_codes: [],
    candidate_ref: bound.baseline_candidate_ref, evidence_digest: sha("5"), safety_passed: true,
    schema_version: "agent-gym-regression-replay-evaluator-output/v1", score: 0.8 }).score, 0.8);
  assert.throws(() => validateAgentGymRegressionReplayEvaluatorOutput({ binding_digest: bound.binding_digest,
    blocker_codes: ["unsafe"], candidate_ref: bound.baseline_candidate_ref, evidence_digest: sha("5"), safety_passed: true,
    schema_version: "agent-gym-regression-replay-evaluator-output/v1", score: 0.8 }));
});

test("rejects evaluator evidence that was not admitted", () => {
  assert.throws(() => bindAgentGymRegressionReplayEvaluators(result(), rubric, [evaluator], { ...admission, admitted: false }, { binding_ref: "agent-gym-evaluator-binding://regression/invalid", bound_at: "2026-08-12T14:01:00.000Z" }));
});
